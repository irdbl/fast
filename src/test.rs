use crate::types::{Target, TestState};
use futures::StreamExt;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const CHUNK_SIZE: u64 = 26_214_400; // 25 MB download chunks

fn make_url_with_path(base_url: &str, path: &str) -> String {
    if let Some(idx) = base_url.find('?') {
        let (base, query) = base_url.split_at(idx);
        format!("{}{}{}", base, path, query)
    } else {
        format!("{}{}", base_url, path)
    }
}

fn make_latency_url(base_url: &str) -> String {
    make_url_with_path(base_url, "/range/0-0")
}

fn make_download_url(base_url: &str) -> String {
    make_url_with_path(base_url, &format!("/range/0-{}", CHUNK_SIZE))
}

fn make_upload_url(base_url: &str) -> String {
    make_latency_url(base_url)
}

pub async fn measure_unloaded_latency(
    client: &reqwest::Client,
    target: &Target,
) -> Result<f64, Box<dyn std::error::Error>> {
    let url = make_latency_url(&target.url);
    let mut latencies = Vec::new();

    for _ in 0..5 {
        let start = Instant::now();
        if client
            .post(&url)
            .timeout(Duration::from_secs(5))
            .body("")
            .send()
            .await
            .is_ok()
        {
            latencies.push(start.elapsed().as_secs_f64() * 1000.0);
        }
    }

    if latencies.is_empty() {
        return Ok(0.0);
    }
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Ok(latencies[latencies.len() / 2])
}

/// Spawns download workers that update shared state
pub fn spawn_download_tasks(
    client: &reqwest::Client,
    targets: &[Target],
    state: &TestState,
) -> Vec<tokio::task::JoinHandle<()>> {
    let urls: Vec<String> = targets.iter().map(|t| make_download_url(&t.url)).collect();
    let mut handles = Vec::new();

    for url in urls {
        let client = client.clone();
        let download_bytes = state.download_bytes.clone();
        let stop_flag = state.stop_flag.clone();

        handles.push(tokio::spawn(async move {
            while !stop_flag.load(Ordering::Relaxed) {
                if let Ok(response) = client.get(&url).send().await {
                    let mut stream = response.bytes_stream();

                    while let Some(chunk) = stream.next().await {
                        if stop_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        if let Ok(data) = chunk {
                            download_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                        }
                    }
                }
            }
        }));
    }

    handles
}

/// Spawns upload workers that update shared state
pub fn spawn_upload_tasks(
    client: &reqwest::Client,
    targets: &[Target],
    state: &TestState,
) -> Vec<tokio::task::JoinHandle<()>> {
    let urls: Vec<String> = targets.iter().map(|t| make_upload_url(&t.url)).collect();
    let mut handles = Vec::new();

    let chunk_size: usize = 131_072; // 128KB
    let chunk: Vec<u8> = vec![0u8; chunk_size];

    for url in urls {
        let client = client.clone();
        let upload_bytes = state.upload_bytes.clone();
        let stop_flag = state.stop_flag.clone();
        let chunk = chunk.clone();

        handles.push(tokio::spawn(async move {
            while !stop_flag.load(Ordering::Relaxed) {
                match client
                    .post(&url)
                    .header("Content-Type", "application/octet-stream")
                    .timeout(Duration::from_secs(10))
                    .body(chunk.clone())
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let _ = resp.bytes().await;
                        upload_bytes.fetch_add(chunk_size as u64, Ordering::Relaxed);
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }));
    }

    handles
}

/// Spawns a latency measurement task that updates shared state
pub fn spawn_latency_task(
    client: &reqwest::Client,
    target: &Target,
    state: &TestState,
) -> tokio::task::JoinHandle<()> {
    let client = client.clone();
    let url = make_latency_url(&target.url);
    let latencies = state.latencies.clone();
    let stop_flag = state.stop_flag.clone();

    tokio::spawn(async move {
        // Small initial delay to let transfers start
        tokio::time::sleep(Duration::from_millis(500)).await;

        while !stop_flag.load(Ordering::Relaxed) {
            let start = Instant::now();
            if let Ok(_) = client
                .post(&url)
                .timeout(Duration::from_secs(5))
                .body("")
                .send()
                .await
            {
                let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                if let Ok(mut lats) = latencies.lock() {
                    lats.push(latency_ms);
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
}

