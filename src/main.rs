use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const API_URL: &str = "https://api.fast.com/netflix/speedtest/v2";
const TOKEN: &str = "YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm";
const CHUNK_SIZE: u64 = 26_214_400; // 25 MB download chunks
const TEST_DURATION: Duration = Duration::from_secs(10);
const PARALLEL_STREAMS: usize = 4;

#[derive(Debug, Deserialize)]
struct ApiResponse {
    client: ClientInfo,
    targets: Vec<Target>,
}

#[derive(Debug, Deserialize)]
struct ClientInfo {
    ip: String,
    isp: String,
    location: Location,
}

#[derive(Debug, Deserialize, Clone)]
struct Location {
    city: String,
    country: String,
}

#[derive(Debug, Deserialize, Clone)]
struct Target {
    url: String,
    location: Location,
}

struct TestResults {
    download_speed: f64,
    upload_speed: f64,
    latency_unloaded: f64,
    latency_loaded: f64,
    downloaded_bytes: u64,
    uploaded_bytes: u64,
}

#[derive(Serialize)]
struct JsonOutput {
    download: SpeedResult,
    upload: SpeedResult,
    latency: LatencyResult,
    client: JsonClient,
    servers: Vec<String>,
}

#[derive(Serialize)]
struct SpeedResult {
    bps: f64,
    bytes: u64,
}

#[derive(Serialize)]
struct LatencyResult {
    unloaded_ms: f64,
    loaded_ms: f64,
}

#[derive(Serialize)]
struct JsonClient {
    ip: String,
    isp: String,
    city: String,
    country: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let json_mode = args.iter().any(|a| a == "--json" || a == "-j");

    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
        .build()?;

    // Fetch speedtest targets
    if !json_mode {
        print!("Connecting...");
        std::io::stdout().flush()?;
    }

    let url = format!("{}?https=true&token={}&urlCount=5", API_URL, TOKEN);
    let response: ApiResponse = client.get(&url).send().await?.json().await?;

    if !json_mode {
        print!("\r\x1b[K"); // Clear line
    }

    if response.targets.is_empty() {
        if json_mode {
            eprintln!("{{\"error\": \"No speedtest targets available\"}}");
        } else {
            eprintln!("No speedtest targets available");
        }
        return Ok(());
    }

    // Use first few targets for parallel streams
    let targets: Vec<_> = response
        .targets
        .into_iter()
        .take(PARALLEL_STREAMS)
        .collect();

    // Collect server locations
    let servers: Vec<String> = targets
        .iter()
        .map(|t| format!("{}, {}", t.location.city, t.location.country))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    // Run download test immediately
    if !json_mode {
        println!("Download");
    }
    let (download_speed, downloaded_bytes, latency_loaded) =
        run_download_test(&client, &targets, json_mode).await?;

    // Run upload test
    if !json_mode {
        println!("\nUpload");
    }
    let (upload_speed, uploaded_bytes) = run_upload_test(&client, &targets, json_mode).await?;

    // Measure unloaded latency after tests complete
    if !json_mode {
        print!("\nMeasuring latency...");
        std::io::stdout().flush()?;
    }
    let latency_unloaded = measure_latency(&client, &targets[0]).await?;
    if !json_mode {
        print!("\r\x1b[K");
    }

    let results = TestResults {
        download_speed,
        upload_speed,
        latency_unloaded,
        latency_loaded,
        downloaded_bytes,
        uploaded_bytes,
    };

    // Display results
    if json_mode {
        print_json(&results, &response.client, &servers);
    } else {
        print_results(&results, &response.client, &servers);
    }

    Ok(())
}

async fn measure_latency(client: &reqwest::Client, target: &Target) -> Result<f64, Box<dyn std::error::Error>> {
    let url = make_latency_url(&target.url);
    let mut latencies = Vec::new();

    // Take 5 measurements
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

    // Return median or 0 if no successful measurements
    if latencies.is_empty() {
        return Ok(0.0);
    }
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Ok(latencies[latencies.len() / 2])
}

fn make_latency_url(base_url: &str) -> String {
    if let Some(idx) = base_url.find('?') {
        let (base, query) = base_url.split_at(idx);
        format!("{}/range/0-0{}", base, query)
    } else {
        format!("{}/range/0-0", base_url)
    }
}

fn make_download_url(base_url: &str) -> String {
    if let Some(idx) = base_url.find('?') {
        let (base, query) = base_url.split_at(idx);
        format!("{}/range/0-{}{}", base, CHUNK_SIZE, query)
    } else {
        format!("{}/range/0-{}", base_url, CHUNK_SIZE)
    }
}

fn make_upload_url(base_url: &str) -> String {
    make_latency_url(base_url) // Upload uses same endpoint, just POST with body
}

async fn run_download_test(
    client: &reqwest::Client,
    targets: &[Target],
    quiet: bool,
) -> Result<(f64, u64, f64), Box<dyn std::error::Error>> {
    let total_bytes = Arc::new(AtomicU64::new(0));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let start = Instant::now();

    let urls: Vec<String> = targets.iter().map(|t| make_download_url(&t.url)).collect();
    let latency_url = make_latency_url(&targets[0].url);

    // Spawn download tasks
    let mut handles = Vec::new();
    for url in &urls {
        let client = client.clone();
        let url = url.clone();
        let total_bytes = Arc::clone(&total_bytes);
        let stop_flag = Arc::clone(&stop_flag);

        handles.push(tokio::spawn(async move {
            download_loop(&client, &url, total_bytes, stop_flag).await
        }));
    }

    // Spawn latency measurement task
    let loaded_latencies = Arc::new(std::sync::Mutex::new(Vec::<f64>::new()));
    let latency_stop = Arc::new(AtomicBool::new(false));
    let latency_client = client.clone();
    let latency_lats = Arc::clone(&loaded_latencies);
    let latency_stop_clone = Arc::clone(&latency_stop);
    let latency_url_clone = latency_url.clone();

    let latency_handle = tokio::spawn(async move {
        // Wait for download to ramp up
        tokio::time::sleep(Duration::from_secs(2)).await;

        while !latency_stop_clone.load(Ordering::Relaxed) {
            if let Ok(lat) = measure_single_latency(&latency_client, &latency_url_clone).await {
                if let Ok(mut lats) = latency_lats.lock() {
                    lats.push(lat);
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    // Progress display loop
    let mut last_bytes = 0u64;
    let mut last_time = Instant::now();
    let mut speeds: Vec<f64> = Vec::new();

    while start.elapsed() < TEST_DURATION {
        tokio::time::sleep(Duration::from_millis(250)).await;

        let bytes = total_bytes.load(Ordering::Relaxed);
        let now = Instant::now();
        let dt = now.duration_since(last_time).as_secs_f64();

        if dt > 0.0 && bytes > last_bytes {
            let instant_speed = ((bytes - last_bytes) as f64 * 8.0) / dt;
            speeds.push(instant_speed);

            let avg_speed = if speeds.len() > 8 {
                speeds[speeds.len() - 8..].iter().sum::<f64>() / 8.0
            } else {
                speeds.iter().sum::<f64>() / speeds.len() as f64
            };

            if !quiet {
                print!("\r  {}   ", format_speed(avg_speed));
                std::io::stdout().flush().ok();
            }
        }

        last_bytes = bytes;
        last_time = now;
    }

    latency_stop.store(true, Ordering::Relaxed);
    let _ = latency_handle.await;

    stop_flag.store(true, Ordering::Relaxed);
    for handle in handles {
        let _ = handle.await;
    }

    let final_bytes = total_bytes.load(Ordering::Relaxed);
    let elapsed = start.elapsed().as_secs_f64();
    let speed = (final_bytes as f64 * 8.0) / elapsed;

    // Calculate loaded latency (median)
    let latency_loaded = if let Ok(mut lats) = loaded_latencies.lock() {
        if !lats.is_empty() {
            lats.sort_by(|a, b| a.partial_cmp(b).unwrap());
            lats[lats.len() / 2]
        } else {
            0.0
        }
    } else {
        0.0
    };

    Ok((speed, final_bytes, latency_loaded))
}

async fn measure_single_latency(client: &reqwest::Client, url: &str) -> Result<f64, reqwest::Error> {
    let start = Instant::now();
    let _ = client.post(url).body("").send().await?;
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

async fn download_loop(
    client: &reqwest::Client,
    url: &str,
    total_bytes: Arc<AtomicU64>,
    stop_flag: Arc<AtomicBool>,
) {
    while !stop_flag.load(Ordering::Relaxed) {
        if let Ok(response) = client.get(url).send().await {
            let mut stream = response.bytes_stream();

            while let Some(chunk) = stream.next().await {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                if let Ok(data) = chunk {
                    total_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
            }
        }
    }
}

async fn run_upload_test(
    client: &reqwest::Client,
    targets: &[Target],
    quiet: bool,
) -> Result<(f64, u64), Box<dyn std::error::Error>> {
    let total_bytes = Arc::new(AtomicU64::new(0));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let start = Instant::now();

    let urls: Vec<String> = targets.iter().map(|t| make_upload_url(&t.url)).collect();

    // Spawn upload tasks
    let mut handles = Vec::new();
    for url in &urls {
        let client = client.clone();
        let url = url.clone();
        let total_bytes = Arc::clone(&total_bytes);
        let stop_flag = Arc::clone(&stop_flag);

        handles.push(tokio::spawn(async move {
            upload_loop(&client, &url, total_bytes, stop_flag).await
        }));
    }

    // Progress display loop
    let mut last_bytes = 0u64;
    let mut last_time = Instant::now();
    let mut speeds: Vec<f64> = Vec::new();

    while start.elapsed() < TEST_DURATION {
        tokio::time::sleep(Duration::from_millis(250)).await;

        let bytes = total_bytes.load(Ordering::Relaxed);
        let now = Instant::now();
        let dt = now.duration_since(last_time).as_secs_f64();

        if dt > 0.0 && bytes > last_bytes {
            let instant_speed = ((bytes - last_bytes) as f64 * 8.0) / dt;
            speeds.push(instant_speed);

            let avg_speed = if speeds.len() > 8 {
                speeds[speeds.len() - 8..].iter().sum::<f64>() / 8.0
            } else {
                speeds.iter().sum::<f64>() / speeds.len() as f64
            };

            if !quiet {
                print!("\r  {}   ", format_speed(avg_speed));
                std::io::stdout().flush().ok();
            }
        }

        last_bytes = bytes;
        last_time = now;
    }

    stop_flag.store(true, Ordering::Relaxed);
    for handle in handles {
        let _ = handle.await;
    }

    let final_bytes = total_bytes.load(Ordering::Relaxed);
    let elapsed = start.elapsed().as_secs_f64();
    let speed = (final_bytes as f64 * 8.0) / elapsed;

    Ok((speed, final_bytes))
}

async fn upload_loop(
    client: &reqwest::Client,
    url: &str,
    total_bytes: Arc<AtomicU64>,
    stop_flag: Arc<AtomicBool>,
) {
    // Use 128KB chunks for upload
    let chunk_size: usize = 131_072;
    let chunk: Vec<u8> = vec![0u8; chunk_size];

    while !stop_flag.load(Ordering::Relaxed) {
        match client
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .timeout(Duration::from_secs(10))
            .body(chunk.clone())
            .send()
            .await
        {
            Ok(resp) => {
                // Wait for response to complete
                let _ = resp.bytes().await;
                total_bytes.fetch_add(chunk_size as u64, Ordering::Relaxed);
            }
            Err(_) => {
                // Small delay on error to avoid tight loop
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

fn print_json(results: &TestResults, client: &ClientInfo, servers: &[String]) {
    let output = JsonOutput {
        download: SpeedResult {
            bps: results.download_speed,
            bytes: results.downloaded_bytes,
        },
        upload: SpeedResult {
            bps: results.upload_speed,
            bytes: results.uploaded_bytes,
        },
        latency: LatencyResult {
            unloaded_ms: results.latency_unloaded,
            loaded_ms: results.latency_loaded,
        },
        client: JsonClient {
            ip: client.ip.clone(),
            isp: client.isp.clone(),
            city: client.location.city.clone(),
            country: client.location.country.clone(),
        },
        servers: servers.to_vec(),
    };
    println!("{}", serde_json::to_string(&output).unwrap());
}

fn print_results(results: &TestResults, client: &ClientInfo, servers: &[String]) {
    println!();
    println!(
        "   Download  {:>10}",
        format_speed(results.download_speed)
    );
    println!(
        "   Upload    {:>10}",
        format_speed(results.upload_speed)
    );
    println!();
    println!("   Latency");
    println!("   Unloaded  {:>7.0} ms", results.latency_unloaded);
    println!("   Loaded    {:>7.0} ms", results.latency_loaded);
    println!();
    println!(
        "   Client     {}, {}",
        client.location.city, client.location.country
    );
    println!("              {}  {}", client.ip, client.isp);
    println!("   Server(s)  {}", servers.join(" | "));
    println!();
    println!(
        "   Data       {} ↓  {} ↑",
        format_bytes(results.downloaded_bytes),
        format_bytes(results.uploaded_bytes)
    );
    println!();
}

fn format_speed(bits_per_sec: f64) -> String {
    if bits_per_sec >= 1_000_000_000.0 {
        format!("{:.1} Gbps", bits_per_sec / 1_000_000_000.0)
    } else if bits_per_sec >= 100_000_000.0 {
        format!("{:.0} Mbps", bits_per_sec / 1_000_000.0)
    } else if bits_per_sec >= 1_000_000.0 {
        format!("{:.1} Mbps", bits_per_sec / 1_000_000.0)
    } else if bits_per_sec >= 1_000.0 {
        format!("{:.0} Kbps", bits_per_sec / 1_000.0)
    } else {
        format!("{:.0} bps", bits_per_sec)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
