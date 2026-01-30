mod display;
mod test;
mod tui;
mod types;

use std::time::Duration;
use types::{ApiResponse, DataPoint, TestHistory, TestResults, TestState};

const API_URL: &str = "https://api.fast.com/netflix/speedtest/v2";
const TOKEN: &str = "YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm";
const PARALLEL_STREAMS: usize = 4;
const TEST_DURATION: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let json_mode = args.iter().any(|a| a == "--json" || a == "-j");

    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
        .build()?;

    // Fetch speedtest targets
    if json_mode {
        // Silent mode for JSON
    } else {
        print!("Connecting to fast.com...");
        std::io::Write::flush(&mut std::io::stdout())?;
    }

    let url = format!("{}?https=true&token={}&urlCount=5", API_URL, TOKEN);
    let response: ApiResponse = client.get(&url).send().await?.json().await?;

    if !json_mode {
        print!("\r\x1b[K");
    }

    if response.targets.is_empty() {
        if json_mode {
            eprintln!("{{\"error\": \"No speedtest targets available\"}}");
        } else {
            eprintln!("No speedtest targets available");
        }
        return Ok(());
    }

    let targets: Vec<_> = response
        .targets
        .into_iter()
        .take(PARALLEL_STREAMS)
        .collect();

    let servers: Vec<String> = targets
        .iter()
        .map(|t| format!("{}, {}", t.location.city, t.location.country))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    if json_mode {
        // Run without TUI for JSON mode
        run_json_mode(&client, &targets, &response.client, &servers).await?;
    } else {
        // Run with TUI
        run_tui_mode(&client, &targets, &response.client, &servers).await?;
    }

    Ok(())
}

async fn run_json_mode(
    client: &reqwest::Client,
    targets: &[types::Target],
    client_info: &types::ClientInfo,
    servers: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let state = TestState::new();

    // Spawn all test tasks
    let download_handles = test::spawn_download_tasks(client, targets, &state);
    let upload_handles = test::spawn_upload_tasks(client, targets, &state);
    let latency_handle = test::spawn_latency_task(client, &targets[0], &state);

    // Wait for test duration
    tokio::time::sleep(TEST_DURATION).await;
    let elapsed = state.elapsed().as_secs_f64();

    // Stop all tasks
    state.stop();
    let _ = latency_handle.await;
    for handle in download_handles {
        let _ = handle.await;
    }
    for handle in upload_handles {
        let _ = handle.await;
    }

    // Measure unloaded latency
    let latency_unloaded = test::measure_unloaded_latency(client, &targets[0]).await?;

    let download_bytes = state.get_download_bytes();
    let upload_bytes = state.get_upload_bytes();

    let results = TestResults {
        download_speed: (download_bytes as f64 * 8.0) / elapsed,
        upload_speed: (upload_bytes as f64 * 8.0) / elapsed,
        latency_unloaded,
        latency_loaded: state.get_median_latency(),
        downloaded_bytes: download_bytes,
        uploaded_bytes: upload_bytes,
    };

    display::print_json(&results, client_info, servers);
    Ok(())
}

async fn run_tui_mode(
    client: &reqwest::Client,
    targets: &[types::Target],
    client_info: &types::ClientInfo,
    servers: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tui = tui::Tui::new()?;
    let state = TestState::new();
    let mut history = TestHistory::new();

    // Spawn all test tasks concurrently
    let download_handles = test::spawn_download_tasks(client, targets, &state);
    let upload_handles = test::spawn_upload_tasks(client, targets, &state);
    let latency_handle = test::spawn_latency_task(client, &targets[0], &state);

    let mut prev_download = 0u64;
    let mut prev_upload = 0u64;
    let mut last_sample = std::time::Instant::now();

    // Main UI loop
    while state.elapsed() < TEST_DURATION {
        // Check for quit
        if tui.should_quit()? {
            state.stop();
            break;
        }

        // Sample and record data
        let now = std::time::Instant::now();
        let dt = now.duration_since(last_sample).as_secs_f64();

        if dt >= 0.05 {
            let point = tui::sample_state(&state, prev_download, prev_upload, dt);
            history.add_point(point);
            prev_download = state.get_download_bytes();
            prev_upload = state.get_upload_bytes();
            last_sample = now;
        }

        // Draw UI
        tui.draw(&state, &history, client_info, servers, "Testing")?;

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let elapsed = state.elapsed().as_secs_f64();

    // Signal stop and wait for tasks
    state.stop();
    let _ = latency_handle.await;
    for handle in download_handles {
        let _ = handle.await;
    }
    for handle in upload_handles {
        let _ = handle.await;
    }

    // Final draw
    tui.draw(&state, &history, client_info, servers, "Measuring unloaded latency...")?;

    // Measure unloaded latency (requires idle connection)
    let latency_unloaded = test::measure_unloaded_latency(client, &targets[0]).await?;

    // Calculate final results
    let download_bytes = state.get_download_bytes();
    let upload_bytes = state.get_upload_bytes();

    // Add final point with average speeds
    let final_point = DataPoint {
        time: elapsed,
        download_speed: (download_bytes as f64 * 8.0) / elapsed,
        upload_speed: (upload_bytes as f64 * 8.0) / elapsed,
        latency: state.get_median_latency(),
    };
    history.add_point(final_point);

    // Show completed state briefly
    tui.draw(&state, &history, client_info, servers, "Complete")?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Restore terminal
    drop(tui);

    // Print final results to terminal
    let results = TestResults {
        download_speed: (download_bytes as f64 * 8.0) / elapsed,
        upload_speed: (upload_bytes as f64 * 8.0) / elapsed,
        latency_unloaded,
        latency_loaded: state.get_median_latency(),
        downloaded_bytes: download_bytes,
        uploaded_bytes: upload_bytes,
    };

    display::print_results(&results, client_info, servers);
    Ok(())
}
