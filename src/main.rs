mod display;
mod nat;
mod test;
mod tui;
mod types;

use std::sync::{Arc, Mutex};
use std::time::Duration;
use nat::DetectionResult;
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
        run_json_mode(&client, &targets, &response.client, &servers).await?;
    } else {
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

    // Spawn all test tasks including NAT detection
    let download_handles = test::spawn_download_tasks(client, targets, &state);
    let upload_handles = test::spawn_upload_tasks(client, targets, &state);
    let latency_handle = test::spawn_latency_task(client, &targets[0], &state);

    let nat_log = nat::new_debug_log();
    let nat_handle = tokio::spawn(nat::detect_nat_topology(nat_log));

    // Wait for test duration
    tokio::time::sleep(TEST_DURATION).await;
    let elapsed = state.elapsed().as_secs_f64();
    let speed = |bytes: u64| if elapsed > 0.0 { (bytes as f64 * 8.0) / elapsed } else { 0.0 };

    // Stop all tasks
    state.stop();
    let _ = latency_handle.await;
    for handle in download_handles {
        let _ = handle.await;
    }
    for handle in upload_handles {
        let _ = handle.await;
    }

    // Get NAT result
    let nat_result = nat_handle.await.ok();

    // Measure unloaded latency
    let latency_unloaded = test::measure_unloaded_latency(client, &targets[0]).await?;

    let download_bytes = state.get_download_bytes();
    let upload_bytes = state.get_upload_bytes();

    let results = TestResults {
        download_speed: speed(download_bytes),
        upload_speed: speed(upload_bytes),
        latency_unloaded,
        latency_loaded: state.get_median_latency(),
        downloaded_bytes: download_bytes,
        uploaded_bytes: upload_bytes,
        nat_topology: nat_result.as_ref().map(|r| r.topology.to_string()),
        nat_type: nat_result.as_ref().map(|r| r.nat_type.to_string()),
        external_ip: nat_result.as_ref().and_then(|r| r.public_ip.clone()),
        nat_confidence: nat_result.as_ref().map(|r| r.confidence),
        nat_evidence: nat_result.as_ref().map(|r| r.evidence.clone()).unwrap_or_default(),
        upnp_available: nat_result.as_ref().map(|r| r.upnp.available).unwrap_or(false),
        upnp_gateway: nat_result.as_ref().and_then(|r| r.upnp.gateway_name.clone()),
        upnp_wan_ip: nat_result.as_ref().and_then(|r| r.upnp.wan_ip.clone()),
        upnp_can_map: nat_result.as_ref().map(|r| r.upnp.can_add_mapping).unwrap_or(false),
        nat_pmp_available: nat_result.as_ref().map(|r| r.nat_pmp.nat_pmp_available).unwrap_or(false),
        pcp_available: nat_result.as_ref().map(|r| r.nat_pmp.pcp_available).unwrap_or(false),
        nat_pmp_external_ip: nat_result.as_ref().and_then(|r| r.nat_pmp.external_ip.clone()),
        ice_host: nat_result.as_ref().map(|r| {
            r.ice_candidates.host.iter().map(|c| (c.address.clone(), c.port)).collect()
        }).unwrap_or_default(),
        ice_srflx: nat_result.as_ref().map(|r| {
            r.ice_candidates.srflx.iter().map(|c| (c.address.clone(), c.port)).collect()
        }).unwrap_or_default(),
        udp_3478: nat_result.as_ref().map(|r| r.udp_connectivity.port_3478).unwrap_or(false),
        udp_443: nat_result.as_ref().map(|r| r.udp_connectivity.port_443).unwrap_or(false),
        udp_19302: nat_result.as_ref().map(|r| r.udp_connectivity.port_19302).unwrap_or(false),
        local_ip: nat_result.as_ref().and_then(|r| r.network.local_ip.clone()),
        default_gateway: nat_result.as_ref().and_then(|r| r.network.default_gateway.clone()),
        dns_servers: nat_result.as_ref().map(|r| r.network.dns_servers.clone()).unwrap_or_default(),
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

    // Spawn NAT detection
    let nat_log = nat::new_debug_log();
    let nat_log_clone = nat_log.clone();
    let nat_result: Arc<Mutex<Option<DetectionResult>>> = Arc::new(Mutex::new(None));
    let nat_result_clone = nat_result.clone();

    let nat_handle = tokio::spawn(async move {
        let result = nat::detect_nat_topology(nat_log_clone).await;
        if let Ok(mut r) = nat_result_clone.lock() {
            *r = Some(result);
        }
    });

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

        // Get current NAT result
        let current_nat = nat_result.lock().ok().and_then(|r| r.clone());

        // Draw UI
        tui.draw(
            &state,
            &history,
            client_info,
            servers,
            "Testing",
            current_nat.as_ref(),
            &nat_log,
        )?;

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let elapsed = state.elapsed().as_secs_f64();
    let speed = |bytes: u64| if elapsed > 0.0 { (bytes as f64 * 8.0) / elapsed } else { 0.0 };

    // Signal stop and wait for tasks
    state.stop();
    let _ = latency_handle.await;
    for handle in download_handles {
        let _ = handle.await;
    }
    for handle in upload_handles {
        let _ = handle.await;
    }

    // Check if NAT detection is still running
    let nat_done = nat_result.lock().ok().map(|r| r.is_some()).unwrap_or(false);

    if !nat_done {
        // Show waiting status while NAT detection completes
        tui.draw(
            &state,
            &history,
            client_info,
            servers,
            "Waiting for NAT detection...",
            None,
            &nat_log,
        )?;
    }

    // Wait for NAT detection to complete (with timeout)
    let _ = tokio::time::timeout(Duration::from_secs(10), nat_handle).await;
    let final_nat = nat_result.lock().ok().and_then(|r| r.clone());

    // Final draw
    tui.draw(
        &state,
        &history,
        client_info,
        servers,
        "Measuring unloaded latency...",
        final_nat.as_ref(),
        &nat_log,
    )?;

    // Measure unloaded latency (requires idle connection)
    let latency_unloaded = test::measure_unloaded_latency(client, &targets[0]).await?;

    // Calculate final results
    let download_bytes = state.get_download_bytes();
    let upload_bytes = state.get_upload_bytes();

    // Add final point with average speeds
    let final_point = DataPoint {
        time: elapsed,
        download_speed: speed(download_bytes),
        upload_speed: speed(upload_bytes),
        latency: state.get_median_latency(),
    };
    history.add_point(final_point);

    // Show completed state briefly
    tui.draw(
        &state,
        &history,
        client_info,
        servers,
        "Complete",
        final_nat.as_ref(),
        &nat_log,
    )?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Restore terminal
    drop(tui);

    // Print final results to terminal
    let results = TestResults {
        download_speed: speed(download_bytes),
        upload_speed: speed(upload_bytes),
        latency_unloaded,
        latency_loaded: state.get_median_latency(),
        downloaded_bytes: download_bytes,
        uploaded_bytes: upload_bytes,
        nat_topology: final_nat.as_ref().map(|r| r.topology.to_string()),
        nat_type: final_nat.as_ref().map(|r| r.nat_type.to_string()),
        external_ip: final_nat.as_ref().and_then(|r| r.public_ip.clone()),
        nat_confidence: final_nat.as_ref().map(|r| r.confidence),
        nat_evidence: final_nat.as_ref().map(|r| r.evidence.clone()).unwrap_or_default(),
        upnp_available: final_nat.as_ref().map(|r| r.upnp.available).unwrap_or(false),
        upnp_gateway: final_nat.as_ref().and_then(|r| r.upnp.gateway_name.clone()),
        upnp_wan_ip: final_nat.as_ref().and_then(|r| r.upnp.wan_ip.clone()),
        upnp_can_map: final_nat.as_ref().map(|r| r.upnp.can_add_mapping).unwrap_or(false),
        nat_pmp_available: final_nat.as_ref().map(|r| r.nat_pmp.nat_pmp_available).unwrap_or(false),
        pcp_available: final_nat.as_ref().map(|r| r.nat_pmp.pcp_available).unwrap_or(false),
        nat_pmp_external_ip: final_nat.as_ref().and_then(|r| r.nat_pmp.external_ip.clone()),
        ice_host: final_nat.as_ref().map(|r| {
            r.ice_candidates.host.iter().map(|c| (c.address.clone(), c.port)).collect()
        }).unwrap_or_default(),
        ice_srflx: final_nat.as_ref().map(|r| {
            r.ice_candidates.srflx.iter().map(|c| (c.address.clone(), c.port)).collect()
        }).unwrap_or_default(),
        udp_3478: final_nat.as_ref().map(|r| r.udp_connectivity.port_3478).unwrap_or(false),
        udp_443: final_nat.as_ref().map(|r| r.udp_connectivity.port_443).unwrap_or(false),
        udp_19302: final_nat.as_ref().map(|r| r.udp_connectivity.port_19302).unwrap_or(false),
        local_ip: final_nat.as_ref().and_then(|r| r.network.local_ip.clone()),
        default_gateway: final_nat.as_ref().and_then(|r| r.network.default_gateway.clone()),
        dns_servers: final_nat.as_ref().map(|r| r.network.dns_servers.clone()).unwrap_or_default(),
    };

    display::print_results(&results, client_info, servers);
    Ok(())
}
