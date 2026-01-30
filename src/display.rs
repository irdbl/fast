use crate::types::{ClientInfo, JsonClient, JsonOutput, LatencyResult, SpeedResult, TestResults};

pub fn format_speed(bits_per_sec: f64) -> String {
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

pub fn format_bytes(bytes: u64) -> String {
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

pub fn print_json(results: &TestResults, client: &ClientInfo, servers: &[String]) {
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
            isp: client.isp.clone().unwrap_or_else(|| "Unknown".to_string()),
            city: client.location.city.clone(),
            country: client.location.country.clone(),
        },
        servers: servers.to_vec(),
    };
    println!("{}", serde_json::to_string(&output).unwrap());
}

pub fn print_results(results: &TestResults, client: &ClientInfo, servers: &[String]) {
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
    println!(
        "              {}  {}",
        client.ip,
        client.isp.as_deref().unwrap_or("Unknown")
    );
    println!("   Server(s)  {}", servers.join(" | "));
    println!();
    println!(
        "   Data       {} down  {} up",
        format_bytes(results.downloaded_bytes),
        format_bytes(results.uploaded_bytes)
    );
    println!();
}
