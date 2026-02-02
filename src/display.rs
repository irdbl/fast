use crate::types::{ClientInfo, IceCandidateInfo, IceCandidatesInfo, JsonClient, JsonOutput, LatencyResult, NatPmpInfo, NatResult, NetworkInfoJson, SpeedResult, TestResults, UdpConnectivityInfo, UpnpInfo};

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
        nat: NatResult {
            topology: results.nat_topology.clone(),
            nat_type: results.nat_type.clone(),
            external_ip: results.external_ip.clone(),
            confidence: results.nat_confidence,
            network: NetworkInfoJson {
                local_ip: results.local_ip.clone(),
                default_gateway: results.default_gateway.clone(),
                dns_servers: results.dns_servers.clone(),
            },
            evidence: results.nat_evidence.clone(),
            upnp: UpnpInfo {
                available: results.upnp_available,
                gateway: results.upnp_gateway.clone(),
                wan_ip: results.upnp_wan_ip.clone(),
                can_add_mapping: results.upnp_can_map,
            },
            nat_pmp: NatPmpInfo {
                nat_pmp_available: results.nat_pmp_available,
                pcp_available: results.pcp_available,
                external_ip: results.nat_pmp_external_ip.clone(),
            },
            ice_candidates: IceCandidatesInfo {
                host: results.ice_host.iter().map(|(ip, port)| IceCandidateInfo {
                    address: ip.clone(),
                    port: *port,
                    protocol: "udp".to_string(),
                }).collect(),
                srflx: results.ice_srflx.iter().map(|(ip, port)| IceCandidateInfo {
                    address: ip.clone(),
                    port: *port,
                    protocol: "udp".to_string(),
                }).collect(),
                relay: vec![],
            },
            udp_connectivity: UdpConnectivityInfo {
                port_3478: results.udp_3478,
                port_443: results.udp_443,
                port_19302: results.udp_19302,
            },
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
    if results.nat_topology.is_some() || results.nat_type.is_some() {
        println!("   NAT");
        if let Some(topology) = &results.nat_topology {
            let confidence = results.nat_confidence.map(|c| format!(" ({:.0}% confidence)", c * 100.0)).unwrap_or_default();
            println!("   Topology   {}{}", topology, confidence);
        }
        if let Some(nat_type) = &results.nat_type {
            println!("   Type       {}", nat_type);
        }
        if let Some(ext_ip) = &results.external_ip {
            println!("   External   {}", ext_ip);
        }
        println!();

        // Network info
        println!("   Network");
        if let Some(local_ip) = &results.local_ip {
            println!("   Local IP   {}", local_ip);
        }
        if let Some(gateway) = &results.default_gateway {
            println!("   Gateway    {}", gateway);
        }
        if !results.dns_servers.is_empty() {
            println!("   DNS        {}", results.dns_servers.join(", "));
        }

        // UPnP info
        if results.upnp_available {
            let gateway = results.upnp_gateway.as_deref().unwrap_or("Unknown");
            let mapping = if results.upnp_can_map { "mapping supported" } else { "no mapping" };
            println!("   UPnP       {} ({})", gateway, mapping);
            if let Some(wan_ip) = &results.upnp_wan_ip {
                println!("   UPnP WAN   {}", wan_ip);
            }
        }

        // NAT-PMP/PCP info
        if results.nat_pmp_available {
            let ext = results.nat_pmp_external_ip.as_deref().unwrap_or("unknown");
            println!("   NAT-PMP    available (external: {})", ext);
        } else if results.pcp_available {
            let ext = results.nat_pmp_external_ip.as_deref().unwrap_or("unknown");
            println!("   PCP        available (external: {})", ext);
        }
        println!();

        // ICE Candidates
        println!("   ICE Candidates");
        for (ip, port) in &results.ice_host {
            println!("   host       {}:{} udp", ip, port);
        }
        for (ip, port) in &results.ice_srflx {
            println!("   srflx      {}:{} udp", ip, port);
        }
        println!("   relay      --");
        println!();

        // UDP Connectivity
        println!("   UDP Connectivity");
        let status_3478 = if results.udp_3478 { "OK" } else { "blocked" };
        let status_443 = if results.udp_443 { "OK" } else { "blocked" };
        let status_19302 = if results.udp_19302 { "OK" } else { "blocked" };
        println!("   Port 3478  {} (STUN/TURN)", status_3478);
        println!("   Port 443   {} (TURN/TLS)", status_443);
        println!("   Port 19302 {} (Google STUN)", status_19302);

        if !results.nat_evidence.is_empty() {
            println!();
            println!("   Evidence");
            for evidence in &results.nat_evidence {
                println!("     - {}", evidence);
            }
        }
        println!();
    }
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
