//! Unified NAT topology detection
//! Combines STUN, traceroute, UPnP, and hairpin tests

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// STUN constants
const BIND_REQUEST: u16 = 0x0001;
const BIND_RESPONSE: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_CHANGE_REQUEST: u16 = 0x0003;
const ATTR_SOURCE_ADDRESS: u16 = 0x0004;
const ATTR_CHANGED_ADDRESS: u16 = 0x0005;
const CHANGE_IP_FLAG: u32 = 0x04;
const CHANGE_PORT_FLAG: u32 = 0x02;
const MAGIC_COOKIE: u32 = 0x2112A442;

// STUN servers to query
const STUN_SERVERS: &[(&str, u16)] = &[
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.ekiga.net", 3478),
    ("stun.voipbuster.com", 3478),
    ("stun.voipstunt.com", 3478),
];

/// NAT topology classification
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NatTopology {
    Direct,        // No NAT (public IP on interface)
    SingleNat,     // Standard home router
    DoubleNat,     // Two NAT layers (router behind router)
    Cgnat,         // Carrier-grade NAT
    CgnatPlusNat,  // Home router behind CGNAT
    Unknown,
}

impl std::fmt::Display for NatTopology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatTopology::Direct => write!(f, "Direct (No NAT)"),
            NatTopology::SingleNat => write!(f, "Single NAT"),
            NatTopology::DoubleNat => write!(f, "Double NAT"),
            NatTopology::Cgnat => write!(f, "CGNAT"),
            NatTopology::CgnatPlusNat => write!(f, "CGNAT + NAT"),
            NatTopology::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Classic NAT type from STUN
#[derive(Debug, Clone, PartialEq)]
pub enum NatType {
    OpenInternet,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
    SymmetricUdpFirewall,
    Blocked,
    Unknown,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::OpenInternet => write!(f, "Open Internet"),
            NatType::FullCone => write!(f, "Full Cone"),
            NatType::RestrictedCone => write!(f, "Restricted Cone"),
            NatType::PortRestrictedCone => write!(f, "Port Restricted Cone"),
            NatType::Symmetric => write!(f, "Symmetric"),
            NatType::SymmetricUdpFirewall => write!(f, "Symmetric UDP Firewall"),
            NatType::Blocked => write!(f, "Blocked"),
            NatType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// UPnP detection details
#[derive(Debug, Clone, Default)]
pub struct UpnpResult {
    pub available: bool,
    pub gateway_name: Option<String>,
    pub wan_ip: Option<String>,
    pub can_add_mapping: bool,
    pub existing_mappings: u32,
}

/// NAT-PMP/PCP detection details
#[derive(Debug, Clone, Default)]
pub struct NatPmpResult {
    pub nat_pmp_available: bool,
    pub pcp_available: bool,
    pub external_ip: Option<String>,
    pub mapping_lifetime: Option<u32>,
    pub epoch: Option<u32>,
}

/// ICE candidate for WebRTC
#[derive(Debug, Clone)]
pub struct IceCandidate {
    pub candidate_type: String, // "host", "srflx", "relay"
    pub address: String,
    pub port: u16,
    pub protocol: String, // "udp" or "tcp"
}

/// ICE candidates that would be gathered
#[derive(Debug, Clone, Default)]
pub struct IceCandidates {
    pub host: Vec<IceCandidate>,
    pub srflx: Vec<IceCandidate>,
    pub relay: Vec<IceCandidate>,
}

/// UDP connectivity to common ports
#[derive(Debug, Clone, Default)]
pub struct UdpConnectivity {
    pub port_3478: bool,  // Standard STUN/TURN
    pub port_443: bool,   // TURN over TLS
    pub port_19302: bool, // Google STUN
}

impl UdpConnectivity {
    pub fn all_blocked(&self) -> bool {
        !self.port_3478 && !self.port_443 && !self.port_19302
    }

    pub fn all_open(&self) -> bool {
        self.port_3478 && self.port_443 && self.port_19302
    }
}

/// Local network information
#[derive(Debug, Clone, Default)]
pub struct NetworkInfo {
    pub local_ip: Option<String>,
    pub default_gateway: Option<String>,
    pub dns_servers: Vec<String>,
}

/// Complete detection result
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub topology: NatTopology,
    pub nat_type: NatType,
    pub confidence: f64,
    pub public_ip: Option<String>,
    pub external_port: Option<u16>,
    pub network: NetworkInfo,
    pub upnp: UpnpResult,
    pub nat_pmp: NatPmpResult,
    pub ice_candidates: IceCandidates,
    pub udp_connectivity: UdpConnectivity,
    pub evidence: Vec<String>,
}

impl Default for DetectionResult {
    fn default() -> Self {
        Self {
            topology: NatTopology::Unknown,
            nat_type: NatType::Unknown,
            confidence: 0.0,
            public_ip: None,
            external_port: None,
            network: NetworkInfo::default(),
            upnp: UpnpResult::default(),
            nat_pmp: NatPmpResult::default(),
            ice_candidates: IceCandidates::default(),
            udp_connectivity: UdpConnectivity::default(),
            evidence: Vec::new(),
        }
    }
}

/// Debug log for real-time updates
pub type DebugLog = Arc<Mutex<Vec<String>>>;

pub fn new_debug_log() -> DebugLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn debug_log(dl: &DebugLog, msg: &str) {
    if let Ok(mut l) = dl.lock() {
        l.push(msg.to_string());
        if l.len() > 15 {
            l.remove(0);
        }
    }
}

/// Check if IP is in CGNAT range (100.64.0.0/10)
fn is_cgnat_range(ip: &IpAddr) -> bool {
    if let IpAddr::V4(v4) = ip {
        let octets = v4.octets();
        // 100.64.0.0/10 = 100.64.0.0 - 100.127.255.255
        octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127)
    } else {
        false
    }
}

/// Check if IP is private (RFC1918)
fn is_private(ip: &IpAddr) -> bool {
    if let IpAddr::V4(v4) = ip {
        v4.is_private()
    } else {
        false
    }
}

/// Check if IP is loopback
fn is_loopback(ip: &IpAddr) -> bool {
    ip.is_loopback()
}

// ============ STUN Implementation ============

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mut state = seed;
    for byte in &mut bytes {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (state >> 33) as u8;
    }
    bytes
}

fn build_stun_request(change_ip: bool, change_port: bool) -> Vec<u8> {
    let mut msg = Vec::with_capacity(28);
    msg.extend_from_slice(&BIND_REQUEST.to_be_bytes());
    let len_pos = msg.len();
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    let txn_id: [u8; 12] = rand_bytes();
    msg.extend_from_slice(&txn_id);

    if change_ip || change_port {
        let mut flags: u32 = 0;
        if change_ip {
            flags |= CHANGE_IP_FLAG;
        }
        if change_port {
            flags |= CHANGE_PORT_FLAG;
        }
        msg.extend_from_slice(&ATTR_CHANGE_REQUEST.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&flags.to_be_bytes());
    }

    let attr_len = (msg.len() - 20) as u16;
    msg[len_pos..len_pos + 2].copy_from_slice(&attr_len.to_be_bytes());
    msg
}

#[derive(Debug, Default)]
struct StunResponse {
    mapped_addr: Option<SocketAddr>,
    source_addr: Option<SocketAddr>,
    changed_addr: Option<SocketAddr>,
}

fn parse_stun_response(data: &[u8]) -> Option<StunResponse> {
    if data.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != BIND_RESPONSE {
        return None;
    }
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + msg_len {
        return None;
    }

    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let txn_id = if cookie == MAGIC_COOKIE {
        Some(<[u8; 12]>::try_from(&data[8..20]).ok()?)
    } else {
        None
    };

    let mut response = StunResponse::default();
    let mut pos = 20;

    while pos + 4 <= 20 + msg_len {
        let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + attr_len > data.len() {
            break;
        }
        let attr_data = &data[pos..pos + attr_len];

        match attr_type {
            ATTR_MAPPED_ADDRESS => response.mapped_addr = parse_address(attr_data),
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(txn_id) = txn_id {
                    response.mapped_addr = parse_xor_address(attr_data, &txn_id);
                }
            }
            ATTR_SOURCE_ADDRESS => response.source_addr = parse_address(attr_data),
            ATTR_CHANGED_ADDRESS => response.changed_addr = parse_address(attr_data),
            _ => {}
        }
        pos += (attr_len + 3) & !3;
    }
    Some(response)
}

fn parse_address(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 8 || data[1] != 0x01 {
        return None;
    }
    let port = u16::from_be_bytes([data[2], data[3]]);
    let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
    Some(SocketAddr::new(ip.into(), port))
}

fn parse_xor_address(data: &[u8], txn_id: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < 8 || data[1] != 0x01 {
        return None;
    }
    let xor_port = u16::from_be_bytes([data[2], data[3]]);
    let port = xor_port ^ ((MAGIC_COOKIE >> 16) as u16);
    let mut ip_bytes = [data[4], data[5], data[6], data[7]];
    let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
    for (b, c) in ip_bytes.iter_mut().zip(cookie_bytes.iter()) {
        *b ^= *c;
    }
    let _ = txn_id; // Reserved for IPv6 XOR, not needed for IPv4.
    let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
    Some(SocketAddr::new(ip.into(), port))
}

fn stun_query(
    socket: &UdpSocket,
    server: SocketAddr,
    change_ip: bool,
    change_port: bool,
) -> Option<StunResponse> {
    let request = build_stun_request(change_ip, change_port);
    socket.send_to(&request, server).ok()?;
    let mut buf = [0u8; 1024];
    let (len, _) = socket.recv_from(&mut buf).ok()?;
    parse_stun_response(&buf[..len])
}

fn resolve_stun_server(host: &str, port: u16) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    format!("{}:{}", host, port)
        .to_socket_addrs()
        .ok()?
        .next()
}

/// Layer 1: Multi-server STUN analysis
fn run_stun_analysis(log: &DebugLog) -> (NatType, HashSet<IpAddr>, Option<SocketAddr>, Vec<u16>) {
    debug_log(log, "STUN: Starting multi-server analysis");

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => {
            debug_log(log, "STUN: Failed to bind socket");
            return (NatType::Unknown, HashSet::new(), None, Vec::new());
        }
    };
    socket.set_read_timeout(Some(Duration::from_secs(3))).ok();
    socket.set_write_timeout(Some(Duration::from_secs(3))).ok();

    let local_ip = get_local_ip();
    let mut public_ips: HashSet<IpAddr> = HashSet::new();
    let mut mapped_ports: Vec<u16> = Vec::new();
    let mut first_mapping: Option<SocketAddr> = None;
    let mut nat_type = NatType::Unknown;

    // Query multiple STUN servers
    for (host, port) in STUN_SERVERS.iter().take(3) {
        debug_log(log, &format!("STUN: Querying {}:{}", host, port));

        let server_addr = match resolve_stun_server(host, *port) {
            Some(a) => a,
            None => continue,
        };

        if let Some(resp) = stun_query(&socket, server_addr, false, false) {
            if let Some(mapped) = resp.mapped_addr {
                debug_log(log, &format!("STUN: Mapped to {}", mapped));
                public_ips.insert(mapped.ip());
                mapped_ports.push(mapped.port());

                if first_mapping.is_none() {
                    first_mapping = Some(mapped);
                    let changed_addr = resp.changed_addr;

                    // Determine NAT type using first responsive server
                    let is_local = local_ip.map(|l| l == mapped.ip()).unwrap_or(false);

                    if is_local {
                        debug_log(log, "STUN: External IP matches local IP");
                        if stun_query(&socket, server_addr, true, true).is_some() {
                            nat_type = NatType::OpenInternet;
                            debug_log(log, "STUN: Open Internet detected");
                        } else {
                            nat_type = NatType::SymmetricUdpFirewall;
                            debug_log(log, "STUN: Symmetric UDP Firewall");
                        }
                    } else {
                        // Behind NAT - test for type
                        debug_log(log, "STUN: Testing Full Cone...");
                        if stun_query(&socket, server_addr, true, true).is_some() {
                            nat_type = NatType::FullCone;
                            debug_log(log, "STUN: Full Cone NAT");
                        } else if let Some(changed) = changed_addr {
                            debug_log(log, "STUN: Testing Symmetric...");
                            if let Some(resp2) = stun_query(&socket, changed, false, false) {
                                if let Some(mapped2) = resp2.mapped_addr {
                                    if mapped2 != mapped {
                                        nat_type = NatType::Symmetric;
                                        debug_log(log, "STUN: Symmetric NAT");
                                    } else {
                                        debug_log(log, "STUN: Testing Restricted...");
                                        if stun_query(&socket, server_addr, false, true).is_some() {
                                            nat_type = NatType::RestrictedCone;
                                            debug_log(log, "STUN: Restricted Cone NAT");
                                        } else {
                                            nat_type = NatType::PortRestrictedCone;
                                            debug_log(log, "STUN: Port Restricted Cone NAT");
                                        }
                                    }
                                }
                            }
                        } else {
                            nat_type = NatType::PortRestrictedCone;
                            debug_log(log, "STUN: Port Restricted (no changed addr)");
                        }
                    }
                }
            }
        }
    }

    if public_ips.is_empty() {
        debug_log(log, "STUN: All servers failed - Blocked");
        nat_type = NatType::Blocked;
    } else if public_ips.len() > 1 {
        debug_log(log, &format!("STUN: Multiple IPs detected: {:?}", public_ips));
    }

    (nat_type, public_ips, first_mapping, mapped_ports)
}

fn get_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|a| a.ip())
}

// ============ Traceroute Analysis ============

#[derive(Debug)]
struct TracerouteResult {
    found_cgnat_ip: bool,
    cgnat_hop: Option<u8>,
    private_after_hop1: u8,
    hops_to_public: u8,
}

fn run_traceroute_analysis(log: &DebugLog) -> TracerouteResult {
    debug_log(log, "Traceroute: Starting analysis");

    let mut result = TracerouteResult {
        found_cgnat_ip: false,
        cgnat_hop: None,
        private_after_hop1: 0,
        hops_to_public: 0,
    };

    // Run traceroute command (limit to 10 hops, 1 second timeout)
    let output = Command::new("traceroute")
        .args(["-n", "-m", "10", "-w", "1", "8.8.8.8"])
        .output();

    let output = match output {
        Ok(o) => o,
        Err(_) => {
            debug_log(log, "Traceroute: Command failed, trying UDP");
            // Try alternative: use udp traceroute or just skip
            return result;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug_log(log, "Traceroute: Parsing results");

    let mut found_first_public = false;

    for line in stdout.lines().skip(1) {
        // Parse hop number and IP
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let hop_num: u8 = match parts[0].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        // Find IP address in the line (skip * for timeouts)
        let ip_str = parts.iter().find(|p| p.contains('.') && !p.contains('*'));
        let ip: Option<IpAddr> = ip_str.and_then(|s| s.parse().ok());

        if let Some(ip) = ip {
            debug_log(log, &format!("Traceroute: Hop {} = {}", hop_num, ip));

            if is_cgnat_range(&ip) {
                debug_log(log, &format!("Traceroute: CGNAT IP found at hop {}", hop_num));
                result.found_cgnat_ip = true;
                result.cgnat_hop = Some(hop_num);
            } else if is_private(&ip) && hop_num > 1 {
                debug_log(log, &format!("Traceroute: Private IP at hop {}", hop_num));
                result.private_after_hop1 += 1;
            } else if !is_private(&ip) && !is_cgnat_range(&ip) && !is_loopback(&ip) {
                if !found_first_public {
                    result.hops_to_public = hop_num;
                    found_first_public = true;
                    debug_log(log, &format!("Traceroute: First public IP at hop {}", hop_num));
                }
            }
        }
    }

    result
}

// ============ UPnP Analysis ============

async fn check_upnp(log: &DebugLog) -> UpnpResult {
    let mut result = UpnpResult::default();
    debug_log(log, "UPnP: Searching for IGD gateway...");

    use rupnp::ssdp::{SearchTarget, URN};

    let search_target = SearchTarget::URN(URN::device("schemas-upnp-org", "InternetGatewayDevice", 1));

    let devices = match tokio::time::timeout(
        Duration::from_secs(3),
        rupnp::discover(&search_target, Duration::from_secs(2)),
    )
    .await
    {
        Ok(Ok(devices)) => devices,
        _ => {
            debug_log(log, "UPnP: Discovery timeout or error");
            return result;
        }
    };

    tokio::pin!(devices);

    use futures::StreamExt;
    while let Some(device) = devices.next().await {
        let device = match device {
            Ok(d) => d,
            Err(_) => continue,
        };

        result.available = true;
        result.gateway_name = Some(device.friendly_name().to_string());
        debug_log(log, &format!("UPnP: Found {}", device.friendly_name()));

        // Look for WANIPConnection or WANPPPConnection service
        for service in device.services() {
            let service_type = service.service_type().to_string();
            if !service_type.contains("WANIPConnection") && !service_type.contains("WANPPPConnection") {
                continue;
            }

            debug_log(log, "UPnP: Found WAN service");

            // 1. GetExternalIPAddress
            if let Ok(Ok(response)) = tokio::time::timeout(
                Duration::from_secs(2),
                service.action(device.url(), "GetExternalIPAddress", ""),
            ).await {
                if let Some(wan_ip) = response.get("NewExternalIPAddress") {
                    debug_log(log, &format!("UPnP: WAN IP = {}", wan_ip));
                    result.wan_ip = Some(wan_ip.clone());
                }
            }

            // 2. Try to get port mapping count (GetGenericPortMappingEntry with index 0, 1, ...)
            debug_log(log, "UPnP: Checking existing mappings...");
            let mut mapping_count = 0u32;
            for i in 0..20 {
                let args = format!("<NewPortMappingIndex>{}</NewPortMappingIndex>", i);
                match tokio::time::timeout(
                    Duration::from_secs(1),
                    service.action(device.url(), "GetGenericPortMappingEntry", &args),
                ).await {
                    Ok(Ok(_)) => mapping_count += 1,
                    _ => break,
                }
            }
            if mapping_count > 0 {
                debug_log(log, &format!("UPnP: Found {} existing mappings", mapping_count));
                result.existing_mappings = mapping_count;
            }

            // 3. Test AddPortMapping capability (try to add and immediately delete)
            debug_log(log, "UPnP: Testing port mapping support...");
            let test_port = 59999u16;
            let local_ip = get_local_ip().map(|ip| ip.to_string()).unwrap_or_default();

            let add_args = format!(
                "<NewRemoteHost></NewRemoteHost>\
                 <NewExternalPort>{}</NewExternalPort>\
                 <NewProtocol>UDP</NewProtocol>\
                 <NewInternalPort>{}</NewInternalPort>\
                 <NewInternalClient>{}</NewInternalClient>\
                 <NewEnabled>1</NewEnabled>\
                 <NewPortMappingDescription>fast_test</NewPortMappingDescription>\
                 <NewLeaseDuration>60</NewLeaseDuration>",
                test_port, test_port, local_ip
            );

            if let Ok(Ok(_)) = tokio::time::timeout(
                Duration::from_secs(2),
                service.action(device.url(), "AddPortMapping", &add_args),
            ).await {
                result.can_add_mapping = true;
                debug_log(log, "UPnP: Port mapping supported");

                // Clean up - delete the test mapping
                let del_args = format!(
                    "<NewRemoteHost></NewRemoteHost>\
                     <NewExternalPort>{}</NewExternalPort>\
                     <NewProtocol>UDP</NewProtocol>",
                    test_port
                );
                let _ = tokio::time::timeout(
                    Duration::from_secs(1),
                    service.action(device.url(), "DeletePortMapping", &del_args),
                ).await;
            } else {
                debug_log(log, "UPnP: Port mapping not supported or blocked");
            }

            return result;
        }
    }

    debug_log(log, "UPnP: No IGD gateway found");
    result
}

// ============ NAT-PMP / PCP Analysis ============

fn get_default_gateway() -> Option<Ipv4Addr> {
    // Try to get default gateway from routing table
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.trim().starts_with("gateway:") {
                let gw = line.split(':').nth(1)?.trim();
                return gw.parse().ok();
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Format: "default via 192.168.1.1 dev eth0"
        for part in stdout.split_whitespace() {
            if let Ok(ip) = part.parse::<Ipv4Addr>() {
                if ip.octets()[0] != 0 {
                    return Some(ip);
                }
            }
        }
    }

    // Fallback: try common gateway addresses
    None
}

fn get_dns_servers() -> Vec<String> {
    let mut servers = Vec::new();

    #[cfg(target_os = "macos")]
    {
        // Parse /etc/resolv.conf or use scutil
        if let Ok(output) = Command::new("scutil")
            .args(["--dns"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if line.starts_with("nameserver[") {
                    if let Some(ip) = line.split(':').nth(1) {
                        let ip = ip.trim();
                        if !servers.contains(&ip.to_string()) {
                            servers.push(ip.to_string());
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Parse /etc/resolv.conf
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with("nameserver") {
                    if let Some(ip) = line.split_whitespace().nth(1) {
                        if !servers.contains(&ip.to_string()) {
                            servers.push(ip.to_string());
                        }
                    }
                }
            }
        }
    }

    servers
}

fn gather_network_info(log: &DebugLog) -> NetworkInfo {
    debug_log(log, "Network: Gathering local network info");

    let local_ip = get_local_ip().map(|ip| ip.to_string());
    let default_gateway = get_default_gateway().map(|ip| ip.to_string());
    let dns_servers = get_dns_servers();

    if let Some(ref ip) = local_ip {
        debug_log(log, &format!("Network: Local IP = {}", ip));
    }
    if let Some(ref gw) = default_gateway {
        debug_log(log, &format!("Network: Gateway = {}", gw));
    }
    if !dns_servers.is_empty() {
        debug_log(log, &format!("Network: DNS = {}", dns_servers.join(", ")));
    }

    NetworkInfo {
        local_ip,
        default_gateway,
        dns_servers,
    }
}

fn check_nat_pmp(log: &DebugLog) -> NatPmpResult {
    let mut result = NatPmpResult::default();

    let gateway = match get_default_gateway() {
        Some(gw) => gw,
        None => {
            debug_log(log, "NAT-PMP: Cannot determine gateway");
            // Try common gateway
            Ipv4Addr::new(192, 168, 1, 1)
        }
    };

    debug_log(log, &format!("NAT-PMP: Trying gateway {}", gateway));

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => {
            debug_log(log, "NAT-PMP: Failed to bind socket");
            return result;
        }
    };
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok();

    let gateway_addr = SocketAddr::new(gateway.into(), 5351);

    // NAT-PMP: Request external address (version=0, opcode=0)
    let request = [0u8, 0u8];

    if socket.send_to(&request, gateway_addr).is_err() {
        debug_log(log, "NAT-PMP: Send failed");
        return result;
    }

    let mut buf = [0u8; 16];
    match socket.recv_from(&mut buf) {
        Ok((len, _)) if len >= 12 => {
            let version = buf[0];
            let opcode = buf[1];
            let result_code = u16::from_be_bytes([buf[2], buf[3]]);

            if version == 0 && opcode == 128 && result_code == 0 {
                result.nat_pmp_available = true;
                result.epoch = Some(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]));
                let ext_ip = Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]);
                result.external_ip = Some(ext_ip.to_string());
                debug_log(log, &format!("NAT-PMP: External IP = {}", ext_ip));

                // Try to request a mapping to test capability and get lifetime
                debug_log(log, "NAT-PMP: Testing mapping support...");
                let map_request: [u8; 12] = [
                    0,    // version
                    1,    // opcode: map UDP
                    0, 0, // reserved
                    0x00, 0x00, // internal port (0 = just query)
                    0x00, 0x00, // suggested external port
                    0, 0, 0, 60, // lifetime: 60 seconds
                ];

                if socket.send_to(&map_request, gateway_addr).is_ok() {
                    let mut map_buf = [0u8; 16];
                    if let Ok((mlen, _)) = socket.recv_from(&mut map_buf) {
                        if mlen >= 16 && map_buf[1] == 129 {
                            let lifetime = u32::from_be_bytes([map_buf[12], map_buf[13], map_buf[14], map_buf[15]]);
                            result.mapping_lifetime = Some(lifetime);
                            debug_log(log, &format!("NAT-PMP: Mapping lifetime = {}s", lifetime));
                        }
                    }
                }
            } else {
                debug_log(log, &format!("NAT-PMP: Error response (code {})", result_code));
            }
        }
        Ok(_) => {
            debug_log(log, "NAT-PMP: Invalid response");
        }
        Err(_) => {
            debug_log(log, "NAT-PMP: No response (not supported)");

            // Try PCP (Port Control Protocol) - version 2
            debug_log(log, "PCP: Trying PCP protocol...");
            check_pcp(log, &socket, gateway_addr, &mut result);
        }
    }

    result
}

fn check_pcp(log: &DebugLog, socket: &UdpSocket, gateway_addr: SocketAddr, result: &mut NatPmpResult) {
    // PCP request for external address (MAP opcode with ANNOUNCE)
    // PCP header: version(1) + opcode(1) + reserved(2) + lifetime(4) + client_ip(16)
    let local_ip = get_local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));

    let mut request = vec![
        2,    // version = 2 (PCP)
        0,    // opcode = ANNOUNCE
        0, 0, // reserved
        0, 0, 0, 0, // lifetime
    ];

    // Add client IP (IPv4-mapped IPv6)
    match local_ip {
        IpAddr::V4(v4) => {
            request.extend_from_slice(&[0u8; 10]);
            request.extend_from_slice(&[0xff, 0xff]);
            request.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            request.extend_from_slice(&v6.octets());
        }
    }

    if socket.send_to(&request, gateway_addr).is_err() {
        return;
    }

    let mut buf = [0u8; 60];
    if let Ok((len, _)) = socket.recv_from(&mut buf) {
        if len >= 24 && buf[0] == 2 {
            let result_code = buf[3];
            if result_code == 0 {
                result.pcp_available = true;
                debug_log(log, "PCP: Protocol available");

                // Extract external IP from response if present
                if len >= 40 {
                    // External IP is at offset 24-40 in MAP response
                    let ext_ip = Ipv4Addr::new(buf[36], buf[37], buf[38], buf[39]);
                    if !ext_ip.is_unspecified() {
                        result.external_ip = Some(ext_ip.to_string());
                        debug_log(log, &format!("PCP: External IP = {}", ext_ip));
                    }
                }
            } else {
                debug_log(log, &format!("PCP: Error response (code {})", result_code));
            }
        }
    } else {
        debug_log(log, "PCP: No response");
    }
}

// ============ Hairpin Test ============

fn test_hairpin(log: &DebugLog, public_addr: Option<SocketAddr>) -> Option<bool> {
    let public_addr = public_addr?;

    debug_log(log, &format!("Hairpin: Testing connection to {}", public_addr));

    // Try to connect to our own public IP:port
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok();

    // Send a packet to our public address
    let test_data = b"hairpin_test";
    if socket.send_to(test_data, public_addr).is_err() {
        debug_log(log, "Hairpin: Send failed");
        return Some(false);
    }

    // Try to receive (this would only work if hairpin NAT is supported)
    let mut buf = [0u8; 64];
    match socket.recv_from(&mut buf) {
        Ok(_) => {
            debug_log(log, "Hairpin: Success - NAT supports hairpin");
            Some(true)
        }
        Err(_) => {
            debug_log(log, "Hairpin: Failed - NAT doesn't support hairpin");
            Some(false)
        }
    }
}

// ============ ICE Candidate Gathering ============

fn get_local_interfaces() -> Vec<(IpAddr, u16)> {
    let mut interfaces = Vec::new();

    // Get the primary local IP by connecting to external server
    if let Some(local_ip) = get_local_ip() {
        // Use a random high port as example
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
            if let Ok(addr) = socket.local_addr() {
                interfaces.push((local_ip, addr.port()));
            }
        }
    }

    interfaces
}

fn gather_ice_candidates(
    log: &DebugLog,
    local_interfaces: &[(IpAddr, u16)],
    stun_mapping: Option<SocketAddr>,
) -> IceCandidates {
    debug_log(log, "ICE: Gathering candidates");

    let mut candidates = IceCandidates::default();

    // Host candidates (local interfaces)
    for (ip, port) in local_interfaces {
        candidates.host.push(IceCandidate {
            candidate_type: "host".to_string(),
            address: ip.to_string(),
            port: *port,
            protocol: "udp".to_string(),
        });
        debug_log(log, &format!("ICE: host {}:{} udp", ip, port));
    }

    // Server reflexive candidates (from STUN)
    if let Some(mapping) = stun_mapping {
        candidates.srflx.push(IceCandidate {
            candidate_type: "srflx".to_string(),
            address: mapping.ip().to_string(),
            port: mapping.port(),
            protocol: "udp".to_string(),
        });
        debug_log(log, &format!("ICE: srflx {}:{} udp", mapping.ip(), mapping.port()));
    }

    // Relay candidates would require TURN server (not available without credentials)
    debug_log(log, "ICE: relay -- (no TURN server)");

    candidates
}

// ============ UDP Connectivity Check ============

fn check_udp_connectivity(log: &DebugLog) -> UdpConnectivity {
    debug_log(log, "UDP: Checking outbound connectivity");

    let mut result = UdpConnectivity::default();

    // Test targets: (host, port, description)
    let targets = [
        ("stun.l.google.com", 19302, "Google STUN (19302)"),
        ("stun.cloudflare.com", 3478, "Cloudflare STUN (3478)"),
        ("stun.nextcloud.com", 443, "Nextcloud STUN (443)"),
    ];

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => {
            debug_log(log, "UDP: Failed to bind socket");
            return result;
        }
    };
    socket.set_read_timeout(Some(Duration::from_millis(1500))).ok();
    socket.set_write_timeout(Some(Duration::from_millis(1500))).ok();

    for (host, port, desc) in targets {
        let addr = match resolve_stun_server(host, port) {
            Some(a) => a,
            None => {
                debug_log(log, &format!("UDP: {} - DNS failed", desc));
                continue;
            }
        };

        // Send a simple STUN binding request
        let request = build_stun_request(false, false);
        if socket.send_to(&request, addr).is_err() {
            debug_log(log, &format!("UDP: {} - send failed", desc));
            continue;
        }

        let mut buf = [0u8; 1024];
        match socket.recv_from(&mut buf) {
            Ok((len, _)) if len > 0 => {
                debug_log(log, &format!("UDP: {} - OK", desc));
                match port {
                    3478 => result.port_3478 = true,
                    443 => result.port_443 = true,
                    19302 => result.port_19302 = true,
                    _ => {}
                }
            }
            _ => {
                debug_log(log, &format!("UDP: {} - blocked/timeout", desc));
            }
        }
    }

    result
}

// ============ Unified Detection ============

pub async fn detect_nat_topology(log: DebugLog) -> DetectionResult {
    let mut result = DetectionResult::default();
    let mut scores: std::collections::HashMap<NatTopology, i32> = std::collections::HashMap::new();

    debug_log(&log, "=== Starting NAT Detection (parallel) ===");

    // Spawn all independent tests in parallel
    let stun_handle = tokio::task::spawn_blocking({
        let log = log.clone();
        move || run_stun_analysis(&log)
    });

    let traceroute_handle = tokio::task::spawn_blocking({
        let log = log.clone();
        move || run_traceroute_analysis(&log)
    });

    let upnp_handle = {
        let log = log.clone();
        tokio::spawn(async move { check_upnp(&log).await })
    };

    let nat_pmp_handle = tokio::task::spawn_blocking({
        let log = log.clone();
        move || check_nat_pmp(&log)
    });

    let udp_handle = tokio::task::spawn_blocking({
        let log = log.clone();
        move || check_udp_connectivity(&log)
    });

    let network_handle = tokio::task::spawn_blocking({
        let log = log.clone();
        move || gather_network_info(&log)
    });

    // Wait for all tests to complete in parallel
    let (stun_result, traceroute_result, upnp_result, nat_pmp_result, udp_result, network_result) = tokio::join!(
        stun_handle,
        traceroute_handle,
        upnp_handle,
        nat_pmp_handle,
        udp_handle,
        network_handle
    );

    // Store network info
    result.network = network_result.unwrap_or_default();

    // Process STUN results
    let (nat_type, public_ips, first_mapping, mapped_ports) =
        stun_result.unwrap_or((NatType::Unknown, HashSet::new(), None, Vec::new()));

    result.nat_type = nat_type.clone();
    if let Some(mapping) = first_mapping {
        result.public_ip = Some(mapping.ip().to_string());
        result.external_port = Some(mapping.port());
    }

    if public_ips.len() > 1 {
        result.evidence.push(format!(
            "Multiple public IPs from STUN: {:?}",
            public_ips
        ));
        *scores.entry(NatTopology::Cgnat).or_insert(0) += 40;
    }

    if nat_type == NatType::Symmetric {
        result.evidence.push("Symmetric NAT detected".to_string());
        *scores.entry(NatTopology::Cgnat).or_insert(0) += 20;
        *scores.entry(NatTopology::DoubleNat).or_insert(0) += 20;
    }

    let high_ports = mapped_ports.iter().filter(|p| **p > 40000).count();
    if high_ports > 0 && mapped_ports.len() > 1 {
        result.evidence.push(format!(
            "High mapped ports (>40000): {}/{}",
            high_ports,
            mapped_ports.len()
        ));
        *scores.entry(NatTopology::Cgnat).or_insert(0) += 10;
    }

    // Gather ICE candidates
    let local_interfaces = get_local_interfaces();
    result.ice_candidates = gather_ice_candidates(&log, &local_interfaces, first_mapping);

    // Process UDP connectivity results
    result.udp_connectivity = udp_result.unwrap_or_default();
    if result.udp_connectivity.all_blocked() {
        result.evidence.push("UDP blocked on all tested ports".to_string());
    } else if !result.udp_connectivity.all_open() {
        let mut blocked = Vec::new();
        if !result.udp_connectivity.port_3478 {
            blocked.push("3478");
        }
        if !result.udp_connectivity.port_443 {
            blocked.push("443");
        }
        if !result.udp_connectivity.port_19302 {
            blocked.push("19302");
        }
        if !blocked.is_empty() {
            result.evidence.push(format!("UDP blocked on ports: {}", blocked.join(", ")));
        }
    }

    // Process Traceroute results
    let traceroute = traceroute_result.unwrap_or(TracerouteResult {
        found_cgnat_ip: false,
        cgnat_hop: None,
        private_after_hop1: 0,
        hops_to_public: 0,
    });

    if traceroute.found_cgnat_ip {
        result.evidence.push(format!(
            "CGNAT IP (100.64.x.x) found at hop {}",
            traceroute.cgnat_hop.unwrap_or(0)
        ));
        *scores.entry(NatTopology::Cgnat).or_insert(0) += 100;

        if traceroute.private_after_hop1 > 0 {
            *scores.entry(NatTopology::CgnatPlusNat).or_insert(0) += 50;
        }
    }

    if traceroute.private_after_hop1 > 0 && !traceroute.found_cgnat_ip {
        result.evidence.push(format!(
            "Private IPs found after hop 1: {}",
            traceroute.private_after_hop1
        ));
        *scores.entry(NatTopology::DoubleNat).or_insert(0) += 60;
    }

    // Process UPnP results
    let upnp_result = upnp_result.unwrap_or_default();
    result.upnp = upnp_result.clone();

    if upnp_result.available {
        result.evidence.push(format!(
            "UPnP: {} gateway found",
            upnp_result.gateway_name.as_deref().unwrap_or("Unknown")
        ));

        if let Some(wan_ip) = &upnp_result.wan_ip {
            if let Ok(ip) = wan_ip.parse::<IpAddr>() {
                if is_cgnat_range(&ip) {
                    result.evidence.push(format!("UPnP reports CGNAT-range WAN IP: {}", wan_ip));
                    *scores.entry(NatTopology::Cgnat).or_insert(0) += 100;
                } else if is_private(&ip) {
                    result.evidence.push(format!("UPnP reports private WAN IP: {}", wan_ip));
                    *scores.entry(NatTopology::DoubleNat).or_insert(0) += 80;
                } else if let Some(stun_ip) = &result.public_ip {
                    if wan_ip != stun_ip {
                        result.evidence.push(format!(
                            "UPnP WAN ({}) differs from STUN ({})",
                            wan_ip, stun_ip
                        ));
                        *scores.entry(NatTopology::Cgnat).or_insert(0) += 60;
                    } else {
                        result.evidence.push("UPnP WAN matches STUN public IP".to_string());
                        *scores.entry(NatTopology::SingleNat).or_insert(0) += 30;
                    }
                }
            }
        }

        if upnp_result.can_add_mapping {
            result.evidence.push("UPnP port mapping supported".to_string());
            *scores.entry(NatTopology::SingleNat).or_insert(0) += 15;
        }

        if upnp_result.existing_mappings > 0 {
            result.evidence.push(format!(
                "UPnP: {} existing port mappings",
                upnp_result.existing_mappings
            ));
        }
    }

    // Process NAT-PMP results
    let nat_pmp_result = nat_pmp_result.unwrap_or_default();
    result.nat_pmp = nat_pmp_result.clone();

    if nat_pmp_result.nat_pmp_available {
        result.evidence.push("NAT-PMP protocol available".to_string());
        *scores.entry(NatTopology::SingleNat).or_insert(0) += 20;

        if let Some(ext_ip) = &nat_pmp_result.external_ip {
            if let Ok(ip) = ext_ip.parse::<IpAddr>() {
                if is_cgnat_range(&ip) {
                    result.evidence.push(format!("NAT-PMP reports CGNAT-range IP: {}", ext_ip));
                    *scores.entry(NatTopology::Cgnat).or_insert(0) += 100;
                } else if is_private(&ip) {
                    result.evidence.push(format!("NAT-PMP reports private IP: {}", ext_ip));
                    *scores.entry(NatTopology::DoubleNat).or_insert(0) += 80;
                }
            }
        }

        if let Some(lifetime) = nat_pmp_result.mapping_lifetime {
            result.evidence.push(format!("NAT-PMP mapping lifetime: {}s", lifetime));
        }
    } else if nat_pmp_result.pcp_available {
        result.evidence.push("PCP protocol available".to_string());
        *scores.entry(NatTopology::SingleNat).or_insert(0) += 20;

        if let Some(ext_ip) = &nat_pmp_result.external_ip {
            if let Ok(ip) = ext_ip.parse::<IpAddr>() {
                if is_cgnat_range(&ip) {
                    result.evidence.push(format!("PCP reports CGNAT-range IP: {}", ext_ip));
                    *scores.entry(NatTopology::Cgnat).or_insert(0) += 100;
                } else if is_private(&ip) {
                    result.evidence.push(format!("PCP reports private IP: {}", ext_ip));
                    *scores.entry(NatTopology::DoubleNat).or_insert(0) += 80;
                }
            }
        }
    }

    // Hairpin test (depends on STUN result, runs after parallel tests complete)
    let hairpin_result = tokio::task::spawn_blocking({
        let log = log.clone();
        let mapping = first_mapping;
        move || test_hairpin(&log, mapping)
    })
    .await
    .ok()
    .flatten();

    if hairpin_result == Some(false) {
        result.evidence.push("Hairpin NAT test failed".to_string());
        *scores.entry(NatTopology::Cgnat).or_insert(0) += 15;
    } else if hairpin_result == Some(true) {
        result.evidence.push("Hairpin NAT supported".to_string());
        *scores.entry(NatTopology::SingleNat).or_insert(0) += 10;
    }

    // Synthesize results
    debug_log(&log, "=== Synthesizing Results ===");

    // Check for direct connection (no NAT)
    if nat_type == NatType::OpenInternet {
        result.topology = NatTopology::Direct;
        result.confidence = 0.95;
        result.evidence.push("Direct internet connection".to_string());
    } else {
        // Find highest scoring topology
        let best = scores
            .iter()
            .max_by_key(|&(_, score)| *score)
            .map(|(t, _)| t.clone());

        let total_score: i32 = scores.values().sum();

        if let Some(topology) = best {
            let score = scores.get(&topology).copied().unwrap_or(0);
            if score >= 20 {
                result.topology = topology;
                result.confidence = (score as f64 / (total_score as f64 + 50.0)).min(0.95);
            } else {
                result.topology = NatTopology::SingleNat;
                result.confidence = 0.5;
                result.evidence.push("Default: assuming single NAT".to_string());
            }
        } else {
            result.topology = NatTopology::SingleNat;
            result.confidence = 0.5;
        }
    }

    debug_log(
        &log,
        &format!(
            "Result: {} ({:.0}% confidence)",
            result.topology,
            result.confidence * 100.0
        ),
    );

    result
}
