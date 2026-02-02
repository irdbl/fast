use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Deserialize)]
pub struct ApiResponse {
    pub client: ClientInfo,
    pub targets: Vec<Target>,
}

#[derive(Debug, Deserialize)]
pub struct ClientInfo {
    pub ip: String,
    pub isp: Option<String>,
    pub location: Location,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Location {
    pub city: String,
    pub country: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Target {
    pub url: String,
    pub location: Location,
}

pub struct TestResults {
    pub download_speed: f64,
    pub upload_speed: f64,
    pub latency_unloaded: f64,
    pub latency_loaded: f64,
    pub downloaded_bytes: u64,
    pub uploaded_bytes: u64,
    pub nat_topology: Option<String>,
    pub nat_type: Option<String>,
    pub external_ip: Option<String>,
    pub nat_confidence: Option<f64>,
    pub nat_evidence: Vec<String>,
    // UPnP results
    pub upnp_available: bool,
    pub upnp_gateway: Option<String>,
    pub upnp_wan_ip: Option<String>,
    pub upnp_can_map: bool,
    // NAT-PMP/PCP results
    pub nat_pmp_available: bool,
    pub pcp_available: bool,
    pub nat_pmp_external_ip: Option<String>,
    // ICE candidates
    pub ice_host: Vec<(String, u16)>,      // (ip, port)
    pub ice_srflx: Vec<(String, u16)>,
    // UDP connectivity
    pub udp_3478: bool,
    pub udp_443: bool,
    pub udp_19302: bool,
    // Network info
    pub local_ip: Option<String>,
    pub default_gateway: Option<String>,
    pub dns_servers: Vec<String>,
}

#[derive(Serialize)]
pub struct JsonOutput {
    pub download: SpeedResult,
    pub upload: SpeedResult,
    pub latency: LatencyResult,
    pub nat: NatResult,
    pub client: JsonClient,
    pub servers: Vec<String>,
}

#[derive(Serialize)]
pub struct NatResult {
    pub topology: Option<String>,
    #[serde(rename = "type")]
    pub nat_type: Option<String>,
    pub external_ip: Option<String>,
    pub confidence: Option<f64>,
    pub network: NetworkInfoJson,
    pub evidence: Vec<String>,
    pub upnp: UpnpInfo,
    pub nat_pmp: NatPmpInfo,
    pub ice_candidates: IceCandidatesInfo,
    pub udp_connectivity: UdpConnectivityInfo,
}

#[derive(Serialize)]
pub struct IceCandidateInfo {
    pub address: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Serialize)]
pub struct IceCandidatesInfo {
    pub host: Vec<IceCandidateInfo>,
    pub srflx: Vec<IceCandidateInfo>,
    pub relay: Vec<IceCandidateInfo>,
}

#[derive(Serialize)]
pub struct UdpConnectivityInfo {
    #[serde(rename = "port_3478")]
    pub port_3478: bool,
    #[serde(rename = "port_443")]
    pub port_443: bool,
    #[serde(rename = "port_19302")]
    pub port_19302: bool,
}

#[derive(Serialize)]
pub struct NetworkInfoJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_gateway: Option<String>,
    pub dns_servers: Vec<String>,
}

#[derive(Serialize)]
pub struct UpnpInfo {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wan_ip: Option<String>,
    pub can_add_mapping: bool,
}

#[derive(Serialize)]
pub struct NatPmpInfo {
    pub nat_pmp_available: bool,
    pub pcp_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ip: Option<String>,
}

#[derive(Serialize)]
pub struct SpeedResult {
    pub bps: f64,
    pub bytes: u64,
}

#[derive(Serialize)]
pub struct LatencyResult {
    pub unloaded_ms: f64,
    pub loaded_ms: f64,
}

#[derive(Serialize)]
pub struct JsonClient {
    pub ip: String,
    pub isp: String,
    pub city: String,
    pub country: String,
}

/// Shared state for concurrent speed tests
#[derive(Clone)]
pub struct TestState {
    pub download_bytes: Arc<AtomicU64>,
    pub upload_bytes: Arc<AtomicU64>,
    pub latencies: Arc<Mutex<Vec<f64>>>,
    pub stop_flag: Arc<AtomicBool>,
    pub start_time: std::time::Instant,
}

impl TestState {
    pub fn new() -> Self {
        Self {
            download_bytes: Arc::new(AtomicU64::new(0)),
            upload_bytes: Arc::new(AtomicU64::new(0)),
            latencies: Arc::new(Mutex::new(Vec::new())),
            stop_flag: Arc::new(AtomicBool::new(false)),
            start_time: std::time::Instant::now(),
        }
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    pub fn get_download_bytes(&self) -> u64 {
        self.download_bytes.load(Ordering::Relaxed)
    }

    pub fn get_upload_bytes(&self) -> u64 {
        self.upload_bytes.load(Ordering::Relaxed)
    }

    pub fn get_latest_latency(&self) -> Option<f64> {
        self.latencies.lock().ok()?.last().copied()
    }

    pub fn get_median_latency(&self) -> f64 {
        if let Ok(mut lats) = self.latencies.lock() {
            if lats.is_empty() {
                return 0.0;
            }
            lats.sort_by(|a, b| a.partial_cmp(b).unwrap());
            lats[lats.len() / 2]
        } else {
            0.0
        }
    }

    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }
}

/// Data point for charting
#[derive(Clone, Copy)]
pub struct DataPoint {
    pub time: f64,
    pub download_speed: f64,
    pub upload_speed: f64,
    pub latency: f64,
}

/// History of measurements for charting
pub struct TestHistory {
    pub points: Vec<DataPoint>,
    pub max_download: f64,
    pub max_upload: f64,
}

impl TestHistory {
    pub fn new() -> Self {
        Self {
            points: Vec::new(),
            max_download: 1.0,
            max_upload: 1.0,
        }
    }

    pub fn add_point(&mut self, point: DataPoint) {
        if point.download_speed > self.max_download {
            self.max_download = point.download_speed;
        }
        if point.upload_speed > self.max_upload {
            self.max_upload = point.upload_speed;
        }
        self.points.push(point);
    }
}
