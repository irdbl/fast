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
}

#[derive(Serialize)]
pub struct JsonOutput {
    pub download: SpeedResult,
    pub upload: SpeedResult,
    pub latency: LatencyResult,
    pub client: JsonClient,
    pub servers: Vec<String>,
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
