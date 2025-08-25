use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NetworkStats {
    pub flow_count: i64,
    // Future fields
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub total_packets: i64,
    pub total_bytes: i64,
    pub uptime_seconds: i64,

}

impl Default for NetworkStats {
    fn default() -> Self {
        Self {
            flow_count: 0,
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
            total_packets: 0,
            total_bytes: 0,
            uptime_seconds: 0,
        }
    }
}