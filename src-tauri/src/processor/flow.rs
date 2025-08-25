use std::time::SystemTime;

pub const FLOW_TIMEOUT_US: u64 = 120_000_000; // 120 seconds
const SUBFLOW_TIMEOUT_US: u64 = 1_000_000; // 1 second
const ACTIVITY_TIMEOUT_US: u64 = 5_000_000; // 5 seconds
const BULK_THRESHOLD: u32 = 4; // Minimum packets for bulk transfer

#[derive(Debug,Clone,Hash,PartialEq,Eq,Copy)]
pub struct FlowKey{
    pub ip_a: u32,
    pub ip_b: u32,
    pub port_a: u16,
    pub port_b: u16,
    pub protocol: u8,
}


impl FlowKey {
    pub fn new(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        // Normalize flow key so both directions map to the same entry
        if (src_ip, src_port) <= (dst_ip, dst_port) {
            Self { 
                ip_a: src_ip, 
                ip_b: dst_ip, 
                port_a: src_port, 
                port_b: dst_port, 
                protocol 
            }
        } else {
            Self { 
                ip_a: dst_ip, 
                ip_b: src_ip, 
                port_a: dst_port, 
                port_b: src_port, 
                protocol 
            }
        }
    }
}

#[derive(Debug,Clone,Copy)]
pub enum FlowDirection{ Forward, Backward }

#[derive(Debug, Clone)]
pub enum FlowStatus { Active, Idle, Closed, Expired }

#[derive(Debug, Clone)]
pub enum FlowCloseState { NonClosing, FinCli, AckFinSv, AckCli }

#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub key: FlowKey,

    // Flow state
    pub status: FlowStatus,                     // Done
    pub close_state: FlowCloseState,

    // Helper attributes
    pub first_packet_forward: bool,             // Done
    pub last_packet_timestamp: u64,             // Done
    pub last_fwd_packet_timestamp: u64,         // Done
    pub last_bwd_packet_timestamp: u64,         // Done

    // Flow duration
    pub flow_start_time: u64,                   // Done
    pub flow_last_time: u64,                    // Done
    pub flow_duration: u64,                     // Done
    pub last_checked_time: u64,                 // Done

    // Packet counts
    pub total_packets: u64,                     // Done
    pub total_fwd_packets: u64,                 // Done
    pub total_bwd_packets: u64,                 // Done
    pub fwd_packet_count: u64,                  // Done
    pub bwd_packet_count: u64,                  // Done

    // Size-based features
    pub total_bytes: u64,                       // Done
    pub total_fwd_bytes: u64,                   // Done
    pub total_bwd_bytes: u64,                   // Done

    pub fwd_packet_len_min: u32,                // Done
    pub fwd_packet_len_max: u32,                // Done
    pub fwd_packet_len_mean: f64,               // Done
    pub fwd_packet_len_std: f64,                // Done
    pub fwd_packet_len_m2: f64,                 // Done 

    pub bwd_packet_len_min: u32,                // Done
    pub bwd_packet_len_max: u32,                // Done
    pub bwd_packet_len_mean: f64,               // Done
    pub bwd_packet_len_std: f64,                // Done
    pub bwd_packet_len_m2: f64,                 // Done

    // Header information
    pub fwd_header_len: u32,                    // Done
    pub bwd_header_len: u32,                    // Done

    // Flow rate features
    pub flow_bytes_per_sec: f64,                // Done
    pub flow_packets_per_sec: f64,              // Done

    // Inter-Arrival Time features
    pub flow_iat_total: u64,                    // Done
    pub flow_iat_min: u64,                      // Done
    pub flow_iat_max: u64,                      // Done
    pub flow_iat_mean: f64,                     // Done
    pub flow_iat_std: f64,                      // Done
    pub flow_iat_m2: f64,                       // Done

    // Forward Inter-Arrival
    pub fwd_iat_min: u64,                       // Done
    pub fwd_iat_max: u64,                       // Done
    pub fwd_iat_mean: f64,                      // Done
    pub fwd_iat_std: f64,                       // Done
    pub fwd_iat_total: u64,                     // Done
    pub fwd_iat_m2: f64,

    // Backward Inter-Arrival
    pub bwd_iat_min: u64,                       // Done
    pub bwd_iat_max: u64,                       // Done
    pub bwd_iat_mean: f64,                      // Done
    pub bwd_iat_std: f64,                       // Done
    pub bwd_iat_total: u64,                     // Done
    pub bwd_iat_m2: f64,                        // Done

    // FWD && BWD Specific flag counts
    pub fwd_psh_flags: u16,                     // Done
    pub bwd_psh_flags: u16,                     // Done
    pub fwd_urg_flags: u16,                     // Done
    pub bwd_urg_flags: u16,                     // Done

    // Packet rate
    pub fwd_packets_per_sec: f64,               // Done
    pub bwd_packets_per_sec: f64,               // Done

    // Aggregate packet length statistics
    pub packet_len_min: u32,                    // Done           
    pub packet_len_max: u32,                    // Done
    pub packet_len_mean: f64,                   // Done
    pub packet_len_std: f64,                    // Done
    pub packet_len_variance: f64,               // Done
    pub packet_len_m2: f64,                     // Done

    // Flag counts
    pub fin_flag_count: u16,                    // Done
    pub syn_flag_count: u16,                    // Done
    pub rst_flag_count: u16,                    // Done
    pub psh_flag_count: u16,                    // Done
    pub ack_flag_count: u16,                    // Done
    pub urg_flag_count: u16,                    // Done
    pub cwr_flag_count: u16,                    // Done
    pub ece_flag_count: u16,                    // Done

    // Ratio and averages
    pub down_up_ratio: f64,                     // Done
    pub avg_packet_size: f64,                   // Done
    pub fwd_segment_size_avg: f64,              // Done
    pub bwd_segment_size_avg: f64,              // Done
    pub fwd_segment_size_tot: f64,              // Done
    pub bwd_segment_size_tot: f64,              // Done
    pub fwd_seg_size_min: f64,                  // Done

    // FWD Bulk Features
    pub num_fwd_bulk_transmissions: i32,        // Done
    pub fwd_bulk_start: u64,                    // Done
    pub fwd_bulk_end: u64,                      // Done
    pub fwd_bulk_duration: u64,                 // Done
    pub fwd_bytes_curr_bulk: f64,               // Done
    pub fwd_bytes_bulk_tot: f64,                // Done
    pub fwd_packet_bulk_tot: f64,               // Done
    pub fwd_bytes_bulk_avg: f64,                // Done
    pub fwd_packet_bulk_avg: f64,               // Done
    pub fwd_bulk_rate_avg: f64,                 // Done

    // BWD Bulk Features
    pub num_bwd_bulk_transmissions: i32,        // Done
    pub bwd_bulk_start: u64,                    // Done
    pub bwd_bulk_end: u64,                      // Done
    pub bwd_bulk_duration: u64,                 // Done
    pub bwd_bytes_curr_bulk: f64,               // Done
    pub bwd_bytes_bulk_tot: f64,                // Done
    pub bwd_packet_bulk_tot: f64,               // Done
    pub bwd_bytes_bulk_avg: f64,                // Done
    pub bwd_packet_bulk_avg: f64,               // Done
    pub bwd_bulk_rate_avg: f64,                 // Done

    // Helpers to compute FWD and BWD bulks
    pub fwd_consecutive_packets: u32,           // Done
    pub bwd_consecutive_packets: u32,           // Done
    pub last_bulk_direction: Option<FlowDirection>,

    // Subflow features
    pub total_fwd_subflows: i32,                // Done
    pub subflow_fwd_packets: u32,               // Done
    pub subflow_fwd_bytes: u32,                 // Done
    pub total_bwd_subflows: i32,                // Done
    pub subflow_bwd_packets: u32,               // Done
    pub subflow_bwd_bytes: u32,                 // Done

    // Window features
    pub fwd_init_win_bytes: u32,                // Done
    pub bwd_init_win_bytes: u32,                // Done
    pub fwd_act_data_packets: u32,              // Done

    // Active/Idle features
    pub active_counts: u64,                     // Done
    pub active_time_tot: u64,                   // Done
    pub active_min: u64,                        // Done
    pub active_max: u64,                        // Done
    pub active_mean: f64,                       // Done
    pub active_std: f64,                        // Done
    pub active_time_m2: f64,                    // Done
    pub last_activity_time: u64,                // Done
    pub current_active_start: u64,              // Done              
    pub current_idle_start: u64,                // Done
    pub is_in_active_period: bool,              // Done

    pub idle_counts: u64,                       // Done
    pub idle_time_tot: u64,                     // Done
    pub idle_min: u64,                          // Done
    pub idle_max: u64,                          // Done
    pub idle_mean: f64,                         // Done
    pub idle_std: f64,                          // Done
    pub idle_time_m2: f64,                      // Done

    // Classification results
    pub classification_time: SystemTime,
    pub classified: bool,
    pub benign: bool,
    pub confidence: f32,
}

impl FlowRecord {
    pub fn new(key: FlowKey, start_time: u64, first_packet_direction: FlowDirection) -> Self {
        #![allow(unused_mut, unused_assignments)]
        let mut s = Self {
            key,
            status: FlowStatus::Active,
            first_packet_forward: matches!(first_packet_direction, FlowDirection::Forward),
            close_state: FlowCloseState::NonClosing,
            last_packet_timestamp: start_time,
            last_fwd_packet_timestamp: start_time,
            last_bwd_packet_timestamp: 0,
            flow_start_time: start_time,
            flow_last_time: start_time,
            flow_duration: 0,
            last_checked_time: start_time,
            total_packets: 0, // Done
            fwd_packet_count: 0,
            bwd_packet_count: 0,
            total_fwd_packets: 0, 
            total_bwd_packets: 0,
            total_bytes: 0,
            total_fwd_bytes: 0,
            total_bwd_bytes: 0,
            fwd_packet_len_min: u32::MAX,
            fwd_packet_len_max: 0,
            fwd_packet_len_mean: 0.0,
            fwd_packet_len_std: 0.0,
            fwd_packet_len_m2: 0.0,
            bwd_packet_len_min: u32::MAX,
            bwd_packet_len_max: 0,
            bwd_packet_len_mean: 0.0,
            bwd_packet_len_std: 0.0,
            bwd_packet_len_m2: 0.0,
            flow_bytes_per_sec: 0.0,
            flow_packets_per_sec: 0.0,
            flow_iat_mean: 0.0,
            flow_iat_std: 0.0,
            flow_iat_max: 0,
            flow_iat_min: u64::MAX,
            flow_iat_total: 0,
            flow_iat_m2: 0.0,
            fwd_iat_min: u64::MAX,
            fwd_iat_max: 0,
            fwd_iat_mean: 0.0,
            fwd_iat_std: 0.0,
            fwd_iat_total: 0,
            fwd_iat_m2: 0.0,
            bwd_iat_min: u64::MAX,
            bwd_iat_max: 0,
            bwd_iat_mean: 0.0,
            bwd_iat_std: 0.0,
            bwd_iat_total: 0,
            bwd_iat_m2: 0.0,
            fwd_psh_flags: 0,
            bwd_psh_flags: 0,
            fwd_urg_flags: 0,
            bwd_urg_flags: 0,
            fwd_header_len: 0,
            bwd_header_len: 0,
            fwd_packets_per_sec: 0.0,
            bwd_packets_per_sec: 0.0,
            packet_len_min: u32::MAX,
            packet_len_max: 0,
            packet_len_mean: 0.0,
            packet_len_std: 0.0,
            packet_len_variance: 0.0,
            packet_len_m2: 0.0,
            fin_flag_count: 0,
            syn_flag_count: 0,
            rst_flag_count: 0,
            psh_flag_count: 0,
            ack_flag_count: 0,
            urg_flag_count: 0,
            cwr_flag_count: 0,
            ece_flag_count: 0,
            down_up_ratio: 0.0,
            avg_packet_size: 0.0,
            fwd_segment_size_avg: 0.0,
            bwd_segment_size_avg: 0.0,
            fwd_segment_size_tot: 0.0,
            bwd_segment_size_tot: 0.0,
            fwd_seg_size_min: f64::INFINITY,
            num_fwd_bulk_transmissions: 0,
            fwd_bulk_start: 0,
            fwd_bulk_end: 0,
            fwd_bulk_duration: 0,
            fwd_bytes_curr_bulk: 0.0,
            fwd_bytes_bulk_tot: 0.0,
            fwd_packet_bulk_tot: 0.0,
            fwd_bytes_bulk_avg: 0.0,
            fwd_packet_bulk_avg: 0.0,
            fwd_bulk_rate_avg: 0.0,
            num_bwd_bulk_transmissions: 0,
            bwd_bulk_start: 0,
            bwd_bulk_end: 0,
            bwd_bulk_duration: 0,
            bwd_bytes_curr_bulk: 0.0,
            bwd_bytes_bulk_tot: 0.0,
            bwd_packet_bulk_tot: 0.0,
            bwd_bytes_bulk_avg: 0.0,
            bwd_packet_bulk_avg: 0.0,
            bwd_bulk_rate_avg: 0.0,
            fwd_consecutive_packets: 1,
            bwd_consecutive_packets: 0,
            last_bulk_direction: None,
            total_fwd_subflows: 0,
            subflow_fwd_packets: 0,
            subflow_fwd_bytes: 0,
            total_bwd_subflows: 0,
            subflow_bwd_packets: 0,
            subflow_bwd_bytes: 0,
            fwd_init_win_bytes: 0,
            bwd_init_win_bytes: 0,
            fwd_act_data_packets: 0,
            active_counts: 0,
            active_time_tot: 0,
            active_min: u64::MAX,
            active_mean: 0.0,
            active_max: 0,
            active_std: 0.0,
            active_time_m2: 0.0,
            last_activity_time: start_time,
            current_active_start: start_time,
            current_idle_start: 0,
            is_in_active_period: true,
            idle_counts: 0,
            idle_time_tot: 0,
            idle_min: u64::MAX,
            idle_mean: 0.0,
            idle_max: 0,
            idle_std: 0.0,
            idle_time_m2: 0.0,
            classification_time: SystemTime::now(),
            classified: false,
            benign: true,
            confidence: 0.0,
        };
        s
    }

    
    /// Helper the engine uses to expire idle flows.
    #[inline]
    pub fn last_seen_micros(&self) -> u64 {
        self.flow_last_time
    }


    fn get_flow_direction(&self, src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) -> FlowDirection {
        // Compare packet's actual src/dst with normalized flow key
        if self.key.ip_a == src_ip && self.key.ip_b == dst_ip && 
           self.key.port_a == src_port && self.key.port_b == dst_port {
            FlowDirection::Forward
        } else {
            FlowDirection::Backward
        }
    }

    pub fn update_subflow_features(&mut self, timestamp: u64, direction: FlowDirection, payload_len: u32) {        
        match direction {
            FlowDirection::Forward => {
                if self.last_fwd_packet_timestamp > 0 {
                    let time_gap = timestamp.saturating_sub(self.last_fwd_packet_timestamp);
                    if time_gap > SUBFLOW_TIMEOUT_US {
                        // New subflow detected
                        self.total_fwd_subflows += 1;
                        // Reset subflow counters for new subflow
                        self.subflow_fwd_packets = 1;
                        self.subflow_fwd_bytes = payload_len;
                    } else {
                        // Continue current subflow
                        self.subflow_fwd_packets += 1;
                        self.subflow_fwd_bytes += payload_len;
                    }
                } else {
                    // First forward packet
                    self.total_fwd_subflows = 1;
                    self.subflow_fwd_packets = 1;
                    self.subflow_fwd_bytes = payload_len;
                }
            }
            FlowDirection::Backward => {
                if self.last_bwd_packet_timestamp > 0 {
                    let time_gap = timestamp.saturating_sub(self.last_bwd_packet_timestamp);
                    if time_gap > SUBFLOW_TIMEOUT_US {
                        // New subflow detected
                        self.total_bwd_subflows += 1;
                        // Reset subflow counters for new subflow
                        self.subflow_bwd_packets = 1;
                        self.subflow_bwd_bytes = payload_len;
                    } else {
                        // Continue current subflow
                        self.subflow_bwd_packets += 1;
                        self.subflow_bwd_bytes += payload_len;
                    }
                } else {
                    // First backward packet
                    self.total_bwd_subflows = 1;
                    self.subflow_bwd_packets = 1;
                    self.subflow_bwd_bytes = payload_len;
                }
            }
        }
    }

    fn update_packet_length_stats(&mut self, packet_len: u32, direction: FlowDirection) {
        let len = packet_len as f64;
        
        // Update aggregate packet length stats
        self.total_packets += 1;
        let n = self.total_packets as f64;
        
        // Online mean and variance calculation (Welford's algorithm)
        let delta = len - self.packet_len_mean;
        self.packet_len_mean += delta / n;
        let delta2 = len - self.packet_len_mean;
        self.packet_len_m2 += delta * delta2;
        
        if self.total_packets > 1 {
            self.packet_len_variance = self.packet_len_m2 / (n - 1.0);
            self.packet_len_std = self.packet_len_variance.sqrt();
        }
        
        // Min/Max
        self.packet_len_min = self.packet_len_min.min(packet_len);
        self.packet_len_max = self.packet_len_max.max(packet_len);
        
        // Direction-specific stats
        match direction {
            FlowDirection::Forward => {
                // Same but for FWD direction
                self.fwd_packet_count += 1;
                self.total_fwd_packets += 1;
                let n_fwd = self.fwd_packet_count as f64;
                
                let delta = len - self.fwd_packet_len_mean;
                self.fwd_packet_len_mean += delta / n_fwd;
                let delta2 = len - self.fwd_packet_len_mean;
                self.fwd_packet_len_m2 += delta * delta2;
                
                if self.fwd_packet_count > 1 {
                    self.fwd_packet_len_std = (self.fwd_packet_len_m2 / (n_fwd - 1.0)).sqrt();
                }

                self.fwd_packet_len_min = self.fwd_packet_len_min.min(packet_len);
                self.fwd_packet_len_max = self.fwd_packet_len_max.max(packet_len);
                
            }
            FlowDirection::Backward => {
                // Same but for BWD direction
                self.bwd_packet_count += 1;
                self.total_bwd_packets += 1;
                let n_bwd = self.bwd_packet_count as f64;
                
                let delta = len - self.bwd_packet_len_mean;
                self.bwd_packet_len_mean += delta / n_bwd;
                let delta2 = len - self.bwd_packet_len_mean;
                self.bwd_packet_len_m2 += delta * delta2;
                
                if self.bwd_packet_count > 1 {
                    self.bwd_packet_len_std = (self.bwd_packet_len_m2 / (n_bwd - 1.0)).sqrt();
                }
                
                self.bwd_packet_len_min = self.bwd_packet_len_min.min(packet_len);
                self.bwd_packet_len_max = self.bwd_packet_len_max.max(packet_len);
            }
        }
    }

    fn update_iat_stats(&mut self, timestamp: u64, direction: FlowDirection) {
        if self.total_packets > 1 {
            // Flow-level IAT
            let flow_iat = timestamp.saturating_sub(self.last_packet_timestamp);
            self.flow_iat_total += flow_iat;
            
            self.flow_iat_min = self.flow_iat_min.min(flow_iat);
            self.flow_iat_max = self.flow_iat_max.max(flow_iat);

            // Online IAT statistics
            let n = (self.total_packets - 1) as f64;
            let delta = flow_iat as f64 - self.flow_iat_mean;
            self.flow_iat_mean += delta / n;
            let delta2 = flow_iat as f64 - self.flow_iat_mean;
            self.flow_iat_m2 += delta * delta2;
            
            if n > 1.0 {
                self.flow_iat_std = (self.flow_iat_m2 / (n - 1.0)).sqrt();
            }
            
            // Direction-specific IAT
            match direction {
                FlowDirection::Forward => {
                    if self.last_fwd_packet_timestamp > 0 {
                        let fwd_iat = timestamp - self.last_fwd_packet_timestamp;
                        self.fwd_iat_total += fwd_iat;
                        
                        self.fwd_iat_min = self.fwd_iat_min.min(flow_iat);
                        self.fwd_iat_max = self.fwd_iat_max.min(flow_iat);
                        
                        let n_fwd = self.total_fwd_packets as f64;
                        if n_fwd > 1.0 {
                            let delta = fwd_iat as f64 - self.fwd_iat_mean;
                            self.fwd_iat_mean += delta / (n_fwd - 1.0);
                            let delta2 = fwd_iat as f64 - self.fwd_iat_mean;
                            self.fwd_iat_m2 += delta * delta2;
                            
                            if n_fwd > 2.0 {
                                self.fwd_iat_std = (self.fwd_iat_m2 / (n_fwd - 2.0)).sqrt();
                            }
                        }
                    }
                    self.last_fwd_packet_timestamp = timestamp;
                }
                FlowDirection::Backward => {
                    if self.last_bwd_packet_timestamp > 0 {
                        let bwd_iat = timestamp - self.last_bwd_packet_timestamp;
                        self.bwd_iat_total += bwd_iat;
                        
                        self.bwd_iat_min = self.bwd_iat_min.min(flow_iat);
                        self.bwd_iat_max = self.bwd_iat_max.min(flow_iat);
                        
                        let n_bwd = self.total_bwd_packets as f64;
                        if n_bwd > 1.0 {
                            let delta = bwd_iat as f64 - self.bwd_iat_mean;
                            self.bwd_iat_mean += delta / (n_bwd - 1.0);
                            let delta2 = bwd_iat as f64 - self.bwd_iat_mean;
                            self.bwd_iat_m2 += delta * delta2;
                            
                            if n_bwd > 2.0 {
                                self.bwd_iat_std = (self.bwd_iat_m2 / (n_bwd - 2.0)).sqrt();
                            }
                        }
                    }
                    self.last_bwd_packet_timestamp = timestamp;
                }
            }
        } else {
            // First packet - initialize timestamps
            match direction {
                FlowDirection::Forward => self.last_fwd_packet_timestamp = timestamp,
                FlowDirection::Backward => self.last_bwd_packet_timestamp = timestamp,
            }
        }
        
        self.last_packet_timestamp = timestamp;
    }

    /// Update Active/Idle time features according to CICFlowMeter rules
    fn update_active_idle_stats(&mut self, timestamp: u64) {
        if self.total_packets > 1 {
            let time_since_last = timestamp - self.last_activity_time;
            
            if time_since_last > ACTIVITY_TIMEOUT_US {
                // Transition from active to idle
                if self.is_in_active_period {
                    let active_duration = self.last_activity_time - self.current_active_start;
                    self.update_active_time_stats(active_duration);
                    self.current_idle_start = self.last_activity_time;
                    self.is_in_active_period = false;
                }
                
                // We're in idle period
                let idle_duration = timestamp - self.current_idle_start;
                // Don't update idle stats yet - wait for next active period
            } else {
                // Still active or transition from idle to active
                if !self.is_in_active_period {
                    let idle_duration = timestamp - self.current_idle_start;
                    self.update_idle_time_stats(idle_duration);
                    self.current_active_start = timestamp;
                    self.is_in_active_period = true;
                }
            }
        }
        
        self.last_activity_time = timestamp;
    }

    fn update_active_time_stats(&mut self, duration: u64) {
        self.active_counts += 1;
        self.active_time_tot += duration;
        
        self.active_min.min(duration);
        self.active_max.max(duration);
        
        let n = self.active_counts as f64;
        let delta = duration as f64 - self.active_mean;
        self.active_mean += delta / n;
        let delta2 = duration as f64 - self.active_mean;
        self.active_time_m2 += delta * delta2;
        
        if n > 1.0 {
            self.active_std = (self.active_time_m2 / (n - 1.0)).sqrt();
        }
    }

    fn update_idle_time_stats(&mut self, duration: u64) {
        self.idle_counts += 1;
        self.idle_time_tot += duration;
        
        if duration < self.idle_min { self.idle_min = duration; }
        if duration > self.idle_max { self.idle_max = duration; }
        
        let n = self.idle_counts as f64;
        let delta = duration as f64 - self.idle_mean;
        self.idle_mean += delta / n;
        let delta2 = duration as f64 - self.idle_mean;
        self.idle_time_m2 += delta * delta2;
        
        if n > 1.0 {
            self.idle_std = (self.idle_time_m2 / (n - 1.0)).sqrt();
        }
    }

    /// Update bulk transfer features
    fn update_bulk_features(&mut self, direction: FlowDirection, payload_len: u32) {
        match direction {
            FlowDirection::Forward => {
                if matches!(self.last_bulk_direction, Some(FlowDirection::Forward)) {
                    self.fwd_consecutive_packets += 1;
                } else {
                    // Direction changed or first packet
                    if self.bwd_consecutive_packets >= BULK_THRESHOLD {
                        self.finalize_bwd_bulk();
                    }
                    self.fwd_consecutive_packets = 1;
                    self.fwd_bulk_start = self.last_packet_timestamp;
                }
                
                if payload_len > 0 {
                    self.fwd_bytes_curr_bulk += payload_len as f64;
                }
                
                self.last_bulk_direction = Some(FlowDirection::Forward);
            }

            FlowDirection::Backward => {
                if matches!(self.last_bulk_direction, Some(FlowDirection::Backward)) {
                    self.bwd_consecutive_packets += 1;
                } else {
                    // Direction changed or first packet
                    if self.fwd_consecutive_packets >= BULK_THRESHOLD {
                        self.finalize_fwd_bulk();
                    }
                    self.bwd_consecutive_packets = 1;
                    self.bwd_bulk_start = self.last_packet_timestamp;
                }
                
                if payload_len > 0 {
                    self.bwd_bytes_curr_bulk += payload_len as f64;
                }
                
                self.last_bulk_direction = Some(FlowDirection::Backward);
            }
        }
    }

    fn finalize_fwd_bulk(&mut self) {
        if self.fwd_consecutive_packets >= BULK_THRESHOLD {
            self.num_fwd_bulk_transmissions += 1;
            self.fwd_bytes_bulk_tot += self.fwd_bytes_curr_bulk;
            self.fwd_packet_bulk_tot += self.fwd_consecutive_packets as f64;
            
            // Calculate averages
            let n_bulk = self.num_fwd_bulk_transmissions as f64;
            self.fwd_bytes_bulk_avg = self.fwd_bytes_bulk_tot / n_bulk;
            self.fwd_packet_bulk_avg = self.fwd_packet_bulk_tot / n_bulk;
            
            // Calculate bulk rate if we have duration
            self.fwd_bulk_end = self.last_packet_timestamp;
            self.fwd_bulk_duration = self.fwd_bulk_end - self.fwd_bulk_start;
            if self.fwd_bulk_duration > 0 {
                self.fwd_bulk_rate_avg = self.fwd_bytes_curr_bulk / (self.fwd_bulk_duration as f64 / 1_000_000.0);
            }
        }
        
        self.fwd_bytes_curr_bulk = 0.0;
        self.fwd_consecutive_packets = 0;
    }

    fn finalize_bwd_bulk(&mut self) {
        if self.bwd_consecutive_packets >= BULK_THRESHOLD {
            self.num_bwd_bulk_transmissions += 1;
            self.bwd_bytes_bulk_tot += self.bwd_bytes_curr_bulk;
            self.bwd_packet_bulk_tot += self.bwd_consecutive_packets as f64;
            
            // Calculate averages
            let n_bulk = self.num_bwd_bulk_transmissions as f64;
            self.bwd_bytes_bulk_avg = self.bwd_bytes_bulk_tot / n_bulk;
            self.bwd_packet_bulk_avg = self.bwd_packet_bulk_tot / n_bulk;
            
            // Calculate bulk rate if we have duration
            self.bwd_bulk_end = self.last_packet_timestamp;
            self.bwd_bulk_duration = self.bwd_bulk_end - self.bwd_bulk_start;
            if self.bwd_bulk_duration > 0 {
                self.bwd_bulk_rate_avg = self.bwd_bytes_curr_bulk / (self.bwd_bulk_duration as f64 / 1_000_000.0);
            }
        }
        
        self.bwd_bytes_curr_bulk = 0.0;
        self.bwd_consecutive_packets = 0;
    }

    /// Update TCP flags according to CICFlowMeter rules (count ALL packets, not just first)
    fn update_tcp_flags(&mut self, tcp_flags: u8, direction: FlowDirection) {
        // Count flags for all packets (CICFlowMeter bug fix)
        if tcp_flags & 0x01 != 0 { self.fin_flag_count += 1; }
        if tcp_flags & 0x02 != 0 { self.syn_flag_count += 1; }
        if tcp_flags & 0x04 != 0 { self.rst_flag_count += 1; }
        if tcp_flags & 0x08 != 0 { 
            self.psh_flag_count += 1;
            match direction {
                FlowDirection::Forward => self.fwd_psh_flags += 1,
                FlowDirection::Backward => self.bwd_psh_flags += 1,
            }
        }
        if tcp_flags & 0x10 != 0 { self.ack_flag_count += 1; }
        if tcp_flags & 0x20 != 0 { 
            self.urg_flag_count += 1;
            match direction {
                FlowDirection::Forward => self.fwd_urg_flags += 1,
                FlowDirection::Backward => self.bwd_urg_flags += 1,
            }
        }
        if tcp_flags & 0x40 != 0 { self.ece_flag_count += 1; }
        if tcp_flags & 0x80 != 0 { self.cwr_flag_count += 1; }
    }

    pub fn update_tcp_flow(
        &mut self,
        timestamp: u64,
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        packet_len: u32,
        payload_len: Option<u32>,
        tcp_flags: u8,
        window_size: u16,
        header_len: u32,
    ) {
        let direction = self.get_flow_direction(src_ip, dst_ip, src_port, dst_port);
        let payload_size = payload_len.unwrap_or(0);
        

        // Update subflow features
        let payload_size = payload_len.unwrap_or(0);
        self.update_subflow_features(timestamp, direction, payload_size);

        // Update packet length statistics
        self.update_packet_length_stats(packet_len, direction);
        
        // Update byte counters
        self.total_bytes += payload_size as u64;
        match direction {
            FlowDirection::Forward => {
                self.total_fwd_bytes += payload_size as u64;
                self.fwd_header_len += header_len;
                
                // Track minimum segment size for forward direction
                if payload_size > 0 {
                    self.fwd_act_data_packets += 1;
                    let seg_size = payload_size as f64;
                    if seg_size < self.fwd_seg_size_min {
                        self.fwd_seg_size_min = seg_size;
                    }
                }
                
                // Initialize window size on first packet
                if self.total_fwd_packets == 1 {
                    self.fwd_init_win_bytes = window_size as u32;
                }
            }
            FlowDirection::Backward => {
                self.total_bwd_bytes += payload_size as u64;
                self.bwd_header_len += header_len;
                
                // Initialize window size on first backward packet
                if self.total_bwd_packets == 1 {
                    self.bwd_init_win_bytes = window_size as u32;
                }
            }
        }
        
        // Update Inter-Arrival Time statistics
        self.update_iat_stats(timestamp, direction);
        
        // Update Active/Idle statistics
        self.update_active_idle_stats(timestamp);
        
        // Update bulk transfer features
        self.update_bulk_features(direction, payload_size);
        
        // Update TCP flags
        self.update_tcp_flags(tcp_flags, direction);
        
        // Update flow metadata
        self.flow_last_time = timestamp;
        self.flow_duration = self.flow_last_time.saturating_sub(self.flow_start_time);
        self.last_checked_time = timestamp;
        self.status = FlowStatus::Active;
        
        // Calculate derived features
        self.calculate_derived_features();
    }

    /// Calculate derived features like rates and ratios
    fn calculate_derived_features(&mut self) {
        let duration_seconds = (self.flow_duration as f64) / 1_000_000.0;
        
        if duration_seconds > 0.0 {
            self.flow_packets_per_sec = (self.total_packets as f64) / duration_seconds;
            self.flow_bytes_per_sec = (self.total_bytes as f64) / duration_seconds;
            self.fwd_packets_per_sec = (self.total_fwd_packets as f64) / duration_seconds;
            self.bwd_packets_per_sec = (self.total_bwd_packets as f64) / duration_seconds;
        }
        
        if self.total_packets > 0 {
            self.avg_packet_size = (self.total_bytes as f64) / (self.total_packets as f64);
        }
        
        if self.total_fwd_packets > 0 {
            self.fwd_segment_size_avg = (self.total_fwd_bytes as f64) / (self.total_fwd_packets as f64);
        }
        
        if self.total_bwd_packets > 0 {
            self.bwd_segment_size_avg = (self.total_bwd_bytes as f64) / (self.total_bwd_packets as f64);
        }
        
        // Down/Up ratio (backward/forward)
        if self.total_fwd_bytes > 0 {
            self.down_up_ratio = (self.total_bwd_bytes as f64) / (self.total_fwd_bytes as f64);
        }
    }

    /// Check if flow should be terminated according to CICFlowMeter rules
    pub fn should_terminate(&self, current_time: u64, has_fin_flag: bool) -> bool {
        // TCP flows: terminate on FIN flag OR timeout
        if has_fin_flag {
            return true;
        }
        // Timeout check
        (current_time - self.flow_start_time) > FLOW_TIMEOUT_US
    }
}




