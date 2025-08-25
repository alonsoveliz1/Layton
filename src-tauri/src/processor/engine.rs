use crossbeam_channel::{select, tick, Receiver, Sender};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::collections::hash_map::Entry;

use crate::capture::ParsedPacket;
use crate::types::NetworkStats;
use super::flow::{FlowKey, FlowRecord , FlowDirection, FLOW_TIMEOUT_US};


#[inline]
fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

pub fn processing_loop(running: Arc<AtomicBool>, packet_rx: Receiver<ParsedPacket>, stats_tx: Sender<NetworkStats>, classifier_tx: Sender<FlowRecord>) {
    let start_time = now_micros();

    // Timers to send expired flows to the classifier and stats to the frontend
    let expire_tick = tick(Duration::from_secs(1));
    let stats_tick  = tick(Duration::from_secs(1));

    // We create the HashMap for the FlowRecords
    let mut flows: HashMap<FlowKey, FlowRecord> = HashMap::new();

    let mut last_rate_us = now_micros();
    let mut pkts_acc: u64 = 0;
    let mut bytes_acc: u64 = 0;

    let mut total_pkts: i64 = 0;
    let mut total_bytes: i64 = 0;

    let mut suspicious_flows: i64 = 0;

    loop {
        // While we're running
        if !running.load(Ordering::Relaxed) { break; }

        select! {
            // We get the packets from the sniffer
            recv(packet_rx) -> msg => {
                if let Ok(pkt) = msg {
                    // Create normalized key for HashMap lookup
                    let normalized_key = FlowKey::new(pkt.flow_key.ip_a, pkt.flow_key.ip_b, pkt.flow_key.port_a, pkt.flow_key.port_b, pkt.flow_key.protocol);

                    let flow = match flows.entry(normalized_key.clone()) {
                        // If Key exist we get value and make it mutable
                        Entry::Occupied(e) => e.into_mut(),
                        // If it doesn't we compute direction
                        Entry::Vacant(e) => {
                            // For new flows, determine the direction of the FIRST packet
                            let first_direction = if (pkt.flow_key.ip_a, pkt.flow_key.port_a) <= (pkt.flow_key.ip_b, pkt.flow_key.port_b) {
                                FlowDirection::Forward
                            } else {
                                FlowDirection::Backward
                                
                            };    
                           // And insert the flow
                           let mut flow = FlowRecord::new(normalized_key, pkt.timestamp, first_direction);
                           e.insert(flow)
                        },
                    };

                    // Check for flow termination (FIN flag)
                    let has_fin = pkt.tcp_flags & 0x01 != 0;
                    
                    // Update flow features
                    flow.update_tcp_flow(
                        pkt.timestamp,
                        pkt.flow_key.ip_a, pkt.flow_key.ip_b, 
                        pkt.flow_key.port_a, pkt.flow_key.port_b,
                        pkt.flow_key.protocol,
                        pkt.packet_len,
                        Some(pkt.payload_len),
                        pkt.tcp_flags,
                        pkt.window_size,
                        pkt.header_len,
                    );

                    // And send it to the classifier and remove it from the HashMap if should be removed
                    if flow.should_terminate(pkt.timestamp, has_fin) {
                        // TODO SEND TO CLASSIFIER
                        // flow.finalize();
                        let flow_copy = flow.clone();
                        flows.remove(&normalized_key);
                        let _ = classifier_tx.send(flow_copy);
                    }

                    pkts_acc += 1;
                    total_pkts += 1;
                    bytes_acc += pkt.payload_len as u64;
                    total_bytes += pkt.payload_len as i64;
                }
            },

            recv(expire_tick) -> _ => {
                let now = now_micros();
                // Create a vector with the flows ready to be sent to the classifier
                let mut flows_to_classify: Vec<FlowRecord> = Vec::new();
                // Populate the vector
                flows.retain(|key, flow| {
                    let should_keep = (now - flow.last_seen_micros()) < FLOW_TIMEOUT_US;
                    if !should_keep{
                        // flow.finalize(); Compute final features
                        flows_to_classify.push(flow.clone());
                    }
                    should_keep
                });

                // And send them to the classifier
                for flow in flows_to_classify{
                    let _ = classifier_tx.send(flow);
                }
            },

            recv(stats_tick) -> _ => {
                let now = now_micros();
                let dt = ((now - last_rate_us) as f64 / 1_000_000.0).max(1e-6);

                let stats = NetworkStats {
                    flow_count: flows.len() as i64,
                    packets_per_second: (pkts_acc as f64) / dt,
                    bytes_per_second: (bytes_acc as f64) / dt,
                    total_packets: total_pkts,
                    total_bytes: total_bytes,
                    uptime_seconds: ((now - start_time) / 1_000_000) as i64,
                };

                let _ = stats_tx.send(stats);
                pkts_acc = 0;
                bytes_acc = 0;
                last_rate_us = now;
            },
        }
    }
}


