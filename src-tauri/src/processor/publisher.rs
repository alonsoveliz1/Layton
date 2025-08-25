use crossbeam_channel::{select, tick, Receiver};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};

use crate::types::NetworkStats;

pub fn publisher_loop(
    running: Arc<AtomicBool>,
    stats_rx: Receiver<NetworkStats>,
    app: AppHandle,
) {
    let emit_tick = tick(Duration::from_millis(250));
    let mut latest: Option<NetworkStats> = None;

    loop {
        if !running.load(Ordering::Relaxed) { break; }

        select! {
            recv(stats_rx) -> msg => {
                if let Ok(s) = msg { latest = Some(s); }
            }
            recv(emit_tick) -> _ => {
                if let Some(ref s) = latest {
                    let _ = app.emit("network-stats", s);
                }
            }
        }
    }
}
