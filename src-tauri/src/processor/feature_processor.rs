use crossbeam_channel::{unbounded, Receiver, Sender};
use std::error::Error;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use tauri::AppHandle;

use crate::processor::FlowRecord;
use crate::capture::ParsedPacket;
use crate::types::NetworkStats;
use super::{engine, publisher};

pub struct FeatureProcessor {
    running: Arc<AtomicBool>,
    processing_thread: Option<JoinHandle<()>>,
    publisher_thread: Option<JoinHandle<()>>,
    packet_tx: Sender<ParsedPacket>,
    packet_rx: Receiver<ParsedPacket>,
    stats_tx: Sender<NetworkStats>,
    stats_rx: Receiver<NetworkStats>,
}

impl FeatureProcessor {
    pub fn new() -> Self {
        let (packet_tx, packet_rx) = unbounded();
        let (stats_tx, stats_rx) = unbounded();
        Self {
            running: Arc::new(AtomicBool::new(false)),
            processing_thread: None,
            publisher_thread: None,
            packet_tx,
            packet_rx,
            stats_tx,
            stats_rx,
        }
    }

    pub fn get_sender(&self) -> Sender<ParsedPacket> { self.packet_tx.clone() }

    pub fn start_processor(&mut self, app: AppHandle, classifier_tx: Sender<FlowRecord>) -> Result<(), Box<dyn Error>> {
        if self.running.load(Ordering::Relaxed) {
            return Err("Processor is already running".into());
        }
        self.running.store(true, Ordering::Relaxed);

        let processing = {
            let running = self.running.clone();
            let rx = self.packet_rx.clone();
            let stats_tx = self.stats_tx.clone();
            thread::spawn(move || engine::processing_loop(running, rx, stats_tx, classifier_tx))
        };

        let publisher = {
            let running = self.running.clone();
            let stats_rx = self.stats_rx.clone();
            let app = app.clone();
            thread::spawn(move || publisher::publisher_loop(running, stats_rx, app))
        };

        self.processing_thread = Some(processing);
        self.publisher_thread = Some(publisher);
        Ok(())
    }

    pub fn stop_processor(&mut self) -> Result<(), Box<dyn Error>> {
        if !self.running.load(Ordering::Relaxed) {
            return Err("Processor isn't running".into());
        }
        self.running.store(false, Ordering::Relaxed);

        if let Some(h) = self.processing_thread.take() { let _ = h.join(); }
        if let Some(h) = self.publisher_thread.take() { let _ = h.join(); }
        Ok(())
    }
}
