use pcap::{Active, Capture, PacketHeader};
use serde::{Serialize};
use std::error::Error;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use std::thread::{self, JoinHandle};
use crossbeam_channel::Sender;
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};

use crate::processor::FlowKey;

#[derive(Debug, Clone, Serialize)]
pub struct NetworkInterface {
    pub name: String,
    pub description: String,
    pub is_up: bool,
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub timestamp: u64,
    pub flow_key: FlowKey,
    pub packet_len: u32,
    pub payload_len: u32,
    pub tcp_flags: u8,
    pub window_size: u16,
    pub header_len: u32,
}

pub struct PacketSniffer {
    sniffer_running: Arc<AtomicBool>,
    sniffer_thread: Option<JoinHandle<()>>,
    capture: Option<Capture<Active>>,      // owned until start, then moved into thread
    packet_sender: Sender<ParsedPacket>,
}

impl PacketSniffer {
    pub fn new_with_sender(sender: Sender<ParsedPacket>) -> Self {
        Self {
            sniffer_running: Arc::new(AtomicBool::new(false)),
            sniffer_thread: None,
            capture: None,
            packet_sender: sender,
        }
    }

    pub fn init_sniffer(&mut self, interface: &str, filter: &str) -> Result<(), Box<dyn Error>> {
        let mut cap = Capture::from_device(interface)?
            .promisc(true)
            .immediate_mode(true)
            .timeout(10)
            .open()?;

        cap.filter(filter, true)?;
        println!("Interface: {interface} successfully opened");
        println!("Filter: {filter} applied");

        self.capture = Some(cap);
        Ok(())
    }

    pub fn start_sniffer(&mut self) -> Result<(), Box<dyn Error>> {
        let cap = self
            .capture
            .take()
            .ok_or("Capture is not initialized. Call init_sniffer first")?;

        if self.sniffer_running.swap(true, Ordering::Relaxed) {
            return Err("Sniffer is already running".into());
        }

        let mut cap = cap.setnonblock()?;

        let running = self.sniffer_running.clone();
        let sender = self.packet_sender.clone();

        self.sniffer_thread = Some(thread::spawn(move || {
            println!("Sniffer thread started");
            while running.load(Ordering::Relaxed) {
                match cap.next_packet() {
                    Ok(packet) => PacketSniffer::packet_handler(&packet.header, &packet.data, &sender),
                    Err(pcap::Error::TimeoutExpired) => {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(e) => { eprintln!("Error capturing packet: {e}"); break; }
                }
            }
            println!("Sniffer thread exiting");
            // cap drops here
        }));

        Ok(())
    }



    pub fn stop_sniffer(&mut self) -> Result<(), Box<dyn Error>> {
        if !self.sniffer_running.swap(false, Ordering::Relaxed) {
            return Ok(());
        }

        if let Some(handle) = self.sniffer_thread.take() {
            let _ = handle.join();
        }

        // If start succeeded, capture is already moved. If not, drop it now.
        self.capture = None;
        println!("Sniffer stopped");
        Ok(())
    }



    fn packet_handler(header: &PacketHeader, packet_data: &[u8], sender: &Sender<ParsedPacket>) {
        match Self::parse_packet(header, packet_data) {
            Ok(parsed_packet) => {
                // If can parse the packet we send it to the engine
                let _ = sender.try_send(parsed_packet);
            }
            Err(_) => {
            }
        }
    }

    

    fn parse_packet(header: &PacketHeader, data: &[u8]) -> Result<ParsedPacket, Box<dyn Error>> {
        let timestamp = (header.ts.tv_sec as u64 * 1_000_000) + header.ts.tv_usec as u64;

        let parsed = PacketHeaders::from_ethernet_slice(data)
            .map_err(|e| format!("Failed to parse packet: {e}"))?;

        let (src_ip, dst_ip) = match &parsed.net {
            Some(NetHeaders::Ipv4(ipv4, _)) => (
                u32::from_be_bytes(ipv4.source),
                u32::from_be_bytes(ipv4.destination),
            ),
            _ => return Err("Not an IPv4 packet".into()),
        };

        let (src_port, dst_port, tcp_flags, window_size, tcp_header_len, protocol) = match &parsed.transport {
            Some(TransportHeader::Tcp(tcp)) => {
                let header_len = tcp.data_offset() as u32 * 4;
                let flags = (tcp.cwr as u8) << 7
                    | (tcp.ece as u8) << 6
                    | (tcp.urg as u8) << 5
                    | (tcp.ack as u8) << 4
                    | (tcp.psh as u8) << 3
                    | (tcp.rst as u8) << 2
                    | (tcp.syn as u8) << 1
                    | (tcp.fin as u8);
                (
                    tcp.source_port,
                    tcp.destination_port,
                    flags,
                    tcp.window_size,
                    header_len,
                    6,
                )
            }
            _ => return Err("Not a TCP packet".into()),
        };

        

        let flow_key = FlowKey::new(src_ip, dst_ip, src_port, dst_port, protocol);

        let eth_header_len = 14;
        let ip_header_len = parsed.net.map_or(0, |ip| match ip {
            etherparse::NetHeaders::Ipv4(ipv4, _) => ipv4.header_len() as u32,
            _ => 0,
        });
        let total_header_len = eth_header_len + ip_header_len + tcp_header_len;

        Ok(ParsedPacket {
            timestamp,
            flow_key,
            packet_len: header.len,
            payload_len: (header.len as u32).saturating_sub(total_header_len),
            tcp_flags,
            window_size,
            header_len: total_header_len,
        })
    }
}
