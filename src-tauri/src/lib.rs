pub mod capture; 
pub mod processor;
pub mod types; 
pub mod classifier;
pub mod csv_writer;

use capture::{PacketSniffer, NetworkInterface};
use processor::{FeatureProcessor};
use classifier::ClassifierHandles;

use dirs::data_local_dir;
use tauri::{Manager, State, path::BaseDirectory};
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path};
use tauri::{Emitter};
use rusqlite::{Connection, params};
use std::thread::JoinHandle;
use std::sync::atomic::Ordering;




pub struct AppState {
    pub sniffer: Arc<Mutex<Option<PacketSniffer>>>,
    pub processor: Arc<Mutex<Option<FeatureProcessor>>>,
    pub selected_interface: Arc<Mutex<Option<String>>>,
    pub classifier: Arc<Mutex<Option<ClassifierHandles>>>,
    pub db: Arc<Mutex<Connection>>,
    pub csv_writer_thread: Arc<Mutex<Option<JoinHandle<()>>>>,
    pub baseline_mode: Arc<Mutex<bool>>,
}

impl Default for AppState {
    fn default() -> Self {
        let db_path = data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("nids.db");

        let conn = Connection::open(db_path).expect("Failed to open DB");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                total_packets INTEGER,
                total_bytes INTEGER,
                duration_us INTEGER,
                is_attack BOOLEAN,
                p_attack REAL,
                multi_class INTEGER,
                multi_label TEXT
            );"
        ).expect("Failed to create flows table");
        Self {
            sniffer: Arc::new(Mutex::new(None)),
            processor: Arc::new(Mutex::new(None)),
            classifier: Arc::new(Mutex::new(None)),
            selected_interface: Arc::new(Mutex::new(None)),
            db : Arc::new(Mutex::new(conn)),
            csv_writer_thread: Arc::new(Mutex::new(None)),
            baseline_mode: Arc::new(Mutex::new(false)),
        }
    }
}


#[derive(Debug, Deserialize)]
struct ClassMap {
    num_classes: usize,
    id_to_label: HashMap<String, String>,
}

// Maps the json generated in training for the multiclass model giving a vector of the categories 
fn load_label_vector<P: AsRef<Path>>(path: P) -> Result<Vec<String>, String> {
    let s = fs::read_to_string(path).map_err(|e| format!("read class_map.json: {e}"))?;
    let m: ClassMap = serde_json::from_str(&s).map_err(|e| format!("parse class_map.json: {e}"))?;
    let mut labels = vec!["Unknown".to_string(); m.num_classes.max(1)];
    for (k, v) in m.id_to_label {
        if let Ok(idx) = k.parse::<usize>() {
            if idx < labels.len() { labels[idx] = v; }
        }
    }
    Ok(labels)
}


#[derive(Debug, Serialize, Clone)]
struct FlowKeyDTO {
    ip_a: u32, ip_b: u32, port_a: u16, port_b: u16, protocol: u8,
}

impl From<crate::processor::FlowKey> for FlowKeyDTO {
    fn from(k: crate::processor::FlowKey) -> Self {
        Self { ip_a: k.ip_a, ip_b: k.ip_b, port_a: k.port_a, port_b: k.port_b, protocol: k.protocol }
    }
}

#[derive(Debug, Serialize, Clone)]
struct ClassifiedFlowEvent {
    key: FlowKeyDTO,
    start_us: u64,
    end_us: u64,
    duration_us: u64,
    total_packets: u64,
    total_bytes: u64,
    // Binario
    is_attack: bool,
    p_attack: f32,
    // Multiclase (solo si is_attack)
    multi_class: Option<u8>,
    multi_label: Option<String>,
    multi_probs: Option<Vec<f32>>,
}


#[tauri::command]
async fn list_network_devices() -> Result<Vec<NetworkInterface>, String> {
    let devices = pcap::Device::list().map_err(|e| e.to_string())?;

    let want_prefixes = ["en", "eth", "wl", "br-", "docker", "veth", "virbr", "vboxnet"];

    let filtered: Vec<NetworkInterface> = devices
        .into_iter()
        .filter(|d| {
            let n = d.name.as_str();
            // keep common NICs, docker bridges, and virt adapters; drop loopback
            (want_prefixes.iter().any(|p| n.starts_with(p))) && !d.flags.is_loopback()
        })
        .map(|d| {
            let description = d.desc.unwrap_or_else(|| {
                if d.name.starts_with("br-") || d.name == "docker0" { "Docker Bridge".into() }
                else if d.name.starts_with("en") || d.name.starts_with("eth") { "Ethernet Interface".into() }
                else if d.name.starts_with("wl") { "Wi-Fi Interface".into() }
                else { "Network Interface".into() }
            });
            NetworkInterface { name: d.name, description, is_up: d.flags.is_up() }
        })
        .collect();
    Ok(filtered)
}


#[tauri::command]
fn get_selected_interface_info(interface_name: String) -> Result<NetworkInterface, String>{
    let devices = pcap::Device::list().map_err(|e| e.to_string())?;
    for device in devices{
        if device.name == interface_name{
            return Ok(NetworkInterface {
                name: device.name,
                description: device.desc.unwrap_or_else(|| "No description".to_string()),
                is_up:device.flags.is_up(),
            });
        }
    }
    Err(format!("Interface '{}' not found", interface_name))
}



#[tauri::command]
fn start_system(interface: &str, state: State<AppState>, app_handle: tauri::AppHandle) -> Result<(), String>{
    let mut processor = FeatureProcessor::new();

    let model_path = app_handle.path().resolve("classifier-models/l1_model.onnx", BaseDirectory::Resource).map_err(|e| format!("Could not resolve model resource path: {e}"))?;
    let model_path2 = app_handle.path().resolve("classifier-models/l2_multiclass.onnx", BaseDirectory::Resource).map_err(|e| format!("Could not resolve model resource path: {e}"))?;

    let classifier = classifier::spawn_classifier(model_path.to_string_lossy().into_owned(), model_path2.to_string_lossy().into_owned())
    .map_err(|e| format!("Failed to start classifier: {e}"))?;


    let class_map_path = app_handle.path().resolve("classifier-models/class_map.json", BaseDirectory::Resource)
        .map_err(|e| format!("Could not resolve class_map path: {e}"))?;
    let labels = load_label_vector(&class_map_path)
        .map_err(|e| format!("Failed to load class_map: {e}"))?;
    let labels = std::sync::Arc::new(labels);

    // Thread to receive the classified flows
    {
        let rx = classifier.rx.clone();           
        let app = app_handle.clone();
        let labels = labels.clone();
        let db = state.db.clone();
        
        std::thread::spawn(move || {
            let mut num_alerts: i128 = 0;

            while let Ok((flow, res)) = rx.recv() {
                let is_attack = res.bin.pred_label == 1;
                let p_attack = res.bin.probs.get(1).copied().unwrap_or(0.0);

                let (multi_class, multi_label, multi_probs) = if let Some(m) = res.multi {
                    let idx = m.pred_label;
                    let label = labels.get(idx as usize).cloned().unwrap_or_else(|| "Unknown".into());
                    (Some(idx), Some(label), Some(m.probs))
                } else {
                    (None, None, None)
                };
                if is_attack {
                    num_alerts += 1;
                    let db = db.lock().map_err(|_| "Failed to lock DB").unwrap();
                    db.execute(
                        "INSERT INTO flows (src_ip, dst_ip, src_port, dst_port, protocol, total_packets, total_bytes, duration_us, is_attack, p_attack, multi_class, multi_label) 
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                         rusqlite::params![
                            flow.key.ip_a.to_string(),
                            flow.key.ip_b.to_string(),
                            flow.key.port_a as i64,
                            flow.key.port_b as i64,
                            flow.key.protocol as i64,
                            flow.total_packets as i64,
                            flow.total_bytes as i64,
                            flow.flow_duration as i64,
                            is_attack as i64,
                            p_attack as f64,
                            multi_class.map(|v| v as i64),
                            multi_label,
                         ]
                    ).ok();
                }

                let payload = ClassifiedFlowEvent {
                    key: flow.key.into(),
                    start_us: flow.flow_start_time,
                    end_us: flow.flow_last_time,
                    duration_us: flow.flow_duration,
                    total_packets: flow.total_packets,
                    total_bytes: flow.total_bytes,
                    is_attack,
                    p_attack,
                    multi_class,
                    multi_label,
                    multi_probs,
                };
                
                let _ = app.emit("num_alerts", num_alerts);
                // Nombre del evento Tauri para el frontend:
                let _ = app.emit("flow_classified", payload);
            }
        });
    }




    let mut sniffer = PacketSniffer::new_with_sender(processor.get_sender());

    sniffer.init_sniffer(interface, "tcp").map_err(|e| e.to_string())?;
    sniffer.start_sniffer().map_err(|e| e.to_string())?;

    processor.start_processor(app_handle, classifier.tx.clone()).map_err(|e| e.to_string())?;
    
    let mut state_sniffer = state.sniffer.lock().map_err(|_| "Failed to lock sniffer state")?;
    let mut state_processor = state.processor.lock().map_err(|_| "Failed to lock processor state")?;  // ADD THIS
    
    *state_sniffer = Some(sniffer);
    *state_processor = Some(processor);
    *state.classifier.lock().map_err(|_| "Failed to lock classifier state")? = Some(classifier);

    println!("Sniffer started succesfully");
    Ok(())
}

#[tauri::command]
fn stop_system(state: State<AppState>) -> Result<(), String> {
    // Stop the sniffer
    let mut sniffer_state = state.sniffer.lock()
        .map_err(|_| "Failed to lock sniffer state")?;
    
    // Stop the processor
    let mut processor_state = state.processor.lock()
        .map_err(|_| "Failed to lock processor state")?;

    if let Some(mut sniffer) = sniffer_state.take() {
        sniffer.stop_sniffer()
            .map_err(|e| format!("Error stopping sniffer: {}", e))?;
    }

    if let Some(mut processor) = processor_state.take() {
        processor.stop_processor()
            .map_err(|e| format!("Error stopping processor: {}", e))?;
    }



    
    println!("System stopped successfully");
    Ok(())
}

#[tauri::command]
fn start_baseline_collection(
    interface: &str, 
    output_dir: Option<String>,
    session_name: Option<String>,
    state: State<AppState>, 
    app_handle: tauri::AppHandle
) -> Result<(), String> {
    // Check if system is already running
    if *state.baseline_mode.lock().map_err(|_| "Failed to lock baseline mode")? {
        return Err("Baseline collection is already running".into());
    }
    
    let mut processor = FeatureProcessor::new();
    
    // Create channel for CSV writer
    let (csv_tx, csv_rx) = crossbeam_channel::unbounded();
    

    // Start CSV writer thread
    let output_path = if let Some(path) = output_dir {
        path
    } else {
        dirs::document_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("network_traffic.csv")
            .to_string_lossy()
            .into_owned()
    };
    print!("Using output directory: {}\n", output_path);
    
    // Start sniffer
    let mut sniffer = PacketSniffer::new_with_sender(processor.get_sender());
    sniffer.init_sniffer(interface, "tcp").map_err(|e| e.to_string())?;
    sniffer.start_sniffer().map_err(|e| e.to_string())?;
    
    let running_flag = processor.running.clone();

    // Start processor with CSV writer instead of classifier
    processor.start_processor_baseline(app_handle, csv_tx.clone()).map_err(|e| e.to_string())?;
    
    let csv_thread = {
        std::thread::spawn(move || {
            csv_writer::csv_writer_loop(running_flag, csv_rx, output_path, session_name)
        })
    };

    // Store state
    *state.sniffer.lock().map_err(|_| "Failed to lock sniffer")? = Some(sniffer);
    *state.processor.lock().map_err(|_| "Failed to lock processor")? = Some(processor);
    *state.csv_writer_thread.lock().map_err(|_| "Failed to lock CSV thread")? = Some(csv_thread);
    *state.baseline_mode.lock().map_err(|_| "Failed to lock baseline mode")? = true;
    
    println!("Baseline collection started successfully");
    Ok(())
}

#[tauri::command]
fn stop_baseline_collection(state: State<AppState>) -> Result<String, String> {
    if !*state.baseline_mode.lock().map_err(|_| "Failed to lock baseline mode")? {
        return Err("Baseline collection is not running".into());
    }
    
    // Stop sniffer and processor (reuse existing stop logic)
    let mut sniffer_state = state.sniffer.lock().map_err(|_| "Failed to lock sniffer")?;
    let mut processor_state = state.processor.lock().map_err(|_| "Failed to lock processor")?;
    
    if let Some(mut sniffer) = sniffer_state.take() {
        sniffer.stop_sniffer().map_err(|e| format!("Error stopping sniffer: {}", e))?;
    }
    
    if let Some(mut processor) = processor_state.take() {
        processor.stop_processor().map_err(|e| format!("Error stopping processor: {}", e))?;
    }
    
    // Wait for CSV writer to finish
    if let Some(thread) = state.csv_writer_thread.lock()
        .map_err(|_| "Failed to lock CSV thread")?.take() {
        let _ = thread.join();
    }
    
    *state.baseline_mode.lock().map_err(|_| "Failed to lock baseline mode")? = false;
    
    Ok("Baseline collection stopped successfully".into())
}


#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            list_network_devices,
            get_selected_interface_info,
            start_system,
            stop_system,
            start_baseline_collection,
            stop_baseline_collection,
            ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
