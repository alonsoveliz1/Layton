pub mod capture; 
pub mod processor;
pub mod types; 
pub mod classifier;

use capture::{PacketSniffer, NetworkInterface};
use processor::{FeatureProcessor};
use classifier::ClassifierHandles;

use tauri::{Manager, State, path::BaseDirectory};
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path};
use tauri::{Emitter};


pub struct AppState {
    pub sniffer: Arc<Mutex<Option<PacketSniffer>>>,
    pub processor: Arc<Mutex<Option<FeatureProcessor>>>,
    pub selected_interface: Arc<Mutex<Option<String>>>,
    pub classifier: Arc<Mutex<Option<ClassifierHandles>>>
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            sniffer: Arc::new(Mutex::new(None)),
            processor: Arc::new(Mutex::new(None)),
            classifier: Arc::new(Mutex::new(None)),
            selected_interface: Arc::new(Mutex::new(None)),
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

        std::thread::spawn(move || {
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


#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            list_network_devices,
            get_selected_interface_info,
            start_system,
            stop_system,
            ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
