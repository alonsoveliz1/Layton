use anyhow::{anyhow, Context, Result};
use crossbeam_channel::{unbounded, Receiver, Sender};
use ort::{
    Environment, Session, SessionBuilder, Value,
    GraphOptimizationLevel, LoggingLevel,
};
use ndarray::{Array2, CowArray, IxDyn};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crate::processor::FlowRecord;

pub const FEATURE_L1_COUNT: usize = 48;
pub const FEATURE_L2_COUNT: usize = 52;
pub const ATTACK_THRESHOLD: f32 = 0.85;

pub struct NidsModel {
    environment: Arc<Environment>,
    binary: Arc<Mutex<Session>>,
    multiclass: Arc<Mutex<Session>>,
}

#[derive(Debug, Clone)]
pub struct Inference {
    pub pred_label: u8,
    pub probs: Vec<f32>,
    pub micros: u128,
}

#[derive(Debug, Clone)]
pub struct MultiResult {
    pub bin: Inference,
    pub multi: Option<Inference>,
}

pub struct ClassifierHandles {
    pub tx: Sender<FlowRecord>,
    pub rx: Receiver<(FlowRecord, MultiResult)>,
}

impl NidsModel {
    fn load(binary_path: &str, multiclass_path: &str) -> Result<Self> {
        let environment = Arc::new(
            Environment::builder()
                .with_name("nids-model")
                .with_log_level(LoggingLevel::Warning)
                .build()
                .context("Failed to create ONNX environment")?
        );

        let binary = SessionBuilder::new(&environment)?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .with_intra_threads(1)?
            .with_model_from_file(binary_path)
            .with_context(|| format!("Failed to load binary model from {}", binary_path))?;

        let multiclass = SessionBuilder::new(&environment)?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .with_intra_threads(1)?
            .with_model_from_file(multiclass_path)
            .with_context(|| format!("Failed to load multiclass model from {}", multiclass_path))?;

        Ok(Self {
            environment,
            binary: Arc::new(Mutex::new(binary)),
            multiclass: Arc::new(Mutex::new(multiclass)),
        })
    }

    fn run_binary(&self, flow: &FlowRecord) -> Result<Inference> {
        let mut feats = [0f32; FEATURE_L1_COUNT];
        extract_l1_features(flow, &mut feats);

        let input = Array2::from_shape_vec((1, FEATURE_L1_COUNT), feats.to_vec())
            .context("Failed to create binary input array")?;
        let cow = CowArray::from(input.into_dyn());

        let t0 = Instant::now();
        
        let session = self.binary.lock()
            .map_err(|e| anyhow!("Failed to lock binary session: {}", e))?;
        
        let tensor = Value::from_array(session.allocator(), &cow)
            .context("Failed to create input tensor")?;
        
        let outputs = session.run(vec![tensor])
            .context("Failed to run binary model")?;
        
        let dt = t0.elapsed().as_micros();

        let probs = outputs.iter()
            .find_map(|o| o.try_extract::<f32>().ok())
            .and_then(|t| Some(t.view().iter().copied().collect::<Vec<f32>>()))
            .ok_or_else(|| anyhow!("No probability output from binary model"))?;

        if probs.len() < 2 {
            return Err(anyhow!("Expected 2 probabilities, got {}", probs.len()));
        }

        let p_attack = probs[1];
        let pred_label = if p_attack >= ATTACK_THRESHOLD { 1 } else { 0 };

        Ok(Inference { pred_label, probs, micros: dt })
    }

    fn run_multiclass(&self, flow: &FlowRecord) -> Result<Inference> {
        let mut feats = [0f32; FEATURE_L2_COUNT];
        extract_l2_features(flow, &mut feats);

        let input = Array2::from_shape_vec((1, FEATURE_L2_COUNT), feats.to_vec())
            .context("Failed to create multiclass input array")?;
        let cow = CowArray::from(input.into_dyn());

        let t0 = Instant::now();
        
        let session = self.multiclass.lock()
            .map_err(|e| anyhow!("Failed to lock multiclass session: {}", e))?;
        
        let tensor = Value::from_array(session.allocator(), &cow)
            .context("Failed to create input tensor")?;
        
        let outputs = session.run(vec![tensor])
            .context("Failed to run multiclass model")?;
        
        let dt = t0.elapsed().as_micros();

        let probs = outputs.iter()
            .find_map(|o| o.try_extract::<f32>().ok())
            .and_then(|t| Some(t.view().iter().copied().collect::<Vec<f32>>()))
            .ok_or_else(|| anyhow!("No probability output from multiclass model"))?;

        let pred_label = probs.iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(idx, _)| idx as u8)
            .ok_or_else(|| anyhow!("Empty probability vector"))?;

        Ok(Inference { pred_label, probs, micros: dt })
    }

    fn classify_flow(&self, flow: &FlowRecord) -> Result<MultiResult> {
        let bin = self.run_binary(flow)?;
        println!("Flow predicted {} time consumed: {} µs", bin.pred_label, bin.micros);

        let multi = if bin.pred_label == 1 {
            let multi_result = self.run_multiclass(flow)?;
            println!("Malicious flow predicted class {} time consumed: {} µs", 
                     multi_result.pred_label, multi_result.micros);
            Some(multi_result)
        } else {
            None
        };

        Ok(MultiResult { bin, multi })
    }
}

pub fn spawn_classifier(binary_path: String, multiclass_path: String) -> Result<ClassifierHandles> {
    let (tx_in, rx_in) = unbounded::<FlowRecord>();
    let (tx_out, rx_out) = unbounded::<(FlowRecord, MultiResult)>();
    
    println!("Loading models from:\n  Binary: {}\n  Multiclass: {}", binary_path, multiclass_path);
    
    thread::spawn(move || {
        let model = match NidsModel::load(&binary_path, &multiclass_path) {
            Ok(m) => {
                println!("Models loaded successfully");
                m
            },
            Err(e) => {
                eprintln!("Failed to load models: {:?}", e);
                return;
            }
        };
        
        println!("Classifier thread ready, waiting for flows...");
        
        // Simply process flows until the channel is closed
        while let Ok(flow) = rx_in.recv() {
            match model.classify_flow(&flow) {
                Ok(result) => {
                    if tx_out.send((flow, result)).is_err() {
                        // Output channel closed, exit gracefully
                        break;
                    }
                },
                Err(e) => eprintln!("Classification error: {:?}", e),
            }
        }
        
        println!("Classifier thread exiting (channel closed)");
    });
    
    Ok(ClassifierHandles { tx: tx_in, rx: rx_out })
}

#[inline]
fn as_f32(v: f64) -> f32 {
    let f = v as f32;
    if f.is_finite() { f } else { 0.0 }
}

fn extract_l1_features(flow: &FlowRecord, out: &mut [f32; FEATURE_L1_COUNT]) {
    out[0] = flow.flow_duration as f32;
    out[1] = flow.total_fwd_bytes as f32;
    out[2] = flow.total_bwd_bytes as f32;
    out[3] = flow.fwd_packet_len_min as f32;
    out[4] = as_f32(flow.fwd_packet_len_std);
    out[5] = flow.bwd_packet_len_max as f32;
    out[6] = flow.bwd_packet_len_min as f32;
    out[7] = as_f32(flow.flow_bytes_per_sec);
    out[8] = as_f32(flow.flow_packets_per_sec);
    out[9] = as_f32(flow.flow_iat_mean);
    out[10] = as_f32(flow.flow_iat_std);
    out[11] = flow.fwd_iat_total as f32;
    out[12] = as_f32(flow.fwd_iat_mean);
    out[13] = as_f32(flow.fwd_iat_std);
    out[14] = flow.fwd_iat_max as f32;
    out[15] = flow.fwd_iat_min as f32;
    out[16] = flow.bwd_iat_total as f32;
    out[17] = as_f32(flow.bwd_iat_mean);
    out[18] = as_f32(flow.bwd_iat_std);
    out[19] = flow.fwd_psh_flags as f32;
    out[20] = flow.fwd_urg_flags as f32;
    out[21] = flow.bwd_header_len as f32;
    out[22] = as_f32(flow.bwd_packets_per_sec);
    out[23] = flow.packet_len_min as f32;
    out[24] = flow.packet_len_max as f32;
    out[25] = as_f32(flow.packet_len_mean);
    out[26] = flow.fin_flag_count as f32;
    out[27] = flow.syn_flag_count as f32;
    out[28] = flow.rst_flag_count as f32;
    out[29] = flow.psh_flag_count as f32;
    out[30] = flow.urg_flag_count as f32;
    out[31] = flow.cwr_flag_count as f32;
    out[32] = flow.ece_flag_count as f32;
    out[33] = as_f32(flow.down_up_ratio);
    out[34] = as_f32(flow.bwd_bytes_bulk_avg);
    out[35] = as_f32(flow.bwd_packet_bulk_avg);
    out[36] = as_f32(flow.bwd_bulk_rate_avg);
    out[37] = flow.subflow_fwd_packets as f32;
    out[38] = flow.subflow_fwd_bytes as f32;
    out[39] = flow.subflow_bwd_packets as f32;
    out[40] = flow.fwd_init_win_bytes as f32;
    out[41] = flow.bwd_init_win_bytes as f32;
    out[42] = flow.fwd_act_data_packets as f32;
    out[43] = as_f32(flow.fwd_seg_size_min);
    out[44] = as_f32(flow.active_mean);
    out[45] = as_f32(flow.active_std);
    out[46] = as_f32(flow.idle_std);
    out[47] = flow.idle_min as f32;
}

fn extract_l2_features(flow: &FlowRecord, out: &mut [f32; FEATURE_L2_COUNT]) {
    out[0] = flow.flow_duration as f32;
    out[1] = flow.total_fwd_packets as f32;
    out[2] = flow.fwd_packet_len_max as f32;
    out[3] = flow.fwd_packet_len_min as f32;
    out[4] = flow.bwd_packet_len_min as f32;
    out[5] = as_f32(flow.bwd_packet_len_mean);
    out[6] = as_f32(flow.bwd_packet_len_std);
    out[7] = as_f32(flow.flow_bytes_per_sec);
    out[8] = as_f32(flow.flow_packets_per_sec);
    out[9] = as_f32(flow.flow_iat_mean);
    out[10] = as_f32(flow.flow_iat_std);
    out[11] = flow.flow_iat_max as f32;
    out[12] = flow.flow_iat_min as f32;
    out[13] = as_f32(flow.fwd_iat_mean);
    out[14] = as_f32(flow.fwd_iat_std);
    out[15] = flow.fwd_iat_min as f32;
    out[16] = flow.bwd_iat_total as f32;
    out[17] = as_f32(flow.bwd_iat_mean);
    out[18] = as_f32(flow.bwd_iat_std);
    out[19] = flow.bwd_iat_max as f32;
    out[20] = flow.bwd_iat_min as f32;
    out[21] = flow.fwd_psh_flags as f32;
    out[22] = flow.fwd_urg_flags as f32;
    out[23] = as_f32(flow.bwd_packets_per_sec);
    out[24] = flow.packet_len_min as f32;
    out[25] = flow.packet_len_max as f32;
    out[26] = flow.packet_len_variance as f32;
    out[27] = flow.fin_flag_count as f32;
    out[28] = flow.syn_flag_count as f32;
    out[29] = flow.rst_flag_count as f32;
    out[30] = flow.psh_flag_count as f32;
    out[31] = flow.ack_flag_count as f32;
    out[32] = flow.urg_flag_count as f32;
    out[33] = flow.cwr_flag_count as f32;
    out[34] = flow.ece_flag_count as f32;
    out[35] = as_f32(flow.down_up_ratio);
    out[36] = flow.avg_packet_size as f32;
    out[37] = flow.fwd_segment_size_avg as f32;
    out[38] = as_f32(flow.bwd_bytes_bulk_avg);
    out[39] = as_f32(flow.bwd_packet_bulk_avg);
    out[40] = as_f32(flow.bwd_bulk_rate_avg);
    out[41] = flow.subflow_fwd_packets as f32;
    out[42] = flow.subflow_fwd_bytes as f32;
    out[43] = flow.subflow_bwd_packets as f32;
    out[44] = flow.subflow_bwd_bytes as f32;
    out[45] = flow.fwd_init_win_bytes as f32;
    out[46] = flow.bwd_init_win_bytes as f32;
    out[47] = flow.fwd_act_data_packets as f32;
    out[48] = as_f32(flow.fwd_seg_size_min);
    out[49] = as_f32(flow.active_std);
    out[50] = flow.active_max as f32;
    out[51] = as_f32(flow.idle_std);
}