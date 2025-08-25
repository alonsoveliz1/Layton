# Layton - A cross-platform ML-Based NIDS for TCP/IP Flow Classification

Today I present you Layton, my bachelor's thesis (in progress). It's a **novel** machine learning-powered **Network Intrusion Detection System (NIDS)** designed for real-time **flow-level TCP/IP traffic classification**.

Powered by Tauri, Layton captures packets using pcap, extracts flow features mimicking **CIC-FlowMeter**, and uses two trained **XGBoost models** (exported to ONNX) for flow classification. The first model distinguish between **benign or malicious** and the second one between 9 attack categories — all in one lightweight pipeline. 

---

## Key Features

- Real-time packet sniffing (TCP/IP)
- Multithreaded architecture for optimal performance
- Flow extraction & feature engineering (CIC-FlowMeter-style)
- XGBoost-based binary and multiclass classification.

---

## How It Works

1. **Sniffing** — Captures live packets from the selected interface. 
2. **Flow Aggregation** — Groups packets into bidirectional flows, storing them in a HashMap where their features are updated while the flows are alive.
3. **Feature Extraction** — Computes statistical features per flow (duration, packet size, flags, etc.).
4. **Classification** — When flows are finished (a TCP closing sequence is registered or the flow expired) classification is done by ONNX. Features given to inference are the ones the model expect (from the training phase).
5. **Output** — Labels each flow.

---

## Build Requirements

---


## Model & Dataset

Layton uses an **XGBoost binary classifier** trained on the **CIC-BCCC-TabularIoT-2024 dataset**, specifically designed for IoT network traffic analysis. The model achieves:

- **High accuracy** in distinguishing benign vs malicious flows
- **Low latency** inference suitable for real-time processing  
- **Compact size** when exported to ONNX format

*Note: The trained model and dataset are not included in this repository due to not owning the source data. The dataset can be obtained from the original publishers and the ML pipeline is included in [this repository](https://github.com/alonsoveliz1/NIDS-ML-MODELS).*

---

## References & Acknowledgments

- **Dataset**: Tinshu Sasi, Arash Habibi Lashkari, Rongxing Lu, Pulei Xiong, Shahrear Iqbal, "An Efficient Self Attention-Based 1D-CNN-LSTM Network for IoT Attack Detection and Identification Using Network Traffic", *Journal of Information and Intelligence*, 2024.

- **CICFlowMeter**: Arash Habibi Lashkari, Gerard Draper-Gil, Mohammad Saiful Islam Mamun and Ali A. Ghorbani, "Characterization of Tor Traffic Using Time Based Features", in *the proceeding of the 3rd International Conference on Information System Security and Privacy, SCITEPRESS*, Porto, Portugal, 2017.
