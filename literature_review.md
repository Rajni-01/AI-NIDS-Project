# Literature Review & System Overview: AI-Based Network Intrusion Detection System (NIDS)

## 1. Project Context & Objectives
Traditional rule-based Network Intrusion Detection Systems (such as Snort) rely on static signatures written by experts. Consequently, they fail to detect zero-day or polymorphic attacks and often generate high volumes of false alerts. 

This project implements an end-to-end, AI-powered modular NIDS that bridges the gap between offline model training and real-time packet capture inference.

### Key Objectives:
- *Data Preprocessing:* Clean the CIC-IDS2017 dataset by removing zero-variance features, duplicate records, and invalid values while handling class imbalance.
- *Model Development:* Train and evaluate LightGBM, XGBoost, and Random Forest classifiers using stratified splits and class weighting.
- *Pipeline Consistency:* Implement a feature-extraction module (via CICFlowMeter-style processing) ensuring identical feature computation between offline training and live packet capture.
- *Dashboard & Alerting:* Build an interactive Streamlit dashboard supporting real-time alerts, flow logging, confidence scores, and PCAP file replay.

---

## 2. Literature Survey & Academic References

### A. Benchmark Dataset & Traffic Characterization
- *CICIDS2017 Foundation:* 
  - Reference: I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP, 2018.
  - Summary: Introduces the 5-day CICIDS2017 dataset containing benign traffic and 14 attack categories (DoS, Brute Force, Web Attacks, Botnet, Infiltration, etc.). Emphasizes bidirectional network flow feature generation using CICFlowMeter.
- *Dataset Audit & Pipeline Integrity:*
  - Reference: G. Engelen, V. Rimmer, and W. Joosen, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study", IEEE SPW, 2021.
  - Summary: Highlights flaws in initial flow construction and labels. Underlines that feature generation pipeline consistency matters as much as classifier choice to prevent shortcut learning and data leakage.

### B. Machine Learning Frameworks
- *Random Forest (Baseline):* L. Breiman, "Random Forests", Machine Learning, 2001. Provides a robust baseline for tabular flow data.
- *Gradient Boosting Algorithms:*
  - XGBoost: T. Chen and C. Guestrin, "XGBoost: A Scalable Tree Boosting System", KDD, 2016.
  - LightGBM: G. Ke et al., "LightGBM: A Highly Efficient Gradient Boosting Decision Tree", NIPS, 2017. Both algorithms offer high classification accuracy and fast inference suitable for real-time detection.
- *Imbalance Handling:* N. V. Chawla et al., "SMOTE: Synthetic Minority Over-sampling Technique", JAIR, 2002. Applied alongside class weighting to prioritize Macro F1 and Precision-Recall metrics over simple accuracy.

---

## 3. System Architecture & Methodology

The system follows an end-to-end modular pipeline designed for both offline model training and real-time packet capture inference:

1. *Packet Capture & Replay*: Captures live network traffic interfaces or replays archived PCAP files using packet parsing libraries (Scapy/PyShark).
2. *Feature Extraction*: Aggregates raw packets into 5-tuple network flows (source/destination IPs, ports, protocol) and computes statistical flow metrics (duration, packet counts, inter-arrival times, flag counts) using a CICFlowMeter-style engine.
3. *Ensemble Classification*: Feeds processed feature vectors into trained machine learning models (LightGBM, XGBoost, and Random Forest) to classify traffic as Benign or one of 14 attack categories, generating confidence scoring.
4. *Dashboard & Alerting*: Displays real-time security alerts, traffic KPIs, flow logs, and interactive charts via a Streamlit-powered web dashboard.

## 4. Dashboard & Alerting 
* *Real-time Monitoring:* The system incorporates an interactive Streamlit web dashboard designed to display real-time security alerts, traffic KPIs, flow logs, and performance charts[cite: 10].
* *Confidence-Based Alerting:* Threat notifications are filtered using configurable confidence score thresholds (70%, 85%, and 95%) to minimize false-positive fatigue for network analysts[cite: 12].
* *PCAP File Replay:* In addition to live interface parsing, the dashboard supports uploading and replaying archived PCAP capture files for retrospective security investigations[cite: 10].