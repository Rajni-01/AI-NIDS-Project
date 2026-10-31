# Literature Review & System Overview: AI-Based Network Intrusion Detection System (NIDS)

## 1. Project Context & Objectives
* *Problem Statement:* Modern computer networks face growing security threats such as DoS, port scanning, and botnet activity[cite: 6]. Traditional signature-based detection tools like Snort rely heavily on static expert rules, rendering them ineffective against novel or zero-day attacks while generating high false-alarm rates[cite: 7].
* *Core Objective:* Design and implement a modular, AI-powered NIDS that bridges the gap between offline machine learning model training and real-time network flow inference[cite: 6, 7].
* *Key Innovation:* Maintaining strict feature-extraction consistency between the training pipeline and live deployment to ensure high detection accuracy on live or replayed traffic[cite: 8].

---

## 2. Literature Survey & Academic References

### A. Benchmark Dataset & Traffic Characterization
* *CICIDS2017 Dataset Foundation:* Sharafaldin et al. established the CICIDS2017 dataset, recording 5 days of realistic network traffic encompassing benign data and fourteen major attack categories (DoS, brute force, web attacks, botnets, and port scans)[cite: 7].
* *Dataset Audit & Pipeline Integrity:* Engelen et al. audited the dataset, identifying critical flaws in traffic generation, flow construction, and labeling. Their findings highlight that data integrity and feature extraction pipelines matter just as much as algorithm selection[cite: 7, 8].

### B. Machine Learning Frameworks & Comparative Analysis
| Study / Reference | Core Focus / Method | Key Findings / Limitations Addressed |
| :--- | :--- | :--- |
| *Breiman (2001)* | Random Forests | Serves as a reliable tabular baseline by combining multiple decision trees[cite: 8]. |
| *Chen & Guestrin (2016)* / *Ke et al. (2017)* | XGBoost & LightGBM | Gradient boosting frameworks providing high accuracy, fast training, and scalable inference speed essential for real-time deployment[cite: 8]. |
| *Chawla et al. (2002)* | SMOTE & Class Weighting | Mitigates severe class imbalance in rare attack categories (e.g., Heartbleed, Infiltration)[cite: 8]. |

> *Key Takeaway from Literature:* To prevent artificially inflated performance metrics, datasets must undergo strict data cleaning, duplicate removal, and stratified leakage-free splitting[cite: 8].

---

## 3. System Architecture & Methodology
The system architecture follows a modular 5-stage pipeline:
1. *Packet Capture:* Capturing live interface traffic or parsing .pcap files utilizing Scapy or PyShark[cite: 10].
2. *Flow Construction:* Aggregating raw packets into 5-tuples (Source IP, Destination IP, Source Port, Destination Port, Protocol)[cite: 6, 10].
3. *Feature Extraction:* Computing CICFlowMeter-style statistical metrics such as duration, packet counts, inter-arrival times, and TCP flags[cite: 6, 10].
4. *Classification:* Running preprocessed vectors through trained LightGBM, XGBoost, or Random Forest models to categorize traffic into benign or specific attack classes[cite: 7, 10].
5. *Dashboard Visualization:* Displaying predictions, confidence scores, and analytics on an interactive interface[cite: 6, 10].

---

## 4. Dashboard & Alerting System
* *Real-time Monitoring:* Integrates a Streamlit-powered web dashboard to present live traffic KPIs, flow logs, and performance visualizations[cite: 10, 12].
* *Confidence-Based Alerting:* Applies configurable confidence thresholds (70%, 85%, and 95%) to minimize analyst alert fatigue[cite: 12].
* *PCAP File Replay:* Supports retrospective security investigation by allowing users to upload and analyze historical capture files[cite: 10].