# AI-Powered Network Intrusion Detection System (Phase 1)

*B.Tech CSE (VII Semester) mini project, Birla Institute of Applied Sciences, Bhimtal.*  
*Mentor:* Mr. Prabhat Prakash, Assistant Professor, Dept. of CSE.  

*Team:* Rajni Bisht, Tejashvi Pratap Singh, Vinay Singh Mehra, Vineeta Tiwari, Yogesh Chandra Pant  

## What this project does

A network intrusion detection system (NIDS) that learns normal traffic and flags attacks. Network traffic is grouped into flows, statistical features are computed, and a machine learning classifier labels each flow as benign or as one of 14 attack types. A Streamlit dashboard shows the result with a confidence score.

*Pipeline:* Packet capture -> Flow construction -> Feature extraction -> Classification -> Dashboard  

*Models compared:* LightGBM, XGBoost, and a Random Forest baseline. *Main metric:* Macro F1.  

## Repository structure

```text
AI-NIDS-Project/
├── data/                    # CIC-IDS2017 CSV files (not tracked by Git)
├── notebooks/               # Jupyter notebooks (EDA, training, evaluation)
├── src/                     # Reusable modules (cleaning, features, inference)
├── Dashboard/               # Streamlit dashboard
├── literature_review.md
├── requirements.txt
└── README.md


## SETUP & ENVIRONMENT CONFIGURATION
1. Step 1: Install Python 3.12 or later (Tested on Python 3.14).

2. Step 2: Create and activate a virtual environment:
python -m venv nids-env
nids-env\Scripts\activate # Windows
source nids-env/bin/activate # Linux / macOS

3. Step 3: Install required dependencies:
pip install -r requirements.txt
4. Step 4: Verify environment setup:
python src/check_env.py

5. Step 5: Wireshark Dependency: pyshark requires Wireshark (providing tshark ) installed on the system for


## DATASET DETAILS
The project utilizes the benchmark CIC-IDS2017 dataset (Sharafaldin et al., 2018), specifically the
MachineLearningCSV release containing 8 CSV files and approximately 2.8 million flow records. Download
the dataset from the Canadian Institute for Cybersecurity portal and place the CSV files inside the data/
directory.

## PROJECT PROGRESS TRACKER
Weeks Key Tasks & Deliverables Status
Week 1 Environment set-up and literature review completion Done
Week 2 Dataset exploration and class-distribution analysis In progress
Week 3 Data cleaning, missing value handling, and merging Planned
Week 4 Stratified train/test splitting and class imbalance handling Planned
Weeks 5–6 Model training, hyperparameter tuning (RF, XGBoost, LightGBM) Planned
Week 7 Comprehensive model evaluation and metric logging Planned
Weeks 8–9 PCAP feature extraction integration (CICFlowMeter) Planned
Week 10 Real-time packet processing and PCAP-replay inference testing Planned
Week 11 Streamlit dashboard development and laboratory testing Planned
Week 12 Final report documentation, presentation slides, and demo video Planned

## ETHICS STATEMENT
The dataset is publicly available and contains no personal identifiable information (PII). All attack generation
and penetration tools are executed strictly within isolated virtual machines on a controlled lab network, never
on college or public infrastructure.

## LITERATURE REVIEW
For detailed background research, comparative analysis, and academic references, refer to literature review.md