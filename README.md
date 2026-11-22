# AI-Powered Network Intrusion Detection System (Phase 1)

B.Tech CSE (VII Semester) mini project, Birla Institute of Applied Sciences, Bhimtal.

**Mentor:** Mr. Prabhat Prakash, Assistant Professor, Dept. of CSE.

**Team:** Rajni Bisht, Tejashvi Pratap Singh, Vinay Singh Mehra, Vineeta Tiwari, Yogesh Chandra Pant

## What this project does

A Network Intrusion Detection System (NIDS) that learns network traffic patterns and identifies potentially malicious activity. Network traffic is grouped into flows, statistical features are extracted, and machine learning classifiers label each flow as benign or one of 14 attack types.

A Streamlit dashboard is part of the project for displaying detection results with confidence scores.

**Pipeline:** Packet Capture → Flow Construction → Feature Extraction → Classification → Dashboard

**Models compared:** LightGBM, XGBoost, and Random Forest.

**Main evaluation metric:** Macro F1-score.

## Repository structure

```text
AI-NIDS-Project/
├── data/              CIC-IDS2017 dataset (not tracked by Git)
├── notebooks/         Data cleaning, splitting, training and evaluation
├── src/               Reusable feature extraction and inference modules
├── Dashboard/         Streamlit dashboard
├── literature_review.md
├── requirements.txt
└── README.md
```

## Technologies used

- Python
- Pandas and NumPy
- Scikit-learn
- LightGBM
- XGBoost
- Random Forest
- CICFlowMeter
- Streamlit
- Java 8 (required for CICFlowMeter)

## Setup

1. Install Python 3.12 or later.
2. Create and activate a virtual environment:

```bash
python -m venv nids-env
```

Windows:
```bash
nids-env\Scripts\activate
```

Linux / macOS:
```bash
source nids-env/bin/activate
```

3. Install the required Python libraries:

```bash
pip install -r requirements.txt
```

4. CICFlowMeter also requires Java 8 and its native dependencies.
5. Wireshark/tshark may be required for packet capture and processing workflows.

## Dataset

The project uses CIC-IDS2017 (Sharafaldin et al., 2018), specifically the MachineLearningCSV version containing 8 CSV files and approximately 2.8 million network flows.

Download the dataset from the Canadian Institute for Cybersecurity:

https://www.unb.ca/cic/datasets/ids-2017.html

Place the CSV files in the `data/` folder. Dataset files are not stored in this repository because of their size.

## Project progress

| Week | Work | Status |
|---|---|---|
| 1 | Environment setup and literature review | Done |
| 2 | Dataset exploration and class distribution analysis | Done |
| 3 | Data cleaning, duplicate removal and merging | Done |
| 4 | Stratified data splitting and class imbalance handling | Done |
| 5–6 | Model training and hyperparameter tuning | Done |
| 7 | Model evaluation using test data | Done |
| 8 | PCAP feature extraction using CICFlowMeter | Done |
| 9 | Feature consistency and repeatability verification | Done |
| 10 | PCAP-based inference using trained XGBoost model | Done |
| 11 | Dashboard and backend integration, laboratory testing | Pending |
| 12 | Final report, slides and demo video | Done |

## Model evaluation

Three models were evaluated on the test dataset.

| Model | Test Accuracy | Macro F1 |
|---|---:|---:|
| LightGBM | 99.7429% | 74.51% |
| XGBoost | 99.8774% | 87.34% |
| Random Forest | 99.8279% | 83.54% |

XGBoost achieved the best test Macro F1-score among the three models.

Note: Some attack classes have very few test samples, so their individual evaluation results should be interpreted cautiously.

## PCAP-based inference

The trained XGBoost model was tested on network flows extracted from a 10,000-packet PCAP sample using CICFlowMeter.

The inference pipeline:
- Processes a PCAP file using CICFlowMeter.
- Extracts network flow features.
- Aligns extracted features with the model's 78 training features.
- Handles missing and infinite values.
- Predicts traffic labels using the trained XGBoost model.
- Generates prediction confidence scores.
- Saves the results as a CSV report.

The sample inference generated predictions for 636 valid flows. All 636 were predicted as BENIGN in this particular sample.

**Important:** Prediction confidence is not the same as prediction accuracy. Accuracy requires ground-truth labels.

## Ethics

The dataset is public and has no personal data. Attack tools are used only on virtual machines in an isolated lab network, never on the college or public network.

## Literature review

See [literature_review.md](literature_review.md).
