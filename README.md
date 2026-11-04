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


## Setup

1. *Install Python 3.12 or later* (tested on Python 3.14).

2. *Create and activate a virtual environment:*
   ```bash
   python -m venv nids-env
   nids-env\Scripts\activate      # Windows
   source nids-env/bin/activate   # Linux / macOS
 
3. *Install the libraries:*
   ```bash
   pip install -r requirements.txt

4. *Check that everything imports:*
   ```bash
   python src/check_env.py

5.Wireshark requirement:
 pyshark also needs Wireshark (which provides tshark) installed on the machine. It is only needed for packet capture in later weeks.

Dataset

The project uses CIC-IDS2017 (Sharafaldin et al., 2018), the MachineLearningCSV version with 8 CSV files and about 2.8 million flows. Download it from the [Canadian Institute for Cybersecurity datasets page](https://www.unb.ca/cic/datasets/ids-2017.html) and place the CSV files in the data/ folder. The files are not stored in this repository because of their size.

Progress

| Weeks | Work | Status |
| :--- | :--- | :--- |
| *1* | Environment set-up and literature review | Done |
| *2* | Dataset exploration and class-distribution analysis | In progress |
| *3* | Data cleaning and merging | Planned |
| *4* | Stratified splitting and imbalance handling | Planned |
| *5-6* | Model training and tuning | Planned |
| *7* | Model evaluation | Planned |
| *8-9* | PCAP feature extraction (CICFlowMeter) | Planned |
| *10* | Real-time and PCAP-replay inference | Planned |
| *11* | Dashboard and laboratory testing | Planned |
| *12* | Final report, slides and demo video | Planned |

Ethics

The dataset is public and has no personal data. Attack tools are used only on virtual machines in an isolated lab network, never on the college or public network.

Literature review

See [literature_review.md](literature_review.md).