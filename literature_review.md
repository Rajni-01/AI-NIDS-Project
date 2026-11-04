# Literature Review: AI-Powered Network Intrusion Detection System

Project: AI-Powered Network Intrusion Detection System (Phase 1), B.Tech CSE, BIAS Bhimtal
Citation numbers [1] to [17] match the reference list in the project synopsis and the list at the end of this file.

---

## 1. Why this review matters for the project

Traditional intrusion detection tools depend on rules written by experts [2]. They miss attacks that have no rule yet, and they can raise many false alarms. Machine learning can learn what attacks look like from data [3], [5], but research results often fail in practice because of dataset problems, data leakage and inconsistent features [6], [10]. This review looks at the papers that shape how we clean the data, choose models, handle rare attacks and present results.

---

## 2. Papers by theme

### A. Rule-based detection and the case for machine learning

| Ref | Paper | What it contributes | How it helps our project |
|---|---|---|---|
| [2] | Roesch (1999), Snort | A lightweight network IDS that checks packets against signature rules. | Our example of the rule-based approach. It shows the limit we want to overcome: only known attacks are caught. |
| [5] | Buczak & Guven (2016) | A survey of data mining and machine learning methods for intrusion detection. | Gives us the overall map of methods and helps justify choosing tree-based models. |
| [6] | Sommer & Paxson (2010) | Explains why intrusion detection is harder than ordinary classification: mistakes are costly, normal traffic varies a lot, and training data rarely matches real traffic. | Reminds us to evaluate honestly, test on realistic traffic, and report weak classes. |

### B. Dataset and its known problems

| Ref | Paper | What it contributes | How it helps our project |
|---|---|---|---|
| [1] | Sharafaldin et al. (2018) | Creates CIC-IDS2017: five days of benign traffic plus common attacks, with labelled flow features. | This is our training dataset. It defines the attack types we will classify. |
| [9] | Lashkari et al. (2017) | Describes time-based flow features, which later became part of CICFlowMeter. | Helps us understand the timing features in the dataset and in our live extractor. |
| [10] | Engelen et al. (2021) | Audits CIC-IDS2017 and finds problems in traffic generation, flow construction, feature extraction and labelling, then publishes corrections. | Shows why we clean the data carefully and why feature generation matters as much as the model. |

### C. Evaluating models across datasets and in real time

| Ref | Paper | What it contributes | How it helps our project |
|---|---|---|---|
| [3] | D'hooge et al. (2019) | Compares supervised machine learning classifiers on cybersecurity data. | Supports our plan to compare several classifiers instead of trusting one. |
| [4] | Verkerken et al. (2022) | Studies how well unsupervised techniques generalise across intrusion datasets. | Background for our future zero-day detection extension. |
| [7] | Ferrag et al. (2020) | Reviews deep learning methods and the public datasets used to test them. | Gives context on datasets and on why we start with tree-based models rather than deep learning. |
| [8] | Mirsky et al. (2018), Kitsune | An ensemble of autoencoders for online, lightweight anomaly detection. | A reference for real-time detection and a possible Phase 2 direction. |

### D. Models used in this project

| Ref | Paper | What it contributes | How it helps our project |
|---|---|---|---|
| [11] | Breiman (2001) | Introduces Random Forests, which combine many decision trees. | Our baseline model. |
| [12] | Chen & Guestrin (2016) | XGBoost: a scalable gradient boosting system. | One of our two main classifiers. Fast training and inference suit real-time use. |
| [13] | Ke et al. (2017) | LightGBM: a gradient boosting method designed for speed and low memory use. | Our other main classifier. |

### E. Class imbalance, metrics and interpretability

| Ref | Paper | What it contributes | How it helps our project |
|---|---|---|---|
| [14] | Chawla et al. (2002) | SMOTE: creates synthetic samples for minority classes. | A way to handle rare attacks such as Heartbleed and Infiltration. We apply it to training data only. |
| [15] | Lemaitre et al. (2017) | Imbalanced-learn: a Python toolbox for imbalanced data. | The library we use to apply SMOTE. |
| [16] | Saito & Rehmsmeier (2015) | Shows that precision-recall measures are more informative than ROC curves on imbalanced data. | Supports using Macro F1 and per-class precision and recall instead of plain accuracy. |
| [17] | Lundberg & Lee (2017) | SHAP: a unified method to explain individual model predictions. | Lets us show analysts which features drove an alert. |

---

## 3. Gaps in existing work

1. Many studies stop at offline experiments on ready-made CSV files [3], [4], [7].
2. Dataset flaws such as flow-construction and labelling errors are often ignored, which can inflate results [10].
3. Features used in training are often different from those produced during live capture, which hurts real-world accuracy.
4. Rare attack classes get little attention, even though they are the hardest to detect.

## 4. Takeaways that guide our plan

1. **Clean the data before modelling.** Remove duplicates, identifier columns and invalid values [10].
2. **Split carefully.** Use stratified splits so near-identical flows do not leak between training and test sets [6], [10].
3. **Use the same feature logic in training and live use.** We will use CICFlowMeter for both [1], [9].
4. **Handle imbalance and report honestly.** Use class weights or SMOTE on training data only [14], [15], and judge models with Macro F1 and per-class results [16].
5. **Make output interpretable.** Show a class, a confidence score and SHAP explanations [17].

---

## References

[1] I. Sharafaldin, A. H. Lashkari and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP), pp. 108-116, 2018.

[2] M. Roesch, "Snort - Lightweight Intrusion Detection for Networks", Proceedings of the 13th USENIX Conference on System Administration (LISA), pp. 229-238, 1999.

[3] L. D'hooge, T. Wauters, B. Volckaert and F. De Turck, "In-depth Comparative Evaluation of Supervised Machine Learning Approaches for Detection of Cybersecurity Threats", Proceedings of the 4th International Conference on Internet of Things, Big Data and Security (IoTBDS), pp. 125-136, 2019.

[4] M. Verkerken, L. D'hooge, T. Wauters, B. Volckaert and F. De Turck, "Towards Model Generalization for Intrusion Detection: Unsupervised Machine Learning Techniques", Journal of Network and Systems Management, vol. 30, art. 12, 2022.

[5] A. L. Buczak and E. Guven, "A Survey of Data Mining and Machine Learning Methods for Cyber Security Intrusion Detection", IEEE Communications Surveys & Tutorials, vol. 18, no. 2, pp. 1153-1176, 2016.

[6] R. Sommer and V. Paxson, "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection", Proceedings of the IEEE Symposium on Security and Privacy, pp. 305-316, 2010.

[7] M. A. Ferrag, L. Maglaras, S. Moschoyiannis and H. Janicke, "Deep Learning for Cyber Security Intrusion Detection: Approaches, Datasets, and Comparative Study", Journal of Information Security and Applications, vol. 50, art. 102419, 2020.

[8] Y. Mirsky, T. Doitshman, Y. Elovici and A. Shabtai, "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection", Proceedings of the Network and Distributed System Security Symposium (NDSS), San Diego, USA, 2018.

[9] A. H. Lashkari, G. Draper-Gil, M. S. I. Mamun and A. A. Ghorbani, "Characterization of Tor Traffic Using Time Based Features", Proceedings of the 3rd International Conference on Information Systems Security and Privacy (ICISSP), pp. 253-262, 2017.

[10] G. Engelen, V. Rimmer and W. Joosen, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study", Proceedings of the IEEE Security and Privacy Workshops (SPW), pp. 7-12, 2021.

[11] L. Breiman, "Random Forests", Machine Learning, vol. 45, no. 1, pp. 5-32, 2001.

[12] T. Chen and C. Guestrin, "XGBoost: A Scalable Tree Boosting System", Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining, pp. 785-794, 2016.

[13] G. Ke et al., "LightGBM: A Highly Efficient Gradient Boosting Decision Tree", Advances in Neural Information Processing Systems 30 (NIPS), pp. 3146-3154, 2017.

[14] N. V. Chawla, K. W. Bowyer, L. O. Hall and W. P. Kegelmeyer, "SMOTE: Synthetic Minority Over-sampling Technique", Journal of Artificial Intelligence Research, vol. 16, pp. 321-357, 2002.

[15] G. Lemaitre, F. Nogueira and C. K. Aridas, "Imbalanced-learn: A Python Toolbox to Tackle the Curse of Imbalanced Datasets in Machine Learning", Journal of Machine Learning Research, vol. 18, no. 17, pp. 1-5, 2017.

[16] T. Saito and M. Rehmsmeier, "The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets", PLOS ONE, vol. 10, no. 3, art. e0118432, 2015.

[17] S. M. Lundberg and S.-I. Lee, "A Unified Approach to Interpreting Model Predictions", Advances in Neural Information Processing Systems 30 (NIPS), Long Beach, USA, 2017.