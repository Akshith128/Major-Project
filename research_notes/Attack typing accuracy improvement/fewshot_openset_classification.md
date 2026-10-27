# Few-shot and open-set attack-family classification for flow-window aggregates (CSE-CIC-IDS2018)

Scope: naming the attack family of an already-flagged anomalous window (100 CICFlowMeter flows, about 14 aggregate features) when there are few labelled windows (about 440) and some families never appear in the training day-files. AEGIS baseline for comparison: kNN (k=5, Euclidean on standardized features, top-3 majority vote) gets 62%, qwen2.5:3b with neighbours gets 54%, and Gemini gets 7-11%, under leave-test-day-out. Botnet and Brute Force each occur on only one day-file.

Note on evidence quality: most published few-shot and open-set NIDS numbers are per-flow or per-packet-payload, use random or episodic splits rather than day-out splits, and run on deep models. None evaluates 100-flow window aggregates. Treat the headline numbers as upper bounds that are not directly comparable to AEGIS.

---

## Q1. Which classifiers work best for few-shot / small-sample tabular attack classification?

### Takeaway
Published few-shot NIDS papers report 93-97% accuracy at 5-10 shots on CICIDS2017/2018, but only with episodic in-distribution splits and deep metric-learning models. Under a cross-domain shift (train on 2017, test on 2018, 10-shot), plain kNN/SVM/DT fall to about 84-87%. For a CPU student project, the cheapest well-founded upgrade to the current kNN is a learned metric (scikit-learn NCA, i.e. a learned Mahalanobis distance) plus distance weighting, compared against Random Forest/XGBoost on the same aggregates.

### Cited Findings
- **Few-shot NIDS table (PLoS One 2025, Xu et al.):** The paper uses an N-way K-shot protocol: 5 attack classes + benign on CICIDS2017, 4 attack classes + benign on CICIDS2018, K = 5 and 10. Baselines it compiles: one-shot Siamese network (2023) 80.81% (1-shot, CICIDS2017); FC-Net (2020) 94.33% / 94.64% (5/10-shot, CICIDS2017); multi-scale deep CapsNet 92.04% / 94.49%; MetaMRE 93.30% (10-shot); MAML+L2F 96.00% / 97.29% (5/10-shot, CICIDS2018); enhanced triplet network 96.18% (5-shot); FS-IDS 97.51% (5-shot). The proposed model reports 99.03% (CICIDS2017) and 98.64% (CICIDS2018) at 10-shot. — [PMC12221178](https://pmc.ncbi.nlm.nih.gov/articles/PMC12221178/)
- **Same paper, cross-domain (train CICIDS2017 → test CICIDS2018, 10-shot):** SVM 84.07%, kNN 83.98%, DT 87.25%, FC-Net 93.92%, proposed 95.93%. This is the closest published analogue to a day-out or domain shift, and it shows the classical models losing roughly 10 points. — [PMC12221178](https://pmc.ncbi.nlm.nih.gov/articles/PMC12221178/)
- The paper does not clearly state which classes were held out as novel test classes. It does not report prototypical networks, relation networks or Random Forest. — [PMC12221178](https://pmc.ncbi.nlm.nih.gov/articles/PMC12221178/)
- **Prototypical-network variants:** A prototypical capsule network with attention and voting for imbalanced few-shot NIDS appeared in PLoS ONE 2023. — [PMC10118191](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10118191/) A semi-supervised few-shot meta-learning method reports about 96% on known attacks (CICIDS2017, UNSW-NB15). This figure comes from a search abstract only. — [AMiner](https://aminer.org/pub/663304c801d2a3fbfc667fae/semi-supervised-few-shot-network-intrusion-detection-based-on-meta-learning)
- **Siamese networks:** Hindy et al. (EuroMLSys 2021) trained Siamese similarity networks on CICIDS2017, KDD99 and NSL-KDD. They argue that pair-similarity learning needs less data and can take new classes without retraining. — [Strathprints PDF](https://strathprints.strath.ac.uk/76005/1/Hindy_etal_EuroMLS_2021_Developing_a_Siamese_network_for_intrusion_detection.pdf) A 2022 follow-up on one-shot classification of a new attack class reports a trade-off between performance and how distinct the class representations are. — [ASU record](https://research.asu.edu.eg/handle/123456789/189822) SN-IDS (Siamese CNN on traffic "images") claims state-of-the-art 5-shot accuracy on CICIDS2017; the exact number was not seen. — [AMiner](https://www.aminer.org/pub/654a2450939a5f40827da754/few-shot-network-traffic-anomaly-detection-based-on-siamese-neural-network)
- **Triplet GCN few-shot IDS on CSE-CIC-IDS2018** exists, but no numbers were retrieved. — [River Publishers JWE](https://journals.riverpublishers.com/index.php/JWE/article/view/6947)
- **scikit-learn NCA:** It learns a linear map L, equivalent to a squared Mahalanobis metric M = LᵀL, by maximizing a stochastic leave-one-out kNN score. It is optimized with L-BFGS-B, so no learning rate needs tuning. Memory is O(n²), which is trivial at n ≈ 440. It chains as `Pipeline([('nca', NeighborhoodComponentsAnalysis()), ('knn', KNeighborsClassifier())])`. `KNeighborsClassifier(weights='distance')` weights votes by inverse distance. `NearestCentroid(shrink_threshold=...)` gives a shrunken-centroid (prototype) classifier that zeroes out noisy features; the docs example shows it raising accuracy from 0.81 to 0.82. — [scikit-learn neighbors docs](https://scikit-learn.org/stable/modules/neighbors.html)
- **Tree ensembles on CSE-CIC-IDS2018:** Simple decision trees using two features reached AUC/AUPRC above 0.99 for brute-force detection, in-distribution and not cross-day (Hancock, Khoshgoftaar, Leevy, ICMLA 2021). — [CPS-VO](https://archive.cps-vo.org/biblio/author/31861) A random forest reportedly reached about 99.69% multiclass accuracy (F1 ≈ 97.8%) on a random split. — [ijai.iaescore.com](https://ijai.iaescore.com/index.php/IJAI/article/download/22511/13827) (search snippet; split type not verified)
- **Cross-dataset generalization:** Models trained on CSE-CIC-IDS2018 attack classes rarely learned a broadly applicable representation of their class. The best models kept losses under 5% for brute-force, DoS and DDoS. — [typeset.io PDF](https://typeset.io/pdf/investigating-generalized-performance-of-data-constrained-3abadjmu.pdf) Supervised models trained on CIC-IDS2017 and applied to CSE-CIC-IDS2018 lost 0-50% depending on attack class. — [MDPI search snippet](https://mdpi.com/2624-800X/3/2/8/xml)

### Inferences
- The roughly 10-point drop for kNN under cross-domain shift (about 84% versus 93-97% in-domain) matches AEGIS's 62% day-out result in kind. Part of the gap is distribution shift between day-files, not only a lack of model capacity.
- **Ranked low-cost experiments**, all CPU and scikit-learn, evaluated with the same leave-day-out folds:
  1. `KNeighborsClassifier(weights='distance')` replacing the top-3 majority vote.
  2. NCA (or LDA) + kNN, with the NCA transform fit inside each training fold only.
  3. `NearestCentroid` (prototype, with and without shrinkage). This is the scikit-learn analogue of a prototypical network on raw features, and it can be more robust than kNN when classes have few windows.
  4. RandomForest / ExtraTrees / HistGradientBoosting with `class_weight='balanced'`.
  5. Feature transforms: log1p on packets/s, bytes/s and duration, then a RobustScaler. Heavy-tailed rate features dominate Euclidean distance otherwise.
- Deep Siamese and prototypical networks are probably not worth the effort with only about 440 windows and 14 features. Metric learning on raw features (NCA) gets most of the same benefit.

### Gaps
- No paper found evaluates few-shot classification on window-level aggregates, or with a strict leave-day-out protocol on CSE-CIC-IDS2018.
- No head-to-head of NCA/LMNN versus plain kNN on NIDS data was found. LMNN is not in scikit-learn; it would need the `metric-learn` package, whose documentation was not checked.

---

## Q2. Open-set recognition: outputting "unknown" instead of a wrong known class

### Takeaway
Open-set NIDS methods (OpenMax, DOC/DOC++, one-class SVMs, distance-to-prototype with Weibull/EVT thresholds, conformal prediction) can flag unseen attack classes. Per-class unknown-detection rates on CIC-IDS2017/2018 are modest and very uneven, roughly 35-97% depending on the held-out attack. For AEGIS, a simple distance-to-nearest-neighbour or distance-to-prototype threshold, calibrated on held-out known windows, is the feasible version.

### Cited Findings
- **Soltani et al. (arXiv 2108.09199), CIC-IDS2017 held out one attack label at a time.** On the unknown class, DOC++ reached 63.14% on Botnet, 47.64% on DDoS, 87.61% on Port Scan and 37.33% on Web XSS. AutoSVM_NN (autoencoder + per-class one-class SVM, ν=0.01, RBF) reached 83.02% on Botnet. OpenMax_NN reached 96.72% on Port Scan. On CSE-CIC-IDS2018 (DOC++ only), unknown accuracy ranged from 35.47% (SQL injection) to 72.16% (DDoS), with web attacks at 40.06%. When similar attacks are grouped and counted as correct, DOC++ scores about 99.8-100% on most groups but only 37-42% on web-attack groups. — [ar5iv 2108.09199](https://ar5iv.arxiv.org/html/2108.09199)
- **Same paper, setup:** "_NN" variants exclude benign traffic, on the premise that a separate anomaly module has already filtered it. This is architecturally the same as AEGIS: Isolation Forest first, then the family classifier. DOC rejects unknowns by thresholding the maximum sigmoid output; no numeric threshold is given. — [ar5iv 2108.09199](https://ar5iv.arxiv.org/html/2108.09199)
- **Clustering of rejected samples:** Rejected samples go to a clustering module, measured by completeness and homogeneity. Post-training raised Port Scan completeness from 48.94 to 92.33 but lowered Botnet from 67.44 to 58.39. — [ar5iv 2108.09199](https://ar5iv.arxiv.org/html/2108.09199)
- **VAEMax (ICTC 2024):** A 1D-CNN with OpenMax, then a per-class VAE that rejects samples by reconstruction loss, on CIC-IDS2017 and CSE-CIC-IDS2018. It is claimed to beat baselines; the numbers were not available in the abstract. — [arXiv 2403.04193](https://arxiv.org/abs/2403.04193)
- **Prototype loss + per-class Weibull/EVT outlier thresholds** for open-set industrial IDS, evaluated on CICIDS2017 (Yu et al., 2024). — [Bohrium summary](https://bohrium.dp.tech/paper/arxiv/622856fd5aee126c0f59c9c3)
- **OpenMax mechanics:** Each class has a mean activation vector. A Weibull distribution is fit to the largest distances of correctly classified samples from that mean and used as an outlier probability (survey). — [Open-set malware survey, arXiv 2004.04272](https://arxiv.org/pdf/2004.04272); [OSR survey, arXiv 1811.08581](https://arxiv.org/pdf/1811.08581)
- **Mahalanobis OOD score (Lee et al., NeurIPS 2018):** Fit class-conditional Gaussians with a tied covariance (LDA) and score each sample by the maximum over classes of the negative Mahalanobis distance. The authors note softmax posteriors can be highly confident on abnormal inputs. — [arXiv 1807.03888](https://arxiv.org/abs/1807.03888v2)
- **Conformal / abstaining classifiers:** BCOPS (a conformal-style method with a random forest) on KDD99 kept vanilla-RF accuracy on observed classes. It refused to predict on 97.3% of samples from novel attack types. The dataset is old and has few attack types. — [arXiv 1905.04396](https://arxiv.org/pdf/1905.04396)
- **Other conformal NIDS work:** conformal layers that reject uncertain botnet predictions — [arXiv 2409.00667](https://arxiv.org/pdf/2409.00667); FIRCE, conformal evaluation for drift detection on CICIDS2018 and UNSW-NB15 (preprint, not verified) — [alphaXiv 2605.01962](https://www.alphaxiv.org/abs/2605.01962); WisdomNet + MC-dropout reject option driving error to zero at a substantial rejection rate — [PSU record](https://pure.psu.edu/en/publications/trustable-network-intrusion-detection-system-through-wisdomnet-an/)
- **Threshold trade-off:** A higher novelty threshold flags more traffic as unknown, catching more novel attacks but raising alert volume (IRAIS 2026). — [AIS eLibrary](https://aisel.aisnet.org/irais2026/6)
- **EVM limitation:** Extreme Value Machine rejection relies on the geometry of the known classes and can fail when that geometry misleads about the unknowns (search-result summary). — [arXiv 1808.09902](https://arxiv.org/pdf/1808.09902v2)
- **Strength depends on the attack:** open-set APT detection (OpenMax + KDE + MCD) reports class-wise accuracy above 0.99 for high-volume behaviours (brute force, scans) and about 0.93-0.94 for stealthy ones. — [MJET](https://mjet.mnu.edu.mv/mjet/article/view/21)

### Inferences
- **Feasible AEGIS recipe:**
  1. Compute d1, the distance from the query to its nearest labelled window, ideally in NCA space, or the Mahalanobis distance to each class centroid.
  2. Calibrate a threshold τ on the training folds, e.g. the 95th percentile of each class's leave-one-out nearest-neighbour distance.
  3. Output "Unknown" when d1 > τ, or when the top-k neighbours disagree, e.g. the vote margin is below 2 of 5.
- Split-conformal prediction gives the same mechanism with a coverage guarantee. Use the nonconformity score 1 − kNN/RF class probability. An empty or large prediction set maps to "Unknown" or "ambiguous". The `mapie` package implements this, though its docs page was not retrieved.
- Because Botnet and Brute Force have no training examples under leave-day-out, the right answer for them is "Unknown". Counting "Unknown" as correct for families absent from the training folds, and reporting known-class accuracy separately, is the standard open-set framing. It would likely raise AEGIS's reported accuracy, since those windows are currently forced into wrong classes (Botnet→DDoS, Brute Force→DoS).
- Soltani's group-level result (about 100% when similar attacks are merged) suggests reporting both a fine-grained family score and a coarse-group score.

### Gaps
- No open-set NIDS paper found uses window-aggregate features or plain kNN distance thresholds with reported numbers; the evidence is all deep models.
- The 2025 Extreme Value Machine on IoT result (unknown recall 0.9998 on Kitsune, 0.6555 on IoT-23) appeared only in a search summary without a resolvable primary URL, so it is excluded.
- The MAPIE documentation URL returned 404, so conformal API details are not cited.

---

## Q3. Hierarchical classification (volumetric vs non-volumetric, etc.)

### Takeaway
The main empirical study (10 classifiers × 10 datasets) found no significant overall accuracy gain from hierarchical over flat IDS classification. Hierarchy changes where errors fall: fewer attacks are mislabelled as benign, and more are confused between attack types. A hierarchy is mainly useful in AEGIS as a coarse-group fallback output and for routing hand-crafted rules.

### Cited Findings
- **Three-level hierarchy (benign/attack → coarse family → fine type):** "No significant difference in terms of overall classification performance" versus flat. Flat models misclassify attacks as normal; hierarchical models instead misclassify one attack type as another. — [arXiv 2403.13013](https://arxiv.org/abs/2403.13013)
- **Same work, DoS split:** One design splits CIC-DoS2017 at level 2 into high-volume versus low-volume DoS, with native subtypes at level 3. — [arXiv 2403.13013 PDF](https://arxiv.org/pdf/2403.13013) (search snippet)
- **IoV hierarchy (CICIoT2023: Benign / DDoS / multi-attack, then Recon):** reduced errors and beat flat multiclass on Spoofing, Brute Force and Web classes. — [arXiv 2505.16215](https://arxiv.org/pdf/2505.16215) (search snippet)
- **DOC++ group-level evaluation:** when similar attacks are merged into groups, unknown-class accuracy jumps to about 99.8-100% for most groups. This supports a coarse-level output for confusable families. — [ar5iv 2108.09199](https://ar5iv.arxiv.org/html/2108.09199)

### Inferences
- **Proposed AEGIS hierarchy:**
  - Level 1 (from features): volumetric (high packets/s or bytes/s, low unique TCP window ratio, high dominant-signature share; covers DoS/DDoS) versus connection-pattern (high SYN/RST/no-response share, many short flows; covers Port Scan, Brute Force) versus low-and-slow/other (Botnet C2, Infiltration, Web).
  - Level 2: a separate small classifier per group.
- **DDoS vs DoS** within one window of 100 flows: source diversity is the defining difference, and none of the 14 listed features measures source-IP diversity. Adding a "unique source IPs / 100" or source-entropy feature, if the flow records keep Src IP, is likely more valuable than any classifier change. This is an inference from attack definitions; no cited paper tests this feature.
- **Brute Force vs DoS:** brute force (FTP/SSH-Patator) targets a single service port with complete TCP sessions of similar small size. Adding destination-port share (e.g. a port 21/22 indicator) and "flows completing handshake" share would separate them (inference).

### Gaps
- No CIC-IDS2017/2018 confusion-matrix comparison of flat versus hierarchical models was retrieved.
- The abstract of arXiv 2403.13013 does not name the classifiers or datasets; the full text was not read.

---

## Q4. How zero-day family classification is evaluated, and what accuracy is realistic

### Takeaway
The standard protocol holds out one attack class at a time (leave-one-attack-out). Under it, deep open-set methods on CIC-IDS2017/2018 detect the held-out class as "unknown" 35-97% of the time, depending on the class. Cross-day or cross-dataset transfer costs about 10-50 points versus in-distribution. AEGIS's 62% under leave-day-out is not out of line, and reporting it alongside an open-set metric is more honest than chasing in-distribution 99% figures.

### Cited Findings
- **Leave-one-label-out on CIC-IDS2017** (one label unknown at test, the rest known in training), with CSE-CIC-IDS2018 as a check. Closed-set known-class accuracy is about 80-92% (web attacks about 81-82%). Unknown accuracy is 35-97% depending on class (see Q2). — [ar5iv 2108.09199](https://ar5iv.arxiv.org/html/2108.09199)
- **Leave-one-attack-type-out on NSL-KDD** used to emulate zero-days for GAN-augmented IDS (2026 preprint). — [arXiv 2603.19350](https://arxiv.org/pdf/2603.19350)
- **Supervised MLP/CNN on CICIDS2017:** near-perfect on familiar attacks but drastic recall drops on novel ones. — [fugumt 2506.19877](https://fugumt.com/fugumt/paper_check/2506.19877v1_enmode)
- **Unsupervised NIDS models** scored high within one dataset but lost about 25.63% accuracy on a second related dataset (inter-dataset evaluation, JNSM 2021). — [Springer s10922-021-09615-7](https://link.springer.com/content/pdf/10.1007/s10922-021-09615-7.pdf)
- **Retrieval-augmented, QLoRA-tuned LLaMA-1B** gave 42.63% accuracy on unseen attack types in CICIoT2023 without retraining (search summary). — [arXiv 2601.15269](https://www.arxiv.org/pdf/2601.15269)
- **Dataset-quality caveat:** CSE-CIC-IDS2018 has many undocumented errors in attack orchestration, feature generation and labelling. The authors released corrected labelling scripts and a modified CICFlowMeter (Liu, Engelen et al., IEEE CNS 2022). — [CPS-VO record](https://archive.cps-vo.org/node/97449); [GitHub CNS2022_Code](https://www.github.com/GintsEngelen/CNS2022_Code)
- **CICIDS2017:** more than 25% of flows are meaningless artefacts; label fixes changed detection performance significantly (Lanvin et al. 2022, search summary). — [GitHub PR thread](https://gh.r-mj.com/GintsEngelen/CNS2022_Code/pull/3); background in Engelen et al., "Troubleshooting an Intrusion Detection Dataset" (IEEE SPW 2021) — [imec record](https://imec-publications.be/handle/20.500.12860/37518?show=full)
- **BCCC-CSE-CIC-IDS2018 (York University)** corrects DoS labels by aligning them with attacker IPs rather than timestamps. — [YorkU BCCC](https://www.yorku.ca/research/bccc/ucs-technical/cybersecurity-datasets-cds/large-scale-intrusion-detection-dataset-bccc-cse-cic-ids2018/)
- **Day layout:** Brute force is on 02/14 and Botnet on 03/02, so day-based splits isolate them. — [J. Big Data table](https://journalofbigdata.springeropen.com/articles/10.1186/s40537-022-00661-9/tables/1); dataset documentation — [COMIDDS](https://fkie-cad.github.io/COMIDDS/content/datasets/cse_cic_ids2018)

### Inferences
- **Recommended AEGIS reporting:**
  - (a) Closed-set accuracy on families present in the training folds.
  - (b) Open-set metrics: unknown-recall for families absent from the training folds (Botnet, Brute Force) plus macro-F1 including "Unknown".
  - (c) Coarse-group accuracy.
  - (d) A random stratified split as an optimistic upper bound, labelled as such.
- Timestamp-labelled DoS/DDoS windows in the original CSE-CIC-IDS2018 may contain benign or mixed flows. Some of the DDoS↔DoS confusion may be label noise; checking against the BCCC or Engelen relabelling would show whether that's the case.

### Gaps
- No published number was found for leave-day-out attack-family accuracy on CSE-CIC-IDS2018 using window aggregates, so there is no exact benchmark for the 62%.

---

## Q5. Ensembles / voting between retrieval, an ML classifier and an LLM

### Takeaway
Evidence consistently shows tree ensembles beating LLMs on tabular flow features, often by a wide margin. Small zero-shot LLMs (including Qwen2.5-3B) are near chance. Stacking classical learners gives modest gains, mostly on rare classes. An LLM is best used to explain the decision, or as a tie-breaker with hard-coded feature flags, not as the primary classifier.

### Cited Findings
- **"From Flows to Words" (UNSW-NB15, binary, 2025):**
  - Qwen2.5-3B zero-shot: accuracy 0.455, macro-F1 0.313. Mistral-7B zero-shot: 0.09.
  - Qwen2.5-7B with engineered boolean flags: 0.785 on 200 flows, but performance declined as evaluation size grew.
  - Baselines: Random Forest accuracy 0.871 / F1 0.894; XGBoost/LightGBM 0.953 / 0.947; linear SVM 0.933.
  - Zero-shot prompting often collapsed to one class. Flags, grammar-constrained JSON output and threshold calibration helped. The authors make no multiclass claims.
  - [arXiv 2510.17883](https://arxiv.org/html/2510.17883v1)
- **Zero-shot LLMs on NF-UNSW-NB15-v2** performed near or below chance, versus RF weighted-F1 92.17% and LSTM 92.82% (search summary). — [arXiv 2408.04342](https://arxiv.org/pdf/2408.04342)
- **LLMs on CICIoT2023:** fine-tuned small LLMs reached F1 above 95%, but XGBoost was higher (96.96%) using only 4% CPU — [Springer AI Review 2025](https://link.springer.com/10.1007/s10462-025-11432-2) (search summary). QLoRA LLaMA-1B F1 0.7124 versus RF 0.7159 on known attacks — [arXiv 2601.15269](https://www.arxiv.org/pdf/2601.15269) (search summary)
- **Stacking kNN + FFNN + DT with an RF meta-learner** on NSL-KDD, UNSW-NB15 and CSE-CIC-IDS2018 reports a meaningful multiclass detection-rate gain and lower false positive rate; figures not retrieved. — [Al-Rafidain Eng. J.](https://rengj.uomosul.edu.iq/index.php/rengj/article/view/64955)
- **NB + RF + XGBoost stacked with LR** on CSE-CIC-IDS2018: 97.98% accuracy, 96.34% F1, described as better than the base learners (likely binary). — [IJCSIS / Babcock](https://publications.babcock.edu.ng/publication/view/5389)

### Inferences
- **When combining helps:** when the members are individually competent and make different errors. kNN (local, distance-based) and RF (axis-aligned splits) usually err differently. An LLM at 54%, below kNN's 62% and fed the same neighbours, is mostly a correlated, weaker copy, so majority-voting it in is unlikely to help and may hurt.
- **Practical scheme:** soft-vote kNN-distance-weighted and RF probabilities, with weights tuned on the training folds. Apply the open-set rejection rule from Q2. Use the LLM only to (a) write the explanation, or (b) adjudicate when kNN and RF disagree, giving it explicit rule flags (e.g. "SYN share > 0.8 → scan-like").
- Measure on the same leave-day-out folds with a confusion matrix. Report whether the ensemble fixes the specific Botnet→DDoS, Brute Force→DoS and DDoS↔DoS errors.

### Gaps
- No study found compares retrieval + ML + LLM voting for multiclass NIDS family labelling on CIC-IDS2018.
- The individual base-learner numbers for the stacking papers were not retrieved.
