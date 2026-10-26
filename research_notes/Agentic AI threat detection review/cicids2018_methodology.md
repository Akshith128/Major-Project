# Methodological best practices and pitfalls: CSE-CIC-IDS2018 (CICFlowMeter flows) and windowed/aggregate evaluation

Scope note: these notes cover what the literature says. Comparisons to the project's design (100-flow windows, ≥50% attack-flow labelling, about 10 windows per run, one day-file at a time, features such as TCP share, RST share and unique TCP-window ratio) are in the "Inferences" subsections. They are my reasoning, not claims from the sources.

## Q1. Documented labelling errors and data-quality issues in CIC-IDS2017/2018; corrected versions

### Takeaway
Both CIC datasets have well-documented errors at every stage: attack orchestration, the CICFlowMeter feature extractor, documentation and labels. Large shares of flows labelled "attack" contain no attack payload at all. At least three corrected releases exist: DistriNet's improved CIC-IDS2017/CSE-CIC-IDS2018 (Engelen 2021, Liu 2022), York BCCC-CSE-CIC-IDS2018 and LycoS-Unicas-IDS2018. The DistriNet release is the most widely cited fix and comes with public labelling logic and a "Attempted" category.

### Cited Findings
- Liu, Engelen, Lynar, Essam and Joosen published "Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018" at IEEE CNS 2022 (pp. 254–263, DOI 10.1109/CNS56114.2022.9947235). They report many previously undocumented errors in attack orchestration, feature generation, documentation and labelling, and say these errors undermine results in many published studies. They release a fully recreated dataset whose labelling logic was reverse-engineered, corrected and published. — [CPS-VO record](https://archive.cps-vo.org/node/97449); [DistriNet CNS2022 page](https://intrusion-detection.distrinet-research.be/CNS2022/index.html)
- DistriNet also publishes a fixed CICFlowMeter and download pages for the improved datasets, and urges dataset creators to release their labelling logic. — [DistriNet CNS2022 page](https://intrusion-detection.distrinet-research.be/CNS2022/index.html)
- The companion paper is Engelen, Rimmer and Joosen, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study" (IEEE SPW 2021, pp. 7–12, DOI 10.1109/SPW53761.2021.00009). It criticises studies that treat good ML results as the only confirmation that CICIDS2017 is correct, without checking the data itself. — [imec publications record](https://imec-publications.be/handle/20.500.12860/37518?show=full)
- Secondary summaries of the Engelen work say more than 25% of CIC-IDS2017 flows are meaningless artefacts and that the issue persists in CSE-CIC-IDS2018. I could not verify the exact figure in the primary PDF. — [search-surfaced summary via KU Leuven Lirias](https://lirias.kuleuven.be/retrieve/713070)
- Per-day findings for CSE-CIC-IDS2018, from the DistriNet documentation:
  - **FTP-Patator (14-02, 16-02):** port 21 was closed, so the attacker only received RST/ACK replies and no brute force took place. These flows are relabelled "Attempted". The 16-02 run was probably a mis-launched DoS-Slowhttptest.
  - **DoS-Slowhttptest (16-02):** no successful attack was found, and the tool appears to have targeted port 21.
  - **DoS-GoldenEye:** about a quarter of flows end with a forward RST after one HTTP transaction and are relabelled "Attempted".
  - **DDoS-LOIC-UDP on 20-02:** had no UDP labels, so it was mislabelled as HTTP. The old CICFlowMeter also misparsed ICMP as UDP.
  - **HOIC (21-02):** started 6 minutes later than documented.
  - **Web Brute Force (23-02):** 151 of 362 labelled flows (41.7%) are mislabelled, mostly UDP/500 and DHCP.
  - **Botnet day:** TCP segmentation-offset issues produce protocol/port-0 flows that split single requests.
  - **Tooling:** CICFlowMeter's 120 s timeout splits long connections (for example Slowloris) into several flows.

  — [DistriNet CSE-CIC-IDS2018 page](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html)
- The DistriNet "Attempted" taxonomy:
  - 0: no payload
  - 1: port closed
  - 2: start-up/teardown artefact
  - 3: no malicious payload
  - 4: attack artefact
  - 5: attack implemented incorrectly
  - 6: target unresponsive

  — [DistriNet CSE-CIC-IDS2018 page](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html)
- Lanvin, Gimenez, Han, Majorczyk, Mé and Totel, "Errors in the CICIDS2017 dataset and the significant differences in detection performances it makes" (CRiSIS 2022, LNCS 2023, pp. 18–33), document packet misordering, packet duplication and attacks that were performed but not labelled. They measure how the corrections change the evaluation of supervised IDS. — [HAL hal-03775466](https://hal.archives-ouvertes.fr/hal-03775466)
- A 2025 survey of NIDS datasets lists the errors reported by users of both datasets: duplicated features, duplicated packets, incorrect flow construction, incoherent timestamps, labelling issues and deprecated attack tools (citing Engelen 2021, Lanvin 2023, Liu 2022, Rosay 2022). It names "CIC-IDS2017 Imp." and "CSE-CIC-IDS2018 Imp." as the repaired versions, built by fixing CICFlowMeter (Liu) or reimplementing it (Rosay) and rerunning it on the raw PCAPs. — [Network Intrusion Datasets survey, arXiv 2502.06688](https://arxiv.org/pdf/2502.06688)
- The same survey finds that most users of CIC-IDS2017 still rely on the original version with known errors, which suggests they are unaware of the flaws and fixes. — [arXiv 2502.06688](https://arxiv.org/pdf/2502.06688)
- York University's BCCC-CSE-CIC-IDS2018 is a separate fix:
  - It re-extracts features with NTLFlowLyzer because the original extractor produced feature anomalies.
  - It realigns DoS labels with attacker IPs instead of timestamps.
  - It removes UDP-based attacks that were misclassified because the analysis was TCP-specific.

  — [York BCCC page](https://www.yorku.ca/research/bccc/ucs-technical/cybersecurity-datasets-cds/large-scale-intrusion-detection-dataset-bccc-cse-cic-ids2018/)
- Cantone et al. built LycoS-Unicas-IDS2018, a re-extracted version that addresses extraction and labelling problems in the original. — [Cantone et al., arXiv 2402.10974](https://arxiv.org/html/2402.10974)
- One 2024 study found duplicates in CSE-CIC-IDS2018. Deduplication cut Infiltration from 161,934 to 139,775 rows and raised benign from about 83% to about 89%. Another paper claims duplicates are few, so sources conflict. — [arXiv 2408.07729](https://arxiv.org/pdf/2408.07729); contradicted by [arXiv 2205.07323](https://arxiv.org/pdf/2205.07323) (as summarised by search; not verified in full text)

### Inferences
- The project uses the original "TrafficForML_CICFlowMeter" CSVs/parquets, so its labels include the errors above. This matters most for:
  - Bruteforce: FTP-Patator flows are RST-only failures, which the project's RST-share and no-response features will strongly respond to.
  - DoS2 (16-02, Slowhttptest/Hulk)
  - DDoS (LOIC-UDP labelled as HTTP)
  - Web2 (23-02)
  - Infiltration
- The window-labelling rule (≥50% attack flows) inherits the flow-label errors. "Attempted" or artefact flows labelled as attacks can flip a window's label.
- Best practice is to re-run on the DistriNet improved CSE-CIC-IDS2018. One choice is to treat "Attempted" flows as benign or as a separate class. The other is to drop them and report results both ways. At minimum, cite the known errors as a threat to validity.

### Gaps
- I could not open the Liu 2022 full text to get the overall percentage of mislabelled or artefact flows in CSE-CIC-IDS2018. A LinkedIn profile claims about 20% artefacts and about 10% label errors, but that is not authoritative and I did not cite it.
- I could not confirm the exact download URL or licence of the DistriNet improved 2018 data beyond its "Dataset Download" page link.

## Q2. Shortcut and leakage features; does relying on TCP window values count as a shortcut?

### Takeaway
IPs, ports, timestamps, flow IDs and TTL are recognised shortcut features in NIDS datasets. Destination port alone gives 70–100% accuracy on popular datasets. Initial TCP window size (Init Fwd/Bwd Win Byts) is reported as a near-perfect single-feature separator on CIC-IDS2017 web attacks, but that evidence is recent and partly preprint. Attack tools and victim OS stacks in a testbed fix these values, so detection based on TCP window values is very likely a testbed artefact rather than attack semantics.

### Cited Findings
- A 2025 survey names IP addresses, port numbers, timestamps, flow IDs and even TTL values as features that can cause shortcut learning and overestimated performance. It cites D'hooge et al. (2022), who reached 70–100% accuracy on popular NID datasets using destination port as the only feature. It recommends removing such artefacts or encoding them into general features, for example IP → local/global. — [arXiv 2502.06688](https://arxiv.org/pdf/2502.06688)
- The D'hooge study is "Establishing the contaminating effect of metadata feature inclusion in machine-learned network intrusion detection models" (2022). A 2023 follow-up, "Castles built on sand: Observations from classifying academic cybersecurity datasets with minimalist methods" (IoTBDS 2023), shows these datasets are classifiable with very simple methods. — [references in arXiv 2502.06688](https://arxiv.org/pdf/2502.06688)
- The same survey says benign traffic in these testbed datasets lacks real-world complexity and is easy to tell apart from intrusions even with simplistic methods. — [arXiv 2502.06688](https://arxiv.org/pdf/2502.06688)
- Arp et al. (P4, Spurious Correlations) give the NIDS example of attacks coming from one network region, where the model learns the IP range instead of the attack. P4 was present in 20% of the 30 top-tier papers they analysed. — [Arp et al., USENIX Security 2022](https://www.usenix.org/system/files/sec22-arp.pdf)
- A preprint (October 2026) reports that tree ensembles exceed 94% F1 on CIC-IDS2017 web attacks. A depth-3 tree on backward initial TCP window size alone reaches AUC 0.985, so much of the apparent skill is a dataset artefact. With corrected labels, only 104 of 2,056 web-attack flows are successful attacks. The preprint is not peer reviewed, and I could not fetch the full text (HTTP 403). — [Preprints.org 202610.1120](https://www.preprints.org/manuscript/202610.1120) (search-snippet only)
- A 2026 paper on frequency-domain augmentation reports that a fixed packet-length sequence [60, 182, 60] in CIC-IDS2017 botnet traffic gives 88.6% recall and 93.3% precision by string matching. It calls such features collection-process biases that do not carry over to real networks. Its TCP-window finding concerns CIC-DoH. — [arXiv 2609.07156](https://arxiv.org/pdf/2609.07156) (via search summary)
- In CIC-IDS2017, the Heartbleed HTTPS connection was never closed during the attack, so it stands out by backward bytes and inter-arrival time. A detector tuned to that artefact scored 0.000 on out-of-distribution Heartbleed. — [IETF116 ANRP talk (Jacobs)](https://irtf.org/anrp/IETF116-ANRP-Jacobs.pdf) (via search summary)

### Inferences
- These project features probably encode testbed artefacts more than attack behaviour:
  - "Unique TCP window ratio": a single attacker tool or OS gives a constant Init Win value across many flows, so attack windows have a low unique ratio.
  - "Dominant signature share"
  - "RST share", which matters especially given the FTP-Patator closed-port RST artefact.
- These features count as shortcut and P4 risks. An ablation is the recommended check:
  1. Drop the TCP-window-based features and report the metric change.
  2. Run a single-feature baseline (e.g. destination-port-only or Init-Win-only threshold) to show what "trivial" performance looks like.
- If Timestamp, Dst Port or IPs are used anywhere in the window grouping or features, for example "dominant signature", they should be checked for leakage.

### Gaps
- I found no peer-reviewed paper that specifically quantifies Init_Fwd_Win_Byts as a shortcut on CSE-CIC-IDS2018. The evidence is for CIC-IDS2017 and is a preprint.
- The full D'hooge 2022 results per dataset (including 2018) were not retrieved.

## Q3. Single-day evaluation vs cross-day/cross-dataset generalisation

### Takeaway
Within-dataset scores near 99% fall to about 30% MCC when a model is trained on one CIC dataset and tested on the other. Several attack types, Infiltration included, never generalise. Single-day, single-file evaluation is the most optimistic setting possible: the attack is one tool and configuration, from one attacker host, in one time block.

### Cited Findings
- Cantone, Marrocco and Bria (J. Information Security and Applications, arXiv 2402.10974) report MCC as follows:

  | Train → test | MCC |
  |---|---|
  | CIC17 → CIC17 | 99.7% (DT/RF/XGB) |
  | CIC18 → CIC18 | about 96.4% |
  | CIC18 → CIC17 | 35–44% |
  | CIC17 → CIC18 | 26–36% |

  - Average within-dataset MCC is 94.63%; average cross-dataset MCC is 29.35%.
  - On their cleaned LycoS versions, LycoS17 → LycoS18 averages only 10.83%.
  - Slowhttptest, Infiltration and web attacks stay below 50% MCC in every cross-dataset setting.
  - Sample redundancy is heavy: DoS-Slowhttptest has only 56 unique instances among 105,550 samples.

  — [arXiv 2402.10974](https://arxiv.org/html/2402.10974)
- Cantone et al. conclude that near-perfect within-dataset scores may reflect homogeneous, redundant data rather than detection skill. They recommend cross-dataset evaluation and MCC. — [arXiv 2402.10974](https://arxiv.org/html/2402.10974)
- A 2023 Sensors paper trained binary per-attack classifiers on CSE-CIC-IDS2018 and tested them on CIC-IDS2017, CIC-DoS2017 and CIC-DDoS2019. It found the models had rarely learned a generally applicable representation of their attack class. — [DOAJ record, Sensors Feb 2023](https://doaj.org/article/e5cfe9603ea1492e8213e96c5353c8e0) (via search summary)
- An inter-dataset study of unsupervised models (autoencoder, OC-SVM, iForest, PCA) uses train-on-one/test-on-other between CIC-IDS2017 and 2018 as a generalisation test. A model that overfits one dataset does worse on the other. — [J. Netw. Syst. Manag. 2021, 10.1007/s10922-021-09615-7](https://link.springer.com/doi/10.1007/s10922-021-09615-7)
- Arp et al. P3 (data snooping, including temporal snooping) was present in 57% of papers. P9 (lab-only evaluation) was present in 47%. They recommend complementing experiments on well-known datasets with more recent data. — [Arp et al. 2022](https://www.usenix.org/system/files/sec22-arp.pdf)

### Inferences
- The project's per-day-file evaluation, with consecutive or spread-sampled windows from the same file, is within-day and within-attack. It does not test generalisation.
- Defensible protocols, in increasing order of difficulty:
  1. Calibrate or train on benign-only data, or on other days, and test on held-out days.
  2. Leave-one-attack-day-out.
  3. Train on 2018 and test on 2017, or on the improved version.
- Thresholds or rules tuned while looking at the same day's windows are test snooping (Arp P3/P5).

### Gaps
- I found no paper that reports cross-day results within CSE-CIC-IDS2018 alone (leave-one-day-out). Most work is cross-dataset.

## Q4. Class imbalance, sampling, sample size (e.g. 10 windows), and recommended evaluation protocol

### Takeaway
The literature warns against metrics that ignore base rates. It recommends MCC, bounded or low-FPR ROC analysis, per-class results, simple baselines and reporting FPs relative to the negative-class base rate. Ten windows per run is far too few to estimate FPR or precision credibly. Repeated seeds and confidence intervals are required. That last point is my own statistical reasoning, because I found no CIC-specific source that gives a minimum window count.

### Cited Findings
- Arp et al. P7 (inappropriate performance measures): macro- and micro-averaging can respectively over- and under-estimate small classes. — [Arp et al. 2022](https://www.usenix.org/system/files/sec22-arp.pdf)
- Arp et al. P8 (base-rate fallacy): 99% TPR at 1% FPR with a 1:100 class ratio gives 100 false positives for every 99 true positives.
  - Precision and recall can mislead if minority prevalence is inflated by sampling. MCC is more suitable in that case.
  - Use ROC/AUC only up to tractable FPRs (bounded AUC).
  - Discuss false positives relative to the negative base rate.

  — [Arp et al. 2022](https://www.usenix.org/system/files/sec22-arp.pdf)
- Arp et al. P1 (sampling bias) and P3 (data snooping) are the most prevalent pitfalls. Every one of the 30 papers had at least three pitfalls, and only 22% of instances were discussed. — [Arp et al. 2022](https://www.usenix.org/system/files/sec22-arp.pdf)
- Arp et al. P6 (inappropriate baseline) uses an NIDS case study. A 10-second sliding-window packet-count boxplot baseline (IQR thresholds) beat the KITSUNE autoencoder ensemble on the Mirai capture.
  - AUC: 0.998 vs 0.968.
  - TPR at FPR 0.001: 0.996 vs 0.882.
  - The attack is "overly conspicuous" in lab data.

  — [Arp et al. 2022](https://www.usenix.org/system/files/sec22-arp.pdf)
- Cantone et al. recommend MCC because accuracy can look high on imbalanced data. They report per-attack results that show big disparities. — [arXiv 2402.10974](https://arxiv.org/html/2402.10974)
- The 2025 survey lists class imbalance as a core NIDS dataset limitation. It notes that simple tree models like Random Forest often match complex models, so they should be included as baselines. — [arXiv 2502.06688](https://arxiv.org/pdf/2502.06688)
- Infiltration is a small minority class in CSE-CIC-IDS2018, and studies highlight its imbalance against Benign. — [arXiv 2408.07729](https://arxiv.org/pdf/2408.07729) (via search summary)

### Inferences
These points are my statistics, not the sources'.
- **The CI is wide at 10 windows.** With about 5 benign windows, one false positive moves FPR by 20 percentage points. A 95% Wilson interval for 0 errors out of 5 is about [0%, 43%]. Single-run P/R/F1/FPR on 10 windows cannot support claims.
- **A stronger protocol would:**
  - use all windows in a file, or at least hundreds
  - stratify by window label
  - repeat over 5–10 or more seeds or offsets
  - report mean ± std or bootstrap 95% CIs
  - report per-attack-type metrics and MCC
  - report FPR on benign-only days or segments, with absolute false-positive counts per hour of traffic
  - compare against trivial baselines: majority class, single-feature threshold, and RF on flow features
- **Spread sampling sets the base rate.** It controls the attack:benign window ratio. The reported precision depends on this artificial ratio (P8), so the ratio should be reported, or precision recomputed at realistic prevalence.

### Gaps
- I found no source that prescribes a minimum number of windows or samples for NIDS evaluation on CIC data.
- I did not retrieve guidance on statistical significance testing specific to NIDS papers. General ML practice (bootstrap, McNemar) applies, but I have no citation from this search.

## Q5. Is window/time-based aggregation of flows an accepted approach?

### Takeaway
Yes. Aggregating flows or packets over time windows, or over the last N flows, is an established NIDS technique. Kitsune uses damped windows, Arp et al. use a sliding-window baseline, and surveys describe multi-flow features. It suits volumetric and distributed attacks (DoS, DDoS, scans, brute force) but blurs attribution and can hide low-and-slow attacks. Window construction must happen after the train/test split, and padding or labelling conventions must be disclosed, because these choices can dominate results.

### Cited Findings
- A survey of NIDS from the KDD-process perspective says flows are commonly grouped as "flows inside a time window T" or "last n flows". These multi-flow features help detect attacks spread over several connections, such as (D)DoS and probes. Used as the only data source, they make it hard to trace the attack source. — [arXiv 2001.09697](https://arxiv.org/pdf/2001.09697) (via search summary)
- Arp et al. use a 10 s sliding-window packet-frequency baseline in their NIDS case study. It was enough to detect Mirai in lab data, which illustrates that window aggregates can make lab attacks trivially conspicuous. — [Arp et al. 2022](https://www.usenix.org/system/files/sec22-arp.pdf)
- Moczkodan and Ragab (arXiv 2606.11098, 2026) benchmark windowed flow sequences on CIC-IDS2017 under a random split, two leakage-free splits and a padding ablation.
  - Padding convention, not architecture, decides Transformer performance.
  - A repeat-last padding cue hid a 67× rise in false-alarm rate, which only leakage-free evaluation revealed.
  - A class-balanced Random Forest was the most robust model.
  - They recommend leakage-free splits and explicit disclosure of padding.

  — [arXiv 2606.11098](https://arxiv.org/abs/2606.11098)
- Per a search summary of the same work, about 1.46M five-tuple groups yield about 630k windows, about 73% of them padded. Window labels come from the final flow. A leakage-free split builds windows after partitioning. — [arXiv 2606.11098 summary](https://themodelwire.com/article/do-transformers-actually-help-intrusion-detection-a-temporal-sequence-evaluation-01KTQSGY3S0XV3C4FVFF4NQ8QX)
- Other window-based IDS work:
  - An OPC UA/5G IDS aggregates per-flow statistics (sum, mean, max, count) over fixed non-overlapping 5 s windows. — [arXiv 2603.23416](https://arxiv.org/pdf/2603.23416)
  - A DDoS detector classifies fixed-length sliding windows independently, and flows that span windows contribute sub-flows to each. — [arXiv 2609.12605](https://arxiv.org/pdf/2609.12605) (via search summary)

### Inferences
- The approach is legitimate, but the project's specific choices need justification and sensitivity analysis:
  - The ≥50% labelling threshold. Alternatives are any-attack, or a separate class for mixed windows.
  - Window size N=100.
  - Count-based windows over consecutive CSV rows. CSV row order is not guaranteed to be time order, and windows should be built on Timestamp-sorted flows or per host.
- In single-attack day files, attack flows are contiguous blocks. Consecutive windows are therefore almost pure (0% or 100% attack), which makes window classification easy.
- "Spread-sampled" windows mix flows from distant times, which no real-time detector would see. This is a form of temporal snooping (Arp P3).
- The low-and-slow attacks most hurt by aggregation are Infiltration, Web/SQLi/XSS and Botnet, whose flows are few.

### Gaps
- I found no peer-reviewed paper that does window-level (N-flow) evaluation specifically on CSE-CIC-IDS2018 with a ≥50% labelling rule. There is no direct precedent for that exact protocol.

## Q6. Are the Infiltration days problematic?

### Takeaway
Yes, severely. DistriNet found the original Infiltration labels "largely unrecoverable" and rebuilt them as three sub-labels. Cross-dataset studies find Infiltration never generalises.

### Cited Findings
- DistriNet splits Infiltration (28-02 and 01-03) into three labels:
  - "Dropbox Download"
  - "Communication Victim-Attacker": only 44 flows on 28-02, between 172.31.69.24 and 13.58.225.34
  - "NMAP Portscan": the victim scanning 21 hosts

  The original labels were largely unrecoverable. On 28-02, ARP traffic misparsed as IP was labelled benign. — [DistriNet CSE-CIC-IDS2018 page](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html)
- Infiltration stays below 50% MCC in all cross-dataset settings. — [Cantone et al. arXiv 2402.10974](https://arxiv.org/html/2402.10974)
- Deduplication reduced Infiltration rows from 161,934 to 139,775 in one study, so duplicates are present. — [arXiv 2408.07729](https://arxiv.org/pdf/2408.07729) (via search summary)
- The DistriNet page also notes that Heartleech is listed in the official docs, but the data shows no attacker/victim IPs, timeframe or evidence for it. — [DistriNet CSE-CIC-IDS2018 page](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html)

### Inferences
- In the original Infil1/Infil2 files, flows labelled "Infilteration" are commonly understood to be labelled by victim IP and time window. Much of that traffic is ordinary browsing or background traffic of the victim host, so window-level "attack" labels on these days mostly measure label noise, not detection. This is consistent with DistriNet's "unrecoverable" finding, but the exact original labelling rule is my inference.
- Results on Infil days should be reported separately or excluded, or the DistriNet relabelled sub-classes should be used.
- A 100-flow window with the ≥50% rule may rarely be labelled attack for the true Infiltration behaviours, given only 44 C2 flows on 28-02.

### Gaps
- I did not find a source that quantifies what fraction of original "Infilteration" flows are benign-looking victim traffic.
- I did not find a source on exact feature-vector overlap between Infiltration and Benign rows.
