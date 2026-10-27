# Shortcut-aware CICFlowMeter window features for CSE-CIC-IDS2018 attack-family discrimination

Scope note: these notes cover published feature-importance evidence, the split between behavioural features and testbed artefacts, the use of Dst Port, window aggregation methods, and per-family signatures. They compare against the AEGIS 14-feature window design described in the assignment; no project files were read. Sources that were seen only as search snippets, not fetched in full, are marked "(snippet)". Treat those claims as leads.

## 1. Which CICFlowMeter features rank highest for separating these families in published importance / selection studies?

### Takeaway
The dataset authors' own per-attack selection (Random Forest regressor importance, CIC-IDS2017) puts **backward packet-length std, flow IAT stats, flow duration, active time, and forward-payload volume (Subflow Fwd Bytes / Total Len Fwd Packets)** at the top for DoS, DDoS, Bot and Infiltration. For SSH/FTP brute force, web attacks and PortScan it picks **Init Fwd Win Bytes**, which later audits show is an artefact. Independent audits of CSE-CIC-IDS2018 show that almost every class can be separated by a single feature (single-feature RF F1 of about 0.99 to 1.0). That makes per-flow importance rankings on this dataset poor guides to what generalises.

### Cited Findings
- **Sharafaldin et al., ICISSP 2018 (CIC-IDS2017), Table 3.** RandomForestRegressor importance, multiplied by the per-class standardised mean, gives the top four features per class. Table 3 below is reconstructed from the two-column PDF layout (13 labels; 51 feature rows) — [Sharafaldin et al. 2018 PDF](https://www.scitepress.org/papers/2018/66398/66398.pdf):
  - Benign: B.Packet Len Min 0.0479, Subflow F.Bytes 0.0007, Total Len F.Packets 0.0004, F.Packet Len Mean 0.0002
  - DoS GoldenEye: B.Packet Len Std 0.1585, Flow IAT Min 0.0317, Fwd IAT Min 0.0257, Flow IAT Mean 0.0214
  - Heartbleed: B.Packet Len Std 0.2028, Subflow F.Bytes 0.1367, Flow Duration 0.0991, Total Len F.Packets 0.0903
  - DoS Hulk: B.Packet Len Std 0.2028, B.Packet Len Std 0.1277 (duplicated in the printed table), Flow Duration 0.0437, Flow IAT Std 0.0227
  - DoS Slowhttptest: Flow Duration 0.0443, Active Min 0.0228, Active Mean 0.0219, Flow IAT Std 0.0200
  - DoS slowloris: Flow Duration 0.0431, F.IAT Min 0.0378, B.IAT Mean 0.0300, F.IAT Mean 0.0265
  - SSH-Patator: **Init Win F.Bytes 0.0079**, Subflow F.Bytes 0.0052, Total Len F.Packets 0.0034, ACK Flag Count 0.0007
  - FTP-Patator: **Init Win F.Bytes 0.0077**, F.PSH Flags 0.0062, SYN Flag Count 0.0061, F.Packets/s 0.0014
  - Web Attack: **Init Win F.Bytes 0.0200**, Subflow F.Bytes 0.0145, **Init Win B.Bytes 0.0129**, Total Len F.Packets 0.0096
  - Infiltration: Subflow F.Bytes 4.3012, Total Len F.Packets 2.8427, Flow Duration 0.0657, Active Mean 0.0227
  - Bot: Subflow F.Bytes 0.0239, Total Len F.Packets 0.0158, F.Packet Len Mean 0.0025, B.Packets/s 0.0021
  - PortScan: **Init Win F.Bytes 0.0083**, B.Packets/s 0.0032, PSH Flag Count 0.0009 (three features only)
  - DDoS: B.Packet Len Std 0.1728, Avg Packet Size 0.0162, Flow Duration 0.0137, Flow IAT Std 0.0086
- The authors summarise the results this way: IAT stats (min, mean, max) and Flow Duration are the best common DoS features. Brute force is best traced by initial window bytes plus ACK, PSH and SYN flags. DDoS is best captured by backward packet length, average packet size and IAT features — [Sharafaldin et al. 2018](https://www.scitepress.org/papers/2018/66398/66398.pdf)
- The method is a RandomForestRegressor over 80 CICFlowMeter features: importance times the average standardised mean of each feature split by class — [Sharafaldin et al. 2018](https://www.scitepress.org/papers/2018/66398/66398.pdf)
- **Flood, Engelen, Aspinall, Desmet, "Bad Design Smells in Benchmark NIDS Datasets", IEEE EuroS&P 2024.** Their "highly dependent feature" heuristic (HDF) is the max F1 of an RF trained on a single feature to separate a class from background. In the extracted Table 8 the fourth numeric column appears to be HDF (column order inferred from the text extraction). On CSE-CIC-IDS2018 the values are: Bot 0.99, Hulk 1.0, Slowloris 0.99, SSH-BruteForce 1.0, FTP-BruteForce 0.99, LOIC 1.0, LOIC-UDP 0.99, HOIC 1.0, GoldenEye 1.0, SlowHTTPTest 1.0, XSS 0.83, Web BF 0.79, SQL 0.77, Infiltration 0.63 — [Flood et al. 2024 PDF](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf); [DBLP entry](https://dblp.org/rec/conf/eurosp/FloodEAD24.html)
- Same paper: on CIC-18, DoS Hulk is classified with near-perfect F1 from **FWD Init Win Bytes alone**. On CIC-17 the same single-feature RF misclassifies every DoS Hulk flow, which the authors say shows "the arbitrary nature of the connection" — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf)
- Cross-dataset SHAP study (Şengül & Kılıç): RF/XGBoost trained on CICIDS2017 with TreeSHAP-selected subsets (Top-20, COMMON-10, UNION-30), tested on CSE-CIC-IDS2018. Macro-F1 falls to about 0.127 (RF) and 0.119 (XGB) — [Atilim repository](https://ada.atilim.edu.tr/items/d25563f0-322c-4384-b748-fe9d5695f1af) (snippet)
- An XAI feature-selection paper reports that all models on CICIDS-2017 rely heavily on Destination Port — [arXiv 2410.10050](https://arxiv.org/pdf/2410.10050) (snippet)
- Zuech et al. (J. Big Data 2022) ran ensemble feature selection on the CSE-CIC-IDS2018 web attacks (Brute Force, SQLi, XSS). They argue that the popular time-dimension, L3/L4 NetFlow-style features cannot properly identify those web attacks — [Zuech et al. 2022](https://doi.org/10.1186/s40537-022-00661-9) (snippet)
- A study of CSE-CIC-IDS2018 on AWS with five attack types combined six feature-selection methods into averaged rankings, with per-attack subsets. The specific features were not retrieved — [arXiv 2307.11544](https://arxiv.org/abs/2307.11544)

### Inferences
- In the dataset authors' own ranking, the families AEGIS confuses are split by features AEGIS does not read: **Bwd Packet Length Std** (DoS/DDoS/Hulk/GoldenEye), **Flow IAT Min/Mean/Std and Fwd/Bwd IAT** (slow DoS vs volumetric), **Active Mean/Min** (Slowhttptest, Infiltration), and **forward-payload volume** (Subflow Fwd Bytes / Total Len Fwd Packets for Bot and Infiltration). These are the main candidates to add.
- Brute force is the class whose "best" feature in the original paper is Init Win F.Bytes. Once that feature is removed as a shortcut, brute force has the weakest behavioural signature in the published ranking. That fits the Brute Force vs DoS confusion AEGIS sees (see also section 5 on closed-port FTP and SlowHTTPTest).
- Per-flow importance rankings on CIC-18 are inflated by single-feature separability. Treat them as hypotheses and validate any window feature with a leave-one-day-out or 2017-to-2018 transfer test.

### Gaps
- I found no peer-reviewed paper that reports **per-class SHAP rankings for CSE-CIC-IDS2018** across all the families named here. The candidate papers (arXiv 2104.07183, 2307.11544) were not read in full.
- Sharafaldin's Table 3 is from CIC-IDS2017, not 2018. The 2018 dataset reuses the tools, but I found no equivalent official 2018 per-attack table.

## 2. Which features are behavioural, and which are testbed artefacts?

### Takeaway
Init Fwd/Bwd Win Bytes, Dst Port, Timestamp/IPs, Protocol in edge cases, the CICFlowMeter flow-timeout split, and anything that encodes a single fixed target page or closed port are **artefacts** on CSE-CIC-IDS2018. Packet-length and payload statistics, IAT, active/idle time, flag ratios and the fwd/bwd asymmetry are **mechanism-linked**. Even these are low-diversity in CIC-18 because each attack hit a fixed target under fixed network conditions.

### Cited Findings
- **Init Fwd Win Bytes:** single-feature near-perfect Hulk detection on CIC-18 that collapses to zero on CIC-17. This marks it as a dataset artefact with no tie to the attack mechanism — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf)
- **Init Win B.Bytes:** a 2026 preprint reports that a depth-3 tree on backward initial TCP window size alone reaches AUC 0.985 on CIC-IDS2017 web-attack data, which it calls a dataset artefact — [preprints.org 202610.1120](https://www.preprints.org/manuscript/202610.1120) (snippet; not peer-reviewed)
- CICFlowMeter definition: Init_Win_bytes_forward is the total bytes sent in the initial window in the forward direction. Fwd Seg Size Min (min_seg_size_forward) is the minimum forward segment size. Fwd Act Data Pkts counts forward packets with at least 1 byte of TCP payload — [CICFlowMeter ReadMe](https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt)
- Testbed homogeneity: all brute-force, DoS, Heartbleed and web attacks came from **Kali Linux** attackers against Ubuntu servers. Botnet victims were Windows hosts — [UNB CSE-CIC-IDS2018 page](https://www.unb.ca/cic/datasets/ids-2018.html). (Inference: the initial window and minimum segment size largely fingerprint the attacker OS/TCP stack rather than the attack.)
- **TTL / OS fingerprinting precedent:** in UNSW-NB15, TTL values inadvertently fingerprint operating systems, and Protocol plus TTL alone separate benign from malicious at 98% accuracy — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf). (CICFlowMeter CSVs for CIC-18 have no TTL column; Init Win / Seg Size Min play the analogous role.)
- **Timestamp:** CIC-18 attacks sit in narrow time windows, so Timestamp is highly performant with no connection to attack mechanism. Removing it and fixing labels severely degraded CADE results — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf)
- **Low diversity of volumetric attacks:** "Without exception, DoS attacks were launched against static targets", which produces millions of near-identical flows. In CIC-17, DoS was launched against a single web page under fixed network conditions — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf). When page size (1 to 10 MB) and bandwidth were randomised, Hulk models trained on the original data failed to generalise — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf)
- **Single fixed payload values:** in CIC-17, Total Length of Fwd Packets equals 7920 for 72.7% of Heartbleed flows — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf). (Payload-size features can therefore also become shortcuts when one tool or target produces a fixed payload.)
- **Flow-timeout artefact:** CICFlowMeter's 120-second timeout splits long connections (for example Slowloris, LOIC) into multiple flows — [DistriNet CSE-CIC-IDS2018 page](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html). Duration near 120 s is therefore partly an extractor setting. Timeouts are user-configurable in CICFlowMeter — [CICFlowMeter ReadMe](https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt)
- **Protocol artefact (Bot):** a TCP segmentation offload issue leaves many Ares flows with protocol and ports set to 0, which splits single requests into multiple flows — [DistriNet CSE-CIC-IDS2018](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html)
- **ICMP counted as UDP:** the old CICFlowMeter treated ICMP packets as UDP. In the corrected data, ICMP Destination Unreachable replies during LOIC-UDP are labelled "Attempted" — [DistriNet CSE-CIC-IDS2018](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html)
- **Retransmission artefact (artificial diversity):** the TCP retransmission rate in CIC-17 exceeds 15%, against a usual rate of 3% or less, adding unrealistic variability to flow features — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf)
- Packet/flow-level shortcut warnings: individual packet features can give misleadingly high detection that fails to generalise across datasets (Kostas, Just, Lones) — summarised in [search result referencing Kostas et al.](https://inderscience.com/offers.php?id=124374) (snippet; attribution to that URL uncertain)

### Inferences
- **Classification for AEGIS (inferred from the evidence above):**
  - *Artefact / drop:* Init Fwd Win Bytes, Init Bwd Win Bytes, Fwd Seg Size Min, Dst Port (for detection), Timestamp, IPs, Src Port.
  - *Use with care:* Protocol (Protocol=0 rows in Bot; ICMP-as-UDP in old CICFlowMeter); Flow Duration near the 120 s cap; absolute payload byte values (fixed target page or tool payload).
  - *Behavioural, keep or add:* Fwd/Bwd Packet Length Mean/Std/Max/Min; Total Length Fwd/Bwd and the bwd/fwd byte ratio (Down/Up Ratio); Flow/Fwd/Bwd IAT Mean/Std/Min/Max; Active/Idle Mean; flag counts as ratios; Fwd Act Data Pkts (payload-bearing packets); Fwd/Bwd Header Length per packet; packets per flow.
- AEGIS's `dominant_signature_share` includes Init Fwd Win Bytes in the signature tuple. That carries the shortcut into a window-level feature. Recommend redefining the signature as (protocol, fwd pkt bucket, bwd pkt bucket, fwd payload-bytes bucket).
- AEGIS's `unique_tcp_window_ratio` is also derived from the init window. It measures attacker-tool homogeneity, which is partly behavioural (one tool, many flows) but is driven by the OS stack. Replace it with diversity of payload-size or packet-count signatures.
- "Behavioural" features are still low-diversity on CIC-18, so window features built from them will look near-perfect in-dataset. The real test is held-out-day or cross-dataset evaluation.

### Gaps
- I found no published ablation that quantifies family-level (not binary) accuracy loss on CIC-18 when Init Win Bytes and Dst Port are removed.
- I could not verify the Kostas, Just and Lones claim from its primary source within this session.

## 3. Is Dst Port acceptable as a coarse service category for naming, as opposed to detection?

### Takeaway
The literature says **do not feed Dst Port (or other metadata) to the detection model**. Using it as a coarse, post-hoc service tag for naming or explanation is not ruled out, and Flood et al. themselves use port lists diagnostically. The catch on CIC-18: several attacks hit the "wrong" port, so port-based naming would produce wrong family names for those labelled flows.

### Cited Findings
- D'Hooge et al., DIMVA 2022: destination port alone separates ten NIDS datasets, including CIC-IDS2017, at 70 to 100% accuracy on class-balanced test sets. It is a prime target for shortcut learning, and they recommend that users not include destination port or any other metadata feature in models — [AMiner: D'Hooge et al. 2022](https://www.aminer.org/pub/634d80d090e50fcafd4ebcbc/establishing-the-contaminating-effect-of-metadata-feature-inclusion-in-machine-learned-network)
- Flood et al. use Dst Port diagnostically, flagging flows to well-known background-service ports BG = {0, 53, 67, 68, 111, 123, 137, 161, 179, 389, 427, 520, 1723, 1900} as possibly mislabelled ("unclear ground truth") — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf)
- **Port-to-family mismatches in CSE-CIC-IDS2018** — [DistriNet CSE-CIC-IDS2018](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html):
  - SSH-Patator on 14-02 started on **port 21** and moved to port 22 about 30 s later (30 flows affected).
  - FTP-Patator on 14-02 hit a **closed port 21**: RST,ACK only, so no brute force happened.
  - **DoS SlowHTTPTest on 16-02 appears to have targeted port 21 by mistake**; no successful attack was found.
  - Ares Bot traffic is all on **port 8080**.
  - Web brute force on 23-02: 151 of 362 labelled flows (41.7%) were mislabelled, including 128 UDP flows to port 500, plus SSH on 22 and DHCP on 68.
  - XSS on 23-02 includes DHCP (67/68) and port-500 background flows.
- Flood et al. also list CIC-18 FTP-BruteForce among attacks launched against closed ports, and flag SlowHTTPTest as clashing with FTP-BruteForce in their heuristics — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf)

### Inferences
- A defensible design: never put port into the classifier or the anomaly score. After the behavioural model has picked a family, use a coarse port bucket (login service 21/22/23/3389; web 80/443/8080; other) only to **refine the name or wording**, for example "brute-force-like against a login service". Report it as context, not evidence.
- Ablate this explicitly: report family accuracy with and without the port-bucket tie-breaker. Note that on CIC-18 the bucket would rename SlowHTTPTest (16-02) to "FTP/login" — arguably the *correct* behavioural description of that traffic.
- On 8080, a port bucket would group Ares Bot with "web". This may actually help explain Botnet vs DDoS confusion if both look like HTTP to the model.

### Gaps
- I found no paper that explicitly endorses port as a naming-only feature. The recommendation above is my inference from D'Hooge (exclude from models) and Flood (diagnostic use).

## 4. How should flow features be aggregated per window?

### Takeaway
Window/multi-flow NIDS work uses counts, means/variances, entropies and covariances over flows grouped by time or host (Kitsune: count, mean, std, magnitude, radius, covariance, correlation over damped windows). For heavy-tailed CICFlowMeter values, robust statistics fit better than means alone: median, IQR or p90 on log-scaled values, coefficient of variation, and the entropy of a binned histogram. I found no paper that benchmarks these choices on 100-flow windows of CIC-18.

### Cited Findings
- Survey (NIDS from the KDD-process perspective): "multiple flow derived" features aggregate flows by time window or by host. From those groups, counts of bytes, packets and flows are obtained, and entropy values (and covariance matrices) are calculated. Such features help with distributed activity like DDoS or probing, at the cost of traceability and memory — [arXiv 2001.09697](https://arxiv.org/pdf/2001.09697) (snippet)
- Kitsune maintains incremental statistics over **damped windows** at several decay rates: 1D (count/weight, mean, std, magnitude) and 2D (radius, approximate covariance, correlation coefficient) between directions. Updates are O(1) per packet — [Kitsune, arXiv 1802.09089](https://arxiv.org/pdf/1802.09089); feature table summarised in [arXiv 2508.08655](https://arxiv.org/pdf/2508.08655)
- Multi-Level Distributional Entropy (2026 preprint): entropy features computed from flow-level summary statistics reach weighted F1 of 0.708 to 0.989 across NSL-KDD, CICIDS-2017, CICIDS-2018 and UNSW-NB15. On CICIDS-2018 an F1 of 0.74 hides a detection rate of 0.48 — [EmergentMind summary of 2606.29797](https://www.emergentmind.com/papers/2606.29797) (preprint, snippet)
- Flow aggregation by grouping similar flows adds a higher abstraction level that helps detect attacks that imitate benign traffic (CICIDS2017; Sensors 2021, 21, 1761) — [arXiv 2103.04208](https://arxiv.org/abs/2103.04208)
- Single-feature and near-identical-flow behaviour in CIC-18 (HDF of about 0.99 to 1.0; DoS against static targets) — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf). (Inference: window statistics over such classes will have tiny within-window variance. Std and CV themselves become strong but brittle discriminators.)

### Inferences (recommended aggregation recipe for a 100-flow window)
- **Log-transform** rate, duration, bytes and IAT before aggregating (`log1p`), because CICFlowMeter values span many orders of magnitude.
- **Median + p90 (or IQR)** per key feature in place of the mean. Means are dominated by a few long or huge flows, such as a split Slowloris connection or one large benign download.
- **Coefficient of variation (std/mean)** for duration, fwd packets and IAT mean. This captures *regularity*: bots and brute-forcers repeat near-identical sessions with low CV, while benign traffic has high CV.
- **Shannon entropy of binned histograms** (for example 8 to 10 log-bins) for fwd packets per flow, fwd payload bytes per flow and duration. Low entropy means a repetitive tool. Normalise by log(#bins) so the value does not depend on window size.
- **Share features** (fraction of flows meeting a condition) are robust and interpretable. AEGIS already uses them for flags. Extend them to zero-payload flows, RST-terminated flows, long flows and single-transaction flows.
- **Ratio features at window level:** sum(bwd bytes)/sum(fwd bytes), and sum(bwd pkts)/sum(fwd pkts). These are the server-response asymmetry: volumetric HTTP floods get many small responses or errors, Infiltration gets large downloads toward the victim, and UDP floods get almost no responses.
- Keep the window at 100 flows, but validate with **windows built per day or per time block** so a window never mixes days. Evaluate leave-one-day-out, because CIC-18 attacks are time-localised.

### Gaps
- I found no study comparing mean vs median vs percentile vs histogram aggregation specifically on CIC-IDS2017/2018 windows. The recipe above is reasoned from feature distributions and the artefact literature, not benchmarked.

## 5. Concrete per-family signatures in CICFlowMeter terms

### Takeaway
The documented ground truth (UNB plus DistriNet's PCAP-level audit) gives usable behavioural signatures. It also shows that several AEGIS confusions are probably **label or traffic problems, not feature problems**:
- 2018 SlowHTTPTest and part of FTP-BruteForce are failed connections to closed port 21.
- LOIC-UDP on 20-02 was labelled LOIC-HTTP.
- Ares Bot has protocol-0 fragments.
- Infiltration is a mix of Dropbox downloads, C2 and Nmap.

### Cited Findings
- **Tools and testbed:** Patator (FTP/SSH) with a 90M-word dictionary; Slowloris, GoldenEye, Hulk and SlowHTTPTest against Ubuntu 16.04 Apache; LOIC (HTTP/UDP/TCP) and HOIC for DDoS; Ares and Zeus botnet, with **screenshots requested every 400 s**; DVWA with Selenium for web attacks; infiltration via a malicious PDF exploit, then Nmap from inside — [UNB CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html)
- **DoS GoldenEye (15-02):** the victim's Apache keep-alive timeout is about 5 s. Roughly a quarter of flows are cut short by an **attacker RST**; flows under 5.05 s with a forward RST are labelled Attempted. Single-transaction flows are an artefact of the tool's volumetric behaviour. Victim-overwhelmed flows show one backward RST and zero backward bytes — [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html)
- **DoS Slowloris (15-02):** implemented correctly. It sends a partial `GET / HTTP/1.1`, then bogus `X-a` headers with random values. A real connection can last more than 10 min and is split by the 120 s timeout — [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html). Sharafaldin's top features for slowloris are Flow Duration, Fwd IAT Min, Bwd IAT Mean and Fwd IAT Mean; for Slowhttptest they are Flow Duration, Active Min/Mean and Flow IAT Std — [Sharafaldin 2018](https://www.scitepress.org/papers/2018/66398/66398.pdf)
- **DoS SlowHTTPTest (16-02, CIC-18):** no successful attack; it appears to have targeted **port 21** by mistake. A closed-port FTP-like pattern also appears on 16-02 — [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html)
- **DoS Hulk (16-02):** same implementation issue as in their CIC-17 analysis. Zero-payload flows are labelled Attempted — [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html). Sharafaldin's top Hulk features are Bwd Packet Len Std, Flow Duration and Flow IAT Std — [Sharafaldin 2018](https://www.scitepress.org/papers/2018/66398/66398.pdf)
- **FTP-BruteForce (14-02):** port 21 was closed, the target answered only RST,ACK, and **no brute force occurred** — [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html); also listed by Flood et al. as an attack against a closed port — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf)
- **SSH-BruteForce (14-02):** the paramiko client (`SSH-2.0-paramiko`) is encrypted after key exchange. Zero-payload flows are Attempted. The attack began on port 21 and moved to 22 — [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html). Flood et al. show two SSH-BruteForce clusters, partly launched against a closed port, with "almost all sampled flows identical" in one cluster — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf)
- **Web Brute Force (HTTP/DVWA):** genuine multi-login flows have **153 or more forward packets**. Flows with 20 or fewer forward packets are Attempted (single logins). Each multi-login flow is often preceded by a smaller single-login flow — [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html). (Note: the "about 20 packets" threshold here is for *web* brute force, not SSH.)
- **XSS:** normal attack flows last **about 50 s**. **SQLi:** initial flows only load the page with no payload — [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html)
- **Bot (Ares, 02-03):** all traffic is on port 8080. There are hello messages, reports and uploads, and SYN-then-RST flows near the end (Attempted). A segmentation-offload issue sets protocol and ports to 0 on many flows and splits requests. No evidence of Zeus was found — [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html). Sharafaldin's top Bot features (CIC-17) are Subflow Fwd Bytes, Total Len Fwd Packets, Fwd Packet Len Mean and Bwd Packets/s — [Sharafaldin 2018](https://www.scitepress.org/papers/2018/66398/66398.pdf)
- **DDoS LOIC-HTTP (20-02):** some flows labelled HTTP are actually UDP from LOIC-UDP. Attacker RST batches came later (one nearly two hours after the attack). There is no evidence the server went down and no retransmissions were seen — [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html)
- **DDoS LOIC-UDP:** on 20-02 no flows were labelled UDP; all were labelled HTTP although both tools ran (window 17:14:17 to 17:29:16). ICMP Destination Unreachable replies and zero-payload flows are Attempted — [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html). Flood et al. flag LOIC-UDP as clashing with LOIC (ENN mislabel score of 0.16) — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf)
- **DDoS HOIC (21-02):** started about 6 min later than documented; nothing else noted — [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html). Sharafaldin's DDoS (LOIC, CIC-17) top features are Bwd Packet Len Std, Avg Packet Size, Flow Duration and Flow IAT Std — [Sharafaldin 2018](https://www.scitepress.org/papers/2018/66398/66398.pdf)
- **Infiltration (28-02, 01-03):** three sub-behaviours: TLS Dropbox downloads (cannot be verified), C2 communication with large packets toward the victim, and an internal **Nmap scan of 21 hosts**. Original labels were largely unrecoverable, and some ARP was misparsed as IP flows — [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html). Flood et al.'s ENN mislabel score for CIC-18 Infiltration is 0.65, the highest of any CIC-18 class — [Flood et al. 2024](https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf). Sharafaldin's top features are Subflow Fwd Bytes, Total Len Fwd Packets, Flow Duration and Active Mean — [Sharafaldin 2018](https://www.scitepress.org/papers/2018/66398/66398.pdf)
- **Class sizes:** HOIC about 686,012 flows, LOIC-HTTP 576,191, Hulk 461,912 in one CICFlowMeter-version tally — [J. Big Data table](https://journalofbigdata.springeropen.com/articles/10.1186/s40537-024-00886-w/tables/5) (snippet)

### Inferences (family-to-window signatures; behavioural only; all unvalidated)
- **Volumetric HTTP (Hulk, LOIC-HTTP, HOIC, GoldenEye):** high share of TCP flows with small fwd packet counts (about 3 to 10). Non-zero fwd payload (an HTTP request) and a small or bounded bwd response, so the bwd/fwd byte ratio is moderate. Low entropy of fwd packet-count and fwd-bytes histograms. Short durations (GoldenEye bounded near the 5 s keep-alive; many RST-terminated). High within-window repetitiveness (low CV).
  - *Hulk vs LOIC/HOIC:* Hulk randomises URLs and headers, so expect a higher fwd-payload CV and entropy; HOIC and LOIC repeat fixed requests. This is from general tool knowledge and is not verified in these sources.
  - *DoS vs DDoS:* AEGIS has no IPs, so attacker multiplicity is invisible. The behavioural proxy is lower per-flow diversity in fwd payload for LOIC/HOIC. Expect residual DDoS vs DoS confusion; it may be irreducible without source-address features.
- **Slow DoS (Slowloris, SlowHTTPTest-2017-style):** long durations, very low packets/s, large Flow and Fwd IAT mean/max, high Active/Idle mean, tiny fwd payload per packet. In CIC-18, duration near the 120 s cap is an extractor artefact; use IAT and Idle rather than raw duration. The **CIC-18 SlowHTTPTest label is behaviourally FTP-closed-port traffic**: consider merging it or reporting it as "attempted".
- **Brute force (SSH/FTP/Web):** many medium-length TCP sessions with similar fwd and bwd packet counts and bidirectional small payloads (a login dialogue), so the bwd/fwd ratio is near 1. High PSH share. Low CV of packets per flow. Web brute force has 153 or more fwd packets per real session. **The CIC-18 FTP-BruteForce class is mostly SYN to RST,ACK** (closed port): zero payload and a high rst_share. That looks like a failed-connection flood and explains Brute Force vs DoS confusion. Add `zero_payload_share` and treat these as an "attempted/failed-connection" group.
- **Bot (Ares):** periodic low-volume HTTP-like polling (8080). In flow terms: small fwd payload, small to moderate bwd, low packets/s, long inter-flow gaps. Periodicity is *across* flows (timestamps), and the parquet lacks Timestamp, so use the low CV of flow size together with low mean rate. Protocol-0 fragments inflate a "non-TCP/UDP" share, which may make Bot windows look like DDoS (UDP or other). Check `1 - tcp_share - udp_share` in Bot windows.
- **Infiltration:** heterogeneous: large bwd (download) bytes for the Dropbox part and many tiny flows to many ports for Nmap. Expect it to stay noisy given ENN 0.65; consider evaluating it separately.

### Recommended improved window feature set (synthesis; every item is an inference from the cited evidence above)
Drop or redefine: `unique_tcp_window_ratio` (init-window artefact); remove Init Fwd Win Bytes from `dominant_signature_share`.
Keep: tcp_share, udp_share, syn/rst/fin/psh shares, no_response_share.
Add (all aggregated over the 100 flows, on log1p values where marked †):
1. `median_fwd_payload_per_pkt`† and `p90_fwd_payload_per_pkt`† (Fwd Packet Length Mean)
2. `median_bwd_pkt_len_std`† (Bwd Packet Length Std, the top DoS/DDoS feature in Sharafaldin)
3. `window_bwd_fwd_byte_ratio` = Σ Total Len Bwd / Σ Total Len Fwd (log ratio)
4. `zero_payload_share` (Fwd Act Data Pkts == 0, or Total Len Fwd == 0): marks attempted or closed-port traffic
5. `median_flow_iat_mean`†, `p90_flow_iat_max`†, and `median_idle_mean`† (slow DoS, Bot)
6. `cv_fwd_packets`, `cv_flow_duration`, `cv_fwd_payload` (tool repetitiveness)
7. `entropy_fwd_packets_hist`, `entropy_fwd_bytes_hist` (8 log-bins, normalised)
8. `median_packets_per_flow` and `median_flow_duration`† in place of means; keep the means only if ablation shows benefit
9. `long_flow_share` (duration > 60 s; avoid using the exact 120 s cap)
10. `other_proto_share` = 1 − tcp − udp (diagnostic for Bot protocol-0 artefact and ICMP)
11. `mean_header_bytes_per_pkt` from Fwd/Bwd Header Length / packets (flag-only or option-heavy traffic). It may partially encode OS stack options, so ablate it.
12. Optional, naming-only: `login_port_share`, `web_port_share` from Dst Port buckets, kept **out of the classifier**.
Validation: leave-one-day-out, with and without features 11 and 12, and with SlowHTTPTest-2018, FTP-BruteForce-2018 and zero-payload flows relabelled as "attempted" per DistriNet's corrected labels.

### Gaps
- I found no source with per-tool packet-length distributions for HOIC vs LOIC-HTTP vs Hulk on CIC-18. The search confirmed that none was readily available.
- No source in this session confirmed the commonly repeated claims "SSH brute force ≈ 20-packet flows" or "Hulk = large fwd payload". The 20-packet threshold found applies to **web** brute force.
- Ares periodicity in flow terms (beyond "screenshots every 400 s") was not characterised in any source found.
- DistriNet's corrected CIC-18 (with "Attempted" labels) uses a fixed CICFlowMeter. Whether the AEGIS parquet is the original or the corrected version determines which of the artefacts above are present. That could not be checked under the no-project-files constraint.
