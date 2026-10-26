# Evaluation Methodology for LLM-based / Agentic Intrusion Detection and Response

Context for the comparison: the AEGIS pipeline gates windows of 100 CIC-IDS2018 flows using a deterministic monitoring score, sends gated windows to a Gemini detection agent, and then to risk, response and governance agents. It reports window-level confusion matrices and accuracy, precision, recall, F1 and FPR for the gate alone and for the full pipeline. A typical run is about 10 windows from one day-file. It has no classical ML baseline, no latency or cost measurement, no repeated runs, and no evaluation of attack-type classification or response quality.

## Q1. Baselines in LLM-IDS papers and typical classical scores on CIC-IDS2018

### Takeaway
Every serious LLM-IDS paper compares against classical ML (Random Forest, XGBoost, Decision Tree, LSTM/CNN). On flow-level CIC-IDS2018, RF and XGBoost routinely score 0.97 to 0.999 accuracy and F1. Zero-shot LLMs (GPT-4, Llama3) score near chance on flow classification. LLMs win only in hybrid designs, or when judged on explanation and response rather than raw detection. They are also 3 to 4 orders of magnitude slower per sample.

### Cited Findings
- **Zero-shot GPT-4 on NetFlow CIC-IDS2018 (Houssel et al., 2024):**
  - GPT-4-0613 scored 50.25% macro precision and 51.02% macro recall on NF-CSE-CIC-IDS2018-v2, about chance level (50%).
  - Llama3-8B-Instruct scored 49.66% / 49.73%.
  - Setup: temperature 0.1, binary "1/0" output, 95/5 stratified split. — [Houssel et al., arXiv 2408.04342](https://arxiv.org/html/2408.04342v1)
- **Fine-tuning the LLM helped little (same paper).** Llama3 trained with KTO on 50k samples reached only 55.02% / 58.79% macro P/R on CIC-IDS2018-v2. — [arXiv 2408.04342](https://arxiv.org/html/2408.04342v1)
- **Baselines the same paper cites from prior work (NF-UNSW-NB15-v2, weighted F1):** Random Forest 92.17%, LSTM 92.82%, DANN 97.81%, FlowTransformer 89.98%. These use different metrics from the LLM rows, so they are not directly comparable, a caveat the authors note themselves. — [arXiv 2408.04342](https://arxiv.org/html/2408.04342v1)
- **Per-sample inference cost (same paper):** Llama3-8B about 14,000 µs, LSTM 25 µs, Random Forest 2.03 µs, Decision Tree 1.53 µs. That makes the LLM about 7,000 times slower. GPT-4 latency could not be measured because the model is closed. — [arXiv 2408.04342](https://arxiv.org/html/2408.04342v1)
- **Authors' conclusion:** LLMs are unfit as standalone NetFlow NIDS but promising as complements for explanation and threat response with RAG and function calling. Their explanations were convincing but contained factual errors and hallucinations. — [arXiv 2408.04342](https://arxiv.org/html/2408.04342v1)
- **Hybrid signature + GPT-2 on CSE-CIC-IDS2018:** reported precision 97.5%, recall 96.8%, F1 97.1% and accuracy 98.3%. Latency was about 2.1 ms for the traditional IDS, 9.3 ms for the hybrid and 18.7 ms for GPT-2 alone. — [arXiv 2507.07413](https://arxiv.org/html/2507.07413v1)
- **LLMs vs classical ML on CIC IoT 2023 (Springer AI Review, 2025):** GPT-2, GPT-Neo-125M and LLaMA-3.2-1B exceeded 95% F1 but did not beat XGBoost. XGBoost reached 96.96% F1 using only 4% of available CPU. — [Springer s10462-025-11432-2](https://link.springer.com/10.1007/s10462-025-11432-2)
- **Zero-/few-shot LLMs on UNSW-NB15 (Rehman et al., 2025):**
  - A 7B model reached macro-F1 of about 0.78 on a 200-flow subset.
  - Performance dropped as the evaluation set grew to 2,000 flows, so small subsets overstate LLM performance.
  - Tabular baselines were more stable and faster. — [arXiv 2510.17883](https://arxiv.org/html/2510.17883v2)
- **Few-shot GPT-3.5/GPT-4 for DDoS on CIC-IDS2017 (USC):** about 90% accuracy with 10 few-shot examples and about 95% with fine-tuning on 70 samples. — [USC ANRG paper](https://anrg.usc.edu/www/papers/LLM_Cybersecurity_SmartSP.pdf)
- **Classical baselines on CSE-CIC-IDS2018.** Different preprocessing, sampling and splits explain much of the spread between papers.

  | Source | Random Forest | XGBoost |
  |---|---|---|
  | [SHIELD-IDS, arXiv 2606.07716](https://arxiv.org/pdf/2606.07716) | 0.9995 accuracy / 0.9958 F1 | 0.9994 accuracy / 0.9941 F1 |
  | [Hybrid CNN-LSTM, arXiv 2606.05714](https://arxiv.org/pdf/2606.05714) | about 96.8% accuracy | about 97.5% accuracy |
  | [NEPJOL comparative study](https://nepjol.info/index.php/injet/article/view/95492) | about 97.90% accuracy | about 97.97% accuracy, 0.9797 F1 |

  - The CNN-LSTM paper's authors flag their resampling as a possible reason the results look suspiciously clean.
  - A further study (Wicaksana & Umam) reports about 99.4% accuracy for RF and 99.8% for XGBoost. — [Garuda record](https://garuda.kemdiktisaintek.go.id/documents/detail/6412866) (secondary index; numbers came from a search summary and were not verified in the full text)
- **Leevy, Hancock, Zuech & Khoshgoftaar (2021):** compared 7 classifiers including RF and XGBoost on CSE-CIC-IDS2018 (about 16M instances) using F1 and AUC with ensemble feature selection. — [Journal of Big Data, DOAJ record](https://doaj.org/article/eeb5f5de972346ae8403d45f4b468783)
- **Dataset caveat:**
  - Engelen et al. (IEEE S&P Workshops 2021) found more than 25% of CICIDS2017 flows are meaningless artefacts, and the issue persists in CSE-CIC-IDS2018. — [imec publications](https://imec-publications.be/handle/20.500.12860/37518?show=full)
  - Liu, Engelen et al. (IEEE CNS 2022) documented labelling errors in CIC-IDS-2017 and CSE-CIC-IDS-2018 and released a corrected, re-labelled version. — [CPS-VO record](https://archive.cps-vo.org/node/97449)

### Inferences
- The project needs at least one classical baseline on the same windows and labels. Two cheap options:
  - RF or XGBoost trained on flows from a different day-file, with predictions aggregated to window level, for example "window is attack if ≥k flows are predicted attack."
  - An unsupervised Isolation Forest, which mirrors the gate's anomaly-scoring role.
- Because RF/XGBoost reach about 0.97 to 0.99 on this dataset, the project's claim should not be "the LLM detects better." A defensible claim is "the agentic pipeline adds explanation, attack typing and response at acceptable detection cost." Alternatively, show added value over the gate, such as FP suppression.
- The deterministic monitoring gate is itself a non-LLM baseline. Reporting gate vs gate+LLM is good practice, and the gain attributable to the LLM is the key number.
- Train/test should be split by day-file (temporal split), not randomly within a day. Random splits leak highly similar flows, which is Arp's "data snooping" pitfall (see Q6).

### Gaps
- No published head-to-head of Gemini (any version) on CIC-IDS2018 against RF/XGBoost was found.
- No paper was found that evaluates window-level aggregation (100-flow windows) as AEGIS does. Published numbers are flow-level, so they are not directly comparable with window-level metrics.
- Verified Leevy & Khoshgoftaar RF/XGBoost numbers were not retrieved because the full text was not fetched.
- No isolation forest results on CIC-IDS2018 were retrieved.

## Q2. Metrics beyond F1

### Takeaway
Report the confusion matrix together with MCC, balanced accuracy, per-class (attack-type) recall and macro-F1, PR-AUC where a score exists, and FPR (or alerts per day) at fixed recall. Add operational metrics: latency per window, tokens and cost per window, LLM call rate (fraction of windows the gate escalates), fallback/parse-failure rate, and LLM-vs-rule agreement (Cohen's kappa).

### Cited Findings
- **MCC:**
  - Chicco & Jurman (BMC Genomics 2020) argue that accuracy and F1 "can dangerously show overoptimistic inflated results, especially on imbalanced datasets."
  - MCC is high only if the classifier does well in all four confusion-matrix cells. — [Chicco & Jurman, PMC6941312](https://pmc.ncbi.nlm.nih.gov/articles/PMC6941312)
  - A 2025 follow-up commentary by the same authors recommends reporting MCC plus recall, precision, specificity and NPV, with repeated stratified hold-out. — [secondary summary](https://letsdatascience.com/news/researchers-advocate-mcc-over-f1-and-accuracy-cf31e7c4) (secondary; not verified against the PLOS original)
- **Macro averaging:** Houssel et al. use macro-averaged precision and recall, which makes chance level clearly visible at 50%. — [arXiv 2408.04342](https://arxiv.org/html/2408.04342v1)
- **Micro-F1 for multi-label tagging:** CTIBench scores ATT&CK technique extraction (CTI-ATE) with micro-F1. It uses accuracy for CVE→CWE mapping and mean absolute deviation for CVSS score prediction. — [CTIBench, arXiv 2406.07599](https://arxiv.org/html/2406.07599v3)
- **Latency and cost:** LLM-IDS papers report per-sample latency alongside detection metrics. Examples are 2.1 / 9.3 / 18.7 ms in the hybrid GPT-2 paper and 14,000 µs vs 2 µs for Llama3 vs RF. — [arXiv 2507.07413](https://arxiv.org/html/2507.07413v1); [arXiv 2408.04342](https://arxiv.org/html/2408.04342v1)
- **Resource use:** the Springer benchmark reports CPU/GPU utilisation alongside F1 (XGBoost at 4% CPU). — [Springer s10462-025-11432-2](https://link.springer.com/10.1007/s10462-025-11432-2)
- **Base rates:** in real SOCs about 46% of alerts are false positives and 42% are never investigated (Microsoft/Omdia study, reported via secondary source). This is why FPR and alert volume matter more than accuracy. — [cyberdefenders summary](https://cyberdefenders.org/blog/soc-alert-fatigue/); [Microsoft/Omdia via BusinessWire](https://www.businesswire.com/news/home/20251007362209/en) (vendor/secondary)
- **Structured outputs:** the Rehman et al. flows-to-text study used grammar-constrained outputs. Unguided prompting was unreliable, so output-validity and parse failures are a real failure mode worth counting. — [arXiv 2510.17883](https://arxiv.org/html/2510.17883v2)

### Inferences (recommended metric set for AEGIS)
- **Detection, window level:**
  - Confusion matrix, precision, recall, F1, FPR, MCC and balanced accuracy.
  - Report the attack-window prevalence of each run, because CIC-IDS2018 day-files differ hugely in attack ratio and accuracy is meaningless without it.
- **Threshold-free measures:** the monitoring score is continuous, so report ROC-AUC and PR-AUC for the gate. Also report recall at a fixed FPR (or FPR at 95% recall) to justify the gate threshold.
- **Attack-type classification:** a per-class confusion matrix over CIC-IDS2018 labels (DoS-Hulk, DDoS-LOIC, FTP/SSH-BruteForce, Bot, Infiltration, Web/SQLi...) with per-class recall and macro-F1. Macro weighting stops rare classes like Infiltration or SQLi from being hidden.
- **Cost and operations:**
  - Median and p95 end-to-end latency per window, broken down per agent.
  - Gemini calls per window and input/output tokens per window, giving estimated cost per 1,000 windows.
  - Escalation rate (share of windows the gate sends to the LLM).
  - Fallback rate (LLM error, timeout or invalid JSON → rule fallback).
  - Time from window ingestion to response plan (time-to-respond proxy).
- **Agreement:** Cohen's kappa between the gate verdict and the LLM verdict on escalated windows. Also count windows where the LLM overturns the gate, split into correct vs incorrect overturns. This isolates the LLM's marginal value.

### Gaps
- No standard published "fallback rate" or "LLM-rule agreement" metric was found in IDS literature. These are proposed here as engineering metrics, not drawn from a cited standard.
- No source was found giving FPR-at-fixed-recall conventions specific to LLM-IDS.

## Q3. LLM non-determinism, repeated runs, and calibration

### Takeaway
Temperature 0 does not give deterministic outputs, and accuracy can vary by up to about 15% across identical runs. Run each configuration several times (at least 3 to 5, ideally over different window samples) and report mean ± SD or 95% CI. Verbalized LLM confidence is systematically overconfident, so if the detection agent outputs a confidence, measure ECE and a reliability diagram before using it for risk scoring or auto-approval.

### Cited Findings
- **"Non-Determinism of 'Deterministic' LLM Settings" (arXiv 2408.04667):**
  - Across five models and eight tasks, accuracy varied by up to 15% across runs at temperature 0. (The 15% figure is as reported by a search summary.)
  - Reporting a single score without variance undermines benchmark validity. — [arXiv 2408.04667](https://arxiv.org/html/2408.04667v5)
- **"On Randomness in Agentic Evals" (2026):**
  - Variance persists at temperature 0.0, for example 20.4 ± 1.0% and 22.3 ± 1.8% on agentic benchmarks.
  - Variance does not shrink reliably as temperature is lowered.
  - Causes include floating-point precision and batching. — [arXiv 2602.07150](https://arxiv.org/pdf/2602.07150)
- **Drift study (2026):**
  - Top LLMs did not produce identical completions across ten deterministic runs.
  - Non-determinism can stem from the model or the serving stack.
  - One 120B model was identical in only about 12.5% of runs. — [arXiv 2601.19934](https://arxiv.org/html/2601.19934v1)
- **Calibration of verbalized confidence (Xiong et al., ICLR 2024):**
  - LLMs "tend to be overconfident" when verbalizing confidence.
  - GPT-3, GPT-3.5 and Vicuna had average ECE above 0.377.
  - GPT-4 had lower ECE, but its failure prediction was weak (average AUROC of about 62.7%).
  - Sampling multiple responses and measuring consistency improves calibration but does not fix it. — [Xiong et al., arXiv 2306.13063](https://arxiv.org/abs/2306.13063v2)
- **CTIBench** reports that even strong models show challenges in "contextual calibration" on CTI tasks. — [EmergentMind CTIBench summary](https://www.emergentmind.com/topics/ctibench) (secondary)

### Inferences
- Minimum protocol for AEGIS:
  1. Fix the temperature (0 or a low value), log it, and log the model version string, because Gemini model aliases change over time.
  2. Run N≥5 repeats of the identical window set to measure pure LLM variance.
  3. Separately run over ≥5 different random window samples (seeds), ideally across several day-files, to measure sampling variance.
  4. Report mean ± SD and a 95% CI for each metric.
  5. Report per-window verdict flip rate across repeats, which measures LLM stability.
- **Calibration:**
  - Pool all escalated windows and bin the LLM's reported confidence into 5 to 10 bins.
  - Plot accuracy vs confidence (reliability diagram) and compute ECE and the Brier score.
  - If confidence drives the risk agent or auto-approval, calibration is a prerequisite. Otherwise, consider self-consistency (majority vote over k samples) as the confidence signal.
- Cache LLM responses keyed by prompt hash so that results are reproducible for graders. The cached results are a snapshot, and fresh repeats are still needed to report variance.

### Gaps
- No study was found measuring Gemini-specific run-to-run variance on IDS tasks.
- No IDS paper was found that reports ECE for LLM detection confidence. Calibration evidence here comes from general QA benchmarks.

## Q4. Evaluating explanation / reasoning quality and response-plan quality

### Takeaway
There is no accepted quantitative standard for evaluating LLM IDS explanations. Houssel et al. explicitly call for one and note explanations often contain hallucinations. Practical options:
- Check explanation claims against the actual flow features (a faithfulness/factual-error rate).
- Score MITRE ATT&CK technique mapping against a ground-truth label→technique table (precision/recall/micro-F1, as CTIBench does).
- Have experts rate response plans on a rubric with inter-rater agreement.
- Use LLM-as-judge only as a supplement, with bias controls and human-agreement checks.

### Cited Findings
- **Explanations in LLM-IDS:**
  - Houssel et al. found LLM explanations convincing but containing factual errors and hallucinations, with models struggling to link features to attack signatures.
  - Their analysis was manual and qualitative, and they state a quantitative evaluation method and datasets are lacking. — [arXiv 2408.04342](https://arxiv.org/html/2408.04342v1)
- **ATT&CK mapping benchmark:** CTIBench's CTI-ATE task extracts MITRE ATT&CK techniques from threat descriptions and scores them with micro-F1. It evaluated GPT-3.5, GPT-4, Gemini-1.5 and Llama3-70B/8B. — [CTIBench, arXiv 2406.07599](https://arxiv.org/html/2406.07599v3); [EmergentMind summary](https://www.emergentmind.com/topics/ctibench)
- **Agentic SOC benchmarks:**
  - **ExCyTIn-Bench (Microsoft):** agents investigate a simulated Azure tenant (57 Sentinel-style tables, 44 days of logs). Questions come from incident-graph paths, with partial credit for correct intermediate steps. The average reward across models was 0.249 and the best was 0.368. — [SRA analysis](https://sra.io/blog/examining-the-excytin-bench-approach-for-benchmarking-ai-incident-response-capabilities/) (secondary)
  - **CyberSOCEval (Meta, part of CyberSecEval 4):** covers malware analysis from real sandbox detonation logs and threat-intel reasoning over 45 CTI reports. — [HF paper page 2509.20166](https://huggingface.co/papers/2509.20166.md); [SentinelOne review](https://www.sentinelone.com/labs/llms-in-the-soc-part-1-why-benchmarks-fail-security-operations-teams)
  - **SentinelOne's critique:** even the best agentic SOC benchmark uses a curated environment with canned attacks, so it does not reflect real SOC noise. — [SentinelOne Labs](https://www.sentinelone.com/labs/llms-in-the-soc-part-1-why-benchmarks-fail-security-operations-teams)
- **LLM-as-judge (Zheng et al., NeurIPS 2023):**
  - GPT-4 judges reach over 80% agreement with human preferences, similar to human-human agreement.
  - The paper documents position bias, verbosity bias, self-enhancement bias and limited reasoning ability. — [arXiv 2306.05685](https://arxiv.org/html/2306.05685v4)
  - A secondary source reports that the strongest judge was consistent only about 65% of the time when answer order was swapped. — [memx blog](https://memx.app/blog/llm-as-a-judge-biases-and-fixes/) (secondary; not verified in the primary)

### Inferences (concrete protocol for AEGIS)
- **Attack-type → ATT&CK mapping correctness:**
  - Build a fixed reference table from CIC-IDS2018 label to expected technique IDs, for example:
    - FTP/SSH-BruteForce → T1110
    - DoS/DDoS → T1498/T1499
    - SQL Injection / Web attacks → T1190
    - Bot → C2-related techniques such as T1071
    - Infiltration → multiple techniques
  - Score the agent's technique IDs per window with precision, recall and micro-F1, plus exact-match rate.
  - The table is the project's own mapping and should be documented as an assumption.
- **Explanation faithfulness:**
  - For a sample of windows (for example 30 to 50), check whether each feature-level claim (such as "high SYN rate" or "dst port 22") is true in the window data.
  - Report the share of explanations with ≥1 hallucinated claim. This is partly automatable because the claims are checkable against the dataframe.
- **Response-plan quality:**
  - Use a rubric with 1 to 5 scales for relevance to the attack type, actionability/specificity, proportionality (no over-blocking) and safety (no destructive action without approval).
  - Have ≥2 raters (students or faculty) score the plans and report Cohen's or Fleiss' kappa or Krippendorff's alpha.
  - Optionally add an LLM judge using a *different* model family than Gemini (to avoid self-enhancement bias), randomized order and length-controlled rubrics.
  - Report judge-human agreement on the overlapping subset before trusting judge scores at scale.

### Gaps
- No published rubric specific to IDS response-plan quality was found. The rubric above is a proposal.
- Exact CTI-ATE per-model scores were not retrieved.

## Q5. Evaluating human-in-the-loop governance

### Takeaway
No standard academic metric suite for governing an LLM-driven IDS was found. Evaluation should rest on operational metrics computed from the governance agent's decisions vs ground truth:
- Review load (share of actions sent to humans).
- Auto-approval precision (share of auto-approved actions that were correct and safe).
- Escalation recall (share of high-risk or incorrect actions caught for review).
- Analyst override rate.
- Time-in-queue.

### Cited Findings
- **Alert volume and fatigue in SOCs:**
  - In a Microsoft/Omdia study, 46% of alerts are false positives and 42% are never investigated. — [cyberdefenders blog](https://cyberdefenders.org/blog/soc-alert-fatigue/); [BusinessWire](https://www.businesswire.com/news/home/20251007362209/en) (vendor/secondary)
  - An older FireEye-linked survey found 44% of MSSP analysts ignore alerts when queues are full. — [Campus Safety](https://www.campussafetymagazine.com/news/study-widespread-alert-fatigue-results-in-ignored-cybersecurity-alerts/) (secondary)
- **AI auto-suppression risk:** a CSA research note (September 2026) reports more than 80% of AI-related alerts were auto-suppressed without analyst review. It warns that suppression risks discarding rare true positives. — [CSA research note PDF](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/09/CSA_research_note_ai_soc_alert_noise_20260914-csa-styled.pdf)
- **Human-AI teaming:** an ACM review of alert prioritisation argues human-AI teaming can improve prioritisation and that analyst feedback can reduce false positives over time. — [ACM 10.1145/3695462](https://api.crossref.org/works/10.1145%2F3695462)
- **Calibration matters:** if auto-approval thresholds use LLM-reported confidence, overconfidence (Xiong et al.) translates directly into unsafe auto-approvals. — [arXiv 2306.13063](https://arxiv.org/abs/2306.13063v2)

### Inferences (proposed metrics for AEGIS governance agent)
- **Review load:** the share of windows or actions routed to human approval, together with the projected analyst workload (reviews per hour of traffic).
- **Auto-approval precision:** among auto-approved response actions, the share whose window was truly malicious and whose action is appropriate for the true attack type. Auto-approval on benign windows is the critical safety failure, so report the count explicitly.
- **Escalation recall:** among actions that *should* need human review (wrong attack type, benign window, high-impact action such as blocking a subnet), the share the governance agent escalated.
- **Override rate:** in a simulated review, the share of escalated actions a human reviewer rejects or modifies. A very low override rate may mean either a good agent or rubber-stamping (automation bias), so pair it with the reviewer's agreement with ground truth.
- Report these at several risk thresholds as a trade-off curve (review load vs auto-approval error) rather than at one operating point.

### Gaps
- No controlled study was found measuring SOC analyst override rates or automation bias with AI recommendations. The alert-fatigue figures are mostly vendor surveys.
- No paper was found that evaluates a governance or approval agent in an LLM IDS pipeline.

## Q6. Statistical rigour and minimum sample sizes for a student/research project

### Takeaway
About 10 windows from one day-file is far too few. With n=10, a 95% CI on accuracy spans roughly ±30 percentage points, and the result covers only one or two attack types. Aim for several hundred windows spanning all CIC-IDS2018 day-files and attack types, with temporal (day-based) splits, repeated runs, bootstrap CIs, and a paired test (McNemar) when comparing the pipeline with the gate or an ML baseline on the same windows. Also follow Arp et al.'s pitfalls checklist.

### Cited Findings
- **Arp et al., "Dos and Don'ts of Machine Learning in Computer Security" (USENIX Security 2022, Distinguished Paper):**
  - A review of 30 top-tier security papers found pitfalls in design, implementation and evaluation to be widespread, and individual pitfalls produce unrealistic performance. — [arXiv 2010.09470](https://arxiv.org/abs/2010.09470); [USENIX page](https://www.usenix.org/conference/usenixsecurity22/presentation/arp); [BIFOLD news](https://www.bifold.berlin/news-events/news/view/news-detail/cybersecurity-under-scrutiny)
  - The ten pitfalls are: sampling bias, label inaccuracy, data snooping, spurious correlations, biased parameter selection, inappropriate baseline, inappropriate performance measures, base rate fallacy, lab-only evaluation and inappropriate threat model. Recommendations include comparing with simple baselines, reporting precision/recall-type measures under realistic base rates, and keeping temporal order in splits. — [USENIX paper PDF](https://www.usenix.org/system/files/sec22-arp.pdf)
  - **Verification note:** the PDF could not be text-extracted in this session. The pitfall names come from the reviewer's prior knowledge of the paper; confirm them against the PDF before quoting.
- **Dietterich (1998), comparing classifiers:**
  - McNemar's test is the recommended test, with acceptable Type I error, when algorithms can be run only once on a fixed test set.
  - 5×2cv is slightly more powerful when 10 trainings are affordable.
  - Paired t-tests over random resamples should not be used. — [Dietterich 1998 PDF](https://web.engr.oregonstate.edu/~tgd/publications/dietterich-approximate-statistical-tests-nc1998.pdf)
  - Applying McNemar naively across K-fold CV is invalid because the statistics are correlated. — [arXiv 2304.03990](https://arxiv.org/pdf/2304.03990)
- **Confidence intervals:**
  - Raschka recommends reporting CIs (bootstrap) rather than relying on p-values alone. Bootstrap makes no distributional assumption about the metric. — [Raschka, CIs for ML](https://sebastianraschka.com/blog/2022/confidence-intervals-for-ml.html); [Raschka, arXiv 1811.12808](https://arxiv.org/pdf/1811.12808)
  - A good-practices paper on ML evaluation covers related practice. — [arXiv 2412.03700](https://arxiv.org/pdf/2412.03700)
- **Small samples overstate performance:** Rehman et al. found LLM macro-F1 of about 0.78 on 200 flows that dropped as the set grew to 2,000. — [arXiv 2510.17883](https://arxiv.org/html/2510.17883v2)
- **Repeated runs:** single-run LLM scores are unreliable because run-to-run variance at temperature 0 can reach about 15%. — [arXiv 2408.04667](https://arxiv.org/html/2408.04667v5)
- **Label noise:** CIC-IDS2018 labels contain documented errors, and a corrected version exists (Liu, Engelen et al., CNS 2022), so evaluation on the original labels may mis-score some windows. — [CPS-VO record](https://archive.cps-vo.org/node/97449)

### Inferences (concrete minimum protocol)
- **Sample size arithmetic (normal approximation, binomial):** the 95% CI half-width is about 1.96·√(p(1−p)/n).

  | Windows (n) | Approx. 95% CI half-width |
  |---|---|
  | 10 | ±28 pp at p=0.8 |
  | 100 | ±8 pp |
  | 400 | ±4 pp |
  | 1,000 | ±2.5 pp |

  - Use Wilson intervals for small n or extreme proportions.
  - Target ≥300 to 500 evaluation windows in total, and ≥30 windows per attack type for per-class recall. This is a rule-of-thumb inference, not a cited standard.
- **Coverage:**
  - Sample windows from all 10 CIC-IDS2018 day-files so every attack family appears.
  - Include benign-only days or periods to measure FPR at realistic base rates.
  - Stratify, and report the attack prevalence per run.
- **Splits:**
  - Tune gate thresholds and prompts (few-shot examples) on day-files that are disjoint from the test day-files.
  - Never tune on the test windows (data snooping / biased parameter selection).
- **Repeats:**
  - At least 5 seeds over window sampling and at least 3 LLM repeats per window set.
  - Report mean ± SD and bootstrap 95% CIs (≥1,000 resamples over windows).
- **Paired comparisons:** compare gate-only vs full pipeline vs RF/XGBoost on the *same* windows with McNemar's test on the discordant windows. Bootstrap the difference in F1/MCC.
- **Window labelling rule:** define the threshold explicitly (any attack flow vs ≥x% attack flows) and run a sensitivity analysis, because ground truth depends on it.
- **Budget:** at 500 windows × 5 repeats there are up to 2,500 detection calls before the gate filters, plus the downstream agents. Logging tokens per call lets you report the total cost.

### Gaps
- No published minimum-sample-size guidance specific to LLM-IDS evaluation was found. The numbers above derive from standard binomial CI arithmetic.
- The Arp et al. per-pitfall prevalence percentages could not be extracted, because the PDF text was not readable in this session.
