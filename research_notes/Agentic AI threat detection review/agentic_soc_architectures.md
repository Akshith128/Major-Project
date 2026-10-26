# Agentic / LLM Multi-Agent Architectures for Autonomous Network Threat Detection and Response (2023–2026)

Scope note: These notes compare published research and vendor systems against the project pipeline (Monitoring → Detection via Gemini on aggregate CICFlowMeter features → Risk → Response with recommendations only → Governance with HITL and a hash-chained audit). Most sources were read from the arXiv HTML or abstract, or from vendor or official documentation pages. Where only a search snippet or abstract was available, that is noted.

## Q1. What architectures do recent papers and products use for LLM/agentic intrusion detection and incident response?

### Takeaway
The main 2024–2026 pattern is an orchestrator, or a fixed staged pipeline, coordinating role-specialised agents. These agents call typed tools (SIEM queries, threat intel lookups, ML detectors), often through MCP, and write a structured, auditable report. Multi-agent designs beat single-agent baselines on triage quality, but they cost several times more latency and tokens. The project's fixed linear LangGraph pipeline fits the "staged pipeline" variant. It lacks tool calls, evidence retrieval and an orchestrator loop.

### Cited Findings
**Research systems**
- **IDS-Agent (Li et al., NeurIPS 2024 workshop)** describes itself as the first LLM agent for intrusion detection. It classifies traffic as benign or malicious and explains the decision. The core LLM picks actions from a set covering data preprocessing, classification (by calling ML models), knowledge and memory retrieval, and result aggregation. It keeps a memory and knowledge base, and its system prompts can be adjusted to change detection sensitivity. Reported F1 is 0.97 on ACI-IoT and 0.75 on CIC-IoT, with zero-day recall of 0.61. — [NeurIPS 2024 listing](https://neurips.cc/virtual/2024/100920); [mlanthology](https://mlanthology.org/neuripsw/2024/li2024neuripsw-idsagent)
- A 2025 NIDS survey characterises IDS-Agent as an iterative reasoning-action (ReAct-style) pipeline that calls ML models. It says IDS-Agent focuses mainly on managing detection models rather than the full IDS lifecycle (summarised from search snippet). — [Yang et al., arXiv:2507.04752](https://arxiv.org/abs/2507.04752)
- **Yang et al. 2025 survey, "LLMs for NIDS: Foundations, Implementations, and Future Directions"**, proposes a "Cognitive NIDS". In it the LLM plays three roles (processor, detector, explainer) and an "LLM-centred controller" coordinates detection tools and workflows. — [arXiv:2507.04752](https://arxiv.org/abs/2507.04752)
- **CORTEX (Wei et al., George Mason Univ. & Fluency Security, arXiv Sept 2025)** is a four-stage alert-triage pipeline:
  - an Orchestrator Agent;
  - a Behavior Analysis Agent that routes each alert to workflows;
  - per-workflow Evidence Acquisition Agents that query enterprise systems through MCP-exposed typed tools (getUserRecord, searchBehaviorEvents, runStructuredQuery, updateIncidentRecord, and others);
  - a Reasoning & Coordination Agent that writes a structured, auditable report.

  The Reasoning & Coordination Agent uses a conservative "any workflow escalates → actionable" policy, and each alert gets an ephemeral context. — [arXiv:2510.00311](https://arxiv.org/html/2510.00311v1)
- CORTEX results against a tool-using single agent:
  - actionable F1 rose from 0.66 to 0.78;
  - non-actionable F1 rose from 0.77 to 0.86;
  - false-positive rate fell from 24.9% to 14.2%;
  - macro-F1 reached 0.82.

  Evaluation used several thousand real SOC investigation traces across more than 10 scenarios. — [arXiv:2510.00311](https://arxiv.org/html/2510.00311v1)
- **Drammeh, "Multi-Agent LLM Orchestration Achieves Deterministic, High-Quality Decision Support for Incident Response" (arXiv:2511.15755, Nov 2025, revised 2026)** ran 348 trials. Multi-agent orchestration produced actionable recommendations 100% of the time, against 1.7% for a single agent. The v2 caveats say this is a single incident scenario with TinyLlama-1B and shows "architectural potential", not production readiness. It is also SRE/ops-style incident response rather than a SOC (from abstract/snippet). — [arXiv:2511.15755](https://arxiv.org/html/2511.15755v2)
- **"Multi-Agent Collaboration in Incident Response with LLMs" (arXiv:2412.00652, Dec 2024)** frames LLM agents as emulating human defenders for analysis, detection and response. Results were not verified (snippet only). — [arXiv:2412.00652](https://arxiv.org/pdf/2412.00652)
- **LLM + RL agent teams for autonomous cyber defence (arXiv:2505.04843, 2025)** evaluates LLM agents in the CybORG CAGE-4 multi-agent environment and proposes an LLM↔RL communication protocol. This is simulation-based network defence, not SOC triage (snippet). — [arXiv:2505.04843](https://arxiv.org/abs/2505.04843v2)
- **SJSU "LLM-Based Agentic Network Traffic Incident-Report Approach"** has three phases. A Random Forest pre-detector feeds an MLP+RF+XGBoost ensemble with SHAP attribution, and a ReAct-based LLM agent then writes incident reports. The ensemble's accuracy exceeds 99.8% across 11 classes on ACI-IoT-2023 (snippet). — [SJSU ScholarWorks](https://scholarworks.sjsu.edu/faculty_rsca/7038)
- **HuntGPT (2023, background)** pairs a Random Forest anomaly detector with SHAP/LIME XAI and a GPT-3.5-Turbo conversational agent. It was trained on KDD99. — [arXiv:2309.16021](https://arxiv.org/pdf/2309.16021)

**Industry and reference architectures**
- **Google Cloud reference architecture for an agentic SOC (ADK + MCP).** It has three agent roles:
  - a root "SOC manager" agent that delegates work and loops until runbook criteria or a maximum iteration count are met;
  - a Tier-1 analyst sub-agent for alert details, assets and user context;
  - a CTI researcher sub-agent that correlates IOCs with threat actors and TTPs.

  Tools come through MCP servers: the SecOps (SIEM/SOAR) MCP, the Google Threat Intelligence MCP, and third-party CSPM/EDR MCPs. Supporting services include a RAG knowledge base of runbooks and IR plans, a Memory Bank for cross-session context, and HITL approve/override/pause. — [Google Cloud Architecture Center](https://docs.cloud.google.com/architecture/agentic-ai-orchestrate-security-ops-workflows)
- **Google SecOps Triage and Investigation Agent.** It decides whether an alert is a true or false positive and gives a summarised explanation. It runs an investigation plan using dynamic SecOps search queries and Google Threat Intelligence enrichment of domains, URLs and hashes. An investigation takes about 60 s, with a 20-minute maximum and hourly quotas. — [Google SecOps docs](https://docs.cloud.google.com/chronicle/docs/secops/triage-agent)
- **Microsoft Security Copilot agents (announced March 2025).** These include a Phishing Triage Agent in Defender that separates real phishing from false positives, explains its verdicts in natural language and adapts to admin feedback. — [Microsoft Security blog](https://www.microsoft.com/en-us/security/blog/2025/03/24/microsoft-unveils-microsoft-security-copilot-agents-and-new-protections-for-ai/); [Help Net Security](https://www.helpnetsecurity.com/2025/03/25/microsoft-security-copilot-agents/)
- **CrowdStrike Charlotte AI Detection Triage (Feb 2025).** CrowdStrike says it reaches over 98% triage accuracy under "customer-defined bounded autonomy" and saves more than 40 analyst hours per week. These are vendor-reported figures with no independent verification found. The training data is CrowdStrike's proprietary Falcon Complete analyst triage decisions. — [CrowdStrike press release](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-next-breakthrough-in-ai-powered-agentic-cybersecurity-with-charlotte-ai-detection-triage/)

**Framework (LangGraph)**
- LangGraph's `interrupt()` pauses a graph at any point inside node code and saves state through a checkpointer. Execution resumes with `Command(resume=...)` on the same `thread_id`. The documented patterns cover approve/reject routing, review-and-edit, and interrupts inside tools. Because the node re-runs from its start on resume, side effects placed before `interrupt()` must be idempotent. — [LangGraph interrupts docs](https://docs.langchain.com/oss/python/langgraph/interrupts)

### Inferences
- The project matches the "fixed staged pipeline" family (like CORTEX's stages) more than the "LLM controller/ReAct" family (IDS-Agent, the Google root agent). Its Detection agent does not use tools, retrieve evidence or query external context. That is the biggest architectural gap compared with the 2025 state of the art.
- Using LangGraph `interrupt()` for the Governance approval step would match the documented HITL pattern, if the project does not already do so.

### Gaps
- No peer-reviewed head-to-head comparison of LangGraph, AutoGen and CrewAI for SOC use cases was found.
- Results for arXiv:2412.00652 and full details of arXiv:2505.04843 were not verified beyond snippets.

## Q2. Do strong systems pair a classical ML detector with an LLM? What evidence exists on LLMs classifying tabular flow features directly?

### Takeaway
Yes. The evidence strongly favours ML/DL detectors, especially boosted trees, for numeric flow classification. LLMs add value as orchestrators, explainers and report writers. Prompt-only LLMs on flow features are unreliable: they collapse to a single class without heavy prompt engineering, degrade as the evaluation set grows, and run one to two orders of magnitude slower. The project's "Gemini reads aggregate numeric features" design is the approach the literature finds weakest.

### Cited Findings
- **"From Flows to Words" (Rehman et al., arXiv:2510.17883, Oct 2025)** tested prompt-only LLMs on UNSW-NB15:
  - Mistral-7B zero-shot scored 0.09 accuracy and 0.08 macro-F1.
  - Qwen2.5-3B zero-shot scored 0.455 accuracy and 0.31 macro-F1.
  - The best setting, Qwen2.5-7B with guided prompts plus boolean flags, scored 0.785 accuracy and 0.78 macro-F1, but only on N=200.
  - At N=2,000 with calibration, positive-class F1 was 0.69, with recall 1.00 and precision 0.53.
  - Baselines: XGBoost (balanced) 0.953 accuracy and F1(+) 0.947; Linear SVM 0.933; Random Forest 0.871.

  — [arXiv:2510.17883](https://arxiv.org/html/2510.17883v2)
- The same paper makes three further points:
  - Zero-shot prompting "often collapses to a single class".
  - Performance falls as the number of evaluated flows grows, which the authors attribute to prompt sensitivity and weak numeric reasoning.
  - LLM throughput was hundreds to a few thousand items per hour, one to two orders of magnitude slower than tabular baselines. The authors recommend hybrid designs.

  — [arXiv:2510.17883](https://arxiv.org/html/2510.17883v2)
- A fine-tuned T5 model that converts numeric flow features into an "artificial language" reported more than 99.94% accuracy, precision, recall and F-score on CIC-IDS-2017. This is a fine-tuned result, not zero-shot (snippet). — [Univ. Cádiz repository](https://rodin.uca.es/refworks/handle/10498/38738)
- On CSE-CIC-IDS2018, AutoGluon ensembles reached up to 98.1% accuracy and TabNet 97.8%. LLMs were used only to generate explanations of the predictions (thesis, snippet). — [Univ. Turku thesis](https://www.utupub.fi/items/0e3e29c5-2d56-4c53-a96e-b157ecbad473/full)
- Several hybrid designs follow the pattern "ML detects, LLM explains/acts":
  - IDS-Agent calls ML classifiers as tools ([NeurIPS 2024](https://neurips.cc/virtual/2024/100920)).
  - The SJSU system feeds RF/XGBoost/MLP + SHAP into a ReAct report agent ([SJSU](https://scholarworks.sjsu.edu/faculty_rsca/7038)).
  - HuntGPT pairs RF + SHAP/LIME with GPT-3.5 ([arXiv:2309.16021](https://arxiv.org/pdf/2309.16021)).
- The Yang et al. survey says conventional ML/DL NIDS "lack contextual awareness and explainability". It positions LLMs as processor, detector, explainer and controller layered over them. — [arXiv:2507.04752](https://arxiv.org/abs/2507.04752)

### Inferences
- A strong, defensible upgrade for the project would be a Random Forest or XGBoost per-flow (or per-window) classifier trained on CIC-IDS2018 as the detector. Gemini would then explain the ML verdict and its SHAP top features and map it to ATT&CK, rather than classifying raw aggregates. The current rule fallback (score ≥ 0.75) effectively plays the role of a weak deterministic detector.
- Window-level aggregate features with no labels are an even harder input for an LLM than per-flow features with flags. Expect results at or below the "From Flows to Words" numbers unless the LLM is given engineered boolean flags or calibrated thresholds.

### Gaps
- No published zero-shot LLM accuracy figure specifically on CIC-IDS2018 flow features was found. The closest is UNSW-NB15.
- No Gemini-specific benchmark on tabular NIDS data was found.

## Q3. Which agent roles appear beyond Monitoring, Detection, Risk, Response and Governance?

### Takeaway
Recurring extra roles are an orchestrator/router, evidence acquisition through SIEM queries, CTI/threat-intel enrichment, MITRE ATT&CK mapping through RAG, memory and knowledge retrieval, report writing, and a feedback loop that learns from analyst corrections.

### Cited Findings
- **Orchestrator / router.** CORTEX has an Orchestrator plus a Behavior Analysis router ([arXiv:2510.00311](https://arxiv.org/html/2510.00311v1)). Google's design has a root SOC-manager agent with a runbook-criteria loop ([Google Cloud](https://docs.cloud.google.com/architecture/agentic-ai-orchestrate-security-ops-workflows)).
- **Evidence acquisition / Tier-1 enrichment.** CORTEX's Evidence Acquisition Agents query user, asset and behaviour records ([arXiv:2510.00311](https://arxiv.org/html/2510.00311v1)). Google's Tier-1 sub-agent pulls alert details, assets and user context ([Google Cloud](https://docs.cloud.google.com/architecture/agentic-ai-orchestrate-security-ops-workflows)).
- **CTI researcher / threat-intel enrichment.** Google's design correlates IOCs with threat actors and TTPs ([Google Cloud](https://docs.cloud.google.com/architecture/agentic-ai-orchestrate-security-ops-workflows)). The SecOps triage agent enriches domains, URLs and hashes from Google Threat Intelligence ([Google SecOps docs](https://docs.cloud.google.com/chronicle/docs/secops/triage-agent)).
- **MITRE ATT&CK mapping with RAG.**
  - A 2026 paper maps eBPF kernel-telemetry graphs to ATT&CK and compares pure prompting with RAG over technique descriptions. It cites RAG as a way to reduce hallucination without fine-tuning (snippet). — [arXiv:2609.12841](https://arxiv.org/pdf/2609.12841)
  - In a forensic RAG system, an ablation found that LLMs without RAG context identified victim hosts but missed all attack infrastructure, including C2 and malicious domains (snippet). — [arXiv:2603.18196](https://arxiv.org/abs/2603.18196)
  - On 200 CloudTrail events, Gemini 2.5 Pro with RAG scored about 78% accuracy and 79% F1, against about 46% accuracy and 45% F1 without RAG. The authors call these estimates on a small dataset (snippet). — [BCU/CMC 2026](https://www.sciopen.com/article/10.32604/cmc.2026.077606)
  - A 2025 Twente thesis found that RAG-ATT&CK improved on the plain-LLM baseline for CTI-to-ATT&CK mapping but did not surpass state-of-the-art methods. — [Univ. Twente](https://essay.utwente.nl/essays/106511)
- **Memory / knowledge base.** IDS-Agent has a memory and knowledge-retrieval action ([NeurIPS 2024](https://neurips.cc/virtual/2024/100920)). Google's design uses a Memory Bank for cross-session context and a RAG store of runbooks and IR plans ([Google Cloud](https://docs.cloud.google.com/architecture/agentic-ai-orchestrate-security-ops-workflows)).
- **Feedback / learning from analysts.** In Microsoft's Phishing Triage Agent, a natural-language correction from an admin (for example "this sender is our training vendor") updates the agent's instructions for future reasoning ([Microsoft blog](https://www.microsoft.com/en-us/security/blog/2025/03/24/microsoft-unveils-microsoft-security-copilot-agents-and-new-protections-for-ai/); [efficientlyconnected](https://www.efficientlyconnected.com/breaking-free-from-hardcoded-security-microsoft-introduces-human-in-the-loop-ai-agents/)). CORTEX lists learning from analyst feedback as future work ([arXiv:2510.00311](https://arxiv.org/html/2510.00311v1)). Charlotte AI is trained on millions of past analyst triage decisions ([CrowdStrike](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-next-breakthrough-in-ai-powered-agentic-cybersecurity-with-charlotte-ai-detection-triage/)).
- **Report / case writing.** CORTEX's final agent writes structured reports with observables and evidence links ([arXiv:2510.00311](https://arxiv.org/html/2510.00311v1)). Google's agents post to the SOAR case wall ([Google Cloud](https://docs.cloud.google.com/architecture/agentic-ai-orchestrate-security-ops-workflows)).
- **Queue prioritisation.** In Microsoft's RCT, about 79–84% of the productivity gain came from the agent reordering the queue ("resolve-benign"), not from its explanations. — [arXiv:2511.13860](https://arxiv.org/html/2511.13860v1)

### Inferences
- The roles most worth adding to the project are ATT&CK mapping (a RAG lookup over technique descriptions keyed by attack type) and analyst-feedback memory (storing approve/reject decisions from Governance and feeding them back into Detection or Risk prompts). Both are cheap to add in LangGraph. The project's "correlation bonus for repeated attack types" is a rudimentary form of memory.

### Gaps
- No quantitative ablation was found that isolates the value of a separate "Risk scoring agent" against folding risk into detection.

## Q4. How do these systems handle response: recommendation only or SOAR execution, human approval, rollback?

### Takeaway
Industry is moving to "bounded autonomy". Low-risk dispositions are automated, such as auto-closing benign alerts or tagging incidents, while containment generally stays behind human approval or customer-defined policy. Most academic systems, like the project, only recommend or report. No source found documents explicit automated rollback.

### Cited Findings
- CrowdStrike lets security teams "define when and how AI-driven and automated actions occur — from triage to final response" (bounded autonomy). — [CrowdStrike](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-next-breakthrough-in-ai-powered-agentic-cybersecurity-with-charlotte-ai-detection-triage/)
- Microsoft's Phishing Triage Agent uses a "resolve-benign" protocol: the agent resolves emails it judges non-malicious, and analysts make the final call only on flagged ones ([arXiv:2511.13860](https://arxiv.org/html/2511.13860v1)). Secondary sources disagree on how much approval is needed. One says actions are tagged for human review; another says false positives are auto-resolved ([Help Net Security](https://www.helpnetsecurity.com/2025/03/25/microsoft-security-copilot-agents/); [efficientlyconnected](https://www.efficientlyconnected.com/breaking-free-from-hardcoded-security-microsoft-introduces-human-in-the-loop-ai-agents/)).
- In Microsoft's RCT (167 professional analysts, Oct/Nov 2025), analysts who saw agent verdicts had mean F1 of 0.93 against 0.53 for the control group. They found about 6.5 times as many true positives per analyst minute, or about 3.1 times under a pessimistic 80%-accurate-agent counterfactual. Analysts were not more likely to rubber-stamp agent-flagged malicious items, but they did agree more with agent "benign" verdicts. The author is from Microsoft. — [arXiv:2511.13860](https://arxiv.org/html/2511.13860v1)
- Google's reference architecture recommends that supervisors be able to "approve, override, or pause" agent actions. It does not specify response execution in detail. — [Google Cloud](https://docs.cloud.google.com/architecture/agentic-ai-orchestrate-security-ops-workflows)
- CORTEX writes incident records through `updateIncidentRecord` and uses a conservative escalation policy. It treats human oversight and A/B testing as future work. — [arXiv:2510.00311](https://arxiv.org/html/2510.00311v1)
- LangGraph provides approve/reject and edit patterns through `interrupt()` and `Command(resume=...)` with durable checkpointing. The graph can wait indefinitely for a human decision. — [LangGraph docs](https://docs.langchain.com/oss/python/langgraph/interrupts)

### Inferences
- The project's "recommend, never execute" design plus its policy-gated human approval (HIGH/CRITICAL, confidence < 80, or rule-based) is more conservative than the vendor products. It is consistent with academic practice and with the bounded-autonomy principle.
- A natural extension would be a tiered policy: auto-close low-risk benign windows (the "resolve-benign" pattern, which drove most of the RCT's productivity gain) and require approval for containment.
- The SHA-256 hash-chained audit trail is a governance feature that none of the reviewed papers describe explicitly. CORTEX only emphasises "auditable reports". This could be presented as a differentiator.

### Gaps
- No source found describes automated rollback or undo of SOAR containment actions taken by an LLM agent.
- Primary Microsoft documentation of the exact approval gates was not retrieved.

## Q5. What are the known weaknesses: hallucination, prompt injection through attacker-controlled data, latency and cost, non-determinism?

### Takeaway
Prompt injection through attacker-controlled telemetry fields is now a well-documented 2026 attack class against LLM SOC agents. No tested model or guardrail is fully robust. Multi-agent pipelines multiply latency and token cost by roughly 3–6×. LLMs are weak at numeric reasoning. Grounding through tools and RAG is the main hallucination mitigation.

### Cited Findings
**Prompt injection** (findings from abstracts and snippets)
- **"Poisoning the Watchtower" (Pandey & Bhujang, arXiv:2605.24421, 2026)** defines "log-substrate prompt injection" with four classes: direct override, persona hijack, context manipulation and obfuscated payloads. It evaluates 48 strategy × defence × task combinations with gpt-4o-mini as the analyst. Its example is an attacker appending reclassification text to a malicious request that will be logged anyway. — [arXiv:2605.24421](https://arxiv.org/pdf/2605.24421)
- **LogJack (arXiv:2604.15368, 2026)** tests 42 payloads in cloud logs against 8 models from 7 providers. Log formatting defeated all the input-side guardrail detection tested. — [arXiv:2604.15368](https://arxiv.org/pdf/2604.15368)
- **"Evaluating the Robustness of LLM Cybersecurity Agents to Adversarial Telemetry" (NeurIPS 2026 listing)** used more than 1,100 payloads across 5 model configurations. Injection caused verdict downgrades in every configuration. Larger and "thinking" models were not consistently more robust, and extra read-only telemetry did not reliably neutralise the attack. — [NeurIPS 2026](https://neurips.cc/virtual/2026/168153)
- **Context Contamination / LogInject (Karanjai et al., arXiv:2607.14493)** describes "passive" injection, where payloads persist in storage and fire later when an analyst queries the LLM. — [alphaXiv](https://www.alphaxiv.org/abs/2607.14493)
- CORTEX acknowledges sensitivity to prompt injection and incomplete tool context ([arXiv:2510.00311](https://arxiv.org/html/2510.00311v1)). Google's reference architecture uses Model Armor to sanitise prompts, tool calls and responses, plus per-agent least-privilege identities ([Google Cloud](https://docs.cloud.google.com/architecture/agentic-ai-orchestrate-security-ops-workflows)).

**Latency and cost**
- CORTEX's median latency is 152.4 s per alert, against 44.6 s for a single tool-using agent and 28 s for prompt-only. It uses about 23,600 tokens per alert against 4,152, and 3.1 tool calls against 1.3. — [arXiv:2510.00311](https://arxiv.org/html/2510.00311v1)
- Google's SecOps triage agent takes about 60 s per investigation (20-minute maximum) and is quota-limited per hour. — [Google SecOps docs](https://docs.cloud.google.com/chronicle/docs/secops/triage-agent)
- Batched LLM flow classification handles hundreds to a few thousand items per hour, one to two orders of magnitude slower than tabular models. — [arXiv:2510.17883](https://arxiv.org/html/2510.17883v2)

**Hallucination and grounding**
- CORTEX requires agents to ground claims in tool outputs and attach evidence links, but it does not measure hallucination directly ([arXiv:2510.00311](https://arxiv.org/html/2510.00311v1)). RAG over ATT&CK descriptions is used to reduce hallucination ([arXiv:2609.12841](https://arxiv.org/pdf/2609.12841)).

**Non-determinism and instability**
- Zero-shot LLM classifiers can collapse to one class and become less stable as the evaluation set grows. The mitigations used are grammar-constrained JSON output and threshold calibration. — [arXiv:2510.17883](https://arxiv.org/html/2510.17883v2)
- Drammeh claims multi-agent orchestration gives "deterministic" decision quality, but the evidence is from one scenario with a 1B model. — [arXiv:2511.15755](https://arxiv.org/html/2511.15755v2)

**Vendor claims**
- Vendor accuracy figures, such as Charlotte AI's 98%, are self-reported with undisclosed methodology. — [CrowdStrike](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-next-breakthrough-in-ai-powered-agentic-cybersecurity-with-charlotte-ai-detection-triage/)

### Inferences
- The project's Detection agent reads only numeric aggregate CICFlowMeter features, not free-text fields such as payloads, URLs or user agents. That makes its prompt-injection surface much smaller than the log-reading SOC agents attacked above. This is worth stating as a design property. It would stop being true if raw payloads, hostnames or log strings were added to prompts.
- The rule-based fallback plus mandatory human approval for rule-based and low-confidence decisions is a reasonable hedge against LLM non-determinism and outages. Fixing temperature at 0 and validating JSON against a schema would align with the "grammar-constrained" mitigation in arXiv:2510.17883.
- Per-window LLM calls (one Gemini call for Detection and one for Response per 100-flow window) are cheaper than CORTEX-style multi-agent investigation. They are still far slower than an ML classifier, so the throughput limit should be reported in the evaluation.

### Gaps
- Full results and mitigation evaluations of the 2026 prompt-injection papers were seen only through abstracts and snippets.
- No study was found that quantifies run-to-run variance (non-determinism) of LLM IDS verdicts at temperature 0 against higher temperatures.
- No independent benchmark of Gemini-in-Security, Security Copilot or Charlotte AI detection accuracy was found.
