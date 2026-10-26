# Cybersecurity Governance and Digital Trust Requirements for Agentic AI in Security Operations

Note on sourcing: the claims below come from pages fetched or search-returned on 2026-10-26. Where a claim relies on a secondary or vendor summary rather than the primary text, that is stated. Items marked "(not re-fetched)" are cited to the primary document but were not opened this session, so the report writer should treat them as lower confidence.

## 1. What the frameworks and standards require or recommend (NIST AI RMF / AI 600-1, CSF 2.0 Govern, ISO/IEC 42001, EU AI Act, OWASP LLM Top 10 2025, OWASP Agentic Top 10, MITRE ATLAS, NCSC/CISA)

### Takeaway
All the major frameworks agree on the same core: assign accountable roles, keep humans able to understand, override and stop the system, log events automatically across the lifecycle, give agents as little agency as possible, and treat external content as untrusted. AEGIS-GOV-1 ("recommend-only, gated review, hash-chained audit") fits these ideas well. Its main gaps against them are identity and accountability (no authentication), the strength of the logging integrity, a stop/kill control, and supply-chain and third-party (Gemini) governance.

### Cited Findings
**NIST AI RMF 1.0 and Generative AI Profile**
- AI RMF 1.0 was released 26 Jan 2023, and NIST AI 600-1 (Generative AI Profile) on 26 Jul 2024. The RMF is being revised under the White House AI Action Plan. On 7 Apr 2026 NIST released a concept note for an AI RMF Profile on Trustworthy AI in Critical Infrastructure — [NIST AI RMF page](https://www.nist.gov/itl/ai-risk-management-framework)
- The RMF's core functions are Govern, Map, Measure and Manage — [NIST AI RMF page](https://www.nist.gov/itl/ai-risk-management-framework)
- The trustworthiness characteristics are: valid and reliable; safe; secure and resilient; accountable and transparent; explainable and interpretable; privacy-enhanced; and fair with harmful bias managed — [NIST AI 100-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf) (not re-fetched)
- AI 600-1 names 12 risks that are unique to generative AI or made worse by it. Its suggested actions carry GV/MP/MS/MG IDs. Secondary summaries say it stresses provenance, traceability, documentation and monitoring. They also warn that logs can expose sensitive prompts, so access to provenance records needs controls — [Anaconda summary](https://www.anaconda.com/blog/nist-ai-600-1-generative-ai-profile-guide); [AIGL summary](https://www.aigl.blog/artificial-intelligence-risk-management-framework-generative-artificial-intelligence-profile/); draft text: [NIST AI 600-1 IPD](https://airc.nist.gov/docs/NIST.AI.600-1.GenAI-Profile.ipd.pdf). I could not confirm specific action IDs for logging or provenance.

**NIST CSF 2.0 Govern function**
- Govern is new in CSF 2.0. It has six categories: Organizational Context (GV.OC), Risk Management Strategy (GV.RM), Roles, Responsibilities and Authorities (GV.RR), Policy (GV.PO), Oversight (GV.OV) and Cybersecurity Supply Chain Risk Management (GV.SC). Supply-chain risk management moved there from ID.SC — [Safe Security](https://safe.security/resources/insights/nist-cybersecurity-framework/); [NIST CSF FAQ](https://nist.gov/cyberframework/faqs)
- How these apply to the project (my mapping): AEGIS-GOV-1 is a GV.PO artefact. Analyst approve/reject is GV.RR/GV.OV. Gemini as an external model provider falls under GV.SC.

**ISO/IEC 42001:2023**
- Annex A control A.6.2.8, "AI system recording of event logs", requires the organisation to "determine at which phases of the AI system life cycle event log recording is enabled". Consultancy guidance suggests logging decision rationale and human overrides — [ISMS.online](https://www.isms.online/iso-42001/annex-a-controls/a-6-ai-system-life-cycle/a-6-2-8-ai-system-recording-of-event-logs/); [Cyberday](https://www.cyberday.ai/requirement/iso-42001-a-6-2-8-ai-system-recording-of-event-logs); [Thamer James](https://thamerjames.co.uk/2025/04/08/iso42001-ai-system-event-logs-building-trust-through-accountability/). These are vendor and consultancy sources; the standard itself is paywalled.

**EU AI Act**
- Article 12 requires that high-risk AI systems "technically allow for the automatic recording of events (logs) over the lifetime of the system" — [Mishcon de Reya Art. 12](https://www.mishcon.com/eu-uk-ai-navigator/article-12)
- Article 14(1) requires that high-risk systems can be "effectively overseen by natural persons", including through human-machine interface tools. Article 14(3) makes oversight proportionate to "risks, level of autonomy and context of use" — [artificialintelligenceact.eu Art. 14](https://artificialintelligenceact.eu/article/14/)
- Under Article 14(4), overseers must be able to:
  - (a) understand the system's capacities and limits and detect anomalies;
  - (b) stay aware of "automation bias";
  - (c) correctly interpret the output;
  - (d) decide not to use the output, or disregard, override or reverse it;
  - (e) intervene or halt the system via a "'stop' button or a similar procedure" that brings it "to a halt in a safe state".
  - Source: [artificialintelligenceact.eu Art. 14](https://artificialintelligenceact.eu/article/14/)
- Timing: the AI Omnibus, Regulation (EU) 2026/1744, was published in the OJ on 24 Jul 2026 and took effect on 27 Jul 2026. It defers Annex III high-risk obligations to 2 Dec 2027 and Annex I to 2 Aug 2028. Prohibited-practice and GPAI obligations are unchanged — [Mondaq](https://www.mondaq.com/eu-digital-omnibus-on-ai-enters-into-force/1825722); [NatLawReview](https://natlawreview.com/article/eu-digital-omnibus-ai-enters-force); the dates match the Art. 14 page above. I did not check EUR-Lex directly.
- Whether a SOC threat-detection tool is "high-risk" is not settled. Annex III covers critical infrastructure, and commentators list it among the deferred categories — [secureprivacy.ai](https://secureprivacy.ai/blog/eu-ai-act-digital-omnibus-the-new-high-risk-ai-deadlines-after-council-approval). A generic enterprise SOC tool may fall outside it. Articles 12 and 14 are still the best benchmark of good practice.

**OWASP Top 10 for LLM Applications 2025**
- LLM01 Prompt Injection lists these mitigations: constrain model behaviour; define and validate expected output formats; filter inputs and outputs; enforce privilege control and least privilege; require human approval for high-risk actions; segregate and identify external content; run adversarial testing — [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- LLM06 Excessive Agency has three root causes: excessive functionality, excessive permissions and excessive autonomy. Its mitigations are:
  - minimise extensions and their functions;
  - avoid open-ended tools;
  - minimise permissions;
  - human-in-the-loop approval for high-impact actions;
  - "complete mediation" (enforce authorisation downstream, not by trusting the LLM).
  - Logging, monitoring and rate limiting are listed as damage-limiting controls, not preventive ones.
  - Source: [OWASP LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)

**OWASP Top 10 for Agentic Applications (2026)**
- It was published on 9 Dec 2025 by the OWASP GenAI Security Project with 100+ contributors, and uses categories ASI01–ASI10 — [OWASP GenAI](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026); [Modulos](https://docs.modulos.ai/frameworks/owasp-top-10-agentic)
- The categories and their key mitigations below come from a secondary summary, because the OWASP page only links a download — [Teleport](https://goteleport.com/blog/owasp-top-10-agentic-applications):
  - ASI01 Agent Goal Hijack: treat external content as untrusted; human approval for goal-changing actions.
  - ASI02 Tool Misuse: least agency; validate arguments; confirm destructive actions.
  - ASI03 Identity and Privilege Abuse: unique, bounded agent identities; short-lived credentials.
  - ASI04 Agentic Supply Chain: sign and verify components; SBOM/AIBOM; pin dependencies; kill switches.
  - ASI05 Unexpected Code Execution.
  - ASI06 Memory and Context Poisoning.
  - ASI07 Insecure Inter-Agent Communication: signed messages; schema validation.
  - ASI08 Cascading Failures: circuit breakers; tamper-evident logs; replay testing.
  - ASI09 Human-Agent Trust Exploitation: confirmations for high-impact actions; immutable logs of suggestions; trust cues in the UI.
  - ASI10 Rogue Agents: watchdogs; kill switches; signed audit logs.

**MITRE ATLAS**
- AML.T0051 LLM Prompt Injection has three sub-techniques: .000 Direct, .001 Indirect (payload embedded in data the model later retrieves) and .002 Triggered. It is rated "Realized", meaning it has been used in the wild — [startupdefense AML.T0051](https://www.startupdefense.io/mitre-atlas-techniques/aml-t0051-llm-prompt-injection); [Indirect](https://www.startupdefense.io/mitre-atlas-techniques/aml-t0051-001-indirect). These are third-party catalogues; verify against [atlas.mitre.org](https://atlas.mitre.org).

**NCSC/CISA Guidelines for Secure AI System Development**
- Published 27 Nov 2023 (v1.0). It covers four lifecycle areas: secure design (threat modelling), secure development (supply chain, documentation, asset and technical-debt management), secure deployment (protect models from compromise, incident management, responsible release), and secure operation and maintenance (logging and monitoring, update management, information sharing) — [NCSC](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### Inferences
- AEGIS-GOV-1's "recommend, never auto-execute" approach directly addresses LLM06 excessive autonomy and Art. 14(4)(d). AUTO_APPROVED should be documented as "approved recommendation", not execution, so nobody reads it as autonomous action.
- Missing against the frameworks:
  - an explicit stop/kill control (Art. 14(4)(e); ASI04/ASI10);
  - authenticated operator identity (GV.RR; ASI03; Art. 14 assumes assigned, competent natural persons);
  - a documented supply-chain record for the Gemini model and version (GV.SC; ASI04);
  - UI support for avoiding automation bias, such as showing confidence, rule-fallback status and limitations next to each recommendation (Art. 14(4)(a)–(c); ASI09 "trust cues").
- A good report artefact would be a mapping table of AEGIS controls to NIST AI RMF function, CSF GV category, ISO 42001 A.6.2.8, AI Act Art. 12/14, and OWASP LLM01/LLM06/ASI.

### Gaps
- I could not access the primary OWASP Agentic Top 10 PDF; the ASI names and mitigations come from a vendor summary.
- No specific NIST AI 600-1 action IDs on logging or provenance were confirmed.
- I found no current ATLAS IDs for data poisoning or evasion this session.
- The ISO 42001 human-oversight control number was not confirmed.
- No authoritative ruling on whether SOC tools are AI Act high-risk.

## 2. Human-in-the-loop / on-the-loop patterns, levels of autonomy, approval thresholds, confidence calibration

### Takeaway
Recent literature describes SOC autonomy as graded levels, from manual to fully autonomous, with human roles shifting from in-the-loop (approve each action) to on-the-loop (set boundaries and supervise). Thresholds are set per task by risk and complexity. AEGIS's severity/confidence/fallback gate is a sensible "Level 2–3" design. Its 80-confidence threshold needs calibration evidence, because uncalibrated confidence scores do not justify trust.

### Cited Findings
- Mohsin, Janicke, Ibrahim, Sarker and Camtepe ("A Unified Framework for Human AI Collaboration in SOCs with Trusted Autonomy", ACM TOIT, July 2026) define five autonomy levels, from manual to fully autonomous. Each level maps to a HITL role, and trust thresholds are task-specific and calibrated to task complexity and risk. The paper covers monitoring, triage and incident response, and evaluates an LLM "AI-Avatar" in a cyber range — [arXiv 2505.23397](https://arxiv.org/abs/2505.23397)
- The same work, per search summary, describes three modes: human-in-control; human-on-the-loop (AI runs predefined tasks, analysts monitor and intervene on complex cases); and human-out-of-the-loop. It warns that too much human involvement creates bottlenecks and too little lets errors go unnoticed — [arXiv 2505.23397 PDF](https://arxiv.org/pdf/2505.23397)
- A six-level cyber autonomy scale (Level 0 to 5) is adapted from SAE J3016. It treats the ability to adapt to changing conditions as what separates autonomy from automation — [arXiv 2508.13588](https://arxiv.org/pdf/2508.13588). Mayoral-Vilches argues current "autonomous" pentest tools sit at Levels 3–4 — [arXiv 2506.23592](https://arxiv.org/html/2506.23592v1)
- Level 2 means the human approves each action (in the loop). Level 3 means the human sets boundaries in advance and supervises (on the loop) — [arXiv 2607.03215](https://arxiv.org/pdf/2607.03215) (search summary only)
- An MIT thesis builds human-in, on and out-of-the-loop interfaces on the CybORG simulator — [DSpace@MIT](https://dspace.mit.edu/handle/1721.1/162449)
- Autonomy can be measured from observable behaviour, specifically how far a human can interact with or interdict the system — [arXiv 2407.14975](https://arxiv.org/pdf/2407.14975)
- Regulatory and framework support for these patterns:
  - The AI Act makes oversight proportional to "level of autonomy" and requires awareness of automation bias — [Art. 14](https://artificialintelligenceact.eu/article/14/)
  - OWASP recommends human approval for high-impact actions, plus rate limits as a damage limiter — [LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)

### Inferences
- AEGIS sits at roughly Level 2 for high-impact cases (in-the-loop approval) and Level 3 for low-impact, high-confidence cases (on-the-loop via auto-approval with audit). Since nothing auto-executes, it never reaches Level 4/5.
- Confidence calibration: to defend the cut-off of 80, measure reliability (expected calibration error or a reliability diagram) on held-out data. Report the false-auto-approve rate, meaning CRITICAL attacks that ended up AUTO_APPROVED, and the analyst override rate. Treat LLM self-reported confidence as uncalibrated unless measured.
- Further controls worth adding:
  - two-person approval for CRITICAL;
  - a reviewer SLA and escalation;
  - mandatory rationale notes on reject or override (already present);
  - periodic sampling of AUTO_APPROVED decisions for after-the-fact review (on-the-loop oversight);
  - a global "pause autonomy" switch.

### Gaps
- I found no standard numeric threshold, such as a confidence cut-off, prescribed by any framework. Thresholds are left to the organisation's risk appetite (GV.RM).
- The five levels in arXiv 2505.23397 were not individually extracted.

## 3. Audit trail best practice: hash chains vs signatures / Merkle trees / append-only logs, limitations, anchoring, keys, operator authentication, non-repudiation

### Takeaway
A plain SHA-256 hash chain is tamper-evident only against partial edits. An attacker who can rewrite the whole file can recompute every hash, and nothing in a bare chain detects truncation of the most recent entries. Established designs add one or more of: secret or signing keys (MAC/signature with forward-secure key evolution), external anchoring or witnessing of the head hash, and Merkle trees with consistency proofs. None of these delivers non-repudiation of analyst approvals without authenticated operator identities.

### Cited Findings
- Schneier and Kelsey (1999, ACM TISSEC) designed logs so that entries written before a machine is compromised cannot be read or altered undetectably by the attacker. Each entry's hash chains from the previous value and the new entry, and the logger signs the latest value — [Schneier](https://www.schneier.com/paper-auditlogs.html); [Wallach handout](https://handouts.secappdev.org/handouts/2016/Dan%20Wallach/tamper-evident-structures.pdf)
- "Forward integrity" (Bellare and Yee) means the log is tamper-evident up to an unknown compromise point and untrusted after it — [Wallach handout](https://handouts.secappdev.org/handouts/2016/Dan%20Wallach/tamper-evident-structures.pdf)
- Crosby and Wallach (USENIX Security 2009) proposed history trees with logarithmic-cost membership and consistency proofs, where auditors check commitments rather than trust the logger. They reported more than 1,750 inserts per second — [USENIX slides](https://static.usenix.org/events/sec09/tech/slides/crosby.pdf)
- Limits of the classic schemes:
  - The Schneier-Kelsey and Bellare-Yee schemes do not defend against tail truncation and need a trusted verifier — [DBSec 2008](https://dl.ifip.org/index.html/db/conf/dbsec/dbsec2008/MaT08.pdf)
  - Public-key schemes are costly, and symmetric (MAC) schemes lack public verifiability — [Yavuz et al., TISSEC 2012](https://cse.usf.edu/~attilaayavuz/article/0613/TISSEC2012.pdf)
- RFC 9162 (Certificate Transparency v2) uses Merkle trees so each log can efficiently prove it is a superset of an earlier version (append-only), with signed tree heads and consistency proofs. However, a misbehaving log can show different views to different clients ("split view"), so the log must be treated as a trusted third party unless views are gossiped or witnessed — [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html)
- OWASP's agentic guidance explicitly calls for tamper-evident (ASI08), immutable (ASI09) and signed (ASI10) audit logs — [Teleport summary](https://goteleport.com/blog/owasp-top-10-agentic-applications)
- Article 12 requires logs to be recorded automatically by the system over its lifetime. One commentary argues Article 14 oversight cannot be shown without them; that is an interpretation — [Mishcon Art. 12](https://www.mishcon.com/eu-uk-ai-navigator/article-12); [Weilliptic blog](https://weilliptic.ai/blog/eu-ai-act-where-provenance-once-urged-now-decreed/)

### Inferences
- AEGIS's hash chain plus verify endpoint detects editing a middle record, but **not**:
  - (i) wholesale recomputation by anyone with write access to the file;
  - (ii) deletion of the last N records;
  - (iii) substitution of the verifier.
- Upgrade path, cheapest first:
  1. HMAC each entry with a key held outside the log store, or sign entries or periodic checkpoints with Ed25519 (the private key kept separate from the app host, ideally in an HSM or KMS).
  2. Periodically publish or "anchor" the head hash and sequence number somewhere the attacker cannot rewrite: a separate append-only store or WORM bucket, an email or ticket to a second party, an RFC 3161 timestamping authority, or a transparency log such as Sigstore Rekor.
  3. Store a monotonic sequence number and count in each signed checkpoint to detect truncation.
  4. Optionally move to a Merkle tree for efficient inclusion and consistency proofs.
  5. Use forward-secure key evolution if host compromise is in scope.
- Non-repudiation: today "sign in with name and role, no authentication" means any user can claim any identity. Approvals therefore cannot be attributed, and the audit chain only proves what was written, not who did it. Minimum fix: real authentication (OIDC/SSO or at least passwords plus MFA) and server-side role-based access control, so only the "analyst" role can approve. Record the authenticated subject ID in each review entry. Stronger: have the analyst's client sign the approval. Also separate duties so whoever operates the log cannot approve.
- RFC 3161 and Sigstore Rekor are suggested from general knowledge; I did not fetch sources for them this session.

### Gaps
- I did not fetch NIST SP 800-92 (log management) or SP 800-53 AU-family text (e.g., AU-9 protection of audit information, AU-10 non-repudiation). The report writer should cite them only if verified separately.

## 4. Explainability requirements and recording model version, prompts and inputs for reproducibility

### Takeaway
Regulators frame explainability in terms of oversight. Humans must be able to understand limitations, interpret outputs, and resist automation bias. Lifecycle logging standards expect enough context (inputs, model, decision rationale, overrides) to reconstruct decisions. Exact LLM reproducibility is not guaranteed, so record everything needed to replay or audit, not to promise identical regeneration.

### Cited Findings
- Art. 14(4)(a)–(c) requires that overseers can understand capacities and limitations, are aware of automation bias, and can "correctly interpret" output using available interpretation tools — [Art. 14](https://artificialintelligenceact.eu/article/14/)
- NIST lists "explainable and interpretable" and "accountable and transparent" among the trustworthiness characteristics — [NIST AI 100-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf) (not re-fetched)
- AI 600-1 emphasises traceability and documentation of content lifecycle decisions, and access control on logs because prompts may be sensitive — [AIGL summary](https://www.aigl.blog/artificial-intelligence-risk-management-framework-generative-artificial-intelligence-profile/); [Anaconda](https://www.anaconda.com/blog/nist-ai-600-1-generative-ai-profile-guide)
- For ISO 42001 A.6.2.8, guidance suggests logs cover training through deployment and real-time inference, including decision rationale and human overrides — [ISMS.online](https://www.isms.online/iso-42001/annex-a-controls/a-6-ai-system-life-cycle/a-6-2-8-ai-system-recording-of-event-logs/); [Sprinto](https://sprinto.com/hub/iso-42001-drift-monitoring/)
- OWASP ASI08 recommends replay testing in a cloned environment, and ASI06 recommends rollback of memory and context — [Teleport](https://goteleport.com/blog/owasp-top-10-agentic-applications)
- NCSC/CISA secure development includes documentation and asset management of models — [NCSC](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### Inferences
- Each decision record should capture:
  - the exact Gemini model ID and version string returned by the API (not just "gemini");
  - generation parameters (temperature, top-p, seed if supported);
  - a hash of the system prompt and template version;
  - a hash of, or the actual, input feature vector;
  - the raw model output plus the parsed and validated output;
  - which schema version was validated and whether validation passed or fell back;
  - detector model version and hash; policy version (AEGIS-GOV-1 revision);
  - latency, timestamp, and the reviewer and outcome.
- AEGIS already records the Gemini-vs-rule-fallback flag, which is a strong control for transparency about decision provenance.
- Explanations shown to analysts should be grounded: cite the specific features or thresholds that drove the decision, separate from the free-text rationale the LLM generates.
- LLM-generated rationales can be unfaithful, meaning they don't reflect what actually drove the output. Present them as "model rationale", not ground truth. I found no source this session, so this is an inference.

### Gaps
- I found no authoritative standard prescribing specific LLM log fields (model version, prompt hash) for security tools. The list above is an inference from the frameworks' traceability goals.

## 5. Prompt-injection and data-poisoning risk when LLMs reason over attacker-influenced network data; mitigations

### Takeaway
Network and log data is attacker-controlled, and 2025–26 research shows log-borne prompt injection against SOC LLMs succeeds at high rates; no defence eliminates it. NCSC says prompt injection may never be fully mitigated, so designs should limit impact. AEGIS's label-free aggregate numeric features, recommend-only actions and human gate are exactly the impact-limiting controls guidance recommends. Strict output schemas, action allow-lists and deterministic downstream authorisation should complete the set.

### Cited Findings
- NCSC, "Prompt injection is not SQL injection (it may be worse)", 8 Dec 2025: current LLMs "do not enforce a security boundary between instructions and data inside a prompt". The model is an "inherently confusable deputy". Organisations should focus on reducing impact rather than expecting a full fix, and detection or instruction-hierarchy training alone is doubted — [NCSC blog](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection); [Computer Weekly](https://www.computerweekly.com/news/366636155/NCSC-warns-of-confusion-over-true-nature-of-AI-prompt-injection); [Security Boulevard](https://securityboulevard.com/2025/12/prompt-injection-cant-be-fully-mitigated-ncsc-says-reduce-impact-instead/) (based on press coverage and excerpts, not the full post)
- "Poisoning the Watchtower" (Pandey and Bhujang, arXiv 2605.24421, May 2026):
  - It defines "log-substrate prompt injection": attacker-written log fields carry instructions to an analyst LLM.
  - It uses a four-class taxonomy (direct override, persona hijack, context manipulation, obfuscated payloads) and tests 48 combinations on gpt-4o-mini.
  - Summarisation was the riskiest task, and defences reduced but did not eliminate success.
  - Source: [arXiv 2605.24421](https://arxiv.org/pdf/2605.24421)
- "Context Contamination in LLM Analysis of Network Security Logs" (arXiv 2607.14493, Jul 2026) studies passive injection, where payloads persist in log storage and fire later. Its LogInject-1.0 benchmark has 12,847 entries. It reports attack success up to 88.2% at baseline, and a "Context Stitching" technique that splits payloads across entries to evade filters — [arXiv 2607.14493](https://arxiv.org/abs/2607.14493). Results differ from 2605.24421; I did not verify the methodology.
- SecureCAI lists log contamination (a fake SYSTEM directive in an error log line) among six attack classes on LLM-assisted security operations — [arXiv 2601.07835](https://arxiv.org/pdf/2601.07835)
- MITRE ATLAS AML.T0051.001 Indirect Prompt Injection covers payloads embedded in data the model retrieves — [startupdefense](https://www.startupdefense.io/mitre-atlas-techniques/aml-t0051-001-indirect)
- The OWASP LLM01 mitigations apply directly:
  - constrain behaviour;
  - define and validate output formats;
  - filter inputs and outputs;
  - least privilege;
  - human approval for high-risk actions;
  - segregate and identify external content;
  - adversarial testing.
  - Source: [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- OWASP LLM06 "complete mediation" means enforcing authorisation downstream rather than trusting the LLM — [OWASP LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- OWASP ASI01/ASI02/ASI06 call for treating external instructions as untrusted, validating tool arguments, and validating or segmenting memory writes — [Teleport](https://goteleport.com/blog/owasp-top-10-agentic-applications)

### Inferences
- AEGIS's design of feeding only label-free numeric aggregates (no raw payloads, hostnames, URIs or user-agent strings) greatly shrinks the injection surface. It is a strong argument in the report. Residual risks:
  - any string-valued feature (protocol or service names, top-talker IPs, alert text) re-opens the channel, so keep features numeric or enumerated;
  - an attacker can still shape traffic to manipulate numeric features. That is adversarial evasion or poisoning of the detector, not prompt injection.
- Recommended controls:
  - Gemini structured output (a response schema) plus server-side JSON-schema validation;
  - an enumerated allow-list of response actions, with any unknown action leading to rule fallback and PENDING_REVIEW;
  - LLM severity can only raise and never lower the detector/rule severity (a "monotonic escalation" guard);
  - deterministic policy evaluation outside the LLM (AEGIS-GOV-1 is already code);
  - clearly delimit data in prompts;
  - output length caps;
  - an injection red-team test set, for example strings in any text fields, tracked as a metric.
- Data poisoning: if the detector is retrained on traffic, guard the training data's provenance and keep a held-out clean evaluation set. I did not confirm the ATLAS poisoning IDs.

### Gaps
- I did not retrieve ATLAS technique IDs for training-data poisoning or evasion.
- I did not read the full papers above, so their quantitative results come from abstracts and summaries.

## 6. Privacy and data minimisation when sending network data to a third-party LLM API

### Takeaway
Gemini's terms differ sharply by tier. On unpaid tiers, Google may use prompts and responses to improve products, human reviewers may read them, and Google says not to submit sensitive, confidential or personal information. Paid tiers exclude training use but still log prompts for a limited period for abuse monitoring, possibly in any country. Sending only aggregated, label-free, de-identified features is the key minimisation control.

### Cited Findings
- Gemini API, unpaid services: Google uses content and responses "to provide, improve, and develop Google products and services and machine learning technologies". Human reviewers may read and annotate them after disconnecting them from the account. The terms say: "Do not submit sensitive, confidential, or personal information to the Unpaid Services" — [Gemini API Additional Terms](https://ai.google.dev/gemini-api/terms)
- Gemini API, paid services: prompts and responses are not used to improve products, and processing falls under the Data Processing Addendum. Prompts and responses are logged "for a limited period of time" for policy enforcement, safety and legal purposes, and may be stored in any country where Google has facilities — [Gemini API Additional Terms](https://ai.google.dev/gemini-api/terms)
- AI 600-1 commentary notes that logs and provenance records can expose sensitive prompts and need access controls — [AIGL summary](https://www.aigl.blog/artificial-intelligence-risk-management-framework-generative-artificial-intelligence-profile/)
- CSF 2.0 GV.SC treats third-party providers as supply-chain risk to govern — [Safe Security](https://safe.security/resources/insights/nist-cybersecurity-framework/)
- GDPR Art. 5(1)(c) data minimisation ("adequate, relevant and limited to what is necessary") applies where IP addresses or other identifiers are personal data — [gdpr-info.eu Art. 5](https://gdpr-info.eu/art-5-gdpr/) (not re-fetched)

### Inferences
- For a student or demo project on the free tier, the terms effectively forbid sending real network data containing IPs or identifiers. AEGIS's aggregate-only features are the right design and should be stated as a privacy control.
- Further controls:
  - document a data-flow diagram and data inventory of exactly which fields leave the boundary;
  - pseudonymise or HMAC any identifiers before egress;
  - use a paid tier, or a Vertex AI region-pinned endpoint, for any real deployment;
  - store the Gemini API key in a secrets manager, not in code;
  - add a configuration flag to run fully offline (rule-only) where egress is not allowed;
  - record in the audit log a hash of exactly what was sent;
  - a DPIA for production use.
- Vertex AI regional pinning is from general knowledge and not verified this session.

### Gaps
- I did not verify the exact retention period for paid-tier abuse logging; the terms page says only "limited period".
- I did not check whether Gemini API zero-data-retention options exist.
- I did not fetch ENISA guidance on AI cybersecurity this session.
