# Raising attack-family classification accuracy of a small local LLM (Ollama, CPU, 15 GB RAM)

Context for the report writer: AEGIS currently gets 54% correct on 68 caught attacks with qwen2.5:3b (format "json", temperature 0). A plain kNN majority vote over the 5 retrieved incidents gets 62%, and Gemini flash-lite gets 7%. Ollama also produced 19 schema failures in another mode. The notes below compare that setup against published evidence.

## Which small open models (<=8B, Ollama-available) suit classification over tabular numbers, and what do tabular-LLM benchmarks show?

### Takeaway
No benchmark I found ranks Ollama-sized models specifically on numeric-feature attack typing. The evidence that exists says three things. Qwen3 4B/8B base models match or beat the next-larger Qwen2.5 on most benchmarks. LLMs on tabular data compete with tree models mainly in the very-few-shot regime. A fine-tuned 1B LLM on network flows only matches a Random Forest. So changing the model is a secondary lever compared with integration design.

### Cited Findings
- Qwen3 report: "Qwen3-8B / 4B / 1.7B-Base models even outperform larger size Qwen2.5-14B / 7B / 3B Base models on over half of the benchmarks, especially on STEM-related and coding benchmarks". This is a base-model comparison, not instruct/thinking. — [Qwen3 Technical Report](https://arxiv.org/pdf/2505.09388)
- Ollama tags and download sizes: qwen3:1.7b 1.4 GB, qwen3:4b 2.5 GB (256K context), qwen3:8b 5.2 GB (40K context), qwen3:14b 9.3 GB. All of 4b/8b fit in 15 GB RAM. — [Ollama library: qwen3](https://ollama.com/library/qwen3)
- Qwen3 runs in "thinking" and "non-thinking" modes. Ollama's `think` parameter (`true`/`false`/named level) controls this on supported models (qwen3, deepseek-r1, gpt-oss). Reasoning comes back separately in `message.thinking`, and the answer in `message.content`. — [Ollama docs: Thinking](https://docs.ollama.com/capabilities/thinking)
- Third-party aggregator figures for Qwen2.5-7B-Instruct vs Qwen3-4B: MMLU-Pro 36.5 vs 58.6, GPQA 5.5 vs 39.8. These are unverified and may mix variants, so use with caution. — [pricepertoken comparison](https://pricepertoken.com/compare/qwen-qwen-2.5-7b-instruct-vs-qwen-qwen3-4b)
- One anecdotal local Ollama test on Windows found Qwen3 4B gave the same outcome as Qwen2.5 7B with ~2.27x faster cold start. The author says it is not a general ranking. — [Product Hunt write-up](https://www.producthunt.com/p/linguapilot-ai/qwen2-5-7b-vs-qwen3-4b-8b-writing-coach-benchmark-with-ollama-on-windows)
- TabLLM (AISTATS 2023) serialises each row to natural language plus a task description. It compared templates, table-to-text models and LLM serialisers. It is "competitive with strong traditional baselines like gradient-boosted trees, especially in the very-few-shot setting", and zero-shot is often non-trivial thanks to prior knowledge. — [TabLLM arXiv abstract](https://arxiv.org/abs/2210.10723); [PMLR](https://proceedings.mlr.press/v206/hegselmann23a.html)
- A follow-up proposes new serialisations, including a LaTeX table format, reported to improve domain-specific datasets. — [Towards Better Serialization of Tabular Data (arXiv 2312.12464)](https://arxiv.org/html/2312.12464v1)
- LLMTabBench/TabLens (2026, 91 datasets) reports four findings:
  - Below a data-complexity threshold, zero-shot matches about 16 labelled examples. Above it, the advantage vanishes.
  - Few-shot examples can conflict with the model's prior knowledge and degrade results.
  - Richer prompts reduce the number of demonstrations needed only when they include both real column names and a plain-language task description. Giving only one can be worse than neither.
  - Log-probability label scoring is cheaper and loses almost no accuracy "except for the smallest models".
  — [LLMTabBench arXiv 2605.24417](https://arxiv.org/abs/2605.24417)
- Retrieval-augmented tabular ICL (2025) exists because serialised rows use many tokens. It uses a retrieval module, with kNN-style retrieval as an ablation baseline, evaluated on 29 classification datasets against tuned tabular models. — [arXiv 2502.03147](https://arxiv.org/html/2502.03147v1)
- IoT attack detection with lightweight decoder-only LLMs (structured-to-text, QLoRA, RAG; CICIoT2023): QLoRA-tuned LLaMA-1B reaches F1 0.7124 vs Random Forest 0.7159 on known attacks. RAG gives 42.63% accuracy on unseen attack types without retraining. — [arXiv 2601.15269](https://arxiv.org/abs/2601.15269)
- A study of GPT-2, GPT-Neo-125M and LLaMA-3.2-1B as flow classifiers on CIC IoT 2023, compared with XGBoost/RF/MLP etc., notes that general LLMs may not be optimised for structured classification such as flow analysis. The final numbers were not visible in what I retrieved. — [Springer AI Review 10.1007/s10462-025-11432-2](https://link.springer.com/10.1007/s10462-025-11432-2)
- ICL for intrusion detection (9 DDoS types, 84 features) used GPT-3.5 and GPT-4 only. LLaMA-2-7B was excluded from ICL as "better suited to fine-tuning". GPT-4 with 10 examples exceeded 95% accuracy/F1. — [Zhang et al., arXiv 2405.11002](https://arxiv.org/html/2405.11002v1)

### Inferences
- Moving from qwen2.5:3b to qwen3:4b (non-thinking, `think:false`) or qwen3:8b is a cheap, plausible upgrade that fits in RAM. Expect 8B to roughly double latency on CPU; this is an inference, not measured. Benchmark both on the same 68 cases. No published study predicts the gain on this task.
- The published results point one way: fine-tuned 1B LLM ≈ Random Forest, and ICL success came with GPT-4-class models. A 3B model zero/few-shot is unlikely to beat a well-built classical classifier on ~14 numeric aggregates. The LLM's comparative advantage is the explanation, not the label.
- LLMTabBench's "column names + task description" result supports keeping the family guide and descriptive feature names in the prompt. The guide should be precise, because a vague guide can hurt.

### Gaps
- I found no benchmark of phi-4-mini, gemma3, llama3.2 or mistral specifically on numeric tabular classification. The TabLens abstract does not name its models. I could not extract the full TabLLM PDF (binary), so which serialisation won is not confirmed here.

## Which prompting techniques have evidence for small models?

### Takeaway
The best-supported changes are concrete. Enforce a JSON schema with an enum (this removes schema failures). Score labels via logprobs instead of free generation. Order and balance the retrieved exemplars to fight majority/recency bias. Skip chain-of-thought for this non-mathematical classification. CoT and strict formats mainly matter for math/logic. Constrained JSON tends to help classification while hurting reasoning.

### Cited Findings
- **Structured outputs.** Ollama `format` accepts `"json"` or a full JSON Schema object. A schema "constrain[s] a model's output to a specific format defined by a JSON schema". Tips:
  - Use temperature 0.
  - Build the schema with Pydantic/Zod.
  - Also include the schema as a string in the prompt to ground the response.
  - It works via the OpenAI-compatible `response_format`.
  - It is not supported on Ollama cloud.
  — [Ollama docs: Structured outputs](https://docs.ollama.com/capabilities/structured-outputs); [Ollama blog, Dec 6 2024](https://ollama.com/blog/structured-outputs)
- The structured-outputs docs do not discuss field ordering or reliability guarantees. Enum handling is only shown through Pydantic `Literal` types. — [Ollama docs: Structured outputs](https://docs.ollama.com/capabilities/structured-outputs)
- **Format restrictions.** "Let Me Speak Freely?" (EMNLP 2024 Industry) finds a significant decline in reasoning under format restrictions, larger for stricter formats. However, JSON-mode constrained decoding "can hinder reasoning abilities while enhancing classification task accuracy". Looser formats or NL-then-convert help reasoning tasks. Parsing errors are not the main cause and can be fixed by corrective prompting. — [Tam et al., arXiv 2408.02442](https://arxiv.org/html/2408.02442v3)
- **Chain-of-thought.** A meta-analysis of 100+ papers plus 20 datasets × 14 models finds CoT helps "primarily on tasks involving math or logic, with much smaller gains on other types of tasks". On MMLU, direct answering ≈ CoT unless an equals sign or symbolic operation is involved. CoT can be applied selectively to save cost. — [Sprague et al., ICLR 2025, arXiv 2409.12183](https://arxiv.org/abs/2409.12183)
- **Few-shot exemplar selection.** Results depend heavily on which in-context examples are chosen. kNN retrieval of examples by embedding similarity (KATE) consistently beats random selection, and task-tuned encoders help further. — [Liu et al., arXiv 2101.06804](https://arxiv.org/pdf/2101.06804)
- **Biases in few-shot prompts.** Majority-label bias favours labels frequent in the demos, recency bias favours labels near the end of the prompt, and common-token bias favours tokens frequent in pre-training. Example order alone moved a sentiment task from 54% to 93%. Contextual calibration fixes this without training data: measure the output on a content-free input such as "N/A" and rescale to uniform. It gave up to +30 points absolute on GPT-2/3, and also lowers variance. — [Zhao et al., ICML 2021, arXiv 2102.09690](https://arxiv.org/pdf/2102.09690)
- **ICL style in NIDS.** For GPT-3.5, the weaker model:
  - "Heuristic" prompting (the model's own answers to questions such as "what do malicious examples have in common") did poorly with 2 examples.
  - More examples did not always help.
  - "Interactive" self-reflection raised F1 but over-flagged benign traffic.
  
  Plain "illustrative" labelled cases were the most cost-effective for strong models. — [Zhang et al., arXiv 2405.11002](https://arxiv.org/html/2405.11002v1)
- **Label scoring via logprobs.** Ollama added logprobs to its native and OpenAI-compatible APIs in v0.12.11 (late 2025). It is enabled with `"logprobs": true`, and docs list classification as a use case. The source is a release-notes mirror; check the official release page. — [newreleases.io mirror of Ollama v0.12.11](https://newreleases.io/project/github/ollama/ollama/release/v0.12.11-rc1)
- Log-probability scoring of candidate labels loses almost no accuracy vs generation except for the smallest models. — [LLMTabBench arXiv 2605.24417](https://arxiv.org/abs/2605.24417)
- The IFIP SEC 2026 Qwen2.5-0.5B flow classifier scores the fixed labels ("benign"/"attack") rather than generating free text, and uses a calibrated bias term for the decision. — [FAU CS7 IFIP SEC 2026 post](https://www.cs7.tf.fau.eu/2026/06/15/ifip-sec-conference-2026/)
- **Verbalised probabilities.** For RLHF chat models (ChatGPT, GPT-4, Claude), verbalised confidence was better calibrated than token probabilities, cutting ECE by ~50% relative on QA datasets. Asking the model to consider alternatives first reduced overconfidence further. The study used large models on factual QA, not small models. — [Tian et al., EMNLP 2023, arXiv 2305.14975](https://arxiv.org/pdf/2305.14975)

### Inferences (concrete changes for AEGIS)
1. **Replace `format:"json"` with a JSON Schema.** Set `attack_type` to `{"enum": [...families..., "unknown"]}` and `severity_hint` to an enum, and list all fields as `required`. Repeat the schema text in the prompt. This should eliminate the 19 schema failures. Keep a validate-and-retry once as a fallback.
2. **Decouple label from explanation.** Either (a) get the label by logprob scoring of each enum value, or with one short constrained call, then generate the explanation in a second call conditioned on the chosen label; or (b) keep one call but put a short `evidence` field before `attack_type` in the schema. Sprague et al. suggest (b)'s reasoning will not raise accuracy much here. (a) also gives a probability vector usable for gating and calibration.
3. **Present neighbours as real few-shot exemplars, not just "family + distance".** Show each neighbour's feature vector (same serialisation as the query) and its label (KATE-style). Order them most-similar-last only if you want recency to favour the nearest. Otherwise randomise or put the nearest first. Consider including at least one exemplar of each runner-up family so majority-label bias does not simply echo the vote.
4. **Serialisation.** Use descriptive feature names and units, round to 2–3 significant figures, and keep the family guide crisp and family-discriminative. LLMTabBench found names plus task description must come together. Avoid giving 14 aggregates without telling the model which matter: keep the "top-3 deviations in IQR units" line.
5. **Contextual calibration.** Run the prompt with a content-free window (all features "N/A") once per prompt template. Divide the label probabilities by that prior. This is cheap with logprobs and directly counters the model's default-family bias.
6. **Self-consistency.** I found no direct small-model evidence for this task. With temperature 0 and deterministic decoding it is pointless. It would multiply CPU latency (~2 s × N) for uncertain gains.

### Gaps
- I found no study that measures CoT vs direct answering specifically for <=4B models on tabular classification. No published evidence covered self-consistency on small local models for classification either; the original self-consistency paper was not retrieved. Exact logprob semantics in `/api/chat` (vs `/api/generate`) for multi-token labels were not verified in official docs.

## Should the LLM override retrieval, and how should gating work?

### Takeaway
On current numbers (LLM 54% < kNN 62%) the LLM should not be the final decider. The cascade literature says the standard rule, the cheap model's own confidence (Chow's rule), is "remarkably hard to surpass". So let kNN decide when its vote is confident. Defer to the LLM, restricted to the kNN candidate families, only when the vote is split. Otherwise use the LLM only for explanation.

### Cited Findings
- In cascades the small model handles "easy" instances and defers "hard" ones. For classification the standard deferral rule is the small model's softmax confidence (Chow's rule), which is "remarkably hard to surpass in most natural settings". For generative LLMs, naive sequence probability tends to defer long outputs, and length normalisation over-corrects. — [Gupta et al., Language Model Cascades, ICLR 2024, arXiv 2404.10136](https://arxiv.org/html/2404.10136v1)
- Conformal cascades reportedly give a superior or comparable cost-accuracy frontier vs Agreement/Entropy heuristics on MMLU. This is a secondary summary only. — [alphaXiv overview 2607.25018](https://www.alphaxiv.org/overview/2607.25018)
- RAG with a lightweight LLM gave 42.63% on unseen attack types, which is the scenario where retrieval labels are absent or misleading. On known attacks, the fine-tuned LLM only tied RF. — [arXiv 2601.15269](https://arxiv.org/abs/2601.15269)
- Few-shot demos can conflict with the model's priors and degrade results. — [LLMTabBench arXiv 2605.24417](https://arxiv.org/abs/2605.24417)
- The best flow-IDS setup combined LoRA with ICL: Qwen2.5-0.5B reached 91% accuracy and 90% macro-F1 (binary, CIC-DDoS2019). Zero-shot was near chance. — [FAU CS7 IFIP SEC 2026 post](https://www.cs7.tf.fau.eu/2026/06/15/ifip-sec-conference-2026/)

### Inferences (gating designs to test)
- **G1, kNN-first cascade.** If the top family has ≥4/5 votes, or a distance-weighted vote margin is above a threshold tuned on held-out days, accept kNN. Otherwise call the LLM. Log both answers.
- **G2, LLM as reranker.** On deferral, constrain the schema enum to the families present among the k neighbours, plus "unknown". This stops the LLM from inventing families retrieval never saw, which is a plausible cause of Gemini's 7%. Combine as `score = α·kNN_weighted_vote + (1-α)·LLM_logprob`, with α tuned on held-out days.
- **G3, abstain.** If kNN is split and the LLM's top probability is low, output "unknown / needs analyst". Measure the abstention rate and accuracy-on-answered.
- **G4, explanation-only LLM.** Keep kNN (or a trained classifier) as the label source and have the LLM explain the given label against the feature evidence. This guarantees accuracy ≥ kNN baseline while keeping the XAI value.
- Increasing k beyond 5 (e.g. 7–15 with distance weighting) is worth testing for the kNN itself. That is not evidenced here, so it remains an inference.

### Gaps
- I found no paper that directly compares "LLM as classifier" vs "LLM as reranker of kNN candidates" for intrusion detection. The design above is extrapolated from the cascade and ICL literature.

## Which fine-tuning options are feasible on CPU or free Colab, and what gains can be expected?

### Takeaway
LoRA/QLoRA on 0.5–1B models is what published NIDS work uses. It gets to about Random-Forest level (F1 0.71 vs 0.716) or high binary accuracy when combined with ICL. A small classical classifier on the same numeric features is the cheaper, CPU-native option and likely matches it.

### Cited Findings
- QLoRA-tuned LLaMA-1B on CICIoT2023 reached F1 0.7124 vs RF 0.7159, framed as suitable for "constrained hardware". Hardware and epoch details are not in the abstract. — [arXiv 2601.15269](https://arxiv.org/abs/2601.15269)
- Qwen2.5-0.5B-Instruct with LoRA (frozen base) plus ICL reached 91% accuracy / 90% macro-F1. Zero-shot was near chance, and LoRA-only and ICL-only each improved on zero-shot (exact numbers not given). — [FAU CS7 IFIP SEC 2026 post](https://www.cs7.tf.fau.eu/2026/06/15/ifip-sec-conference-2026/)
- TabLLM fine-tunes the LLM on the few labelled examples in its few-shot setting. — [TabLLM](https://proceedings.mlr.press/v206/hegselmann23a.html)
- LLaMA-2-7B was judged better suited to fine-tuning than ICL for NIDS. — [arXiv 2405.11002](https://arxiv.org/html/2405.11002v1)
- RF needs retraining to detect unseen/zero-day threats, while RAG avoids that. — [arXiv 2601.15269](https://arxiv.org/abs/2601.15269)

### Inferences
- Path A (CPU, minutes): train RF/XGBoost/logistic regression on the same ~14 window aggregates with per-family labels. Use leave-one-day-out CV to match "neighbours from other days". Use it as the label source or as an extra voter.
- Path B (free Colab T4): LoRA-tune qwen2.5:0.5b/1.5b or llama3.2:1b on serialised windows → family label. Export to GGUF and import to Ollama via a Modelfile. Expect at best parity with Path A. The published gains are against zero-shot, not against trees.
- With only 68 attack windows, any fine-tune risks overfitting. Day-held-out evaluation is mandatory.

### Gaps
- I found no CPU-only LoRA training times or Colab memory figures in the retrieved sources. The GGUF/Modelfile import steps were not verified from Ollama docs in this pass.

## How should accuracy be evaluated fairly?

### Takeaway
Report per-family precision, recall and F1, macro-F1, and a confusion matrix. Report accuracy on answered cases alongside the abstention rate. Compare every LLM variant against the kNN and trained-classifier baselines on the same 68 cases, held out by day. Macro-F1 is the metric used by the NIDS LLM papers.

### Cited Findings
- Macro-F1 is the headline metric in the Qwen2.5-0.5B flow-IDS work (90%). — [FAU CS7 IFIP SEC 2026 post](https://www.cs7.tf.fau.eu/2026/06/15/ifip-sec-conference-2026/)
- The ICL NIDS paper reports both accuracy and F1, and shows they diverge: interactive prompting gave higher F1 but lower accuracy because it over-flagged benign traffic. — [arXiv 2405.11002](https://arxiv.org/html/2405.11002v1)
- Separate evaluation of known vs unseen attack types (F1 0.71 known; 42.63% unseen) is standard in the lightweight-LLM IDS work. — [arXiv 2601.15269](https://arxiv.org/abs/2601.15269)
- Prompt and exemplar order can swing accuracy from 54% to 93%, so variance across prompt permutations should be reported. — [Zhao et al., arXiv 2102.09690](https://arxiv.org/pdf/2102.09690)

### Inferences
- On n=68, a 95% binomial interval around 54% is about ±12 points (1.96·√(0.54·0.46/68) ≈ 0.118). So 54% vs 62% is not clearly different. Use a paired test such as McNemar on the same 68 cases, and/or bootstrap CIs, before claiming improvement.
- Report the "schema-failure rate" as its own metric, and count failures as wrong or abstained rather than dropping them.
- Report a per-family table including support counts. Rare families dominate macro-F1.
- Report a risk–coverage curve for the gating threshold (accuracy vs % deferred or abstained).
- Fix the exemplar order or report mean±sd over a few permutations.

### Gaps
- I retrieved no source on CPU latency per model size in Ollama. The latency/accuracy trade-off for qwen3:4b/8b on this laptop must be measured locally.
