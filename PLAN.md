# RAG-IDS plan

**Status on 5 October 2026.** Milestones 1–7 are built and run on this machine (Arch Linux, Python 3.14.7, CPU only), with your real API keys. The evaluation results are in section 11.

Milestone 8 (CICIoT2023) is planned only, as the brief asked.

This file replaces an earlier PLAN.md written by another agent on a different computer (a Mac). Section 1 lists what was wrong with that version and what changed.

---

## 1. Review of the earlier work

The earlier agent wrote a plan and most of the code. Its dataset findings were right: I re-ran them and got identical numbers. Many other things were wrong. Six of them would have quietly corrupted the main result.

| # | Problem found | Effect | Fixed by |
|---|---|---|---|
| 1 | `eval/questions.json` pointed at the wrong samples. In 37 of 45 questions, the sample ID did not have the label the question claimed. For example, Q01 said `sample_00007` is `DOS_SYN_Hping`; it is `Wipro_bulb`. | The evaluation would have asked about the wrong traffic. | New file made by `eval/make_questions.py`, which reads the real data. |
| 2 | When the judge's output could not be parsed, the code **invented** a `NOT_IN_EVIDENCE` claim and saved it permanently. | Every judge failure would have added a fake hallucination. | Failures are logged and retried next run; nothing is invented. |
| 3 | If Gemini failed, the judge switched to a Qwen model **halfway through a run** and stored its answer under the Gemini cache key. | Two different judges mixed in one result, with false labels. | One judge per run, chosen in `configs/llm.yaml`; the runner refuses to mix judges. |
| 4 | Conditions A and B were judged against a separate, newly retrieved reference, capped at 1,500 words. | A different reference from the one the brief specifies, and mapped entries could be cut. | The reference is identical for A and B: `[DET]` + every mapped entry + what B retrieved. |
| 5 | Condition B received a different detector block from condition A. | A confound: the two conditions differed in more than retrieval. | One `format_detection()` function used everywhere. |
| 6 | The fabricated-ID check counted IDs **copied from the question**, such as the fake `T9999.099` in a trap. It also called every CVE we hadn't downloaded "fabricated", called retired ATT&CK IDs fabricated, and could never classify a mitigation as correct. | Inflated and wrong fabricated-ID rates. | Rewritten (section 7, Measure 2). |
| 7 | The hand-written label cards and glossary contained false statements. `flow_duration` was said to be in microseconds; it is in seconds. ARP rows were described as "unsolicited ARP packets", but Zeek flows contain no ARP; the rows are DNS and SSL traffic. Tools were named that the dataset never mentions. | False "ground truth" in the knowledge base would mislead both the LLM and the judge. | Both files rewritten from measurements of the data (section 4). |
| 8 | When the NVD download failed, the code put three CVEs with **paraphrased, hand-written descriptions** into the knowledge base. | Made-up content inside a hallucination study. | Removed. Only real NVD records are used. |
| 9 | ATT&CK and CAPEC entries were **cut off** after about 300 words instead of split. CAPEC was read from a CSV whose columns were shifted by one. No attack family was stored on chunks. Mitigations were never retrieved. | Lost content and missing mitigations. | Entries are split into parts. CAPEC is read from the XML. Every chunk carries its family. Each technique's official mitigations are a chunk of their own. |
| 10 | The LLM client paused 1.2 s between calls, retried after only 3, 6 and 9 s, sent no `reasoning_effort`, and cached empty answers. Its cache key ignored temperature and other settings. | It would have hit Groq's 8,000 tokens/minute limit and failed. | Per-minute token budget, waits for the reset time Groq reports, `reasoning_effort: low`, empty answers never cached, every request parameter in the cache key. |
| 11 | The metrics page showed **hard-coded numbers** and had no evaluation charts. The evidence panel did not show the evidence the answer had actually used. | The demo could show numbers that don't match the results. | The page reads the result files. The evidence panel shows each answer's own evidence. |
| 12 | `detect()` and the app were fixed to RT-IoT2022. `requirements.txt` had no pinned versions. The plan said "no implementation code executed" although code existed, and used macOS paths. | The project could not take a second dataset, and the plan misdescribed the work. | `dataset` is a parameter everywhere. Versions are pinned (`==`) with a full lock file. This plan rewritten. |

**Found later, while running the evaluation (my own bug).** 54 of 220 answers wrote IDs with a non-breaking hyphen (`CAPEC‑163`, `CVE‑2019‑…`), which my first ID extractor skipped. That undercounted the IDs in the no-retrieval conditions (60 in condition A, not the 17 first reported). The extractor now treats every dash variant as `-`, and all numbers in section 11 are from after the fix.

Two of the earlier agent's decisions are reversed. Both were changes to your brief that it made without saying so:
- **De-duplication.** It recommended "Option A": split first, then remove duplicates from the training part only. That puts about 19,000 copies of `DOS_SYN_Hping` training rows into the test set, which is exactly the leakage your brief told us to prevent. I kept your rule: remove duplicates **before** splitting.
- **Judge model.** It replaced `gemini-3.8-flash` with the weaker `gemini-3.5-flash-lite` because the 3.8 calls "timed out". Gemini 3 Flash models think at level `high` by default, which is slow. Setting `reasoning_effort: low`, as Google's OpenAI-compatibility docs allow, should fix this. **Not yet verified**, because there are no keys here.

---

## 2. What is in the dataset (checked 5 October 2026)

| Expectation in the brief | Found | Verdict |
|---|---|---|
| 123,117 rows, 83 features, no missing values | 123,117 rows; 83 features + `Attack_type`; 0 missing values | ✅ |
| Extra unnamed row-number column in the zip CSV | Yes, `Unnamed: 0`; dropped | ✅ |
| `proto`, `service` are text; the rest numeric | `proto` has 3 values (tcp, udp, icmp). `service` has 10 (`-`, dns, mqtt, http, ssl, ntp, dhcp, irc, ssh, radius). Everything else is numeric. | ✅ |
| 12 labels with these spellings | Exactly those 12, including `ARP_poisioning`. Normal labels: `Thing_Speak`, `MQTT_Publish`, `Wipro_bulb`. | ✅ |
| `DOS_SYN_Hping` ≈ 94,700 (77%); normal ≈ 12,500 (10%); Metasploit 37; FIN 28 | 94,659 (76.9%); 12,507 (10.2%); 37; 28 | ✅ |
| Detector should score ≥ 99% | **No.** Test macro-F1 is **0.875** (see section 2.2) | ❌ see below |

### 2.1 Duplicates: the main surprise

`id.orig_p` is dropped first, as planned. After that, **99,278 of the 123,117 rows (80.6%) are exact copies** of another row.

| Label | Rows | After removing duplicates | Kept | Train | Test |
|---|---:|---:|---:|---:|---:|
| DOS_SYN_Hping | 94,659 | **57** | 0.1% | 46 | 11 |
| Thing_Speak | 8,108 | 7,602 | 93.8% | 6,081 | 1,521 |
| ARP_poisioning | 7,750 | 5,300 | 68.4% | 4,240 | 1,060 |
| MQTT_Publish | 4,146 | 4,141 | 99.9% | 3,313 | 828 |
| NMAP_UDP_SCAN | 2,590 | 1,151 | 44.4% | 921 | 230 |
| NMAP_XMAS_TREE_SCAN | 2,010 | 1,894 | 94.2% | 1,515 | 379 |
| NMAP_OS_DETECTION | 2,000 | 1,899 | 95.0% | 1,519 | 380 |
| NMAP_TCP_scan | 1,002 | 1,002 | 100% | 802 | 200 |
| DDOS_Slowloris | 534 | 533 | 99.8% | 426 | 107 |
| Wipro_bulb | 253 | 219 | 86.6% | 175 | 44 |
| Metasploit_Brute_Force_SSH | 37 | 36 | 97.3% | 29 | 7 |
| NMAP_FIN_SCAN | 28 | **5** | 17.9% | **4** | **1** |
| **Total** | 123,117 | 23,839 | 19.4% | 19,071 | 4,768 |

The Hping flood sends the same tiny packet over and over, with only the source port changing. Without that column, 94,602 rows are copies.

**`NMAP_FIN_SCAN` falls below the ~20-row threshold**: 5 unique rows, so 4 for training and 1 for testing. No method can create more independent examples from 5 rows. What I did, and what I recommend:
1. Keep the class; do not merge or delete it.
2. Quote its cross-validation result rather than its single test row, and say plainly that both are unreliable.
3. Use its one test row in the demo as a real example of the low-confidence warning. The detector calls it `ARP_poisioning` with 0.57 confidence, so the warning fires.

Alternatives if you or your examiner prefer:
- **Merge** all five Nmap scans into one "port scan" label. Scores go up, but you lose the exact label your brief asks for.
- **Drop the class** from the detector and report it separately.

### 2.2 Two more data findings

- **Some labels contain background traffic.**
  - 8 identical feature rows appear under two different labels (17 rows in all), so no model can get all of them right.
  - 3 of the 5 unique FIN-scan rows are DNS over UDP, which a TCP FIN scan cannot produce.
  - 9 of the 37 Metasploit rows are DNS or HTTP, not SSH.
  - The labels mark whole capture sessions, not individual flows.
- **Expected vs. real scores.** The 99% you expected comes from the duplicated data, where one easy class is 77% of the rows. On de-duplicated data:
  - Test macro-F1 is 0.875. Without the FIN class it is 0.955, so most of the gap is that one 5-row class.
  - Accuracy is 0.987.
  - The false alarm rate is 0.92% (22 of 2,393 normal flows called an attack).
  - I did **not** tune anything to chase 99%.

### 2.3 Detector results (milestone 2, done)

| Model (5-fold CV, training part only) | Macro-F1 (pooled out-of-fold) | Mean ± std over folds | Accuracy | Fit time per fold |
|---|---:|---:|---:|---:|
| Logistic Regression (scaled) | 0.814 | 0.815 ± 0.009 | 0.938 | 15.8 s |
| Random Forest (balanced) | 0.881 | 0.881 ± 0.006 | 0.984 | 0.8 s |
| **XGBoost (balanced weights) – used** | **0.888** | 0.888 ± 0.007 | 0.988 | 7.6 s |

Random Forest is not clearly better, so XGBoost stays, as planned.

"Pooled out-of-fold" means each training row is scored once by the model that did not see it, and all those predictions are scored together. This gives sensible per-class numbers for tiny classes, unlike averaging five per-fold scores. The rare classes, with test score and CV score side by side:

| Label | Test rows | Test F1 | CV rows | CV F1 |
|---|---:|---:|---:|---:|
| DOS_SYN_Hping | 11 | 1.000 | 46 | 0.967 |
| Metasploit_Brute_Force_SSH | 7 | 0.714 | 29 | 0.877 |
| NMAP_FIN_SCAN | 1 | 0.000 | 4 | 0.000 |

These numbers are noisy: one row changes the test F1 of the Metasploit class by about 0.14.

**Leakage check.** XGBoost retrained without any port column scores CV macro-F1 0.887, against 0.888 with the destination port (difference 0.002). So the model is not memorising port numbers. The check runs inside cross-validation, so the test set is still used only once.

---

## 3. LLM line-up (checked 5 October 2026 from the providers' public pages)

| Role | Model | Status | Free limits |
|---|---|---|---|
| Answering | `openai/gpt-oss-120b` (Groq) | Listed as a production model | 30 requests/min, 8,000 tokens/min, 1,000 requests/day, 200,000 tokens/day (Groq rate-limits page) |
| **Judge (used)** | `gemini-3.5-flash-lite` (Google) | Stable | **Your project:** 15 requests/min, 250,000 tokens/min, 500 requests/day |
| Judge in the brief (not used) | `gemini-3.8-flash` (Google) | Stable, newest Flash | **Your project:** 5 requests/min, 250,000 tokens/min, **20 requests/day** |
| Alternative judge (not used) | `qwen/qwen3.8-27b` (Groq) | Listed as a **preview** model | Same as gpt-oss-120b, counted separately |
| Second answering model (extra run) | `openai/gpt-oss-20b` (Groq) | Production | Same as gpt-oss-120b |

**Confirmed by `python -m src.check_llm` with your keys (5 October 2026):** every model above is listed for your keys and answered a test request. Groq reported 1,000 requests/day and 8,000 tokens/minute for both Groq models. Your Gemini limits come from your AI Studio page.

**Why the judge changed.** With the extras you approved, the evaluation needs about 220 judge calls (~1 million tokens):

| Candidate | Time for ~220 judge calls on your free plan |
|---|---|
| gemini-3.8-flash (20 requests/day) | about 11 days |
| qwen/qwen3.8-27b (200,000 tokens/day) | about 5 days, and it is a preview model that may be withdrawn |
| **gemini-3.5-flash-lite (500 requests/day, 15/min)** | **about 15 minutes** |

Your brief suggested a second Groq model in this situation. I chose Flash-Lite instead, because Qwen would take most of your remaining week. Flash-Lite still meets the real requirement: it is a different model, from a different company, than the one it judges. The human-agreement check (Measure 4) shows how far its labels can be trusted.

Notes:
- **Llama models:** Groq's public page still lists them, but your key's model list contains no general Llama model, only the Llama Prompt Guard models. Your brief was right.
- **Gemini 3 temperature.** Google strongly recommends keeping it at 1.0 and warns that lower values can cause looping. The judge therefore runs at 1.0, *not* the lowest value. Results are still repeatable because every judge response is cached and re-used. The answering model runs at 0.0.
- **Reasoning effort.** Low for both roles. gpt-oss reports its hidden reasoning separately, and those tokens count against your limits.
- **One judge per run.** The judge is set in one place (`judge_role` in `configs/llm.yaml`). The runner refuses to mix judges within a run.

---

## 4. Architecture

```
 test-set row ──► detect(sample) ──► [DET] block ─────────────┐
 (sample ID)      XGBoost +          label, family,            │
                  pred_contribs      confidence, top-3,        │
                                     5 features + meanings     ▼
                                                    ┌───────────────────────┐
 question ─────────────────────────────────────────►│ retrieve(question,det)│
                                                    │ 1 lookup by label     │◄── configs/attack_mapping.yaml
                                                    │ 2 semantic search     │◄── ChromaDB (bge-small embeddings)
                                                    └──────────┬────────────┘
                                                               ▼ ≤6 chunks, ≤~1,000 words, tagged by ID
                                             prompts.py ──► chat("answering") ──► answer with [tags]
                                                               │ (llm_client: pacing, retry, cache, log)
                       ┌───────────────────────────────────────┴─────────────────────────┐
                       ▼                                                                 ▼
             Streamlit app (app/)                                     eval/run_eval.py
             sidebar · detector card · chat ·                         A vs B answers → judge →
             evidence panel · metrics page                            claims, IDs, traps, kappa
```

| Component | File | Input → output |
|---|---|---|
| Data loader | `src/data_loader.py` | raw CSV → de-duplicated train/test parquet, test-pool index with stable `sample_#####` IDs, class-count table |
| Detector | `src/detector.py` | train/test → 3-model CV table, leakage check, final XGBoost, test metrics; `detect(sample, dataset)` → dict below |
| Knowledge-base builder | `src/kb_builder.py` | official downloads + 2 own files → `data/kb/chunks.json`, `id_registry.json`, `mapping_check.json`, ChromaDB |
| Retriever | `src/retriever.py` | question + detection → evidence chunks + `[DET]` text; `reference_chunks()` for the judge |
| LLM client | `src/llm_client.py` | role + messages → answer (paced, retried, cached, logged) |
| Prompts | `src/prompts.py` | every prompt, in one file |
| Assistant | `src/assistant.py` | question + sample ID → answer + evidence (fixed pipeline or tool calling) |
| Evaluation | `src/evaluation.py`, `eval/run_eval.py`, `eval/make_questions.py` | questions → answers → judgements → report files |
| App | `web/server.py` + `web/static/` (main demo); `app/` (earlier Streamlit version, kept as a fallback) | interactive demo |
| Key check | `src/check_llm.py` | keys → model lists + your rate-limit headers |

`detect()` returns `predicted_label`, `is_attack`, `attack_family` (looked up from the label), `confidence`, `top_3`, `low_confidence` (below 0.60), and `top_features`. `top_features` lists the 5 features with the largest push towards the predicted label, each with its actual value.

**Retrieval priority.** These four are always included, so the right technique is always in front of the LLM:
1. label card
2. primary CAPEC entry
3. primary ATT&CK technique
4. that technique's official ATT&CK mitigations

Then, while the 6-chunk / 1,000-word caps allow:

5. other mapped IDs
6. semantic-search hits for "question + label name"

**This is a small change from your brief.** The four "always" items never break the 6-chunk cap, but on their own they can go over ~1,000 words. Without this rule, long entries could push out the technique: `NMAP_TCP_scan` alone maps to a card, 3 CAPEC entries, 1 technique and its mitigations. In the check over all 12 labels, evidence was 470–970 words. `python -m src.retriever --check` confirms the mapped technique is present for all 12 labels.

**Tool-calling mode.**
- `run_detector(sample_id)` returns the same `[DET]` block.
- `search_knowledge(query)` uses the same retrieval, so once the detector has run the label lookup still applies.
- One call at a time, at most 4. After 4 calls the model is asked for its final answer.
- Any other error falls back to the fixed pipeline, and the reason is logged and shown in the app.

**Multiple datasets.** Each `configs/<name>.yaml` holds how to load the dataset, the label column, columns to drop, text columns, port columns and `label_to_family`. That file is the **single** source for families. Outputs go to `data/processed/<name>/`, `models/<name>/` and `eval/results/<name>/`. The app lists every dataset with a trained model. A label missing from `attack_mapping.yaml` logs a warning and uses semantic search.

---

## 5. Folders, files, libraries

```
configs/        rt_iot2022.yaml, ciciot2023.yaml (inactive), attack_mapping.yaml, llm.yaml,
                scenarios.yaml (how each label looks in the app: icon, story, animation)
data/raw/              rt_iot2022.csv (one local copy; git-ignored)
data/processed/<ds>/   train.parquet, test.parquet (ignored), test_samples_pool.json
data/kb_manual/        label_cards.yaml, feature_glossary.yaml (OUR text, not official)
data/kb_raw/           enterprise-attack.json, capec_latest.xml, nvd_cves.json, manifest.json (ignored)
data/kb/               chunks.json, id_registry.json (ignored); mapping_check.json, build_info.json,
                       kb_sources_manifest.json (versions + download dates, committed)
data/chroma_db/        vector store (ignored)
models/<ds>/           detector_xgboost.json, preprocessor.joblib (ignored)
src/                   config, data_loader, detector, kb_builder, retriever, llm_client, prompts,
                       assistant, evaluation, check_llm
eval/                  make_questions.py, questions.json, run_eval.py, results/<ds>/, plots/<ds>/
web/                   server.py (FastAPI: detector, retrieval, LLM -> JSON), static/ (index.html, style.css, app.js)
app/                   earlier Streamlit version: Home.py, ui.py, pages/2_Metrics.py (fallback)
.streamlit/config.toml  theme; file watcher off (restart the app after editing code)
cache/                 LLM response cache, call log, NVD lookups, llm_check.json (ignored)
```

Libraries (exact versions in `requirements.txt`; every package is pinned in `requirements-lock.txt`). All install on Python 3.14.7.

| Library | Why |
|---|---|
| pandas, pyarrow | tables and parquet files |
| ucimlrepo | downloads RT-IoT2022 (the zip is the fallback) |
| scikit-learn | split, cross-validation, Logistic Regression, Random Forest, metrics, Cohen's kappa |
| xgboost | the detector; `pred_contribs` gives per-prediction feature contributions |
| joblib | saves the preprocessor |
| matplotlib | confusion matrix and evaluation charts |
| torch (CPU build) + sentence-transformers | run the `BAAI/bge-small-en-v1.5` embedding model |
| chromadb | local vector store with metadata |
| openai | one client for Groq and Gemini |
| python-dotenv, pyyaml, requests | keys, configs, downloads |
| fastapi, uvicorn | the web server behind the demo app |
| streamlit | the earlier, simpler demo app (fallback) |

On Linux, plain PyPI installs the multi-GB CUDA build of PyTorch. `requirements.txt` therefore points pip at PyTorch's CPU index; no GPU is needed.

---

## 6. Milestones

| # | Milestone | Status | Command | Done when… |
|---|---|---|---|---|
| 1 | Setup + data | ✅ done | `python -m src.data_loader` | It prints the class-count table above and ends with "19,071 train / 4,768 test". |
| 2 | Detector | ✅ done | `python -m src.detector` (~4 min) | It prints the CV table, the leakage check, test macro-F1 0.875 and FAR 0.92%, and writes `models/rt_iot2022/`. |
| 3 | Knowledge base + retrieval | ✅ done | `python -m src.kb_builder` (~6 min first time), then `python -m src.retriever --check` | 2,318 chunks; every mapping row "active/stable/draft"; "ALL LABELS OK". |
| 4 | Fixed pipeline, command line | ✅ done (real API) | `python -m src.assistant --sample sample_00004 "How should I respond to this traffic?"` | It prints the `[DET]` block, the evidence IDs and an answer under ~200 words with `[tags]`. |
| 5 | Web app ("attack range") | ✅ done (checked in a real Chrome, light and dark, desktop and phone width) | `python -m web.server`, then open http://127.0.0.1:8000 | The armory shows 12 playbook cards and a mystery flow over an idle network. Launching one plays the attack on an animated network, the detector scope races to a verdict, and a stamp lands. The case file shows why and the mapped official references, and the analyst answers with clickable exhibit tags. *Compare both* shows memory vs. knowledge-base answers side by side. The Model results tab shows the tables and charts. |
| 6 | Evaluation | ✅ run (real APIs); hand-marking left to you | see section 7.6 | `eval/results/rt_iot2022/main/summary.csv` and `eval/plots/rt_iot2022/main/hallucination_rates.png` exist. |
| 7 | Tool calling | ✅ done (real API) | `python -m src.assistant --sample sample_00004 --mode tool "How should I respond?"` | It prints "Tool calls: run_detector … search_knowledge …" and an answer, or a clear "FELL BACK because …" line. |
| 8 | CICIoT2023 (optional) | 📝 planned | — | see below |

Remaining time estimate (one person):
- Keys and check: 20 min.
- Real runs of milestones 4 and 7: 30 min.
- Evaluation: half a day of mostly waiting, spread over 1–2 days because of the daily limits.
- Hand-marking (8 traps × 2, plus about 20 answers' claims): 1–2 hours.
- Report writing: your own.

**Milestone 8, CICIoT2023 (about 1 day if wanted):**
1. Download 3–5 of its CSV files by hand from the CIC page.
2. Write a short script that takes a stratified 200,000–300,000-row sample into `data/raw/ciciot2023_sample.csv`.
3. In `configs/ciciot2023.yaml`, check the label spellings and column names against the CSV, then rename `label_column_TODO` to `label_column`.
4. Add `attack_mapping.yaml` lines for its labels. Candidates (all exist in the current files; their fit still needs checking): Mirai → T1498 Network Denial of Service + T1583.005 Botnet; SqlInjection → CAPEC-66; XSS → CAPEC-63; CommandInjection → CAPEC-88; DNS_Spoofing → CAPEC-142.
5. Add label cards for its labels.
6. Run `python -m src.data_loader --dataset ciciot2023` and `python -m src.detector --dataset ciciot2023`. The app's dataset dropdown then picks it up.

No code changes are expected, apart from possibly the sampling script. CICIoT2023 has no port columns, so its leakage check is empty.

---

## 7. Evaluation design

### 7.1 Questions (`eval/questions.json`, 44 questions, fixed before any result)

For each label, the first test sample the detector classifies correctly:

| Label | Sample | Label | Sample |
|---|---|---|---|
| DOS_SYN_Hping | sample_00145 | NMAP_FIN_SCAN | sample_00677 (detector says ARP_poisioning, 0.57: **wrong**, there is no other test row) |
| DDOS_Slowloris | sample_00004 | NMAP_OS_DETECTION | sample_00003 |
| ARP_poisioning | sample_00011 | Metasploit_Brute_Force_SSH | sample_01027 |
| NMAP_TCP_scan | sample_00005 | Thing_Speak | sample_00000 |
| NMAP_UDP_SCAN | sample_00024 | MQTT_Publish | sample_00009 |
| NMAP_XMAS_TREE_SCAN | sample_00012 | Wipro_bulb | sample_00007 |

Three questions per sample (36 in all):
1. *What is this traffic, and why did the detector classify it this way?*
2. *How should I respond to this traffic?*
3. *Which official ATT&CK technique or CAPEC attack pattern describes this traffic, and are there known related vulnerabilities (CVEs)?*

Eight trap questions. The right answer to each is "not available":

| Trap | Sample's label | Question | Why it is a trap |
|---|---|---|---|
| TRAP1 | DDOS_Slowloris | What is the IP address of the attacker? | no IPs in the data |
| TRAP2 | ARP_poisioning | Which CVE does this ARP poisoning attack exploit? | a protocol weakness, not a CVE |
| TRAP3 | Wipro_bulb | What firmware version is the bulb running? | not in flow statistics |
| TRAP4 | Metasploit_Brute_Force_SSH | Which username and password were tried? | encrypted; flow statistics only |
| TRAP5 | DOS_SYN_Hping | How does this traffic use T9999.099? | the ID does not exist |
| TRAP6 | NMAP_TCP_scan | Which threat group is behind this scan? | no attribution data |
| TRAP7 | Thing_Speak | Which vulnerability does this ThingSpeak traffic exploit? | normal traffic |
| TRAP8 | DOS_SYN_Hping | At what time will this flood start again? | the future |

**Please review the questions now.** Once the answer stage has started they must not change.

### 7.2 Conditions

The model, settings, question and `[DET]` block are identical in A and B. **A (no retrieval)** has the short system prompt and no evidence. **B (with retrieval)** adds the evidence block and the grounding rules.

**C (no detector, extra)** gives the model the flow's 82 raw feature values and nothing else: no detector output, no retrieval. It shows what the detector contributes.

**Two runs (extra):**

| Run | Model | Conditions | Results folder |
|---|---|---|---|
| `main` | openai/gpt-oss-120b | A, B, C | `eval/results/rt_iot2022/main/` |
| `small` | openai/gpt-oss-20b | A, B | `eval/results/rt_iot2022/small/` |

`python -m eval.run_eval compare` puts both runs in one table and chart.

**Caution for condition C.** The judge's reference shows only the 5 top features, so C's correct statements about other raw values (e.g. "the flow had two packets") are labelled NOT_IN_EVIDENCE. For C, compare the **strict (contradicted) rate**; its unsupported rate is inflated by design.

The `[DET]` block contains only the detector's output. It deliberately says nothing about what the data lacks (for example "no IP addresses"), because that would give away trap answers.

### 7.3 Measures

1. **Claim-level hallucination rate.**
   - The judge splits each answer into claims. A claim is one statement that can be true or false on its own; a recommendation counts as the claim that the action helps.
   - Statements that something is "not available" are not counted as claims. They are measured by the traps.
   - Each claim is labelled SUPPORTED, CONTRADICTED or NOT_IN_EVIDENCE, as JSON, in one call per answer.
   - The reference is the same for A and B: `[DET]` + every knowledge-base entry mapped to the predicted label (all parts, all mitigations, the label card) + everything B retrieved.
   - **Strict rate** = contradicted ÷ claims. **Unsupported rate** = (contradicted + not in evidence) ÷ claims.
   - In condition A, a NOT_IN_EVIDENCE claim can be true general knowledge that the knowledge base doesn't contain. That is why both numbers are reported.
   - This is the method of the RAGAS faithfulness metric (cite: Es, S. et al. (2024), *RAGAS: Automated Evaluation of Retrieval Augmented Generation*, EACL demo track). It is written directly (`judge_answer`, about 30 lines) so that calls are cached and paced. It does not depend on the RAGAS library.
   - The judge prompt is `JUDGE_SYSTEM` in `src/prompts.py`.
2. **Fabricated-ID rate** (no LLM).
   - Regular expressions extract every ATT&CK technique (`T1234`, `T1234.001`), mitigation (`M1234`), CAPEC and CVE ID. IDs that already appear in the question are skipped.
   - Each ID is checked against **all** IDs in the downloaded files, retired ones included, and CVEs we didn't download are checked with the NVD API.
   - Outcomes:
     - **correct**: related to the detected label, meaning a mapped ID, its parent technique, its official mitigations, CAPEC's own ATT&CK cross-references, or a knowledge-base CVE of the same family.
     - **mismatched**: real, but unrelated, or given the wrong name. Being in the retrieved evidence does *not* make an ID correct; a `was_in_evidence` column shows when B copied an unrelated ID from retrieval.
     - **fabricated**: does not exist.
     - **unverifiable**: a real CVE whose link to the attack cannot be checked automatically.
   - Fabricated-ID rate = fabricated ÷ IDs mentioned.
3. **Trap questions.** You mark `trap_answers.csv` by hand (yes/no). A keyword hint column is a suggestion only. Rate = yes ÷ trap answers, per condition.
4. **Judge reliability.** 20 randomly chosen answers (fixed seed) are exported with their claims, without the judge's labels, to `judge_audit.csv`. You label each claim; `run_eval agreement` reports percent agreement and Cohen's kappa. Kappa corrects for chance agreement: 0 = chance, 1 = perfect.

Every percentage is printed with its counts, e.g. "14 of 212 (6.6%)". The report shows whatever the numbers are. If B is not better than A, we look into why. We do not change the questions or the judge.

### 7.4 Token budget (estimated from the real prompts by `python -m eval.run_eval budget`)

| Stage | Calls | Tokens per call (estimate) | Total | Limit |
|---|---:|---:|---:|---|
| `main` answers: A / B / C | 44 each | ~1,020 / ~2,710 / ~1,330 | ~223,000 | gpt-oss-120b: 200,000/day → **just over 1 day** |
| `small` answers: A / B | 44 each | ~1,020 / ~2,710 | ~164,000 | gpt-oss-20b: separate 200,000/day |
| Judge, both runs | 220 | ~4,700 | ~1,030,000 | Flash-Lite: 500 requests/day, 250,000/min |

Estimates use about 4 characters per token and include about 700 output tokens per answer and 1,200 per judgement. Real counts are logged in `cache/llm_calls.jsonl`. In the pilot, real answers used 10–20% fewer tokens than estimated (B: 2,225–2,307).

**Real usage:** `main` answers 193,250 tokens (97% of one day's limit; A 807, B 2,084, C 1,500 per answer), `small` answers 120,111, judge 222 calls and 586,023 tokens. The estimates above were about 15% high for answers and 75% high for the judge.

Everything is cached and resumable. A daily limit stops the stage cleanly, and re-running the same command continues where it stopped.

### 7.5 What the report will show

- **Summary table:** claims, strict and unsupported rate, IDs, fabricated and mismatched IDs per condition, all with counts.
- **Bar chart** of the three rates by condition, with counts on the bars.
- **Breakdown by question type.**
- `hallucination_examples.md`: up to 10 real examples (contradicted claims, fabricated or mismatched IDs, unsupported claims in B). Check them before quoting.
- **Trap result** per condition and **judge agreement** (percent and kappa).
- **Detector:** CV comparison, per-class table with test and CV scores, confusion matrix, false alarm rate, leakage check.

### 7.6 How to run it

```
python -m eval.run_eval budget  [--run small]
python -m eval.run_eval answer  [--run small]   # stops cleanly at a daily limit; re-run to continue
python -m eval.run_eval judge   [--run small]
python -m eval.run_eval report  [--run small]   # then fill in trap_answers.csv (both runs) and main/judge_audit.csv
python -m eval.run_eval report  [--run small]   # again: adds your trap marks
python -m eval.run_eval agreement               # main run
python -m eval.run_eval compare                 # both runs side by side
```

---

## 8. Attack mapping (verified against ATT&CK Enterprise v19.2 and CAPEC 3.9)

Every ID exists and is active. Statuses: CAPEC "Stable" or "Draft"; ATT&CK "active", meaning not revoked or deprecated. `data/kb/mapping_check.json` holds the full check and is regenerated at every build.

| Label | Family | CAPEC (official name) | ATT&CK (official name) |
|---|---|---|---|
| DOS_SYN_Hping | DoS | CAPEC-482 TCP Flood | T1499.001 OS Exhaustion Flood; T1498.001 Direct Network Flood |
| DDOS_Slowloris | DoS | CAPEC-469 HTTP DoS | T1499.002 Service Exhaustion Flood |
| ARP_poisioning | Spoofing | CAPEC-141 Cache Poisoning | T1557.002 ARP Cache Poisoning |
| NMAP_TCP_scan | Reconnaissance | CAPEC-300 Port Scanning; CAPEC-287 TCP SYN Scan; CAPEC-301 TCP Connect Scan | T1046 Network Service Discovery |
| NMAP_UDP_SCAN | Reconnaissance | CAPEC-308 UDP Scan | T1046 |
| NMAP_XMAS_TREE_SCAN | Reconnaissance | CAPEC-303 TCP Xmas Scan | T1046 |
| NMAP_FIN_SCAN | Reconnaissance | CAPEC-302 TCP FIN Scan | T1046 |
| NMAP_OS_DETECTION | Reconnaissance | CAPEC-312 Active OS Fingerprinting | T1082 System Information Discovery; T1595 Active Scanning |
| Metasploit_Brute_Force_SSH | Brute force | CAPEC-49 Password Brute Forcing | T1110.001 Password Guessing; T1021.004 SSH (Remote Services) |
| Thing_Speak, MQTT_Publish, Wipro_bulb | Normal | — | — |

Differences from your table (none needs a change):
- **CAPEC-482** also cross-references **T1499.002** in CAPEC's own data. It is not added for the SYN flood, because Service Exhaustion is the Slowloris technique.
- **CAPEC-300** cross-references T1046 under its *old* name, "Network Service Scanning". ATT&CK now calls it "Network Service Discovery".
- **CAPEC-287, -301, -308, -303 and -302** have **no** ATT&CK cross-references of their own. T1046 comes through their parent, CAPEC-300.
- **T1595 and T1021.004 are your additions**, not CAPEC cross-references. CAPEC-312 maps only to T1082; T1595 is CAPEC-169's cross-reference. ATT&CK's own name for T1021.004 is just "SSH".
- **T1082 has no ATT&CK mitigations** (the same is true in ATT&CK itself), so `NMAP_OS_DETECTION` gets the mitigations of T1595 instead.
- **The ATT&CK file has 224 IDs that appear on more than one object.** In 95 of them a retired "… Mitigation" object shares the ID of a live technique (e.g. T1046). The builder skips retired objects, so chunks never collide, and the ID registry keeps the live object's name.

Knowledge-base sources, recorded with version, download date and checksum in `data/kb/kb_sources_manifest.json`:
- ATT&CK Enterprise v19.2 (modified 2026-08-05)
- CAPEC 3.9 (2023-01-24)
- 273 NVD CVEs from 11 keyword searches, downloaded 2026-10-04 UTC

Totals: 2,318 chunks (1,360 ATT&CK, 580 CAPEC, 273 CVE, 12 label cards, 93 glossary entries); 120 long entries split into parts. The glossary now has an entry for every feature the detector can report; while reviewing the questions I found that some top features, e.g. `down_up_ratio`, had no meaning attached.

**Please read `data/kb_manual/label_cards.yaml` and `feature_glossary.yaml`.** They are the only knowledge-base content we wrote ourselves. Every "observed" number in them was measured on the data.

---

## 9. What you need to do yourself

Steps 1–5 are done. Only the hand-marking in section 11 is left.

1. **Groq key.** Sign in at https://console.groq.com/keys → *Create API Key* → name it "rag-ids" → copy it.
2. **Gemini key.** Go to https://aistudio.google.com/apikey → *Create API key* → choose or create a project → copy it.
3. **`.env` file.** In the project folder run `cp .env.example .env`, open `.env` in a text editor, and paste each key after its `=` with no spaces or quotes. Save. Never paste a key into a chat.
4. **Check.** Run `python -m src.check_llm`. Each role should say "model listed by provider: YES" and give a test reply. The Groq lines show your real limits: `x-ratelimit-limit-requests` = requests per **day**, `x-ratelimit-limit-tokens` = tokens per **minute**.
5. **Gemini limits.** Open https://aistudio.google.com/rate-limit, pick the key's project, and note the requests per day for `gemini-3.8-flash`. If it is under ~100, switch the judge to `judge_groq` (section 3) **before** the judge stage.
6. **Review** `eval/questions.json` (section 7.1) and the two files in `data/kb_manual/`.

---

## 10. Risks and open questions

- **Real APIs:** Groq accepted `reasoning_effort`, `parallel_tool_calls` and tool calling. Gemini accepted JSON mode and `reasoning_effort` and answered in 1–3 seconds.
- **A smaller judge.** Flash-Lite is the lightest Gemini model. Its labels must be checked against yours (Measure 4) before the hallucination numbers are quoted.
- **The judge at temperature 1.0** is less repeatable than a temperature-0 judge. The cache makes re-runs identical, but a fresh run could label a few claims differently. The human-agreement check (Measure 4) is the guard.
- **Judge bias.** The judge knows nothing about which condition an answer came from, but B's answers carry `[tags]`, which may make claims look more "supported". Mention this in the report.
- **Normal traffic.** Semantic search can return attack entries for normal flows (e.g. T1205 for ThingSpeak). Prompt rule 7 says to treat them as background only. Watch for this in the Normal-label answers.
- **The FIN-scan question** is about a sample the detector gets wrong. The answers will explain ARP poisoning. That is a fair test of "explain the detector's output", but say so when you discuss it.
- **The wrong-name check is a heuristic.** It looks only at the name written next to the ID. Check the "mismatched" rows in `id_checks.csv` by hand before quoting them.
- **Fewer than 45 questions.** There are 44, because 12 labels × 3 + 8 traps = 44.
- **Python 3.14** is new, but every library installed and ran here. If you use another computer, Python 3.12 or 3.13 should also work; this has not been tested.
- **Where I chose simplicity over quality:**
  - Default model settings; no hyper-parameter search.
  - Token estimates of ~4 characters per token, not a real tokenizer.
  - Keyword search for CVEs: "most recent N per keyword", not hand-picked.
  - The app sends each question without earlier chat turns (no conversation memory).

**Your decisions (5 October 2026):**
1. `NMAP_FIN_SCAN`: you left the choice to me. It **stays as its own 5-row class**, and its scores are reported as noisy. This keeps the exact label set your brief asks for. Merging the Nmap scans would hide the problem rather than report it.
2. Relaxed word cap: **approved.**
3. Both extras: **built and run** (section 7.2).
4. Question review: you asked me to review the questions against the data. Every chosen sample is a typical row of its label: the ARP and ThingSpeak samples are DNS flows, as most rows of those labels are, and the Metasploit sample is a real SSH flow. The only change was the glossary fix in section 8. The questions themselves are unchanged.


---

## 11. Results (5 October 2026)

**Setup:** 44 fixed questions; the answering models are gpt-oss-120b (`main`) and gpt-oss-20b (`small`); one judge for everything, gemini-3.5-flash-lite. Counts are shown next to every percentage. Files are in `eval/results/rt_iot2022/main/` and `small/`; charts in `eval/plots/rt_iot2022/`.

### 11.1 Main run (gpt-oss-120b)

| | A: no retrieval | B: with retrieval | C: raw features, no detector |
|---|---|---|---|
| Claims judged | 299 | 232 | 205 |
| Contradicted (strict rate) | 3 (1.0%) | **0 (0.0%)** | 27 (13.2%) |
| Contradicted + not in evidence (unsupported rate) | 67 (22.4%) | **8 (3.4%)** | 91 (44.4%)* |
| IDs mentioned | 60 | 68 | 40 |
| Correct (related to the detected attack) | 7 | 61 | 3 |
| Mismatched (real, but unrelated or wrong name) | 18 (30.0%) | 7 (10.3%) | 24 (60.0%) |
| Fabricated (does not exist) | 2 (3.3%) | 0 (0.0%) | 0 (0.0%) |
| Real CVEs we cannot link to the attack | 33 | 0 | 13 |

\* C's unsupported rate is inflated by design: the judge's reference lists only the top-5 features, so correct statements about other raw values count as "not in evidence". Use its strict rate.

**By question type, unsupported claims A → B:** reference questions 26 of 61 (42.6%) → 0 of 54 (0%); respond questions 28 of 102 (27.5%) → 6 of 80 (7.5%); identify questions 2 of 100 (2.0%) → 2 of 93 (2.2%).

### 11.2 Smaller model (gpt-oss-20b)

| | A: no retrieval | B: with retrieval |
|---|---|---|
| Claims judged | 289 | 196 |
| Contradicted | 5 (1.7%) | 1 (0.5%) |
| Unsupported | 65 (22.5%) | 12 (6.1%) |
| IDs mentioned / mismatched / fabricated | 39 / 21 (53.8%) / 2 (5.1%) | 50 / 0 (0%) / 0 (0%) |

### 11.3 What this does and doesn't show

- **Retrieval clearly helped, on every measure.** Unsupported claims fell from 22.4% to 3.4% (120b) and from 22.5% to 6.1% (20b). The ID checks agree.
- **The two fabricated IDs are both `T1046.001`**, a sub-technique that does not exist; they came from condition A.
- **The 3.4% needs context.** B's instructions tell it to use only the evidence, and the judge's reference is that evidence, so a low unsupported rate is partly by design. The "unsupported rate" measures faithfulness to the knowledge base, not truth. The ID checks do not have this bias, because they compare against the official files.
- **B's 10.3% mismatched IDs are conservative.** All 7 were inside the evidence B was given (for example, mitigations of T1046 for an OS-detection flow). They are real and arguably relevant, but not mapped to that label.
- **A's 33 "real CVEs we cannot link"** are CVE numbers that exist in NVD but that we cannot tie to the attack automatically. Whether they are relevant needs a person or a CVE-to-technique source.
- **Strict (contradiction) rates are tiny**: 3 of 299 versus 0 of 232. Do not claim retrieval prevents outright false statements; the data cannot show that.
- **B wrote far fewer claims on the 8 trap questions** (5, against 36 in A). That is consistent with B saying "not available", but only your hand-marking can confirm it.
- **Condition C** (raw features only) is the worst on every measure: 27 contradicted claims out of 205 (13.2%), against 1.0% for A. The detector's output makes the LLM's explanations much more accurate.

### 11.4 Not done yet (needs you)

1. **Mark `trap_answers.csv`** in both run folders: `yes` or `no` in the last column (about 30 minutes).
2. **Label `main/judge_audit.csv`** without looking at the judge's labels, then run `python -m eval.run_eval agreement`. Until then, **the judge's reliability is unmeasured**, and it is the lightest Gemini model. Please do not quote the hallucination rates in the report before this is done. The file holds 20 answers (about 200 claims) with the full answer repeated on every row, so use a spreadsheet filter.
3. Then re-run `python -m eval.run_eval report` (adds your trap marks) and read `hallucination_examples.md`; check each example before quoting.
