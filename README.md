# RAG-IDS

An IoT intrusion-detection prototype with three parts:

1. **Detector.** A machine-learning model (XGBoost) that labels network flows from the RT-IoT2022 dataset as one of 12 traffic types: 9 attacks and 3 kinds of normal traffic.
2. **Analyst.** An LLM that explains a detection and answers questions. It retrieves from a threat knowledge base (MITRE ATT&CK, MITRE CAPEC, NVD CVE records) and must cite every claim with a source tag such as `[T1046]`.
3. **Evaluation.** Measures how often the LLM hallucinates **with and without** that retrieval. This comparison is the main result of the project.

The design, the data findings and the evaluation method are in **[PLAN.md](PLAN.md)**.

The web app, called the **attack range**, lets you launch an attack, watch the detector catch it, and question the analyst:

> pick a playbook → watch the attack on an animated network → see the verdict land → read the case file → ask the analyst (optionally *Compare both*: with vs. without the knowledge base)

---

## Quick start

You need **Python 3.12 or newer** (tested on 3.14.7, Linux), about **3 GB of disk space**, an internet connection for the first run, and **no GPU**. The one-time build takes about **20 minutes**, mostly waiting.

```bash
# 1. Get into the project folder (every command below runs from here)
cd RAG-IDS

# 2. Create a private Python environment and install everything (5-10 min, ~2.5 GB)
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. Add your API keys (see "API keys" below), then check them
cp .env.example .env                 # now open .env in a text editor and paste your keys
python -m src.check_llm              # each model should say "listed by provider: YES"

# 4. Build everything once
python -m src.data_loader            # downloads the dataset, removes duplicates, splits it   (~10 s)
python -m src.detector               # trains and evaluates the detector                       (~4 min)
python -m src.kb_builder             # downloads MITRE + NVD data, builds the knowledge base   (~6 min)
python -m src.retriever --check      # should end with "ALL LABELS OK"

# 5. Start the app
python -m web.server                 # wait for "RAG-IDS range ready", then open:
```

Open **http://127.0.0.1:8000**. The first start takes about 10 seconds while the models load.

Steps 1-4 need **no API key**. Only the analyst (chat) and the evaluation do.

### What you should see

- A headline over an idle network, and a carousel of **playbooks** (13 cards: a mystery flow, 9 attacks, 3 kinds of normal traffic). Drag it, scroll it, or use the arrows.
- Launch one and the attack plays out on the network. The detector's scope races to a result and the verdict lands as a stamp.
- Then the **case file** (why the detector decided, the official MITRE references mapped to the label) and the **analyst** panel on the right.
- **Compare both** (above the chat) answers every question twice, from memory and from the knowledge base, and checks each cited ID against the official MITRE files.
- **Model results** (top left) shows the detector's scores and the hallucination evaluation. The sun/moon button switches light and dark theme.

Press **Esc**, or click the logo, to return to the playbooks.

---

## API keys

Create free keys and put them in `.env` (copy `.env.example`). **`.env` is never committed. Never paste a key into a chat or an issue.**

| Key | Needed for | Where to get it |
|---|---|---|
| `GROQ_API_KEY` | The analyst's answers (gpt-oss-120b) | https://console.groq.com/keys |
| `GEMINI_API_KEY` | The evaluation's judge (gemini-3.5-flash-lite) | https://aistudio.google.com/apikey |
| `NVIDIA_API_KEY` (optional) | Demo fallback, tried first | https://build.nvidia.com |
| `OPENROUTER_API_KEY` (optional) | Demo fallback, tried second | https://openrouter.ai/keys |

If Groq's free limit is hit during a demo, the **web app** switches to NVIDIA's Nemotron-3-Super (then OpenRouter's free copy) instead of showing an error, and labels those answers "fallback model". The **evaluation never uses fallbacks**, so its numbers always come from one model.

Model names, temperatures and rate limits are in `configs/llm.yaml`. Free plans change often: `python -m src.check_llm` shows whether your keys can still reach each model and prints your Groq limits. Google does not publish its free limits; see https://aistudio.google.com/rate-limit.

---

## Using it without the web app

```bash
python -m src.assistant --sample sample_00004 "How should I respond to this traffic?"
python -m src.assistant --sample sample_00004 --no-retrieval "..."        # memory only (evaluation condition A)
python -m src.assistant --sample sample_00004 --mode tool "..."           # the LLM runs the detector and the search itself
python -m src.assistant "What is a TCP Xmas scan?"                         # a general question, no traffic sample
python -m src.retriever --sample sample_00004 "How do I stop this?"        # show the evidence the LLM would get
```

Sample IDs run from `sample_00000` to `sample_04767`: the 4,768 test flows the detector never trained on.

An earlier, simpler Streamlit version of the app is still in `app/` (`streamlit run app/Home.py`). It is a fallback and is not maintained.

---

## The evaluation

It runs offline, separate from the app. Every stage skips work that is already saved, so you can stop at any time (or hit a free-plan daily limit) and run the same command again later.

```bash
python -m eval.run_eval budget                 # token estimate from the real prompts, no API calls
python -m eval.run_eval answer                 # answers from gpt-oss-120b: conditions A, B, C   (~223k tokens, a little over one day of Groq's free limit)
python -m eval.run_eval judge                  # one judge call per answer
python -m eval.run_eval report                 # tables, charts, examples, files to mark by hand
python -m eval.run_eval answer --run small     # optional second model (gpt-oss-20b); also: judge / report --run small
python -m eval.run_eval compare                # both runs side by side
```

| Condition | The model sees |
|---|---|
| A | the question and the detector's output |
| B | the same, plus retrieved knowledge-base evidence and the grounding rules |
| C | only the flow's raw feature values (no detector), to show what the detector adds |

The 44 questions are fixed in `eval/questions.json` (made by `python -m eval.make_questions`). **Do not change them once the answer stage has started.**

**Two things you must do by hand** (files are in `eval/results/rt_iot2022/main/`, and `small/` for the trap file):

1. `trap_answers.csv`: put `yes` or `no` in the last column (did the answer correctly say the information is not available?).
2. `judge_audit.csv`: label each claim SUPPORTED, CONTRADICTED or NOT_IN_EVIDENCE **without** looking at the judge's verdicts.

Then run `python -m eval.run_eval report` again (adds your trap marks) and `python -m eval.run_eval agreement` (percent agreement and Cohen's kappa between you and the judge).

### Results so far

Detector (test set): macro-F1 **0.875**, accuracy **98.7%**, false alarms **0.92%**. It is not 99% because 80% of the raw rows are exact duplicates; removing them first leaves 23,839 unique flows, and one label (`NMAP_FIN_SCAN`) has only 5 unique rows.

Hallucination evaluation (gpt-oss-120b): unsupported claims fell from **22.4% without retrieval to 3.4% with it**, and IDs unrelated to the detected attack from 30% to 10%. **Do not quote these before you have labelled `judge_audit.csv`**: the judge is a light model whose agreement with a human has not yet been measured. Full tables and caveats: PLAN.md section 11.

---

## Where things are

| Path | What |
|---|---|
| `web/` | The web app: `server.py` (data side) and `static/` (the page: `index.html`, `style.css`, `app.js`; no build step) |
| `src/` | The system: `data_loader`, `detector`, `kb_builder`, `retriever`, `llm_client`, `prompts`, `assistant`, `evaluation`, `check_llm` |
| `src/prompts.py` | **Every prompt**, in one file |
| `eval/` | `make_questions.py`, `questions.json`, `run_eval.py`, and the results in `results/<dataset>/` and `plots/<dataset>/` |
| `configs/rt_iot2022.yaml` | Everything about the dataset: how to load it, the label column, dropped and text columns, label → attack family |
| `configs/attack_mapping.yaml` | Label → official CAPEC and ATT&CK IDs (verified against the downloaded files; PLAN.md section 8) |
| `configs/llm.yaml` | Model names, temperature, reasoning effort, rate limits, fallbacks |
| `configs/scenarios.yaml` | How each label looks in the app: icon, story, animation style |
| `data/kb_manual/` | The two knowledge files we wrote ourselves (label cards, feature glossary); not from an official source |
| `data/kb/kb_sources_manifest.json` | Version, download date and checksum of each official source |
| `app/` | The earlier Streamlit version (fallback) |
| `PLAN.md` | Design, dataset findings, evaluation method, results, risks |

Created when you run the steps (all git-ignored, rebuilt by the commands above): `.venv/`, `data/raw/`, `data/processed/*/*.parquet`, `data/kb_raw/`, `data/chroma_db/`, `data/kb/chunks.json`, `models/`, `cache/`.

**Adding a dataset or an attack type** means editing config files, not code:

1. Write `configs/<name>.yaml` like `rt_iot2022.yaml`, then run `python -m src.data_loader --dataset <name>` and `python -m src.detector --dataset <name>`. The web app lists every dataset that has a trained detector.
2. Add its labels to `configs/attack_mapping.yaml` (a label without a mapping still works through semantic search and logs a warning), and cards to `data/kb_manual/label_cards.yaml`, then re-run `python -m src.kb_builder`.
3. Optionally add icons and stories to `configs/scenarios.yaml`.

`configs/ciciot2023.yaml` is a draft for a second dataset and is inactive until you download its data and rename `label_column_TODO` to `label_column` (PLAN.md section 6).

---

## Reproducibility

- Random seed 42 everywhere; a stratified 80/20 split, with duplicates removed before splitting.
- `requirements.txt` pins every direct dependency; `requirements-lock.txt` pins every package in the tested environment.
- Model names are in `configs/llm.yaml`. Every LLM call is logged with its model and token count in `cache/llm_calls.jsonl`, and every response is cached by its full request, so a re-run gives the same text.
- The knowledge base records the ATT&CK version (v19.2), the CAPEC version (3.9) and the download dates in `data/kb/kb_sources_manifest.json`.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'src'` | Run commands from the project folder, with `python -m ...` as shown. |
| `GROQ_API_KEY is missing` | `.env` is missing, misnamed, or not in the project folder next to this README. |
| `Knowledge base not built` | Run `python -m src.kb_builder`. |
| `No trained detector for 'rt_iot2022'` | Run `python -m src.data_loader`, then `python -m src.detector`. |
| The web page does not show a change I made | Hard-reload with Ctrl+Shift+R. After changing a `.py` file, stop the server (Ctrl+C) and start it again. |
| Port 8000 is already in use | Stop the other program, or run `uvicorn web.server:app --port 8010`. |
| "Pacing: waiting ... s" in the terminal | Normal. Groq's free plan allows 8,000 tokens a minute, about three answers with retrieval per minute. |
| "daily limit reached" | Wait until the limit resets and run the same command again; nothing is lost. The web app uses a fallback model if you added the optional keys. |
| `pip install` is very slow or huge | `requirements.txt` already points pip at the small CPU-only PyTorch build. Make sure that first line is still there. |
| First launch is slow | The server loads the model and the embedding model once at start. Wait for "RAG-IDS range ready". |

---

## Limits to know about

- **Free API plans** are small and change often. A public deployment would let strangers use up your quota, so the app is built for localhost. It is not set up for Vercel: the model stack (PyTorch, ChromaDB, XGBoost) is too large for serverless functions.
- **The detector is weakest on the rarest labels.** `NMAP_FIN_SCAN` has 5 unique rows (1 test row), so its scores are very noisy; quote its cross-validation score. The demo shows it honestly: the detector gets it wrong at low confidence.
- **Some labels contain background traffic.** For example, 3 of the 5 unique `NMAP_FIN_SCAN` rows are DNS traffic that a FIN scan cannot produce, so the labels mark capture sessions rather than individual flows.
- **The hallucination numbers describe one model, one judge and 44 questions.** Counts are small, and condition B is judged against the evidence it was told to use. Read PLAN.md section 11 before quoting them.

---

## Credits and licences

- **Dataset:** Sharmila, B. S. and Nagapadma, R. (2023). RT-IoT2022. UCI Machine Learning Repository. https://doi.org/10.24432/C5P338 (CC BY 4.0).
- **MITRE ATT&CK** and **CAPEC** are © The MITRE Corporation and used under MITRE's terms of use. **CVE records** come from the NVD (a public US government service).
- **Embedding model:** BAAI/bge-small-en-v1.5. **Detector:** XGBoost. **LLMs:** gpt-oss (OpenAI, served by Groq), Gemini (Google), Nemotron (NVIDIA).
- The project code has no licence file yet. Add one before publishing it.
