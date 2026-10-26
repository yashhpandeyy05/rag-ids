"""
Milestone 6 - the hallucination evaluation (offline, separate from the app).

Run the stages in this order. Every stage skips work that is already saved,
so you can stop at any time (or hit a daily limit) and simply run it again later.

    python -m eval.run_eval budget              # token estimate from the real prompts (no API calls)
    python -m eval.run_eval answer              # answers from the answering model (Groq)
    python -m eval.run_eval judge               # one judge call per answer
    python -m eval.run_eval report              # tables, charts, examples, files to mark by hand
    python -m eval.run_eval agreement           # after you filled in judge_audit.csv
    python -m eval.run_eval compare             # all runs side by side

Add  --run small  to the first four stages for the optional second model.

Runs (each has its own folder eval/results/<dataset>/<run>/):
    main   openai/gpt-oss-120b   conditions A, B, C
    small  openai/gpt-oss-20b    conditions A, B

Conditions (same model, settings and question):
    A  no retrieval:   question + [DET] (detector output)
    B  with retrieval: question + [DET] + knowledge-base evidence + grounding rules
    C  no detector:    question + the flow's raw feature values only
All conditions of a question are judged against the SAME reference:
[DET] + every entry mapped to the predicted label + whatever B retrieved.
"""

import argparse
import csv
import json
import logging
import random
from datetime import datetime, timezone
from typing import Any, Dict, List

import pandas as pd

from src.assistant import build_messages, build_raw_feature_messages
from src.config import DEFAULT_DATASET, EVAL_DIR, dataset_paths
from src.detector import detect, load_test_sample
from src.evaluation import (JudgeError, agreement, build_reference, check_ids, extract_ids,
                            judge_answer, rates, refusal_hint)
from src.llm_client import DailyLimitReached, LLMError, chat, judge_role, role_settings
from src.retriever import chunks as kb_chunks

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("run_eval")

RUNS = {
    "main": {"role": "answering", "conditions": ["A", "B", "C"]},
    "small": {"role": "answering_small", "conditions": ["A", "B"]},
}
CONDITION_NAMES = {"A": "no retrieval", "B": "with retrieval", "C": "raw features, no detector"}
AUDIT_RUN = "main"       # the human-agreement sample is drawn from this run
AUDIT_ANSWERS = 20
SEED = 42
GROQ_TOKENS_PER_DAY = 200_000


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------
def out_dirs(dataset, run):
    p = dataset_paths(dataset)
    res, plots = p["results_dir"] / run, p["plots_dir"] / run
    res.mkdir(parents=True, exist_ok=True)
    plots.mkdir(parents=True, exist_ok=True)
    return res, plots


def load_questions() -> List[Dict[str, Any]]:
    return json.loads((EVAL_DIR / "questions.json").read_text())["questions"]


def read_jsonl(path) -> Dict[str, Dict[str, Any]]:
    """Records keyed by 'question_id|condition'."""
    if not path.exists():
        return {}
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            out[f"{r['qid']}|{r['condition']}"] = r
    return out


def append_jsonl(path, record) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def condition_messages(cond, q, dataset):
    """Messages for one question in one condition, plus the detector output and the evidence chunks."""
    row = load_test_sample(q["sample_id"], dataset)
    det = detect(row, dataset)
    if cond == "C":
        return build_raw_feature_messages(q["question"], row, dataset), det, []
    msgs, chunks, _ = build_messages(q["question"], det, use_retrieval=(cond == "B"))
    return msgs, det, chunks


def pct(n, d):
    return f"{n} of {d} ({100 * n / d:.1f}%)" if d else f"{n} of 0 (n/a)"


# ---------------------------------------------------------------------------
# Stage: budget
# ---------------------------------------------------------------------------
def stage_budget(dataset, run):
    """Estimate tokens per call from the real prompts and compare with the free limits."""
    res_dir, _ = out_dirs(dataset, run)
    ans, jud = role_settings(RUNS[run]["role"]), role_settings(judge_role())
    est_answer_out = 700    # ~300 visible tokens (200 words) + hidden reasoning at "low"
    est_judge_out = 1200    # JSON list of ~15 claims + reasoning at "low"
    rows = []
    for q in load_questions():
        _, det, b_chunks = condition_messages("B", q, dataset)
        ref = build_reference(det, b_chunks)
        for cond in RUNS[run]["conditions"]:
            msgs, _, _ = condition_messages(cond, q, dataset)
            a_in = len(json.dumps(msgs)) // 4
            j_in = (len(ref) + 1200 * 4 + 2500) // 4   # reference + answer + judge prompt
            rows.append({"condition": cond, "answer_total": a_in + est_answer_out, "judge_total": j_in + est_judge_out})
    df = pd.DataFrame(rows)
    a_tot, j_tot = int(df["answer_total"].sum()), int(df["judge_total"].sum())
    summary = {
        "run": run, "calls": len(df), "answering_model": ans["model"],
        "answering_tokens_per_call": {c: int(df[df.condition == c]["answer_total"].mean())
                                      for c in RUNS[run]["conditions"]},
        "answering_tokens_total": a_tot,
        "answering_days_at_200k_per_day": round(a_tot / GROQ_TOKENS_PER_DAY, 2),
        "answering_minutes_at_tpm_limit": round(a_tot / ans["tokens_per_minute"], 1),
        "judge_model": jud["model"], "judge_tokens_per_call": int(df["judge_total"].mean()),
        "judge_tokens_total": j_tot,
        "judge_minutes_at_rpm_limit": round(len(df) / jud["requests_per_minute"], 1),
        "note": "Estimates use ~4 characters per token. Real counts are logged in cache/llm_calls.jsonl.",
    }
    print(json.dumps(summary, indent=1))
    (res_dir / "budget.json").write_text(json.dumps(summary, indent=1))


# ---------------------------------------------------------------------------
# Stage: answer
# ---------------------------------------------------------------------------
def stage_answer(dataset, run, limit=None):
    res_dir, _ = out_dirs(dataset, run)
    path = res_dir / "answers.jsonl"
    done = read_jsonl(path)
    role = RUNS[run]["role"]
    todo = [(q, c) for q in load_questions()[:limit] for c in RUNS[run]["conditions"]
            if f"{q['id']}|{c}" not in done]
    logger.info("[%s] %d answers already saved, %d to do (model %s)", run, len(done), len(todo),
                role_settings(role)["model"])
    for i, (q, cond) in enumerate(todo, 1):
        msgs, det, chunks = condition_messages(cond, q, dataset)
        try:
            res = chat(role, msgs)
        except DailyLimitReached as e:
            logger.error("%s. Stopping; run the same command again later.", e)
            return
        except LLMError as e:
            logger.error("%s|%s failed: %s (will retry next run)", q["id"], cond, e)
            continue
        append_jsonl(path, {
            "run": run, "qid": q["id"], "condition": cond, "type": q["type"], "true_label": q["true_label"],
            "sample_id": q["sample_id"], "question": q["question"], "predicted_label": det["predicted_label"],
            "confidence": det["confidence"], "detection": det, "evidence_ids": [c["chunk_id"] for c in chunks],
            "answer": res["content"], "model": res["model"], "usage": res["usage"],
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds")})
        logger.info("[%d/%d] %s|%s answered (%s tokens)", i, len(todo), q["id"], cond,
                    res["usage"].get("total_tokens"))


# ---------------------------------------------------------------------------
# Stage: judge
# ---------------------------------------------------------------------------
def stage_judge(dataset, run, limit=None):
    res_dir, _ = out_dirs(dataset, run)
    answers = read_jsonl(res_dir / "answers.jsonl")
    path = res_dir / "judgements.jsonl"
    done = read_jsonl(path)
    judge_model = role_settings(judge_role())["model"]
    other = {r["judge_model_requested"] for r in done.values()} - {judge_model}
    if other:
        raise SystemExit(f"Saved judgements were made by {other}, but the configured judge is {judge_model}. "
                         "One judge per run: move judgements.jsonl away to start a new run.")
    todo = [k for k in answers if k not in done and f"{answers[k]['qid']}|B" in answers][:limit]
    waiting = [k for k in answers if k not in done and f"{answers[k]['qid']}|B" not in answers]
    if waiting:
        logger.info("%d answers wait for their condition-B answer (needed for the reference)", len(waiting))
    logger.info("[%s] %d judgements saved, %d to do (judge: %s)", run, len(done), len(todo), judge_model)
    for i, key in enumerate(todo, 1):
        a = answers[key]
        # Reference = what condition B of the SAME question actually saw (saved at answer time),
        # so it stays correct even if the knowledge base is rebuilt later.
        b = answers[f"{a['qid']}|B"]
        reference = build_reference(b["detection"], [kb_chunks()[cid] for cid in b["evidence_ids"]])
        try:
            j = judge_answer(reference, a["question"], a["answer"])
        except DailyLimitReached as e:
            logger.error("%s. Stopping; run the same command again later.", e)
            return
        except (JudgeError, LLMError) as e:
            logger.error("%s: %s (NOT saved; will be judged again next run)", key, e)
            with open(res_dir / "judge_failures.log", "a") as f:
                f.write(f"{datetime.now(timezone.utc).isoformat()} {key} {e}\n")
            continue
        append_jsonl(path, {"run": run, "qid": a["qid"], "condition": a["condition"],
                            "judge_model_requested": judge_model, "judge_model_served": j["model"],
                            "claims": j["claims"], "usage": j["usage"],
                            "time": datetime.now(timezone.utc).isoformat(timespec="seconds")})
        logger.info("[%d/%d] %s judged: %d claims", i, len(todo), key, len(j["claims"]))


# ---------------------------------------------------------------------------
# Stage: report
# ---------------------------------------------------------------------------
def stage_report(dataset, run, online=True):
    res_dir, plot_dir = out_dirs(dataset, run)
    answers = read_jsonl(res_dir / "answers.jsonl")
    judgements = read_jsonl(res_dir / "judgements.jsonl")
    questions = load_questions()
    conds = RUNS[run]["conditions"]
    if not answers:
        raise SystemExit(f"No answers yet. Run: python -m eval.run_eval answer --run {run}")

    # ---- Measure 1: one row per claim --------------------------------------------
    claim_rows = []
    for key, j in judgements.items():
        a = answers[key]
        for k, c in enumerate(j["claims"], 1):
            claim_rows.append({"qid": a["qid"], "condition": a["condition"], "type": a["type"],
                               "true_label": a["true_label"], "predicted_label": a["predicted_label"],
                               "claim_no": k, "claim": c["claim"], "verdict": c["verdict"],
                               "reason": c.get("reason", ""), "judge_model": j["judge_model_served"]})
    claims = pd.DataFrame(claim_rows, columns=["qid", "condition", "type", "true_label", "predicted_label",
                                               "claim_no", "claim", "verdict", "reason", "judge_model"])
    claims.to_csv(res_dir / "claims.csv", index=False)

    # ---- Measure 2: IDs in every answer ------------------------------------------
    id_rows = []
    for key, a in answers.items():
        given = {m["id"] for cid in a["evidence_ids"] for m in extract_ids(kb_chunks()[cid]["text"])}
        for r in check_ids(a["answer"], a["question"], a["predicted_label"], evidence_ids=given, online=online):
            id_rows.append({"qid": a["qid"], "condition": a["condition"], "type": a["type"], **r})
    ids = pd.DataFrame(id_rows, columns=["qid", "condition", "type", "id", "id_type", "official_name",
                                         "status_in_files", "outcome", "note", "was_in_evidence"])
    ids.to_csv(res_dir / "id_checks.csv", index=False)

    # ---- Summary per condition -----------------------------------------------------
    summary = []
    for cond in conds:
        r = rates(claims[claims.condition == cond]["verdict"].tolist())
        ic = ids[ids.condition == cond]
        n_ids, n_fab = len(ic), int((ic["outcome"] == "fabricated").sum())
        n_mis = int((ic["outcome"] == "mismatched").sum())
        summary.append({
            "run": run, "model": role_settings(RUNS[run]["role"])["model"],
            "condition": f"{cond} ({CONDITION_NAMES[cond]})",
            "answers": sum(1 for x in answers.values() if x["condition"] == cond),
            "answers_judged": sum(1 for x in judgements.values() if x["condition"] == cond),
            "claims": r["claims"],
            "strict_rate (contradicted / claims)": pct(r["contradicted"], r["claims"]),
            "unsupported_rate ((contradicted + not in evidence) / claims)":
                pct(r["contradicted"] + r["not_in_evidence"], r["claims"]),
            "IDs mentioned": n_ids,
            "fabricated IDs": pct(n_fab, n_ids),
            "mismatched IDs": pct(n_mis, n_ids),
            # machine-readable copies for the charts
            "n_contradicted": r["contradicted"], "n_not_in_evidence": r["not_in_evidence"],
            "n_fabricated": n_fab, "n_ids": n_ids,
        })
    sdf = pd.DataFrame(summary)
    sdf.to_csv(res_dir / "summary.csv", index=False)

    # ---- Breakdown by question type --------------------------------------------------
    by_type = []
    for (qtype, cond), g in claims.groupby(["type", "condition"]):
        r = rates(g["verdict"].tolist())
        by_type.append({"question_type": qtype, "condition": cond, "claims": r["claims"],
                        "contradicted": pct(r["contradicted"], r["claims"]),
                        "unsupported": pct(r["contradicted"] + r["not_in_evidence"], r["claims"])})
    pd.DataFrame(by_type).to_csv(res_dir / "by_question_type.csv", index=False)

    plot_rates(sdf, plot_dir / "hallucination_rates.png", f"Hallucination by condition ({sdf['model'][0]})")
    write_examples(claims, ids, answers, res_dir / "hallucination_examples.md")
    write_hand_marking_files(answers, judgements, questions, res_dir, run)

    print("\nSUMMARY (counts shown next to every percentage; the sample is small)\n")
    print(sdf[[c for c in sdf.columns if not c.startswith("n_")]].set_index("condition").T.to_string())
    print("\nBy question type:\n" + pd.DataFrame(by_type).to_string(index=False))
    print(f"\nFiles written to {res_dir} and {plot_dir}")
    if len(judgements) < len(answers):
        print(f"WARNING: only {len(judgements)} of {len(answers)} answers are judged so far.")


def plot_rates(sdf, path, title):
    """Grouped bars: one group per measure, one bar per condition (or run+condition)."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    measures = [("Strict rate\n(contradicted)", lambda r: (r.n_contradicted, r.claims)),
                ("Unsupported rate\n(contradicted + not in evidence)",
                 lambda r: (r.n_contradicted + r.n_not_in_evidence, r.claims)),
                ("Fabricated-ID rate", lambda r: (r.n_fabricated, r.n_ids))]
    palette = ["#2f6690", "#c8553d", "#7a9e7e", "#8c6bb1", "#d9a441", "#5b5b5b"]
    rows = list(sdf.itertuples())
    width = 0.8 / len(rows)
    fig, ax = plt.subplots(figsize=(10, 5))
    for k, r in enumerate(rows):
        xs, vals, labels = [], [], []
        for i, (_, f) in enumerate(measures):
            num, den = f(r)
            xs.append(i - 0.4 + width * (k + 0.5))
            vals.append(100 * num / den if den else 0)
            labels.append(f"{num}/{den}")
        name = r.condition if sdf["run"].nunique() == 1 else f"{r.model}: {r.condition}"
        bars = ax.bar(xs, vals, width, label=name, color=palette[k % len(palette)])
        for b, lab in zip(bars, labels):
            ax.annotate(lab, (b.get_x() + b.get_width() / 2, b.get_height()), ha="center", va="bottom",
                        fontsize=8, xytext=(0, 2), textcoords="offset points")
    ax.set_xticks(range(len(measures)), [m[0] for m in measures])
    ax.set_ylabel("% (count shown on each bar)")
    ax.set_title(title)
    ax.legend(frameon=False, fontsize=9)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def write_examples(claims, ids, answers, path, n=10):
    """Real hallucination examples for the report: contradicted claims first,
    then fabricated/mismatched IDs, then not-in-evidence claims from condition B."""
    lines = ["# Hallucination examples (picked automatically; check them before quoting)\n"]
    picks = []
    for verdict, cond in (("CONTRADICTED", None), ("NOT_IN_EVIDENCE", "B")):
        g = claims[claims.verdict == verdict]
        if cond:
            g = g[g.condition == cond]
        picks += [("claim", r) for _, r in g.head(4).iterrows()]
    picks += [("id", r) for _, r in ids[ids.outcome.isin(["fabricated", "mismatched"])].head(4).iterrows()]
    for kind, r in picks[:n]:
        a = answers[f"{r['qid']}|{r['condition']}"]
        if kind == "claim":
            lines.append(f"## {r['qid']} condition {r['condition']}: {r['verdict']}\n"
                         f"- Question: {a['question']}\n- Detector said: {a['predicted_label']}\n"
                         f"- Claim: {r['claim']}\n- Judge's reason: {r['reason']}\n")
        else:
            lines.append(f"## {r['qid']} condition {r['condition']}: {r['outcome']} ID {r['id']}\n"
                         f"- Question: {a['question']}\n- Detector said: {a['predicted_label']}\n"
                         f"- Note: {r['note']}; official name: {r['official_name']}\n")
        lines.append("<details><summary>Full answer</summary>\n\n" + a["answer"] + "\n\n</details>\n")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_hand_marking_files(answers, judgements, questions, res_dir, run):
    """Files the student fills in by hand.
    - trap_answers.csv is rebuilt on every report (new answers appear), KEEPING any marks
      already typed in, matched by question ID and condition.
    - judge_audit.csv (main run only) is created once EVERY answer is judged (so the
      random 20 are drawn from all answers), and is never changed after that."""
    col = "human_correct (yes/no)"
    trap_path = res_dir / "trap_answers.csv"
    old_marks = {}
    if trap_path.exists():
        for r in pd.read_csv(trap_path, dtype=str).fillna("").to_dict("records"):
            old_marks[(r["qid"], r["condition"])] = r.get(col, "")
    traps = {q["id"]: q for q in questions if q["type"] == "trap"}
    rows = [{"qid": a["qid"], "condition": a["condition"], "question": a["question"],
             "why_trap": traps[a["qid"]]["why_trap"], "answer": a["answer"],
             "keyword_hint_says_refused": "yes" if refusal_hint(a["answer"]) else "no",
             col: old_marks.get((a["qid"], a["condition"]), "")}
            for _, a in sorted(answers.items()) if a["qid"] in traps]
    trap_df = pd.DataFrame(rows, columns=["qid", "condition", "question", "why_trap", "answer",
                                          "keyword_hint_says_refused", col])
    trap_df.to_csv(trap_path, index=False)

    marked = trap_df[trap_df[col].astype(str).str.strip().str.lower().isin(["yes", "no"])]
    if len(marked):
        print("\nTRAP QUESTIONS (your marks):")
        for cond, g in marked.groupby("condition"):
            ok = int((g[col].str.strip().str.lower() == "yes").sum())
            print(f"  condition {cond}: correctly said 'not available' in {pct(ok, len(g))}")
    print(f"\nTrap answers: {len(trap_df)} in {trap_path.name}, {len(marked)} marked by you.")

    if run != AUDIT_RUN:
        return
    audit_path = res_dir / "judge_audit.csv"
    expected = len(questions) * len(RUNS[run]["conditions"])
    if audit_path.exists():
        return
    if len(judgements) < expected:
        print(f"judge_audit.csv not created yet: {len(judgements)} of {expected} answers judged.")
        return
    keys = sorted(judgements)
    random.Random(SEED).shuffle(keys)
    with open(audit_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["qid", "condition", "claim_no", "claim", "answer",
                    "human_verdict (SUPPORTED / CONTRADICTED / NOT_IN_EVIDENCE)"])
        for key in keys[:AUDIT_ANSWERS]:
            a = answers[key]
            for k, c in enumerate(judgements[key]["claims"], 1):
                w.writerow([a["qid"], a["condition"], k, c["claim"], a["answer"], ""])
    logger.info("Wrote %s (%d answers, judge's labels hidden): fill in the last column", audit_path, AUDIT_ANSWERS)


# ---------------------------------------------------------------------------
# Stage: agreement (main run)
# ---------------------------------------------------------------------------
def stage_agreement(dataset):
    res_dir, _ = out_dirs(dataset, AUDIT_RUN)
    audit = pd.read_csv(res_dir / "judge_audit.csv", dtype=str).fillna("")
    col = [c for c in audit.columns if c.startswith("human_verdict")][0]
    audit[col] = audit[col].str.strip().str.upper().str.replace(" ", "_")
    audit = audit[audit[col].isin(["SUPPORTED", "CONTRADICTED", "NOT_IN_EVIDENCE"])]
    judgements = read_jsonl(res_dir / "judgements.jsonl")
    judge = [judgements[f"{r.qid}|{r.condition}"]["claims"][int(r.claim_no) - 1]["verdict"]
             for r in audit.itertuples()]
    result = agreement(audit[col].tolist(), judge)
    (res_dir / "agreement.json").write_text(json.dumps(result, indent=1))
    print(f"Claims compared: {result['items']}")
    print(f"Percent agreement: {pct(result['agreements'], result['items'])}")
    print(f"Cohen's kappa: {result['cohens_kappa']:.3f}" if result["items"] else "No marked rows found.")


# ---------------------------------------------------------------------------
# Stage: compare (all runs)
# ---------------------------------------------------------------------------
def stage_compare(dataset):
    p = dataset_paths(dataset)
    frames = [pd.read_csv(p["results_dir"] / run / "summary.csv") for run in RUNS
              if (p["results_dir"] / run / "summary.csv").exists()]
    if not frames:
        raise SystemExit("No run has a report yet.")
    df = pd.concat(frames, ignore_index=True)
    df.to_csv(p["results_dir"] / "comparison.csv", index=False)
    plot_rates(df, p["plots_dir"] / "comparison.png", "Hallucination by model and condition")
    print(df[[c for c in df.columns if not c.startswith("n_")]].to_string(index=False))
    print(f"\nWrote {p['results_dir'] / 'comparison.csv'} and {p['plots_dir'] / 'comparison.png'}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stage", choices=["budget", "answer", "judge", "report", "agreement", "compare"])
    ap.add_argument("--run", choices=list(RUNS), default="main")
    ap.add_argument("--dataset", default=DEFAULT_DATASET)
    ap.add_argument("--limit", type=int, help="only the first N questions (answer) / N answers (judge)")
    ap.add_argument("--offline", action="store_true", help="report: do not ask NVD about unknown CVEs")
    a = ap.parse_args()
    {"budget": lambda: stage_budget(a.dataset, a.run),
     "answer": lambda: stage_answer(a.dataset, a.run, a.limit),
     "judge": lambda: stage_judge(a.dataset, a.run, a.limit),
     "report": lambda: stage_report(a.dataset, a.run, online=not a.offline),
     "agreement": lambda: stage_agreement(a.dataset),
     "compare": lambda: stage_compare(a.dataset)}[a.stage]()
