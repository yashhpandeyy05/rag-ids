"""
Milestones 4 and 7 - the assistant.

    python -m src.assistant --sample sample_00004 "What is this traffic and why was it flagged?"
    python -m src.assistant --sample sample_00004 --no-retrieval "..."   # condition A
    python -m src.assistant --sample sample_00004 --mode tool "..."      # tool calling
    python -m src.assistant "What is a TCP Xmas scan?"                    # general question

Fixed pipeline (always works):
    sample -> detect() -> retrieve() -> LLM -> answer

Tool-calling mode: the LLM decides when to call
    run_detector(sample_id)   and   search_knowledge(query)
one call at a time, at most four per question. On any error it falls back to
the fixed pipeline automatically, and the reason is logged and returned.
"""

import argparse
import json
import logging
from typing import Any, Dict, List, Optional

from src import prompts
from src.config import DEFAULT_DATASET, get_dataset_config
from src.detector import detect, load_test_sample
from src.llm_client import DailyLimitReached, chat
from src.retriever import format_detection, retrieve

logger = logging.getLogger("assistant")

MAX_TOOL_CALLS = 4
SEARCH_TOOL_CHUNKS = 4

TOOLS = [
    {"type": "function", "function": {
        "name": "run_detector",
        "description": "Run the intrusion detector on one traffic sample from the test pool. "
                       "Returns the predicted label, confidence and the most important flow features.",
        "parameters": {"type": "object", "properties": {
            "sample_id": {"type": "string", "description": "Sample ID such as 'sample_00004'."}},
            "required": ["sample_id"]}}},
    {"type": "function", "function": {
        "name": "search_knowledge",
        "description": "Search the threat knowledge base (MITRE ATT&CK, CAPEC, CVE records, label cards, "
                       "feature glossary). Returns tagged entries.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string", "description": "What to look for, in plain words."}},
            "required": ["query"]}}},
]


# ---------------------------------------------------------------------------
# Fixed pipeline
# ---------------------------------------------------------------------------
def run_detection(sample_id: Optional[str], dataset: str) -> Optional[Dict[str, Any]]:
    if not sample_id:
        return None
    row = load_test_sample(sample_id, dataset)
    if row is None:
        raise ValueError(f"Sample '{sample_id}' is not in the {dataset} test pool.")
    return detect(row, dataset)


def build_messages(question: str, det: Optional[Dict[str, Any]], use_retrieval: bool):
    """The exact messages sent to the answering model, plus the evidence used.
    Shared by the app and the evaluation, so both conditions are built identically."""
    if use_retrieval:
        r = retrieve(question, det)
        user = prompts.USER_TEMPLATE_WITH_EVIDENCE.format(evidence=r["evidence_text"], question=question)
        system = prompts.GROUNDED_SYSTEM
        chunks, warnings = r["chunks"], r["warnings"]
    else:
        det_text = format_detection(det) if det else "[DET] No traffic sample was given."
        user = prompts.USER_TEMPLATE_DET_ONLY.format(det=det_text, question=question)
        system = prompts.NO_RETRIEVAL_SYSTEM
        chunks, warnings = [], []
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    return messages, chunks, warnings


def build_raw_feature_messages(question: str, row, dataset: str = DEFAULT_DATASET):
    """Evaluation condition C: the flow's raw feature values, no detector output and no
    retrieval. Shows what the detector contributes."""
    cfg = get_dataset_config(dataset)
    skip = set(cfg.get("drop_columns", [])) | {cfg["label_column"], "sample_id"}
    features = "\n".join(f"{k} = {v}" for k, v in row.items() if k not in skip)
    user = prompts.USER_TEMPLATE_RAW.format(features=features, question=question)
    return [{"role": "system", "content": prompts.RAW_FEATURES_SYSTEM}, {"role": "user", "content": user}]


def answer_fixed(question: str, sample_id: Optional[str] = None, dataset: str = DEFAULT_DATASET,
                 use_retrieval: bool = True) -> Dict[str, Any]:
    det = run_detection(sample_id, dataset)
    messages, chunks, warnings = build_messages(question, det, use_retrieval)
    res = chat("answering", messages)
    return {"answer": res["content"], "mode": "fixed", "retrieval": use_retrieval, "detection": det,
            "evidence_chunks": chunks, "warnings": warnings, "model": res["model"],
            "usage": res["usage"], "cached": res["cached"], "tool_trace": [], "fallback_reason": None}


# ---------------------------------------------------------------------------
# Tool-calling mode
# ---------------------------------------------------------------------------
def answer_with_tools(question: str, sample_id: Optional[str] = None,
                      dataset: str = DEFAULT_DATASET) -> Dict[str, Any]:
    """Let the LLM call the tools itself. Falls back to the fixed pipeline on any error."""
    try:
        return _tool_loop(question, sample_id, dataset)
    except DailyLimitReached:
        raise
    except Exception as e:  # noqa: BLE001 - any failure -> fixed pipeline, as specified
        reason = f"{type(e).__name__}: {e}"
        logger.warning("Tool calling failed (%s); falling back to the fixed pipeline.", reason)
        out = answer_fixed(question, sample_id, dataset, use_retrieval=True)
        out["fallback_reason"] = reason
        return out


def _tool_loop(question, sample_id, dataset) -> Dict[str, Any]:
    user = f"Traffic sample ID: {sample_id}\n\nQUESTION: {question}" if sample_id else f"QUESTION: {question}"
    messages: List[Dict[str, Any]] = [{"role": "system", "content": prompts.TOOL_SYSTEM},
                                      {"role": "user", "content": user}]
    det, chunks, trace, seen = None, [], [], set()

    for _ in range(MAX_TOOL_CALLS):
        res = chat("answering", messages, tools=TOOLS)
        if not res["tool_calls"]:
            return _tool_result(res, det, chunks, trace)
        call = res["tool_calls"][0]            # one call at a time
        if len(res["tool_calls"]) > 1:
            logger.info("Model asked for %d tool calls at once; running only the first.", len(res["tool_calls"]))
        name = call["function"]["name"]
        args = json.loads(call["function"].get("arguments") or "{}")

        if name == "run_detector":
            try:
                det = run_detection(args.get("sample_id"), dataset)
                output = format_detection(det)
            except ValueError as e:
                output = f"ERROR: {e}"
        elif name == "search_knowledge":
            # Uses the same retrieval as the fixed pipeline, so once the detector
            # has run, the label lookup is included too.
            r = retrieve(args.get("query", ""), det, max_chunks=SEARCH_TOOL_CHUNKS)
            new = [c for c in r["chunks"] if c["chunk_id"] not in seen]
            seen.update(c["chunk_id"] for c in new)
            chunks.extend(new)
            output = "\n\n".join(c["text"] for c in r["chunks"]) or "No matching entries."
        else:
            raise ValueError(f"Model called an unknown tool '{name}'")
        trace.append({"tool": name, "arguments": args})
        messages.append({"role": "assistant", "content": res["content"] or None,
                         "tool_calls": [{"id": call["id"], "type": "function",
                                         "function": {"name": name, "arguments": call["function"]["arguments"]}}]})
        messages.append({"role": "tool", "tool_call_id": call["id"], "content": output})

    # Tool budget used up: ask for the final answer. The tools stay listed (some APIs
    # reject tool messages without them) but tool_choice="none" forbids calling them.
    messages.append({"role": "user", "content": "You have used all tool calls. Write the final answer now "
                                                "from the evidence you have."})
    res = chat("answering", messages, tools=TOOLS, tool_choice="none")
    return _tool_result(res, det, chunks, trace)


def _tool_result(res, det, chunks, trace) -> Dict[str, Any]:
    return {"answer": res["content"], "mode": "tool", "retrieval": True, "detection": det,
            "evidence_chunks": chunks, "warnings": [], "model": res["model"], "usage": res["usage"],
            "cached": res["cached"], "tool_trace": trace, "fallback_reason": None}


def answer(question: str, sample_id: Optional[str] = None, dataset: str = DEFAULT_DATASET,
           use_retrieval: bool = True, mode: str = "fixed") -> Dict[str, Any]:
    """Entry point for the app. Tool mode always uses retrieval."""
    if mode == "tool" and use_retrieval:
        return answer_with_tools(question, sample_id, dataset)
    return answer_fixed(question, sample_id, dataset, use_retrieval)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("question")
    ap.add_argument("--sample", help="test-set sample ID, e.g. sample_00004")
    ap.add_argument("--dataset", default=DEFAULT_DATASET)
    ap.add_argument("--no-retrieval", action="store_true", help="condition A: detector output only")
    ap.add_argument("--mode", choices=["fixed", "tool"], default="fixed")
    a = ap.parse_args()

    out = answer(a.question, a.sample, a.dataset, not a.no_retrieval, a.mode)
    if out["detection"]:
        print(format_detection(out["detection"]), "\n")
    if out["evidence_chunks"]:
        print("Evidence used:", ", ".join(c["chunk_id"] for c in out["evidence_chunks"]))
    if out["tool_trace"]:
        print("Tool calls:", out["tool_trace"])
    if out["fallback_reason"]:
        print("FELL BACK to the fixed pipeline because:", out["fallback_reason"])
    print("\n" + "-" * 70 + "\n" + out["answer"] + "\n" + "-" * 70)
    print(f"model={out['model']} tokens={out['usage'].get('total_tokens')} cached={out['cached']}")
