"""
Web server for the RAG-IDS range.

    python -m web.server            # then open http://127.0.0.1:8000

The page itself is in web/static/ (plain HTML, CSS and JavaScript, no build step).
This file is only the data side: it runs the detector, the retrieval and the LLM
and returns JSON.
"""

import json
import logging
import random
import threading
from contextlib import asynccontextmanager
import os
from pathlib import Path
from typing import Literal, Optional

import io
import time
import pandas as pd
import uvicorn
from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Query
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

logger = logging.getLogger("web.server")

from src import presentation as pres
from src.assistant import answer
from src.config import (DEFAULT_DATASET, EVAL_PLOTS_DIR, dataset_paths, get_dataset_config,
                        get_llm_config, trained_datasets)
from src.detector import detect, load_test_sample, store_custom_sample
from src.evaluation import check_ids, normalize_dashes
from src import llm_client
from src.llm_client import LLMError
from src.retriever import glossary, semantic_search
from src.security_eval import (DEFAULT_SECURITY_AUTH_TOKEN, run_membership_inference_attack,
                               run_data_poisoning_attack, run_retrieved_leakage_attack,
                               parse_uploaded_dataset, get_sample_preset_dataset,
                               simulate_custom_dataset_mia, simulate_custom_dataset_poisoning,
                               simulate_custom_dataset_leakage)

STATIC = Path(__file__).resolve().parent / "static"
LLM_LOCK = threading.Lock()   # one LLM question at a time keeps the free-plan pacing simple
SECURITY_AUTH_KEY = os.getenv("SECURITY_EVAL_SECRET_KEY", DEFAULT_SECURITY_AUTH_TOKEN)
_POOLS = {}


def pool(dataset: str):
    if dataset not in _POOLS:
        _POOLS[dataset] = json.loads(dataset_paths(dataset)["pool"].read_text())
    return _POOLS[dataset]


@asynccontextmanager
async def lifespan(app):
    llm_client.FALLBACK_ENABLED = True   # the demo may use the fallback models; the evaluation never does
    # Load the model and the embedder once, so the first launch is instant.
    detect(load_test_sample("sample_00000", DEFAULT_DATASET), DEFAULT_DATASET)
    semantic_search("warm up", 1)
    print("RAG-IDS range ready: http://127.0.0.1:8000")
    yield


app = FastAPI(title="RAG-IDS range", lifespan=lifespan)


@app.middleware("http")
async def add_no_cache_headers(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static/") or request.url.path == "/":
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# ---------------------------------------------------------------------------
# Meta: everything the lab screen needs
# ---------------------------------------------------------------------------
@app.get("/api/meta")
def meta(dataset: str = DEFAULT_DATASET):
    cfg = get_dataset_config(dataset)
    metrics = json.loads((dataset_paths(dataset)["results_dir"] / "detector_metrics.json").read_text())
    by_label = {}
    for p in pool(dataset):
        by_label.setdefault(p["label"], {"family": p["attack_family"], "count": 0})["count"] += 1
    scenarios = []
    for label, info in by_label.items():
        sc = pres.scenario(label, info["family"])
        sc["count"] = info["count"]
        sc["attack"] = info["family"] != "Normal"
        scenarios.append(sc)
    order = ["DoS", "Brute force", "Spoofing", "Reconnaissance"]
    scenarios.sort(key=lambda s: (not s["attack"], order.index(s["family"]) if s["family"] in order else 9, s["headline"]))
    return {"dataset": dataset, "dataset_name": cfg["dataset_name"], "citation": cfg.get("citation", ""),
            "datasets": trained_datasets(), "scenarios": scenarios, "test_flows": len(pool(dataset)),
            "macro_f1": metrics["test"]["macro_f1"], "labels": len(by_label),
            "answer_model": get_llm_config()["roles"]["answering"]["model"], "colors": pres.FAMILY_COLORS,
            "security_auth_token": SECURITY_AUTH_KEY}


# ---------------------------------------------------------------------------
# Launch: choose a real flow, run the detector
# ---------------------------------------------------------------------------
class LaunchReq(BaseModel):
    dataset: str = DEFAULT_DATASET
    label: Optional[str] = None
    mystery: bool = False
    sample_id: Optional[str] = None


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def extract_flow_facts(row: dict, cfg: dict, num_features: int) -> dict:
    if "proto" in row and row["proto"]:
        service = str(row.get("service", "-"))
        proto_str = str(row["proto"]).upper() + ("" if service in ["-", ""] else f" · {service}")
    elif "Protocol Type" in row:
        pt = _num(row["Protocol Type"])
        if pt == 6 or row.get("TCP") == 1:
            proto_str = "TCP"
        elif pt == 17 or row.get("UDP") == 1:
            proto_str = "UDP"
        elif pt == 1 or row.get("ICMP") == 1:
            proto_str = "ICMP"
        else:
            proto_str = f"Proto #{int(pt)}"
    elif row.get("TCP") == 1:
        proto_str = "TCP"
    elif row.get("UDP") == 1:
        proto_str = "UDP"
    elif row.get("ICMP") == 1:
        proto_str = "ICMP"
    else:
        proto_str = "Network IP"

    port_col = (cfg.get("port_columns") or [None])[0]
    port_val = None
    if port_col and port_col in row and row[port_col] is not None and not pd.isna(row[port_col]):
        port_val = int(_num(row[port_col]))
    else:
        for p_col in ["id.resp_p", "Dst Port", "dst_port", "port"]:
            if p_col in row and row[p_col] is not None and not pd.isna(row[p_col]):
                port_val = int(_num(row[p_col]))
                break

    duration_str = None
    for d_col in ["flow_duration", "Duration", "duration", "IAT"]:
        if d_col in row and row[d_col] is not None and not pd.isna(row[d_col]):
            duration_str = pres.fmt_duration(_num(row[d_col]))
            break
    if not duration_str:
        duration_str = "Live Stream"

    if "fwd_pkts_tot" in row:
        pkts_out = int(_num(row.get("fwd_pkts_tot", 0)))
        pkts_back = int(_num(row.get("bwd_pkts_tot", 0)))
    elif "Rate" in row:
        pkts_out = int(_num(row.get("Rate", 0)))
        pkts_back = int(_num(row.get("Number", 0)))
    elif "Number" in row:
        pkts_out = int(_num(row.get("Number", 0)))
        pkts_back = 0
    else:
        pkts_out = 1
        pkts_back = 0

    return {
        "protocol": proto_str,
        "port": port_val,
        "duration": duration_str,
        "packets_out": pkts_out,
        "packets_back": pkts_back,
        "features": num_features
    }


@app.post("/api/launch")
def launch(req: LaunchReq):
    cfg = get_dataset_config(req.dataset)
    flows = pool(req.dataset)
    if req.sample_id:
        sample_id = req.sample_id
    elif req.mystery:
        sample_id = random.choice(flows)["sample_id"]
    else:
        options = [p["sample_id"] for p in flows if p["label"] == req.label]
        if not options:
            raise HTTPException(404, f"No flows with label '{req.label}'.")
        sample_id = random.choice(options)
    row = load_test_sample(sample_id, req.dataset)
    if row is None:
        raise HTTPException(404, f"There is no flow called '{sample_id}'. "
                                 f"IDs run from sample_00000 to sample_{len(flows) - 1:05d}.")
    det = detect(row, req.dataset)
    true_label = row[cfg["label_column"]]
    true_family = cfg["label_to_family"].get(true_label, "Other")
    gloss = glossary()
    skip = set(cfg.get("drop_columns", [])) | {cfg["label_column"], "sample_id"}
    row_dict = dict(row)
    features = []
    for f in det["top_features"]:
        g = gloss.get(f["feature"], {})
        features.append({"name": f["feature"], "meaning": g.get("meaning", f"Measured {f['feature']} value"),
                         "value": pres.fmt_value(f["value"], g.get("unit", "")), "push": f["contribution"]})
    return {
        "sample_id": sample_id,
        "facts": extract_flow_facts(row_dict, cfg, len([c for c in row.index if c not in skip])),
        "true": {"label": true_label, "family": true_family, "name": pres.pretty_label(true_label),
                 "scenario": pres.scenario(true_label, true_family)},
        "detection": {"label": det["predicted_label"], "name": pres.pretty_label(det["predicted_label"]),
                      "family": det["attack_family"], "color": pres.FAMILY_COLORS.get(det["attack_family"], "#8A94A6"),
                      "is_attack": det["is_attack"], "confidence": det["confidence"],
                      "low_confidence": det["low_confidence"], "probabilities": det["probabilities"],
                      "correct": det["predicted_label"] == true_label, "features": features,
                      "references": pres.mapped_refs(det["predicted_label"])},
    }


# ---------------------------------------------------------------------------
# Upload attack flow: user brings their own file (.csv, .json, .txt)
# ---------------------------------------------------------------------------
@app.post("/api/upload-attack")
async def upload_attack(file: UploadFile = File(...), dataset: str = Query(DEFAULT_DATASET)):
    try:
        content_bytes = await file.read()
        filename = file.filename or "uploaded_traffic.csv"
        ext = Path(filename).suffix.lower()

        df = None
        if ext in [".csv", ".tsv", ".txt"]:
            try:
                df = pd.read_csv(io.BytesIO(content_bytes))
            except Exception:
                try:
                    df = pd.read_csv(io.BytesIO(content_bytes), sep=None, engine="python")
                except Exception:
                    try:
                        data = json.loads(content_bytes.decode("utf-8", errors="replace"))
                        df = pd.DataFrame([data] if isinstance(data, dict) else data)
                    except Exception:
                        pass
        elif ext in [".json", ".jsonl"]:
            text_str = content_bytes.decode("utf-8", errors="replace").strip()
            if ext == ".jsonl" or ("\n" in text_str and not text_str.startswith("[")):
                records = [json.loads(line) for line in text_str.splitlines() if line.strip()]
                df = pd.DataFrame(records)
            else:
                data = json.loads(text_str)
                df = pd.DataFrame([data] if isinstance(data, dict) else data)
        elif ext == ".parquet":
            df = pd.read_parquet(io.BytesIO(content_bytes))

        if df is None or df.empty:
            raise HTTPException(400, "Could not extract valid traffic rows from uploaded file. Please upload a CSV, JSON, or TXT file.")

        row = df.iloc[0].to_dict()

        # Schema auto-detection: determine if the file matches ciciot2023 or rt_iot2022
        cols_lower = [c.lower() for c in df.columns]
        target_dataset = dataset
        if any(c in cols_lower for c in ["header_length", "rate", "tot size", "protocol type", "syn_count", "iat", "time_to_live"]):
            target_dataset = "ciciot2023"
        elif any(c in cols_lower for c in ["fwd_pkts_tot", "flow_duration", "bwd_pkts_tot", "id.resp_p"]):
            target_dataset = "rt_iot2022"

        # Check if true ground truth label is provided in the file
        possible_labels = ["Label", "label", "Attack_type", "attack_type", "class", "target", "attack"]
        true_label = None
        for l_col in df.columns:
            if l_col in possible_labels and l_col in row and row[l_col]:
                val = str(row[l_col]).strip()
                if val:
                    true_label = val
                    break

        sample_id = f"upload_{int(time.time() * 1000) % 1000000:06d}"
        row["sample_id"] = sample_id
        row_series = pd.Series(row)
        store_custom_sample(sample_id, row_series)

        # Run detection using the appropriate dataset model
        det = detect(row_series, target_dataset)
        cfg = get_dataset_config(target_dataset)

        has_ground_truth = bool(true_label and true_label in cfg.get("label_to_family", {}))
        if not has_ground_truth:
            true_label = det["predicted_label"]

        true_family = cfg.get("label_to_family", {}).get(true_label, det["attack_family"])

        # Extract REAL facts directly from the file (NO FAKE / MADE-UP NUMBERS)
        # 1. Protocol
        proto_str = None
        if "proto" in row and row["proto"]:
            proto_str = str(row["proto"]).upper()
            if "service" in row and str(row["service"]) not in ["-", ""]:
                proto_str += f" · {row['service']}"
        elif "Protocol Type" in row:
            pt = _num(row["Protocol Type"])
            if pt == 6 or row.get("TCP") == 1:
                proto_str = "TCP"
            elif pt == 17 or row.get("UDP") == 1:
                proto_str = "UDP"
            elif pt == 1 or row.get("ICMP") == 1:
                proto_str = "ICMP"
            else:
                proto_str = f"Proto #{int(pt)}"
        elif row.get("TCP") == 1:
            proto_str = "TCP"
        elif row.get("UDP") == 1:
            proto_str = "UDP"
        elif row.get("ICMP") == 1:
            proto_str = "ICMP"
        else:
            proto_str = "Network IP"

        # 2. Port (only if present in uploaded columns)
        port_val = None
        for p_col in ["id.resp_p", "Dst Port", "dst_port", "port", "Port"]:
            if p_col in row and row[p_col] is not None and not pd.isna(row[p_col]):
                port_val = int(_num(row[p_col]))
                break

        # 3. Duration (only if present in uploaded columns)
        duration_str = None
        for d_col in ["flow_duration", "Duration", "duration", "IAT"]:
            if d_col in row and row[d_col] is not None and not pd.isna(row[d_col]):
                duration_str = pres.fmt_duration(_num(row[d_col]))
                break
        if not duration_str:
            duration_str = "Live Stream"

        # 4. Packets / Rate (real metrics only)
        if "fwd_pkts_tot" in row:
            pkts_out = int(_num(row.get("fwd_pkts_tot", 0)))
            pkts_back = int(_num(row.get("bwd_pkts_tot", 0)))
        elif "Rate" in row:
            pkts_out = int(_num(row.get("Rate", 0)))
            pkts_back = int(_num(row.get("Number", 0)))
        elif "Number" in row:
            pkts_out = int(_num(row.get("Number", 0)))
            pkts_back = 0
        else:
            pkts_out = len(df)
            pkts_back = 0

        # Build dynamic real preview attributes
        real_preview_stats = []
        real_preview_stats.append({"label": "Protocol", "value": proto_str})
        if port_val is not None:
            real_preview_stats.append({"label": "Target Port", "value": str(port_val)})
        if "Rate" in row and not pd.isna(row["Rate"]):
            real_preview_stats.append({"label": "Packet Rate", "value": f"{_num(row['Rate']):,.1f} /s"})
        if "Tot size" in row and not pd.isna(row["Tot size"]):
            real_preview_stats.append({"label": "Total Size", "value": f"{_num(row['Tot size']):,.0f} B"})
        elif "flow_fwd_bytes" in row and not pd.isna(row["flow_fwd_bytes"]):
            real_preview_stats.append({"label": "Bytes", "value": f"{_num(row['flow_fwd_bytes']):,.0f} B"})
        if "Header_Length" in row and not pd.isna(row["Header_Length"]):
            real_preview_stats.append({"label": "Header Length", "value": f"{_num(row['Header_Length']):,.0f} B"})
        if "Time_To_Live" in row and not pd.isna(row["Time_To_Live"]):
            real_preview_stats.append({"label": "TTL", "value": str(int(_num(row['Time_To_Live'])))})
        real_preview_stats.append({"label": "Dataset Model", "value": target_dataset.upper()})

        gloss = glossary()
        features = []
        for f in det["top_features"]:
            g = gloss.get(f["feature"], {})
            features.append({
                "name": f["feature"],
                "meaning": g.get("meaning", f"Measured {f['feature']} value"),
                "value": pres.fmt_value(f["value"], g.get("unit", "")),
                "push": f["contribution"]
            })

        scenario = pres.scenario(det["predicted_label"], det["attack_family"])
        scenario["headline"] = pres.pretty_label(det["predicted_label"])
        scenario["story"] = f"Analyzed flow from '{filename}' classified as {det['predicted_label']} ({det['attack_family']}) by {target_dataset.upper()} detector."

        return {
            "sample_id": sample_id,
            "filename": filename,
            "target_dataset": target_dataset,
            "total_rows": len(df),
            "columns_found": len(df.columns),
            "has_ground_truth": has_ground_truth,
            "preview_stats": real_preview_stats,
            "facts": extract_flow_facts(row, cfg, len(df.columns)),
            "true": {
                "label": true_label,
                "family": true_family,
                "name": pres.pretty_label(true_label),
                "scenario": scenario
            },
            "detection": {
                "label": det["predicted_label"],
                "name": pres.pretty_label(det["predicted_label"]),
                "family": det["attack_family"],
                "color": pres.FAMILY_COLORS.get(det["attack_family"], "#8A94A6"),
                "is_attack": det["is_attack"],
                "confidence": det["confidence"],
                "low_confidence": det["low_confidence"],
                "probabilities": det["probabilities"],
                "correct": det["predicted_label"] == true_label if has_ground_truth else True,
                "features": features,
                "references": pres.mapped_refs(det["predicted_label"])
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Upload attack flow failed: %s", e)
        raise HTTPException(500, f"Error processing uploaded traffic flow: {str(e)}")


@app.get("/api/sample-flow-template")
def sample_flow_template(dataset: str = Query("ciciot2023")):
    ds = dataset if dataset in ["ciciot2023", "rt_iot2022"] else DEFAULT_DATASET
    csv_path = dataset_paths(ds)["test"]
    df_sample = pd.read_parquet(csv_path).head(5)
    cols = [c for c in df_sample.columns if c != "sample_id"]
    csv_content = df_sample[cols].to_csv(index=False)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=sample_{ds}_attack_flow.csv"}
    )


@app.get("/api/sample-flow-preset")
def sample_flow_preset(dataset: str = Query(DEFAULT_DATASET), preset: str = Query("dos_syn")):
    ds = dataset if dataset in ["ciciot2023", "rt_iot2022"] else DEFAULT_DATASET
    pool_data = pool(ds)
    flow_meta = random.choice([p for p in pool_data if "SYN" in p["label"] or "Flood" in p["label"] or "Mirai" in p["label"]] or pool_data)
    sample = load_test_sample(flow_meta["sample_id"], ds)
    flow_dict = sample.to_dict()
    csv_df = pd.DataFrame([flow_dict])
    cols = [c for c in csv_df.columns if c != "sample_id"]
    csv_content = csv_df[cols].to_csv(index=False)
    return {"preset": preset, "dataset": ds, "csv": csv_content, "label": flow_meta["label"]}


# ---------------------------------------------------------------------------
# Ask: the assistant
# ---------------------------------------------------------------------------
class AskReq(BaseModel):
    dataset: str = DEFAULT_DATASET
    sample_id: Optional[str] = None
    question: str
    mode: Literal["memory", "kb", "compare"] = "kb"
    tools: bool = False


def _one(req: AskReq, use_retrieval: bool):
    out = answer(req.question, req.sample_id, req.dataset, use_retrieval, "tool" if (req.tools and use_retrieval) else "fixed")
    det = out["detection"]
    text = normalize_dashes(out["answer"])
    allowed = pres.allowed_tags(out["evidence_chunks"], det is not None) if use_retrieval else None
    flags = []
    if det:   # checking IDs against "the detected attack" only makes sense when there is a detection
        for r in check_ids(text, req.question, det["predicted_label"], online=False):
            flags.append({"id": r["id"], "outcome": r["outcome"], "note": r["note"], "name": r["official_name"]})
    return {"kind": "kb" if use_retrieval else "memory", "text": text,
            "tags": pres.tag_info(text, allowed, out["evidence_chunks"]), "id_flags": flags,
            "sources": [{"id": c["chunk_id"], "tag": c["tag"], "name": c["name"], "source": c["source"],
                         "url": c.get("url", ""), "kind": pres.tag_kind(c["tag"]),
                         "snippet": c["text"].split("\n", 2)[-1][:320]} for c in out["evidence_chunks"]],
            "model": out["model"], "cached": out["cached"], "mode": out["mode"],
            "fallback": out["model"] != get_llm_config()["roles"]["answering"]["model"],
            "tool_trace": out["tool_trace"], "fallback_reason": out["fallback_reason"], "warnings": out["warnings"]}


@app.post("/api/ask")
def ask(req: AskReq):
    question = req.question.strip()
    if not question:
        raise HTTPException(400, "Type a question first.")
    req.question = question
    try:
        with LLM_LOCK:
            if req.mode == "compare":
                return {"answers": [_one(req, False), _one(req, True)]}
            return {"answers": [_one(req, req.mode == "kb")]}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except LLMError as e:
        raise HTTPException(502, str(e))


# ---------------------------------------------------------------------------
# Results page
# ---------------------------------------------------------------------------
def _records(path: Path):
    return json.loads(pd.read_csv(path).to_json(orient="records")) if path.exists() else []


@app.get("/api/results")
def results(dataset: str = DEFAULT_DATASET):
    rd = dataset_paths(dataset)["results_dir"]
    metrics = json.loads((rd / "detector_metrics.json").read_text())
    per = _records(rd / "test_per_class.csv")
    for r in per:
        r["name"] = pres.pretty_label(r["label"])
    return {"dataset": dataset, "metrics": metrics, "per_label": per, "comparison": _records(rd / "model_comparison.csv"),
            "class_counts": _records(rd / "class_counts.csv"),
            "eval": {run: _records(rd / run / "summary.csv") for run in ("main", "small")},
            "confusion_png": f"/plots/{dataset}/confusion_matrix.png"}


# ---------------------------------------------------------------------------
# Security Evaluation Endpoints (arXiv:2509.20324v1 & arXiv:2510.25025)
# ---------------------------------------------------------------------------
def _check_security_auth(authorization: Optional[str] = Header(None),
                         x_security_key: Optional[str] = Header(None)):
    token = x_security_key or (authorization.replace("Bearer ", "").strip() if authorization else None)
    if not token or token != SECURITY_AUTH_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: Security evaluation endpoints require valid administrative authentication.")


class MembershipInferenceReq(BaseModel):
    sample_size: int = Field(default=6, ge=2, le=8, description="Number of member and non-member documents to evaluate")
    decision_threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Optional manual threshold")


class DataPoisoningReq(BaseModel):
    trigger_phrase: str = Field(default="[IOT-DEF-OVERRIDE]", min_length=3, max_length=80, description="Adversarial trigger token")
    num_queries: int = Field(default=3, ge=1, le=3, description="Number of trigger test queries to evaluate")


class RetrievedLeakageReq(BaseModel):
    num_canaries: int = Field(default=3, ge=1, le=3, description="Number of synthetic canary secrets to test")


@app.get("/api/security/meta")
def security_meta(authorization: Optional[str] = Header(None),
                  x_security_key: Optional[str] = Header(None)):
    _check_security_auth(authorization, x_security_key)
    return {
        "attacks": [
            {
                "id": "membership_inference",
                "name": "Document-Level Membership Inference (DL-MIA)",
                "paper": "arXiv:2509.20324v1, Sec IV-A (Behnia, Ebrahimi, Dutt et al.)",
                "description": "Evaluates whether an adversary can infer if a specific document is present in the RAG knowledge base using observable retrieval similarity and token containment scores.",
                "metrics": ["Precision", "Recall", "F1 Score", "ROC-AUC"]
            },
            {
                "id": "data_poisoning",
                "name": "Knowledge-Base Data Poisoning",
                "paper": "arXiv:2509.20324v1, Sec IV-C & arXiv:2510.25025 (RAGuard)",
                "description": "Injects crafted documents containing trigger tokens into an isolated test environment to evaluate whether malicious documents manipulate retrieved context and generated answers.",
                "metrics": ["RSR", "ASR", "RAGuard TS Score", "Cleanup Verified"]
            },
            {
                "id": "retrieved_leakage",
                "name": "Retrieved-Content Leakage & Access Isolation",
                "paper": "arXiv:2509.20324v1, Sec IV-B",
                "description": "Evaluates whether sensitive canary secrets leak into retrieved chunks and generated outputs under direct and adversarial prompt injection queries across tenant boundaries.",
                "metrics": ["Retrieval Leakage Rate", "Generation Leakage Rate", "Access Control Violation Rate"]
            }
        ]
    }


@app.post("/api/security/membership-inference")
def security_membership_inference(req: MembershipInferenceReq,
                                  authorization: Optional[str] = Header(None),
                                  x_security_key: Optional[str] = Header(None)):
    _check_security_auth(authorization, x_security_key)
    try:
        return run_membership_inference_attack(
            sample_size=req.sample_size,
            decision_threshold=req.decision_threshold,
        )
    except Exception as e:
        logger.exception("Membership inference attack failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/data-poisoning")
def security_data_poisoning(req: DataPoisoningReq,
                            authorization: Optional[str] = Header(None),
                            x_security_key: Optional[str] = Header(None)):
    _check_security_auth(authorization, x_security_key)
    try:
        return run_data_poisoning_attack(
            trigger_phrase=req.trigger_phrase,
            num_queries=req.num_queries,
        )
    except Exception as e:
        logger.exception("Data poisoning attack failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/retrieved-leakage")
def security_retrieved_leakage(req: RetrievedLeakageReq,
                               authorization: Optional[str] = Header(None),
                               x_security_key: Optional[str] = Header(None)):
    _check_security_auth(authorization, x_security_key)
    try:
        return run_retrieved_leakage_attack(
            num_canaries=req.num_canaries,
        )
    except Exception as e:
        logger.exception("Retrieved leakage attack failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


class CustomSimulationReq(BaseModel):
    attack_type: Literal["membership_inference", "data_poisoning", "retrieved_leakage"]
    documents: list[dict]
    query: Optional[str] = None
    decision_threshold: Optional[float] = None
    trigger_phrase: Optional[str] = "[CUSTOM-IOT-OVERRIDE]"
    canary_token: Optional[str] = "CANARY-SECRET-USER-9021"


@app.post("/api/security/upload-dataset")
async def security_upload_dataset(file: UploadFile = File(...),
                                  authorization: Optional[str] = Header(None),
                                  x_security_key: Optional[str] = Header(None)):
    _check_security_auth(authorization, x_security_key)
    try:
        content_bytes = await file.read()
        docs = parse_uploaded_dataset(file.filename, content_bytes)
        if not docs:
            raise HTTPException(400, "Could not extract valid records from uploaded file. Please verify CSV, JSON, TXT, or Parquet format.")
        return {
            "filename": file.filename,
            "count": len(docs),
            "documents": docs,
            "preview": docs[:3],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to parse uploaded dataset: %s", e)
        raise HTTPException(500, f"Dataset parsing failed: {str(e)}")


@app.get("/api/security/sample-preset")
def security_sample_preset(preset: str = Query("mia_intel"),
                           authorization: Optional[str] = Header(None),
                           x_security_key: Optional[str] = Header(None)):
    _check_security_auth(authorization, x_security_key)
    docs = get_sample_preset_dataset(preset)
    return {
        "preset": preset,
        "count": len(docs),
        "documents": docs,
        "preview": docs[:3],
    }


@app.post("/api/security/simulate-custom")
def security_simulate_custom(req: CustomSimulationReq,
                             authorization: Optional[str] = Header(None),
                             x_security_key: Optional[str] = Header(None)):
    _check_security_auth(authorization, x_security_key)
    if not req.documents:
        raise HTTPException(400, "No documents provided for custom attack simulation.")
    
    try:
        if req.attack_type == "membership_inference":
            return simulate_custom_dataset_mia(req.documents, req.decision_threshold, user_query=req.query)
        elif req.attack_type == "data_poisoning":
            return simulate_custom_dataset_poisoning(req.documents, req.trigger_phrase, target_query=req.query)
        elif req.attack_type == "retrieved_leakage":
            return simulate_custom_dataset_leakage(req.documents, req.canary_token, user_query=req.query)
        else:
            raise HTTPException(400, f"Unsupported attack type '{req.attack_type}'.")
    except Exception as e:
        logger.exception("Custom simulation failed: %s", e)
        raise HTTPException(500, f"Attack simulation failed: {str(e)}")



# ---------------------------------------------------------------------------
@app.get("/")
def index():
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache, no-store, must-revalidate"})


app.mount("/static", StaticFiles(directory=STATIC), name="static")
app.mount("/plots", StaticFiles(directory=EVAL_PLOTS_DIR), name="plots")

if __name__ == "__main__":
    uvicorn.run("web.server:app", host="127.0.0.1", port=8000, reload=True, log_level="warning")
