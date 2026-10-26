"""
Milestone 3b - retrieval: choose the evidence the LLM may use.

    python -m src.retriever --sample sample_00004 "How do I stop this?"
    python -m src.retriever "What is ARP cache poisoning?"     # no traffic sample
    python -m src.retriever --check                              # test all 12 labels

Two steps, combined:
 1. Lookup by label. The detector's predicted label is looked up in
    configs/attack_mapping.yaml and the mapped entries are fetched directly by ID.
 2. Semantic search. The question + label name is turned into a vector
    ("embedding") and the closest knowledge-base chunks are added.

Priority order (the first four are ALWAYS included, so the right technique is
always in front of the LLM; the caps of 6 chunks / ~1,000 words only limit the rest):
   1. the label card           2. the primary CAPEC entry
   3. the primary ATT&CK entry 4. that technique's official mitigations
   5. other mapped IDs         6. semantic-search results
"""

import argparse
import json
import logging
import os
from typing import Any, Dict, List, Optional

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

from src.config import CHROMA_DB_DIR, DEFAULT_DATASET, KB_BUILT_DIR, get_attack_mapping, get_dataset_config

logger = logging.getLogger("retriever")

EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
COLLECTION = "threat_kb"
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "   # from the model card
MAX_CHUNKS = 6
MAX_WORDS = 1000

_STATE: Dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Loading (done once, then kept in memory)
# ---------------------------------------------------------------------------
def chunks() -> Dict[str, Dict[str, Any]]:
    if "chunks" not in _STATE:
        path = KB_BUILT_DIR / "chunks.json"
        if not path.exists():
            raise FileNotFoundError("Knowledge base not built. Run: python -m src.kb_builder")
        _STATE["chunks"] = json.loads(path.read_text(encoding="utf-8"))
    return _STATE["chunks"]


def glossary() -> Dict[str, Dict[str, str]]:
    if "glossary" not in _STATE:
        from src.kb_builder import load_glossary
        _STATE["glossary"] = load_glossary()
    return _STATE["glossary"]


def _search_backend():
    if "collection" not in _STATE:
        import chromadb
        from sentence_transformers import SentenceTransformer
        _STATE["embedder"] = SentenceTransformer(EMBEDDING_MODEL, device="cpu")
        _STATE["collection"] = chromadb.PersistentClient(path=str(CHROMA_DB_DIR)).get_collection(COLLECTION)
    return _STATE["embedder"], _STATE["collection"]


def semantic_search(query: str, n: int = 10) -> List[Dict[str, Any]]:
    """The n chunks whose meaning is closest to the query."""
    embedder, col = _search_backend()
    vec = embedder.encode([QUERY_PREFIX + query], normalize_embeddings=True, show_progress_bar=False)
    res = col.query(query_embeddings=vec.tolist(), n_results=n)
    return [chunks()[i] for i in res["ids"][0] if i in chunks()]


# ---------------------------------------------------------------------------
# The [DET] block: ONE function used by every condition and mode
# ---------------------------------------------------------------------------
def format_detection(det: Dict[str, Any]) -> str:
    """Turn detect() output into the [DET] evidence block shown to the LLM."""
    ds = get_dataset_config(det.get("dataset", DEFAULT_DATASET))
    g = glossary()
    lines = [
        f"[DET] Output of the machine-learning detector for traffic sample {det.get('sample_id')} "
        f"(dataset {ds['dataset_name']})",
        f"- Predicted label: {det['predicted_label']}",
        f"- Attack or normal: {'ATTACK' if det['is_attack'] else 'NORMAL'}; attack family: {det['attack_family']}",
        f"- Confidence (predicted probability): {det['confidence']:.2f}"
        + ("  ** LOW CONFIDENCE: below 0.60, the label may be wrong **" if det["low_confidence"] else ""),
        "- Three most likely labels: " + ", ".join(f"{l} ({p:.2f})" for l, p in det["top_3"]),
        "- The 5 flow features that pushed the detector most towards this label (actual value; meaning):",
    ]
    for f in det["top_features"]:
        info = g.get(f["feature"])
        meaning = f"{info['meaning']} ({info['unit']})" if info else "no glossary entry"
        lines.append(f"  - {f['feature']} = {f['value']}; {meaning}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------
def _first_part(chunk_id: str) -> Optional[Dict[str, Any]]:
    """A chunk by ID; for a split entry, its first part."""
    c = chunks()
    return c.get(chunk_id) or c.get(f"{chunk_id}#1")


def _all_parts(chunk_id: str) -> List[Dict[str, Any]]:
    c = chunks()
    if chunk_id in c:
        return [c[chunk_id]]
    parts, k = [], 1
    while f"{chunk_id}#{k}" in c:
        parts.append(c[f"{chunk_id}#{k}"])
        k += 1
    return parts


def mapped_chunk_ids(label: str) -> Dict[str, List[str]]:
    """Chunk IDs linked to a label: 'must' (always shown) and 'extra' (if space)."""
    m = get_attack_mapping().get(label)
    if m is None:
        return {"must": [f"CARD_{label}"], "extra": [], "mapped": False}
    capec, attack = m["capec"], m["attack"]
    must = [f"CARD_{label}"] + capec[:1] + attack[:1] + ([f"{attack[0]}-MIT"] if attack else [])
    extra = capec[1:] + attack[1:] + [f"{t}-MIT" for t in attack[1:]]
    return {"must": must, "extra": extra, "mapped": True}


def retrieve(question: str, det: Optional[Dict[str, Any]] = None,
             max_chunks: int = MAX_CHUNKS, max_words: int = MAX_WORDS) -> Dict[str, Any]:
    """Pick the evidence for one question. Returns
    {chunks, evidence_text, det_text, words, warnings}."""
    selected: List[Dict[str, Any]] = []
    warnings: List[str] = []
    seen = set()

    def add(chunk, force=False) -> bool:
        if chunk is None or chunk["chunk_id"] in seen:
            return False
        words = sum(c["words"] for c in selected)
        if not force and (len(selected) >= max_chunks or words + chunk["words"] > max_words):
            return False
        selected.append(chunk)
        seen.add(chunk["chunk_id"])
        return True

    label = det["predicted_label"] if det else None
    if label:
        ids = mapped_chunk_ids(label)
        if not ids["mapped"]:
            msg = f"Label '{label}' is not in configs/attack_mapping.yaml; using semantic search only."
            logger.warning(msg)
            warnings.append(msg)
        for cid in ids["must"]:
            add(_first_part(cid), force=True)       # step 1: always included
        for cid in ids["extra"]:
            add(_first_part(cid))                   # step 1: if there is room

    query = f"{question} {label.replace('_', ' ')}" if label else question
    for c in semantic_search(query, n=max_chunks * 3):   # step 2
        add(c)

    det_text = format_detection(det) if det else ""
    blocks = ([det_text] if det_text else []) + [c["text"] for c in selected]
    return {"chunks": selected, "det_text": det_text,
            "evidence_text": "\n\n".join(blocks),
            "words": sum(c["words"] for c in selected), "warnings": warnings}


def reference_chunks(label: Optional[str], retrieved: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Reference used by the JUDGE for both conditions: every knowledge-base entry
    mapped to the predicted label (all parts, all mitigations, the label card),
    plus whatever was retrieved in condition B."""
    out, seen = [], set()
    if label:
        ids = mapped_chunk_ids(label)
        for cid in ids["must"] + ids["extra"]:
            for c in _all_parts(cid):
                if c["chunk_id"] not in seen:
                    out.append(c)
                    seen.add(c["chunk_id"])
    for c in retrieved:
        if c["chunk_id"] not in seen:
            out.append(c)
            seen.add(c["chunk_id"])
    return out


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------
def _check_all_labels(dataset: str) -> None:
    """Done-check: every label's mapped technique is in its evidence, caps respected."""
    import pandas as pd
    from src.config import dataset_paths
    from src.detector import detect
    cfg = get_dataset_config(dataset)
    test = pd.read_parquet(dataset_paths(dataset)["test"])
    mapping = get_attack_mapping()
    ok = True
    for label in cfg["label_to_family"]:
        row = test[test[cfg["label_column"]] == label].iloc[0]
        det = detect(row, dataset)
        det = {**det, "predicted_label": label}   # test the lookup for THIS label
        r = retrieve("What is this traffic and how should I respond?", det)
        tags = [c["tag"] for c in r["chunks"]]
        want = (mapping.get(label, {}).get("capec", [])[:1] + mapping.get(label, {}).get("attack", [])[:1])
        missing = [w for w in want if w not in tags]
        ok &= not missing
        print(f"{label:28s} {len(r['chunks'])} chunks {r['words']:4d} words  "
              f"{'OK' if not missing else 'MISSING ' + str(missing)}  {tags}")
    print("\nALL LABELS OK" if ok else "\nSOME LABELS ARE MISSING THEIR MAPPED ENTRIES")


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("question", nargs="?", default="What is this traffic and how should I respond?")
    ap.add_argument("--sample", help="test-set sample ID, e.g. sample_00004")
    ap.add_argument("--dataset", default=DEFAULT_DATASET)
    ap.add_argument("--check", action="store_true", help="test retrieval for every label")
    a = ap.parse_args()
    if a.check:
        _check_all_labels(a.dataset)
    else:
        det = None
        if a.sample:
            from src.detector import detect, load_test_sample
            det = detect(load_test_sample(a.sample, a.dataset), a.dataset)
        res = retrieve(a.question, det)
        print(res["evidence_text"])
        print(f"\n--- {len(res['chunks'])} chunks, {res['words']} words: {[c['chunk_id'] for c in res['chunks']]}")
