"""
Display helpers for the web app: scenario texts, evidence-tag details and number formatting.
Pure Python (no web framework), so the server and any other front end can share them.
"""

import json
import re
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional

import yaml

from src.config import CONFIGS_DIR, KB_BUILT_DIR, KB_MANUAL_DIR, get_attack_mapping
from src.evaluation import extract_ids

# One colour per shared attack family (works on both the light and the dark theme).
FAMILY_COLORS = {
    "Normal": "#1FBF9A", "DoS": "#EF4B4B", "Reconnaissance": "#F2A20C", "Spoofing": "#A56BFF",
    "Brute force": "#F0489E", "Web attack": "#4C7DFF", "Botnet/Malware": "#C8731A", "Other": "#8A94A6",
}


# ---------------------------------------------------------------------------
# Labels and scenarios
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def label_cards() -> Dict[str, Dict[str, str]]:
    return yaml.safe_load((KB_MANUAL_DIR / "label_cards.yaml").read_text(encoding="utf-8"))["labels"]


def pretty_label(label: str) -> str:
    """Plain-English name of a dataset label, from our label cards."""
    return label_cards().get(label, {}).get("name", label.replace("_", " "))


@lru_cache(maxsize=1)
def _scenarios() -> Dict[str, Dict[str, Any]]:
    p = CONFIGS_DIR / "scenarios.yaml"
    return (yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("scenarios", {}) if p.exists() else {}


def scenario(label: str, family: str) -> Dict[str, Any]:
    """Presentation details of a label (icon, story, animation style). Unlisted labels get sensible defaults."""
    sc = dict(_scenarios().get(label, {}))
    card = label_cards().get(label, {})
    sc.setdefault("icon", "🟢" if family == "Normal" else "⚠️")
    sc.setdefault("headline", card.get("name", label.replace("_", " ")))
    sc.setdefault("story", (card.get("meaning", "") or "").strip().split(". ")[0][:150])
    sc.setdefault("motion", "normal" if family == "Normal" else "flood")
    sc.setdefault("from", "Source")
    sc.setdefault("to", "IoT device")
    sc["family"] = family
    sc["color"] = FAMILY_COLORS.get(family, FAMILY_COLORS["Other"])
    sc["label"] = label
    return sc


# ---------------------------------------------------------------------------
# Number formatting
# ---------------------------------------------------------------------------
def fmt_value(v: Any, unit: str = "") -> str:
    """Round float noise away and add a readable unit."""
    if isinstance(v, float):
        if unit == "microseconds" and v >= 1000:
            return f"{v / 1e6:.3g} s" if v >= 1e6 else f"{v / 1e3:.3g} ms"
        v = f"{v:.4g}" if abs(v) < 1e6 else f"{v:,.0f}"
    unit = {"microseconds": "µs", "0 or 1": ""}.get(unit, unit)
    return f"{v} {unit}".strip()


def fmt_duration(seconds: float) -> str:
    if seconds < 1e-3:
        return f"{seconds * 1e6:.0f} µs"
    if seconds < 1:
        return f"{seconds * 1e3:.0f} ms"
    return f"{seconds:.1f} s"


# ---------------------------------------------------------------------------
# Evidence tags
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def id_registry() -> Dict[str, Dict[str, Any]]:
    p = KB_BUILT_DIR / "id_registry.json"
    return json.loads(p.read_text()) if p.exists() else {}


def tag_kind(tag: str) -> str:
    if tag == "DET":
        return "det"
    if tag.startswith("CAPEC-"):
        return "capec"
    if tag.startswith("CVE-"):
        return "cve"
    if tag.endswith("-MIT") or re.fullmatch(r"M\d{4}", tag):
        return "mit"
    if re.fullmatch(r"T\d{4}(\.\d{3})?", tag):
        return "attack"
    return "note"


def tag_url(tag: str) -> str:
    return id_registry().get(tag.removesuffix("-MIT"), {}).get("url", "")


TAG_RE = re.compile(r"\[([A-Za-z0-9_.\-]+)\]")


def allowed_tags(chunks: Iterable[Dict[str, Any]], has_detection: bool) -> set:
    """Every tag/ID the model was actually shown: chunk tags, IDs inside them, and DET."""
    tags = {"DET"} if has_detection else set()
    for c in chunks:
        tags.add(c["tag"])
        tags.update(m["id"] for m in extract_ids(c["text"]))
    return tags


def tag_info(answer: str, allowed: Optional[set], chunks: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Details for every [TAG] in an answer: kind, link, name, and whether it was in the evidence."""
    by_tag = {c["tag"]: c for c in chunks}
    out = {}
    for tag in set(TAG_RE.findall(answer)):
        reg = id_registry().get(tag.removesuffix("-MIT"), {})
        name = by_tag[tag]["name"] if tag in by_tag else reg.get("name", "")
        out[tag] = {"kind": tag_kind(tag), "url": tag_url(tag), "name": name,
                    "ok": True if allowed is None else tag in allowed}
    return out


def mapped_refs(label: str) -> List[Dict[str, str]]:
    """Official entries mapped to a label in configs/attack_mapping.yaml (no AI involved)."""
    m = get_attack_mapping().get(label, {"capec": [], "attack": []})
    reg = id_registry()
    return [{"id": i, "name": reg.get(i, {}).get("name", ""), "url": reg.get(i, {}).get("url", ""),
             "kind": tag_kind(i)} for i in m["capec"] + m["attack"]]
