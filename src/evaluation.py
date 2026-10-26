"""
Building blocks of the hallucination evaluation (the runner is eval/run_eval.py).

Measure 1  claim-level hallucination rate (an LLM judge labels every claim)
Measure 2  fabricated-ID rate (no LLM: regular expressions + the official files)
Measure 3  trap questions (marked by hand; a keyword hint is only a suggestion)
Measure 4  judge reliability (agreement between the student and the judge)
"""

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

from src import prompts
from src.config import CACHE_DIR, KB_BUILT_DIR, family_of, get_attack_mapping
from src.llm_client import chat, judge_role
from src.retriever import chunks as kb_chunks
from src.retriever import format_detection, reference_chunks

logger = logging.getLogger("evaluation")

VERDICTS = ("SUPPORTED", "CONTRADICTED", "NOT_IN_EVIDENCE")


# ===========================================================================
# Measure 1: the judge
# ===========================================================================
def build_reference(det: Dict[str, Any], b_chunks: List[Dict[str, Any]]) -> str:
    """The SAME reference for conditions A and B of one question:
    detector output + every entry mapped to the predicted label + what B retrieved."""
    refs = reference_chunks(det["predicted_label"] if det else None, b_chunks)
    return "\n\n".join(([format_detection(det)] if det else []) + [c["text"] for c in refs])


class JudgeError(RuntimeError):
    pass


def judge_answer(reference: str, question: str, answer: str) -> Dict[str, Any]:
    """One judge call per answer. Returns {"claims": [...], "model": ...}.
    Raises JudgeError if the output is not valid JSON in the expected form;
    nothing is invented in that case, the answer is simply judged again next run."""
    messages = [{"role": "system", "content": prompts.JUDGE_SYSTEM},
                {"role": "user", "content": prompts.JUDGE_USER_TEMPLATE.format(
                    reference=reference, question=question, answer=answer)}]
    # First try the cached reply (if any). If it cannot be used, ask the judge again
    # once with a fresh request; the good reply then replaces the bad one in the cache.
    last_error = None
    for refresh in (False, True):
        res = chat(judge_role(), messages, refresh=refresh)
        try:
            claims = _parse_claims(res["content"])
            break
        except (ValueError, KeyError, TypeError) as e:
            last_error = JudgeError(f"Judge output could not be used ({e}): {res['content'][:300]}")
    else:
        raise last_error
    return {"claims": claims, "model": res["model"], "usage": res["usage"]}


def _parse_claims(text: str) -> List[Dict[str, Any]]:
    """Read the judge's JSON reply; raise ValueError/KeyError if it is not in the expected form."""
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())   # remove a markdown code fence
    claims = json.loads(text)["claims"]
    for c in claims:
        c["verdict"] = c["verdict"].strip().upper().replace(" ", "_")
        if c["verdict"] not in VERDICTS or not c.get("claim"):
            raise ValueError(f"bad claim entry {c}")
    return claims


def rates(verdicts: List[str]) -> Dict[str, Any]:
    n = len(verdicts)
    c = verdicts.count("CONTRADICTED")
    nie = verdicts.count("NOT_IN_EVIDENCE")
    return {"claims": n, "supported": verdicts.count("SUPPORTED"), "contradicted": c, "not_in_evidence": nie,
            "strict_rate": c / n if n else None, "unsupported_rate": (c + nie) / n if n else None}


# ===========================================================================
# Measure 2: fabricated IDs
# ===========================================================================
ID_PATTERNS = {
    "attack": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "mitigation": re.compile(r"\bM\d{4}\b"),
    "capec": re.compile(r"\bCAPEC-\d+\b", re.IGNORECASE),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE),
}

# Models often type IDs with a non-breaking hyphen or an en dash ("CAPEC‑163"). Each is replaced by a plain
# "-" one character for one character, so positions in the text stay the same.
DASHES = re.compile("[\u2010-\u2015\u2212]")


def normalize_dashes(text: str) -> str:
    return DASHES.sub("-", text)


_REGISTRY: Dict[str, Any] = {}


def registry() -> Dict[str, Dict[str, Any]]:
    """Every official ID in the downloaded files, INCLUDING retired ones."""
    if not _REGISTRY:
        _REGISTRY.update(json.loads((KB_BUILT_DIR / "id_registry.json").read_text()))
    return _REGISTRY


def extract_ids(text: str) -> List[Dict[str, Any]]:
    """Every ID mention in a text with its position, e.g. {"id": "T1046", "type": "attack", "pos": 12}."""
    out = []
    text = normalize_dashes(text)
    for kind, pat in ID_PATTERNS.items():
        for m in pat.finditer(text):
            out.append({"id": m.group(0).upper(), "type": kind, "pos": m.start()})
    return sorted(out, key=lambda x: x["pos"])


def related_ids(label: str) -> set:
    """IDs that count as correct for a predicted label: the mapped IDs, their parent
    technique, the mitigations ATT&CK links to them, and CAPEC's own ATT&CK cross-references."""
    reg = registry()
    m = get_attack_mapping().get(label, {"capec": [], "attack": []})
    out = set(m["capec"]) | set(m["attack"])
    for t in m["attack"]:
        out.add(t.split(".")[0])
        out.update(reg.get(t, {}).get("mitigations", []))
    for cp in m["capec"]:
        out.update(reg.get(cp, {}).get("attack_refs", []))
    return out


_NVD_CACHE = CACHE_DIR / "nvd_lookups.json"


def cve_exists_online(cve: str) -> Optional[bool]:
    """Ask NVD whether a CVE we did not download exists (cached on disk).
    Returns None if NVD cannot be reached."""
    cache = json.loads(_NVD_CACHE.read_text()) if _NVD_CACHE.exists() else {}
    if cve in cache:
        return cache[cve]
    import requests   # only needed for this online check, so it stays out of the light install
    try:
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve}, timeout=30)
        time.sleep(6.5)   # NVD: 5 requests per 30 s without a key
        if r.status_code != 200:
            return None
        found = r.json().get("totalResults", 0) > 0
    except requests.RequestException:
        return None
    cache[cve] = found
    _NVD_CACHE.write_text(json.dumps(cache, indent=1))
    return found


_ALL_NAMES: List[str] = []


def _names() -> List[str]:
    """Every official name long enough to be recognisable, longest first."""
    if not _ALL_NAMES:
        names = {v["name"].lower() for v in registry().values() if v.get("name") and len(v["name"]) >= 8}
        _ALL_NAMES.extend(sorted(names, key=len, reverse=True))
    return _ALL_NAMES


def _name_check(answer: str, mention: Dict[str, Any], mentions: List[Dict[str, Any]],
                official: str) -> Optional[bool]:
    """Look only at the name written DIRECTLY next to the ID, i.e. "T1046 (Network
    Service Discovery)", "T1046: Network ..." or "Network Service Discovery (T1046)".
    Returns True (official name), False (a different official name = wrong name)
    or None (no name written)."""
    official = (official or "").lower()
    start, end = mention["pos"], mention["pos"] + len(mention["id"])
    nxt = min([m["pos"] for m in mentions if m["pos"] > start] + [len(answer)])
    prv = max([m["pos"] + len(m["id"]) for m in mentions if m["pos"] < start] + [0])
    after = re.split(r"[.;\n]", answer[end:nxt], maxsplit=1)[0]
    after = after.lstrip(" \t([:\u2013\u2014-\"'*]").lower()
    before = re.split(r"[.;\n]", answer[prv:start])[-1].rstrip(" \t([:\u2013\u2014-\"'*").lower()
    for text, fits in ((after, str.startswith), (before, str.endswith)):
        if not text:
            continue
        # sub-techniques are often written as "Parent: Sub-name"; accept the sub-name part
        if official and (fits(text, official) or (": " + official) in text[:len(official) + 60]):
            return True
        for other in _names():
            if fits(text, other) and other not in official and official not in other:
                return False
    return None


def check_ids(answer: str, question: str, label: Optional[str],
              evidence_ids: Optional[set] = None, online: bool = True) -> List[Dict[str, Any]]:
    """Classify each distinct ID in an answer as
       correct      exists and is related to the detected label
       mismatched   exists, but is unrelated to the detected label, or is given the wrong name
       fabricated   does not exist in the official files (nor in NVD, for CVEs)
       unverifiable a real CVE whose link to the attack cannot be checked automatically,
                    or a CVE that NVD could not be asked about
    IDs that already appear in the question are skipped (e.g. the fake ID in a trap question)."""
    reg = registry()
    answer = normalize_dashes(answer)
    in_question = {i["id"] for i in extract_ids(question)}
    related = related_ids(label) if label else set()
    evidence_ids = evidence_ids or set()
    family = family_of(label) if label else None
    results, seen = [], set()
    mentions = extract_ids(answer)
    for mention in mentions:
        i = mention["id"]
        if i in in_question or i in seen:
            continue
        seen.add(i)
        entry = reg.get(i)
        row = {"id": i, "id_type": mention["type"], "official_name": entry["name"] if entry else None,
               "status_in_files": entry["status"] if entry else None}
        if entry is None and mention["type"] == "cve":
            exists = cve_exists_online(i) if online else None
            if exists is None:
                row["outcome"], row["note"] = "unverifiable", "NVD could not be reached"
            elif not exists:
                row["outcome"], row["note"] = "fabricated", "not found in NVD"
            else:
                row["outcome"], row["note"] = "unverifiable", "real CVE, not in our knowledge base"
        elif entry is None:
            row["outcome"], row["note"] = "fabricated", "not in the official ATT&CK/CAPEC files"
        else:
            name_ok = _name_check(answer, mention, mentions, entry["name"])
            if name_ok is False:
                row["outcome"], row["note"] = "mismatched", "given the wrong name"
            elif i in related:
                row["outcome"], row["note"] = "correct", ""
            elif mention["type"] == "cve" and family and family in kb_chunks().get(i, {}).get("family", ""):
                row["outcome"], row["note"] = "correct", f"example CVE for {family} in our knowledge base"
            elif mention["type"] == "cve":
                row["outcome"], row["note"] = "unverifiable", "real CVE, not linked to this attack in our files"
            else:
                row["outcome"], row["note"] = "mismatched", "real ID not related to the detected label"
        # Being in the evidence does not make an ID related, but it is worth knowing:
        # it means the model copied it from what retrieval gave it.
        row["was_in_evidence"] = i in evidence_ids
        results.append(row)
    return results


# ===========================================================================
# Measure 3: trap questions (hint only; the student marks them by hand)
# ===========================================================================
REFUSAL_HINTS = ["not available", "not in the evidence", "does not contain", "no information",
                 "cannot be determined", "can't be determined", "cannot determine", "not provided",
                 "not included", "unknown", "not possible to", "does not exist", "no evidence"]


def refusal_hint(answer: str) -> bool:
    a = answer.lower()
    return any(h in a for h in REFUSAL_HINTS)


# ===========================================================================
# Measure 4: agreement between the student and the judge
# ===========================================================================
def agreement(human: List[str], judge: List[str]) -> Dict[str, Any]:
    """Percent agreement and Cohen's kappa. Kappa corrects for the agreement
    expected by chance: 1 = perfect, 0 = no better than chance."""
    from sklearn.metrics import cohen_kappa_score
    n = len(human)
    agree = sum(h == j for h, j in zip(human, judge))
    kappa = cohen_kappa_score(human, judge, labels=list(VERDICTS)) if n else None
    return {"items": n, "agreements": agree, "percent_agreement": agree / n if n else None,
            "cohens_kappa": kappa}
