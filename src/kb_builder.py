"""
Milestone 3a - build the threat knowledge base.

    python -m src.kb_builder            # download what is missing, then build
    python -m src.kb_builder --refresh  # download everything again

Sources (in order of importance):
 1. MITRE ATT&CK Enterprise (STIX 2.1 JSON): techniques, sub-techniques, mitigations,
    and the official "mitigates" links between them.
 2. MITRE CAPEC (XML): attack patterns with their mitigations and ATT&CK cross-references.
 3. NVD: a few hundred CVE records found by keyword, tagged as example vulnerabilities.
 4. Our own two files in data/kb_manual/ (label cards, feature glossary).

Raw downloads stay in data/kb_raw/ with data/kb_raw/manifest.json (URL, version,
download date, checksum), so the knowledge base can be rebuilt offline and cited.

Output:
 - data/kb/chunks.json       every chunk (text + metadata), looked up by chunk ID
 - data/kb/id_registry.json  every official ID that exists, INCLUDING retired ones,
                             with name and status (used by the fabricated-ID check)
 - data/kb/mapping_check.json  verification of configs/attack_mapping.yaml
 - data/chroma_db/           the vector store used for semantic search

A "chunk" is one self-contained entry (one technique, one attack pattern, one
mitigation, one CVE...). Entries longer than ~350 words are split into parts,
and every part repeats the entry's ID and name at the top.
"""

import argparse
import hashlib
import json
import logging
import re
import time
from collections import Counter
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List

import requests
import yaml

from src.config import (CHROMA_DB_DIR, KB_BUILT_DIR, KB_MANUAL_DIR, KB_RAW_DIR,
                        available_datasets, get_attack_mapping, get_dataset_config)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("kb_builder")
logging.getLogger("httpx").setLevel(logging.WARNING)   # hide per-request download logs

EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
COLLECTION = "threat_kb"
MAX_WORDS = 350          # split entries longer than this
PART_WORDS = 300         # target size of each part after splitting

SOURCES = {
    "attack": {"url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
                      "enterprise-attack/enterprise-attack.json",
               "file": "enterprise-attack.json"},
    "capec": {"url": "https://capec.mitre.org/data/xml/capec_latest.xml", "file": "capec_latest.xml"},
    "nvd": {"url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "file": "nvd_cves.json"},
}

# NVD keyword searches -> the attack family the CVEs are an example for.
# Up to `n` of the most recently published matches are kept per keyword.
NVD_QUERIES = [
    {"keyword": "Slowloris", "family": "DoS", "n": 60},
    {"keyword": "slow HTTP denial of service", "family": "DoS", "n": 30},
    {"keyword": "SYN flood", "family": "DoS", "n": 40},
    {"keyword": "OpenSSH", "family": "Brute force", "n": 50},
    {"keyword": "SSH brute force", "family": "Brute force", "n": 30},
    {"keyword": "ARP spoofing", "family": "Spoofing", "n": 30},
    {"keyword": "ARP poisoning", "family": "Spoofing", "n": 20},
    {"keyword": "Nmap", "family": "Reconnaissance", "n": 20},
    {"keyword": "Mosquitto", "family": "Normal", "n": 40},
    {"keyword": "MQTT broker", "family": "Normal", "n": 40},
    {"keyword": "smart bulb", "family": "Normal", "n": 30},
    {"keyword": "ThingSpeak", "family": "Normal", "n": 10},
]
NVD_PAUSE_SECONDS = 6.5   # NVD allows 5 requests per 30 s without an API key


# ===========================================================================
# 1. Downloads (each file once) + manifest
# ===========================================================================
def _manifest_path():
    return KB_RAW_DIR / "manifest.json"


def load_manifest() -> Dict[str, Any]:
    p = _manifest_path()
    return json.loads(p.read_text()) if p.exists() else {}


def _record(manifest, key, path, version, records):
    manifest[key] = {
        "url": SOURCES[key]["url"], "file": path.name, "version": version, "records": records,
        "downloaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    _manifest_path().write_text(json.dumps(manifest, indent=2))


def download_all(refresh: bool = False) -> Dict[str, Any]:
    manifest = load_manifest()
    for key in ("attack", "capec"):
        path = KB_RAW_DIR / SOURCES[key]["file"]
        if path.exists() and key in manifest and not refresh:
            logger.info("Using existing %s (%s, downloaded %s)", path.name,
                        manifest[key]["version"], manifest[key]["downloaded_at"])
            continue
        if not path.exists() or refresh:
            logger.info("Downloading %s ...", SOURCES[key]["url"])
            r = requests.get(SOURCES[key]["url"], timeout=300)
            r.raise_for_status()
            path.write_bytes(r.content)
        version = attack_version(path) if key == "attack" else capec_version(path)
        _record(manifest, key, path, version, None)

    nvd_path = KB_RAW_DIR / SOURCES["nvd"]["file"]
    if not nvd_path.exists() or "nvd" not in manifest or refresh:
        cves = fetch_nvd()
        nvd_path.write_text(json.dumps(cves, indent=1))
        _record(manifest, "nvd", nvd_path, "NVD CVE API 2.0", len(cves))
    return manifest


def attack_version(path) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    coll = [o for o in data["objects"] if o["type"] == "x-mitre-collection"][0]
    return f"{coll['name']} v{coll.get('x_mitre_version')} (modified {coll.get('modified', '')[:10]})"


def capec_version(path) -> str:
    root = ET.parse(path).getroot()
    return f"CAPEC {root.get('Version')} ({root.get('Date')})"


def fetch_nvd() -> List[Dict[str, Any]]:
    """Ask the NVD API for each keyword; keep the most recent matches. Slow on purpose."""
    url = SOURCES["nvd"]["url"]
    out, seen = [], set()
    for q in NVD_QUERIES:
        params = {"keywordSearch": q["keyword"], "resultsPerPage": 1}
        r = requests.get(url, params=params, timeout=60)
        r.raise_for_status()
        total = r.json().get("totalResults", 0)
        time.sleep(NVD_PAUSE_SECONDS)
        if total == 0:
            logger.info("NVD '%s': no results", q["keyword"])
            continue
        # NVD lists oldest first, so jump to the end to get the most recent ones.
        params = {"keywordSearch": q["keyword"], "resultsPerPage": q["n"],
                  "startIndex": max(0, total - q["n"])}
        r = requests.get(url, params=params, timeout=60)
        r.raise_for_status()
        new = 0
        for item in r.json().get("vulnerabilities", []):
            cve = item["cve"]
            if cve["id"] in seen:
                continue
            seen.add(cve["id"])
            cve["_query"] = q["keyword"]
            cve["_family"] = q["family"]
            out.append(cve)
            new += 1
        logger.info("NVD '%s': %d total matches, kept %d new", q["keyword"], total, new)
        time.sleep(NVD_PAUSE_SECONDS)
    return out


# ===========================================================================
# 2. Parsing into entries
# ===========================================================================
def clean_attack_text(text: str) -> str:
    """Remove ATT&CK citation markers, markdown links and HTML tags."""
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", r"\1", text)
    text = re.sub(r"</?code>", "", text)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"[ \t]+", " ", text).strip()


def _attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"], ref.get("url", "")
    return None, None


def parse_attack(path, registry, entries) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    objs = data["objects"]
    by_stix = {}
    for o in objs:
        if o["type"] not in ("attack-pattern", "course-of-action"):
            continue
        ext_id, url = _attack_id(o)
        if not ext_id:
            continue
        retired = o.get("revoked", False) or o.get("x_mitre_deprecated", False)
        status = "revoked" if o.get("revoked") else ("deprecated" if retired else "active")
        # Registry: keep EVERY ID, even retired ones. Several retired mitigation
        # objects reuse a technique's ID (e.g. "T1046 ... Mitigation"); an active
        # object always wins the registry slot.
        if ext_id not in registry or status == "active":
            registry[ext_id] = {"name": o["name"], "source": "MITRE ATT&CK", "status": status, "url": url}
        if retired:
            continue
        by_stix[o["id"]] = (ext_id, o)
        kind = "technique" if o["type"] == "attack-pattern" else "mitigation"
        tactics = ", ".join(p["phase_name"] for p in o.get("kill_chain_phases", []))
        body = clean_attack_text(o.get("description", ""))
        if tactics:
            body = f"Tactics: {tactics}.\n{body}"
        entries.append({"official_id": ext_id, "name": o["name"], "source": "MITRE ATT&CK",
                        "kind": kind, "url": url, "body": body})

    # "mitigates" relationships: mitigation (course-of-action) -> technique
    mitigations_of: Dict[str, List[str]] = {}
    for r in objs:
        if (r["type"] != "relationship" or r.get("relationship_type") != "mitigates"
                or r.get("revoked") or r.get("x_mitre_deprecated")):
            continue
        if r["source_ref"] not in by_stix or r["target_ref"] not in by_stix:
            continue
        m_id, m_obj = by_stix[r["source_ref"]]
        t_id, _ = by_stix[r["target_ref"]]
        how = clean_attack_text(r.get("description", "")) or "(no technique-specific advice given)"
        mitigations_of.setdefault(t_id, []).append(f"{m_id} {m_obj['name']}: {how}")
        registry[t_id].setdefault("mitigations", []).append(m_id)

    # One extra entry per technique that lists its official mitigations and how
    # each applies to that technique (text taken from ATT&CK's relationship objects).
    names = {e["official_id"]: e for e in entries if e["source"] == "MITRE ATT&CK"}
    for t_id, lines in mitigations_of.items():
        t = names[t_id]
        entries.append({"official_id": t_id, "chunk_id": f"{t_id}-MIT",
                        "name": f"Mitigations for {t_id} {t['name']}", "source": "MITRE ATT&CK",
                        "kind": "technique_mitigations", "url": t["url"],
                        "body": "\n".join(f"- {l}" for l in sorted(lines))})
    logger.info("ATT&CK: %d techniques/mitigations, %d techniques with mitigation lists",
                len(names), len(mitigations_of))


def _xml_text(el) -> str:
    """All text inside an XML element (CAPEC uses embedded XHTML), whitespace tidied."""
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip() if el is not None else ""


def parse_capec(path, registry, entries) -> None:
    ns = {"c": "http://capec.mitre.org/capec-3"}
    root = ET.parse(path).getroot()
    n = 0
    for ap in root.iter(f"{{{ns['c']}}}Attack_Pattern"):
        cid = f"CAPEC-{ap.get('ID')}"
        url = f"https://capec.mitre.org/data/definitions/{ap.get('ID')}.html"
        status = ap.get("Status", "")
        attack_refs = [f"T{m.findtext('c:Entry_ID', namespaces=ns).strip()}"
                       for m in ap.iter(f"{{{ns['c']}}}Taxonomy_Mapping")
                       if m.get("Taxonomy_Name") == "ATTACK" and m.findtext("c:Entry_ID", namespaces=ns)]
        registry[cid] = {"name": ap.get("Name"), "source": "MITRE CAPEC", "status": status.lower(),
                         "url": url, "attack_refs": attack_refs}
        if status in ("Deprecated", "Obsolete"):
            continue
        parts = [_xml_text(ap.find("c:Description", ns))]
        ext = _xml_text(ap.find("c:Extended_Description", ns))
        if ext:
            parts.append(ext)
        meta = []
        for tag, label in (("Likelihood_Of_Attack", "Likelihood"), ("Typical_Severity", "Severity")):
            v = ap.findtext(f"c:{tag}", namespaces=ns)
            if v:
                meta.append(f"{label}: {v}")
        if meta:
            parts.append(". ".join(meta) + ".")
        mits = [_xml_text(m) for m in ap.findall("c:Mitigations/c:Mitigation", ns)]
        if mits:
            parts.append("Mitigations:\n" + "\n".join(f"- {m}" for m in mits if m))
        if attack_refs:
            parts.append("Related ATT&CK techniques (CAPEC cross-reference): " + ", ".join(attack_refs))
        entries.append({"official_id": cid, "name": ap.get("Name"), "source": "MITRE CAPEC",
                        "kind": "attack_pattern", "url": url, "body": "\n".join(parts)})
        n += 1
    logger.info("CAPEC: %d active attack patterns", n)


def parse_nvd(path, registry, entries) -> None:
    cves = json.loads(path.read_text(encoding="utf-8"))
    for c in cves:
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        url = f"https://nvd.nist.gov/vuln/detail/{c['id']}"
        score = ""
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if c.get("metrics", {}).get(key):
                d = c["metrics"][key][0]["cvssData"]
                score = f"CVSS {d.get('version')} base score {d.get('baseScore')}."
                break
        registry[c["id"]] = {"name": c["id"], "source": "NVD", "status": c.get("vulnStatus", "").lower(), "url": url}
        body = (f"Example vulnerability (found by NVD keyword search '{c['_query']}'). "
                f"Published {c.get('published', '')[:10]}. {score}\n{desc}")
        entries.append({"official_id": c["id"], "name": c["id"], "source": "NVD", "kind": "cve",
                        "url": url, "body": body, "family": c["_family"]})
    logger.info("NVD: %d CVEs", len(cves))


def parse_manual(entries) -> None:
    """Our own label cards and feature glossary (marked as project-authored)."""
    cards = yaml.safe_load((KB_MANUAL_DIR / "label_cards.yaml").read_text(encoding="utf-8"))
    for label, c in cards["labels"].items():
        entries.append({"official_id": f"CARD_{label}", "name": c["name"],
                        "source": "Project label card", "kind": "label_card", "url": "",
                        "label": label,
                        "body": f"Dataset label: {label} ({cards['dataset']}). Tool: {c['tool']}.\n"
                                f"Meaning: {c['meaning']}\nObserved in the dataset: {c['observed']}"})
    gloss = load_glossary()
    for feat, g in gloss.items():
        entries.append({"official_id": f"GLOSSARY_{feat}", "name": feat,
                        "source": "Project feature glossary", "kind": "feature", "url": "",
                        "body": f"Flow feature '{feat}': {g['meaning']} (unit: {g['unit']})."})


def load_glossary() -> Dict[str, Dict[str, str]]:
    return yaml.safe_load((KB_MANUAL_DIR / "feature_glossary.yaml").read_text(encoding="utf-8"))["features"]


# ===========================================================================
# 3. Families, chunking
# ===========================================================================
def label_families() -> Dict[str, str]:
    """label -> family, gathered from every dataset config."""
    fam = {}
    for ds in available_datasets():
        fam.update(get_dataset_config(ds)["label_to_family"])
    return fam


def id_families(registry) -> Dict[str, set]:
    """Official ID -> set of families, for IDs reachable from the mapping file
    (the mapped IDs themselves and the mitigations of mapped techniques)."""
    fam_of_label = label_families()
    out: Dict[str, set] = {}
    for label, ids in get_attack_mapping().items():
        fam = fam_of_label.get(label)
        if not fam:
            continue
        for i in ids["capec"] + ids["attack"]:
            out.setdefault(i, set()).add(fam)
            for m in registry.get(i, {}).get("mitigations", []):
                out.setdefault(m, set()).add(fam)
    return out


def split_words(body: str) -> List[str]:
    """Split a long text into ~PART_WORDS pieces at sentence boundaries."""
    if len(body.split()) <= MAX_WORDS:
        return [body]
    sentences = re.split(r"(?<=[.!?])\s+|\n", body)
    parts, cur = [], []
    for s in sentences:
        if cur and len(" ".join(cur + [s]).split()) > PART_WORDS:
            parts.append(" ".join(cur))
            cur = []
        cur.append(s)
    if cur:
        parts.append(" ".join(cur))
    return parts


def make_chunks(entries, registry) -> List[Dict[str, Any]]:
    fams = id_families(registry)
    chunks = []
    for e in entries:
        base = e.get("chunk_id", e["official_id"])
        family = e.get("family") or ", ".join(sorted(fams.get(e["official_id"], set())))
        if e["kind"] == "label_card":
            family = label_families().get(e["label"], "")
        pieces = split_words(e["body"])
        for k, piece in enumerate(pieces, start=1):
            cid = base if len(pieces) == 1 else f"{base}#{k}"
            part = "" if len(pieces) == 1 else f" (part {k} of {len(pieces)})"
            # The first line is the TAG the LLM must cite, exactly as the prompt asks.
            text = f"[{base}] {e['name']}{part}\nSource: {e['source']}" + \
                   (f" | {e['url']}" if e["url"] else "") + f"\n{piece}"
            chunks.append({"chunk_id": cid, "tag": base, "official_id": e["official_id"],
                           "name": e["name"], "source": e["source"], "kind": e["kind"],
                           "url": e["url"], "family": family, "part": k, "parts": len(pieces),
                           "text": text, "words": len(text.split())})
    return chunks


# ===========================================================================
# 4. Mapping verification
# ===========================================================================
def verify_mapping(registry) -> List[Dict[str, Any]]:
    """Check every ID in configs/attack_mapping.yaml against the downloaded files."""
    rows = []
    for label, ids in get_attack_mapping().items():
        for i in ids["capec"] + ids["attack"]:
            r = registry.get(i)
            row = {"label": label, "id": i, "exists": r is not None,
                   "status": r["status"] if r else "MISSING", "official_name": r["name"] if r else ""}
            if i.startswith("CAPEC") and r:
                row["capec_attack_refs"] = r.get("attack_refs", [])
            rows.append(row)
    for row in rows:
        ok = row["exists"] and row["status"] in ("active", "stable", "draft", "usable")
        (logger.info if ok else logger.error)("mapping %-27s %-10s %-9s %s", row["label"], row["id"],
                                              row["status"], row["official_name"])
    return rows


# ===========================================================================
# 5. Build
# ===========================================================================
def build(refresh: bool = False) -> None:
    KB_BUILT_DIR.mkdir(parents=True, exist_ok=True)
    manifest = download_all(refresh)

    registry: Dict[str, Dict[str, Any]] = {}
    entries: List[Dict[str, Any]] = []
    parse_attack(KB_RAW_DIR / SOURCES["attack"]["file"], registry, entries)
    parse_capec(KB_RAW_DIR / SOURCES["capec"]["file"], registry, entries)
    parse_nvd(KB_RAW_DIR / SOURCES["nvd"]["file"], registry, entries)
    parse_manual(entries)

    chunks = make_chunks(entries, registry)
    ids = [c["chunk_id"] for c in chunks]
    dupes = [i for i, n in Counter(ids).items() if n > 1]
    if dupes:
        raise ValueError(f"Duplicate chunk IDs: {sorted(dupes)[:10]}")

    mapping_rows = verify_mapping(registry)
    (KB_BUILT_DIR / "chunks.json").write_text(json.dumps({c["chunk_id"]: c for c in chunks}, indent=1))
    (KB_BUILT_DIR / "id_registry.json").write_text(json.dumps(registry, indent=1))
    (KB_BUILT_DIR / "mapping_check.json").write_text(json.dumps(mapping_rows, indent=1))
    (KB_BUILT_DIR / "build_info.json").write_text(json.dumps({
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "embedding_model": EMBEDDING_MODEL, "sources": manifest, "chunks": len(chunks)}, indent=1))

    index_chunks(chunks)
    by_source = {}
    for c in chunks:
        by_source[c["source"]] = by_source.get(c["source"], 0) + 1
    print("\nKNOWLEDGE BASE BUILT")
    for s, n in by_source.items():
        print(f"  {s:28s} {n:6,d} chunks")
    print(f"  {'TOTAL':28s} {len(chunks):6,d} chunks")
    for k, v in manifest.items():
        print(f"  {k}: {v['version']}, downloaded {v['downloaded_at']}")


def index_chunks(chunks) -> None:
    """Embed every chunk and store it in ChromaDB (replacing any old collection)."""
    import chromadb
    from sentence_transformers import SentenceTransformer

    logger.info("Embedding %d chunks with %s on CPU (a few minutes) ...", len(chunks), EMBEDDING_MODEL)
    model = SentenceTransformer(EMBEDDING_MODEL, device="cpu")
    client = chromadb.PersistentClient(path=str(CHROMA_DB_DIR))
    if COLLECTION in [c.name for c in client.list_collections()]:
        client.delete_collection(COLLECTION)
    col = client.create_collection(COLLECTION, metadata={"hnsw:space": "cosine"})
    for i in range(0, len(chunks), 256):
        batch = chunks[i:i + 256]
        # Passages are embedded WITHOUT a prefix; only queries get the
        # instruction prefix (as the bge-small-en-v1.5 model card says).
        emb = model.encode([c["text"] for c in batch], normalize_embeddings=True, show_progress_bar=False)
        col.add(ids=[c["chunk_id"] for c in batch], embeddings=emb.tolist(),
                documents=[c["text"] for c in batch],
                metadatas=[{k: c[k] for k in ("official_id", "name", "source", "kind", "url", "family", "tag")}
                           for c in batch])
    logger.info("ChromaDB collection '%s' now holds %d chunks", COLLECTION, col.count())


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--refresh", action="store_true", help="download all sources again")
    build(ap.parse_args().refresh)
