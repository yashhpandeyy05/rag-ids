"""
Look and feel of the RAG-IDS app: colours, fonts and small HTML building blocks.
Both pages call inject_css() first. Everything visual lives here, so the pages
themselves only decide WHAT to show.
"""

import html
import json
import re
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional

import streamlit as st

from src.config import KB_BUILT_DIR, KB_MANUAL_DIR

# One colour per shared attack family (the verdict card and badges use these).
FAMILY_COLORS = {
    "Normal": "#12A594",
    "DoS": "#E5484D",
    "Reconnaissance": "#E8A10C",
    "Spoofing": "#8E4EC6",
    "Brute force": "#D6409F",
    "Web attack": "#3E63DD",
    "Botnet/Malware": "#AD5700",
    "Other": "#6B7280",
}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,500;12..96,700&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');

:root {
  --ink: #14213D; --ink-soft: #4A5876; --paper: #F5F7FA; --panel: #FFFFFF;
  --line: #D9E0EA; --cobalt: #3355FF;
  --src-det: #14213D; --src-attack: #C2410C; --src-capec: #6D28D9; --src-cve: #B91C1C;
  --src-note: #0F766E; --src-mit: #A16207;
}
html, body, [class*="st-"], .stMarkdown, .stButton button { font-family: 'IBM Plex Sans', system-ui, sans-serif; }
h1, h2, h3, .display { font-family: 'Bricolage Grotesque', 'IBM Plex Sans', sans-serif !important; letter-spacing: -0.01em; color: var(--ink); }
/* keep Streamlit's own icon font (the rule above would otherwise turn icons into words) */
[data-testid="stIconMaterial"], [data-testid="stExpanderToggleIcon"] * { font-family: 'Material Symbols Rounded', 'Material Icons' !important; }
code, .mono { font-family: 'IBM Plex Mono', ui-monospace, monospace !important; }
.block-container { padding-top: 2.2rem; max-width: 1180px; }

/* ---------- brand ---------- */
.brand { margin-bottom:.4rem; }
.brand .name { display:block; white-space:nowrap; font-family:'Bricolage Grotesque'; font-weight:700; font-size:1.6rem; color:var(--ink); line-height:1.1; }
.brand .tag { display:block; font-family:'IBM Plex Mono'; font-size:.72rem; color:var(--ink-soft); }
section[data-testid="stSidebar"] { width: 340px !important; min-width: 340px !important; }
.stMain h3 { margin-top: 1.4rem; }
.side-note { font-size:.8rem; color:var(--ink-soft); line-height:1.35; }

/* ---------- flow header ---------- */
.flowline { font-family:'IBM Plex Mono'; font-size:.82rem; color:var(--ink-soft); margin:.1rem 0 .7rem; }
.flowline b { color:var(--ink); font-weight:500; }

/* ---------- verdict card ---------- */
.verdict { position:relative; background:var(--panel); border:1px solid var(--line); border-radius:14px;
  padding:1.25rem 1.4rem 1.1rem 1.6rem; overflow:hidden; animation: rise .35s ease-out; }
.verdict::before { content:""; position:absolute; left:0; top:0; bottom:0; width:7px; background:var(--fam); }
.verdict .eyebrow { font-family:'IBM Plex Mono'; font-size:.72rem; text-transform:uppercase; letter-spacing:.08em; color:var(--ink-soft); }
.verdict .title { font-family:'Bricolage Grotesque'; font-weight:700; font-size:2.05rem; line-height:1.1; color:var(--ink); margin:.25rem 0 .15rem; }
.verdict .raw { font-family:'IBM Plex Mono'; font-size:.85rem; color:var(--ink-soft); }
.verdict .row { display:flex; flex-wrap:wrap; gap:1.6rem; margin-top:1rem; align-items:flex-start; }
.verdict .cell { min-width:170px; }
.verdict .cell .k { font-size:.72rem; text-transform:uppercase; letter-spacing:.07em; color:var(--ink-soft); margin-bottom:.3rem; }
.badge { display:inline-block; font-family:'IBM Plex Mono'; font-size:.74rem; font-weight:500; padding:.18rem .55rem;
  border-radius:999px; color:#fff; background:var(--fam); margin-right:.35rem; }
.badge.ghost { background:transparent; color:var(--ink); border:1px solid var(--line); }
.meter { display:flex; gap:3px; margin:.2rem 0 .25rem; }
.meter span { width:15px; height:9px; border-radius:2px; background:#E3E8EF; }
.meter span.on { background:var(--fam); }
.meter-val { font-family:'IBM Plex Mono'; font-size:1.05rem; color:var(--ink); }
.top3 div { font-family:'IBM Plex Mono'; font-size:.8rem; color:var(--ink-soft); display:flex; justify-content:space-between; gap:1rem; }
.top3 div:first-child { color:var(--ink); font-weight:500; }
.truth.ok { color:#0F766E; } .truth.bad { color:#B91C1C; }
.truth { font-size:.9rem; font-weight:500; }
.warnbar { margin-top:1rem; padding:.6rem .8rem; border-radius:8px; background:#FFF4E5; border:1px solid #F5C77E; color:#7A4B00; font-size:.88rem; }

/* ---------- why rows ---------- */
.why { background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:.4rem 1.2rem .6rem; margin-top:.9rem; }
.why .head { font-family:'Bricolage Grotesque'; font-weight:700; font-size:1.05rem; padding:.6rem 0 .2rem; color:var(--ink); }
.why .sub { font-size:.82rem; color:var(--ink-soft); margin-bottom:.4rem; }
.feat { display:grid; grid-template-columns: 1.1fr 1.6fr 1fr; gap:1rem; align-items:center; padding:.55rem 0; border-top:1px solid #EEF1F6; }
.feat .name { font-family:'IBM Plex Mono'; font-size:.84rem; color:var(--ink); word-break:break-all; }
.feat .meaning { font-size:.85rem; color:var(--ink-soft); }
.feat .val { font-family:'IBM Plex Mono'; font-size:.84rem; color:var(--ink); }
.feat .bar { height:6px; border-radius:3px; background:#E3E8EF; margin-top:.3rem; }
.feat .bar i { display:block; height:6px; border-radius:3px; background:var(--fam); }

/* ---------- citation chips (the signature) ---------- */
a.cite, span.cite { display:inline-block; font-family:'IBM Plex Mono'; font-size:.72rem; font-weight:500; line-height:1.3;
  padding:.05rem .4rem; margin:0 .08rem; border-radius:5px; text-decoration:none !important; vertical-align:1px;
  color:var(--c) !important; background:color-mix(in srgb, var(--c) 10%, white); border:1px solid color-mix(in srgb, var(--c) 35%, white); }
a.cite:hover { background:color-mix(in srgb, var(--c) 20%, white); }
.cite.det { --c: var(--src-det); } .cite.attack { --c: var(--src-attack); } .cite.mit { --c: var(--src-mit); }
.cite.capec { --c: var(--src-capec); } .cite.cve { --c: var(--src-cve); } .cite.note { --c: var(--src-note); }
.cite.missing { --c:#6B7280; border-style:dashed; background:transparent; }
.legend { font-size:.78rem; color:var(--ink-soft); margin:.1rem 0 .6rem; }
.legend .cite { margin-right:.25rem; }

/* ---------- source cards under an answer ---------- */
.src { border:1px solid var(--line); border-radius:10px; padding:.55rem .75rem; margin:.4rem 0; background:#FBFCFE; }
.src .t { font-weight:600; font-size:.88rem; color:var(--ink); }
.src .s { font-size:.75rem; color:var(--ink-soft); font-family:'IBM Plex Mono'; }
.src .x { font-size:.82rem; color:var(--ink-soft); margin-top:.25rem; }

/* ---------- empty state + KPI cards ---------- */
.empty { border:1px dashed var(--line); border-radius:12px; padding:1rem 1.2rem; color:var(--ink-soft); font-size:.9rem; background:#FBFCFE; }
.kpi { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:.9rem 1rem; height:100%; }
.kpi .k { font-size:.72rem; text-transform:uppercase; letter-spacing:.07em; color:var(--ink-soft); }
.kpi .v { font-family:'Bricolage Grotesque'; font-weight:700; font-size:1.9rem; color:var(--ink); line-height:1.15; margin:.2rem 0; }
.kpi .n { font-size:.8rem; color:var(--ink-soft); }

.stButton button { border-radius:999px; border:1px solid var(--line); font-size:.86rem; }
.stButton button:hover { border-color: var(--cobalt); color: var(--cobalt); }

/* ---------- lab: hero + scenario cards ---------- */
.hero { padding:.4rem 0 1.1rem; }
.hero .kicker { font-family:'IBM Plex Mono'; font-size:.74rem; letter-spacing:.09em; text-transform:uppercase; color:var(--cobalt); }
.hero h1 { font-size:2.5rem !important; line-height:1.08; margin:.35rem 0 .5rem !important; max-width:20ch; }
.hero p { color:var(--ink-soft); max-width:62ch; font-size:1.02rem; margin:0; }
.steps4 { display:flex; gap:.6rem; flex-wrap:wrap; margin:1rem 0 .4rem; }
.steps4 span { font-size:.82rem; color:var(--ink); background:var(--panel); border:1px solid var(--line); border-radius:999px; padding:.25rem .7rem; }
.steps4 b { font-family:'IBM Plex Mono'; color:var(--cobalt); margin-right:.3rem; }
.group-title { font-family:'Bricolage Grotesque'; font-weight:700; font-size:1.15rem; margin:1.4rem 0 .15rem; color:var(--ink); }
.group-sub { font-size:.86rem; color:var(--ink-soft); margin-bottom:.6rem; }
[class*="st-key-card-"] { background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:1rem 1rem .8rem !important;
  transition: transform .15s ease, box-shadow .15s ease, border-color .15s ease; height:100%; }
[class*="st-key-card-"]:hover { transform: translateY(-2px); box-shadow:0 8px 22px rgba(20,33,61,.09); border-color:var(--fam, var(--cobalt)); }
.card-top { display:flex; align-items:center; gap:.65rem; }
.card-ico { font-size:1.6rem; width:2.6rem; height:2.6rem; display:grid; place-items:center; border-radius:12px;
  background:color-mix(in srgb, var(--fam) 13%, white); }
.card-title { font-family:'Bricolage Grotesque'; font-weight:700; font-size:1.12rem; color:var(--ink); line-height:1.15; }
.card-story { font-size:.85rem; color:var(--ink-soft); line-height:1.4; margin:.6rem 0 .5rem; min-height:5.7em; }
.mystery { background:linear-gradient(135deg,#14213D,#26407A); color:#fff; border-radius:14px; padding:1rem 1.2rem; }
.mystery .t { font-family:'Bricolage Grotesque'; font-weight:700; font-size:1.2rem; }
.mystery .d { font-size:.88rem; color:#C9D4EE; margin-top:.2rem; }

/* ---------- simulator stage (dark) ---------- */
.stage { background:radial-gradient(120% 140% at 20% 0%, #1B2B52 0%, #0C1428 70%); border-radius:16px; padding:1rem 1.3rem 1rem;
  color:#DCE5FA; position:relative; overflow:hidden; border:1px solid #1F2E57; animation: rise .35s ease-out; }
.stage .cap { display:flex; justify-content:space-between; font-family:'IBM Plex Mono'; font-size:.72rem; letter-spacing:.06em;
  text-transform:uppercase; color:#8FA3D4; }
.stage .cap .live { color:#7EE2B8; } .stage .cap .live::before { content:"● "; animation: blink 1.2s infinite; }
.scene { position:relative; height:150px; margin:.6rem 0 .3rem; }
.node { position:absolute; top:50%; transform:translateY(-50%); text-align:center; width:96px; z-index:2; }
.node .ico { width:56px; height:56px; margin:0 auto .3rem; border-radius:16px; display:grid; place-items:center; font-size:1.7rem;
  background:#16224A; border:1px solid #2C3F78; box-shadow:0 0 0 0 rgba(0,0,0,0); }
.node.hot .ico { border-color:var(--hot); box-shadow:0 0 22px color-mix(in srgb, var(--hot) 55%, transparent); }
.node .lbl { font-family:'IBM Plex Mono'; font-size:.72rem; color:#AFC0EA; }
.node.l { left:0; } .node.r { right:0; } .node.m { left:50%; margin-left:-48px; }
.wire { position:absolute; left:96px; right:96px; top:50%; height:0; border-top:1px dashed #2C3F78; }
.pkt { position:absolute; left:96px; width:9px; height:9px; border-radius:50%; background:var(--pc); box-shadow:0 0 10px var(--pc);
  top:calc(50% + var(--dy)); animation: fly var(--dur) linear var(--delay) infinite; opacity:0; }
.pkt.back { animation-name: flyback; background:#7EE2B8; box-shadow:0 0 8px #7EE2B8; }
@keyframes fly { 0% { left:96px; opacity:0; } 8% { opacity:1; } 92% { opacity:1; } 100% { left:calc(100% - 105px); opacity:0; } }
@keyframes flyback { 0% { left:calc(100% - 105px); opacity:0; } 8% { opacity:1; } 92% { opacity:1; } 100% { left:96px; opacity:0; } }
@keyframes blink { 50% { opacity:.25; } }
.ports { position:absolute; right:106px; top:0; bottom:0; display:flex; flex-direction:column; justify-content:space-between; padding:6px 0;
  font-family:'IBM Plex Mono'; font-size:.6rem; color:#5E74B0; text-align:right; }
.stage .facts { display:flex; gap:1.6rem; flex-wrap:wrap; border-top:1px solid #1F2E57; padding-top:.7rem; margin-top:.4rem; }
.stage .facts div { font-family:'IBM Plex Mono'; font-size:.8rem; color:#DCE5FA; }
.stage .facts small { display:block; font-size:.66rem; letter-spacing:.07em; text-transform:uppercase; color:#8FA3D4; }

/* ---------- step tracker ---------- */
.track { display:flex; gap:.5rem; flex-wrap:wrap; margin:.9rem 0 .2rem; }
.track .st { flex:1; min-width:170px; background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:.55rem .75rem; font-size:.84rem; color:var(--ink-soft); }
.track .st .n { font-family:'IBM Plex Mono'; font-size:.68rem; letter-spacing:.07em; text-transform:uppercase; }
.track .st .ck { opacity:0; color:#12A594; margin-left:.3rem; }
.track .st.done { color:var(--ink); border-color:#BFE3D6; background:#F2FBF7; } .track .st.done .ck { opacity:1; }
/* live run: each step lights up in turn, then settles into "done" (pure CSS, no server waiting) */
.track.live .st { animation: trkNow .9s linear calc(var(--i) * .9s) 1 none, trkDone .01s linear calc((var(--i) + 1) * .9s) 1 forwards; }
.track.live .st .ck { animation: ckOn .01s linear calc((var(--i) + 1) * .9s) 1 forwards; }
@keyframes trkNow { 0%,100% { color:var(--ink); border-color:var(--cobalt); box-shadow:0 0 0 3px rgba(51,85,255,.14); } }
@keyframes trkDone { to { color:var(--ink); border-color:#BFE3D6; background:#F2FBF7; } }
@keyframes ckOn { to { opacity:1; } }
.reveal { opacity:0; animation: show .5s ease-out 3.7s forwards; }
.reveal-wrap { position:relative; }
.pending { position:absolute; inset:0 0 auto 0; height:260px; border-radius:14px; border:1px dashed var(--line); background:
  linear-gradient(100deg, #EEF2F8 30%, #F8FAFD 50%, #EEF2F8 70%) 0 0/200% 100%; animation: shimmer 1.4s linear infinite, gone .3s linear 3.7s forwards;
  display:grid; place-items:center; font-family:'IBM Plex Mono'; font-size:.8rem; color:var(--ink-soft); }
@keyframes shimmer { to { background-position:-200% 0; } }
@keyframes gone { to { opacity:0; visibility:hidden; } }
@keyframes show { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:none; } }
.crumb { font-family:'IBM Plex Mono'; font-size:.8rem; color:var(--ink-soft); }
.vs-head { font-family:'Bricolage Grotesque'; font-weight:700; font-size:1.05rem; margin-bottom:.2rem; }
.vs-sub { font-size:.8rem; color:var(--ink-soft); margin-bottom:.5rem; }
.vs-box { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:.8rem 1rem; font-size:.94rem; }
.vs-box.plain { border-style:dashed; }

@keyframes rise { from { opacity:0; transform: translateY(6px); } to { opacity:1; transform:none; } }
@media (prefers-reduced-motion: reduce) { .verdict, .stage, .reveal { animation:none; opacity:1; } .pkt { animation:none; opacity:.8; left:50%; } }
@media (max-width: 700px) { .feat { grid-template-columns: 1fr; gap:.2rem; } .verdict .title { font-size:1.6rem; } }
</style>
"""


def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def esc(x: Any) -> str:
    return html.escape(str(x))


# ---------------------------------------------------------------------------
# Small formatting helpers
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def label_cards() -> Dict[str, Dict[str, str]]:
    import yaml
    return yaml.safe_load((KB_MANUAL_DIR / "label_cards.yaml").read_text())["labels"]


def pretty_label(label: str) -> str:
    """Plain-English name of a dataset label, from our label cards."""
    return label_cards().get(label, {}).get("name", label.replace("_", " "))


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
# Verdict card + why rows
# ---------------------------------------------------------------------------
def verdict_card(det: Dict[str, Any], true_label: str) -> str:
    fam = det["attack_family"]
    color = FAMILY_COLORS.get(fam, FAMILY_COLORS["Other"])
    conf = det["confidence"]
    segs = "".join(f'<span class="{"on" if i < round(conf * 10) else ""}"></span>' for i in range(10))
    top3 = "".join(f"<div><span>{esc(l)}</span><span>{p:.0%}</span></div>" for l, p in det["top_3"])
    correct = true_label == det["predicted_label"]
    truth = ('<div class="truth ok">✓ Matches the dataset label</div>' if correct else
             f'<div class="truth bad">✗ Dataset says <span class="mono">{esc(true_label)}</span></div>')
    kind = "Attack" if det["is_attack"] else "Normal traffic"
    warn = ('<div class="warnbar"><b>Low confidence.</b> The detector is less than 60% sure, so treat this '
            'label as uncertain. The assistant is told the same.</div>') if det["low_confidence"] else ""
    return f"""
<div class="verdict" style="--fam:{color}">
  <div class="eyebrow">Detector verdict</div>
  <div class="title">{esc(pretty_label(det['predicted_label']))}</div>
  <div class="raw">{esc(det['predicted_label'])}</div>
  <div class="row">
    <div class="cell"><div class="k">Class</div>
      <span class="badge">{esc(fam)}</span><span class="badge ghost">{kind}</span></div>
    <div class="cell"><div class="k">Confidence</div>
      <div class="meter">{segs}</div><div class="meter-val">{conf:.1%}</div></div>
    <div class="cell top3"><div class="k">Most likely labels</div>{top3}</div>
    <div class="cell"><div class="k">Check against the data</div>{truth}</div>
  </div>
  {warn}
</div>"""


def why_rows(det: Dict[str, Any], glossary: Dict[str, Dict[str, str]]) -> str:
    color = FAMILY_COLORS.get(det["attack_family"], FAMILY_COLORS["Other"])
    top = max((f["contribution"] for f in det["top_features"]), default=1) or 1
    rows = []
    for f in det["top_features"]:
        g = glossary.get(f["feature"], {})
        width = max(4, 100 * f["contribution"] / top)
        rows.append(f"""
  <div class="feat">
    <div><div class="name">{esc(f['feature'])}</div></div>
    <div class="meaning">{esc(g.get('meaning', 'no description yet'))}</div>
    <div><div class="val">{esc(fmt_value(f['value'], g.get('unit', '')))}</div>
      <div class="bar"><i style="width:{width:.0f}%"></i></div></div>
  </div>""")
    return f"""
<div class="why" style="--fam:{color}">
  <div class="head">Why the detector decided this</div>
  <div class="sub">The five flow measurements that pushed it hardest towards this label. Longer bar = stronger push.</div>
  {''.join(rows)}
</div>"""


# ---------------------------------------------------------------------------
# Citation chips
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def id_registry() -> Dict[str, Dict[str, Any]]:
    p = KB_BUILT_DIR / "id_registry.json"
    return json.loads(p.read_text()) if p.exists() else {}


def _kind(tag: str) -> str:
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


def _url(tag: str) -> str:
    base = tag.removesuffix("-MIT")
    return id_registry().get(base, {}).get("url", "")


TAG_RE = re.compile(r"\[([A-Za-z0-9_.\-]+)\](?!\()")


def allowed_tags(chunks: Iterable[Dict[str, Any]], has_detection: bool) -> set:
    """Every tag/ID the model was actually shown: chunk tags, IDs inside them, and DET."""
    from src.evaluation import extract_ids
    tags = {"DET"} if has_detection else set()
    for c in chunks:
        tags.add(c["tag"])
        tags.update(m["id"] for m in extract_ids(c["text"]))
    return tags


def answer_with_chips(answer: str, allowed: Optional[set]) -> str:
    """Turn [TAG] citations into coloured, clickable chips. A tag that was not in the
    evidence the model saw is shown as a dashed grey chip with a warning tooltip."""
    from src.evaluation import normalize_dashes
    text = html.escape(normalize_dashes(answer), quote=False)

    def chip(m):
        tag = m.group(1)
        if allowed is not None and tag not in allowed:
            return f'<span class="cite missing" title="Not in the evidence this answer was given">{tag}?</span>'
        url, kind = _url(tag), _kind(tag)
        if url:
            return f'<a class="cite {kind}" href="{url}" target="_blank" title="Open the official entry">{tag}</a>'
        return f'<span class="cite {kind}">{tag}</span>'

    return TAG_RE.sub(chip, text)


CITE_LEGEND = ('<div class="legend">Every claim carries its source: '
               '<span class="cite det">DET</span> detector · '
               '<span class="cite attack">T1046</span> ATT&amp;CK technique · '
               '<span class="cite mit">T1046-MIT</span> its mitigations · '
               '<span class="cite capec">CAPEC-303</span> attack pattern · '
               '<span class="cite cve">CVE-…</span> vulnerability · '
               '<span class="cite note">CARD_…</span> project notes · '
               '<span class="cite missing">X?</span> cited but not in the evidence. Click a chip to open the source.</div>')


def source_cards(chunks: List[Dict[str, Any]]) -> str:
    out = []
    for c in chunks:
        body = c["text"].split("\n", 2)[-1]
        body = body[:260] + ("…" if len(body) > 260 else "")
        link = f' · <a href="{c["url"]}" target="_blank">official page</a>' if c.get("url") else ""
        out.append(f'<div class="src"><span class="cite {_kind(c["tag"])}">{esc(c["chunk_id"])}</span> '
                   f'<span class="t">{esc(c["name"])}</span>'
                   f'<div class="s">{esc(c["source"])}{link}</div><div class="x">{esc(body)}</div></div>')
    return "".join(out)


def kpi(label: str, value: str, note: str = "") -> str:
    return f'<div class="kpi"><div class="k">{esc(label)}</div><div class="v">{esc(value)}</div><div class="n">{note}</div></div>'


# ---------------------------------------------------------------------------
# Lab screen: scenarios, cards, simulator stage, step tracker
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def scenarios() -> Dict[str, Dict[str, Any]]:
    """Presentation details per label (configs/scenarios.yaml). Missing labels get a generic card."""
    import yaml
    from src.config import CONFIGS_DIR
    p = CONFIGS_DIR / "scenarios.yaml"
    return (yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("scenarios", {}) if p.exists() else {}


def scenario(label: str, family: str) -> Dict[str, Any]:
    sc = dict(scenarios().get(label, {}))
    card = label_cards().get(label, {})
    sc.setdefault("icon", "🟢" if family == "Normal" else "⚠️")
    sc.setdefault("headline", card.get("name", label.replace("_", " ")))
    sc.setdefault("story", (card.get("meaning", "") or "").strip().split(". ")[0][:140])
    sc.setdefault("motion", "normal" if family == "Normal" else "flood")
    sc.setdefault("from", "Source")
    sc.setdefault("to", "IoT device")
    return sc


def card_header(label: str, family: str) -> str:
    sc = scenario(label, family)
    color = FAMILY_COLORS.get(family, FAMILY_COLORS["Other"])
    return (f'<div style="--fam:{color}"><div class="card-top"><div class="card-ico">{sc["icon"]}</div>'
            f'<div><div class="card-title">{esc(sc["headline"])}</div>'
            f'<span class="badge" style="--fam:{color}">{esc(family)}</span></div></div>'
            f'<div class="card-story">{esc(sc["story"])}</div></div>')


_MOTION = {   # packets, seconds per crossing, lanes, colour, hot node
    "flood": (30, 1.2, 1, "#FF6B6B"), "slow": (4, 5.5, 1, "#FFB454"), "scan": (16, 2.2, 7, "#FFC857"),
    "spoof": (8, 2.6, 1, "#C792EA"), "brute": (9, 1.9, 1, "#FF7EB6"), "normal": (4, 3.4, 1, "#7EE2B8"),
}


def stage(label: Optional[str], family: str, facts: List[tuple], mystery: bool = False) -> str:
    """Dark panel with an animated picture of the traffic, plus the real numbers of the flow.
    mystery=True draws a neutral scene that does not reveal what the flow is."""
    if mystery:
        sc = {"headline": "Unidentified flow", "motion": "mystery", "from": "Unknown source", "to": "IoT device"}
        n, dur, lanes, color, attack = 12, 2.4, 3, "#8FA3D4", False
    else:
        sc = scenario(label, family)
        n, dur, lanes, color = _MOTION.get(sc["motion"], _MOTION["flood"])
        attack = family != "Normal"
    pkts = []
    for i in range(n):
        lane = i % lanes
        dy = (lane - (lanes - 1) / 2) * 17 - 4
        pkts.append(f'<i class="pkt" style="--dy:{dy:.0f}px;--dur:{dur}s;--delay:{-(i * dur / n):.2f}s;--pc:{color}"></i>')
    if sc["motion"] in ("brute", "normal", "slow"):    # replies coming back
        for i in range(max(2, n // 3)):
            pkts.append(f'<i class="pkt back" style="--dy:10px;--dur:{dur * 1.3:.1f}s;--delay:{-(i * dur):.2f}s"></i>')
    ports = '<div class="ports">' + "".join(f"<span>:{p}</span>" for p in (21, 22, 53, 80, 443, 1883, 8080)) + "</div>" \
        if sc["motion"] == "scan" else ""
    hot = "#FF6B6B" if attack else "#7EE2B8"
    mid = (f'<div class="node m hot" style="--hot:{hot}"><div class="ico">🎭</div><div class="lbl">{esc(sc.get("via", ""))}</div></div>'
           if sc.get("via") else "")
    left_hot = "" if sc.get("via") else (' hot' if attack else '')
    fact_html = "".join(f"<div><small>{esc(k)}</small>{esc(v)}</div>" for k, v in facts)
    return f"""
<div class="stage">
  <div class="cap"><span>{esc(sc['headline'])} · replayed from a real capture</span><span class="live">live</span></div>
  <div class="scene">
    <div class="node l{left_hot}" style="--hot:{hot}"><div class="ico">{'❓' if mystery else '🕶️' if attack and not sc.get('via') else '📟'}</div><div class="lbl">{esc(sc['from'])}</div></div>
    <div class="wire"></div>{ports}{''.join(pkts)}{mid}
    <div class="node r"><div class="ico">{'🔌' if 'device' in sc['to'].lower() or 'bulb' in sc['to'].lower() else '🖥️'}</div><div class="lbl">{esc(sc['to'])}</div></div>
  </div>
  <div class="facts">{fact_html}</div>
</div>"""


STEPS = ["Capture the flow", "Measure {n} features", "Score {k} labels", "Pick the verdict"]


def tracker(live: bool, n_features: int, n_labels: int) -> str:
    """Four step cards. live=True lights them up one after another with CSS animation
    (about 3.6 s); otherwise they are all shown as done."""
    out = []
    for i, text in enumerate(STEPS):
        out.append(f'<div class="st {"" if live else "done"}" style="--i:{i}"><div class="n">Step {i + 1}'
                   f'<span class="ck">✓</span></div>{esc(text.format(n=n_features, k=n_labels))}</div>')
    return f'<div class="track {"live" if live else ""}">{"".join(out)}</div>'


# ---------------------------------------------------------------------------
# ID check shown under each answer
# ---------------------------------------------------------------------------
def id_flags(answer: str, question: str, label: str) -> str:
    """Check every ATT&CK / CAPEC / mitigation / CVE ID in an answer against the official
    files (no LLM, no network) and show the result as small badges. Empty if the answer has no IDs."""
    from src.evaluation import check_ids
    rows = check_ids(answer, question, label, online=False)
    if not rows:
        return ""
    style = {"correct": ("✓", "#0F766E", "matches this detection"),
             "mismatched": ("≠", "#B45309", "real ID, but unrelated to this detection or given the wrong name"),
             "fabricated": ("✗", "#B91C1C", "does not exist in the official files"),
             "unverifiable": ("?", "#6B7280", "real CVE; its link to this attack cannot be checked offline")}
    parts = []
    for r in rows:
        sym, col, tip = style[r["outcome"]]
        parts.append(f'<span class="badge" style="--fam:{col}" title="{esc(r["note"] or tip)}">{sym} {esc(r["id"])}</span>')
    return ('<div class="legend" style="margin-top:.5rem">IDs in this answer, checked against the official MITRE files: '
            + " ".join(parts) + "</div>")


def reveal(inner_html: str, live: bool) -> str:
    """Wrap HTML so that, on a fresh launch, it fades in after the step tracker finishes."""
    if not live:
        return f'<div>{inner_html}</div>'
    return (f'<div class="reveal-wrap"><div class="pending">The detector is working on it…</div>'
            f'<div class="reveal">{inner_html}</div></div>')
