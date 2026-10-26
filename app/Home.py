"""
RAG-IDS app: a small experience zone for the detector and the assistant.

    streamlit run app/Home.py

Lab    pick a scenario (or a mystery flow) and launch it
Run    watch the traffic, see the detector's verdict and why, then question the assistant
Styling and HTML pieces live in app/ui.py; scenario texts in configs/scenarios.yaml.
"""

import json
import random
import sys
from pathlib import Path

import streamlit as st

APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_DIR.parent))   # project root, for "src"
sys.path.insert(0, str(APP_DIR))          # this folder, for "ui"

import ui                                                           # noqa: E402
from src.assistant import answer                                    # noqa: E402
from src.config import dataset_paths, get_dataset_config, trained_datasets  # noqa: E402
from src.detector import detect, load_test_sample                  # noqa: E402
from src.llm_client import LLMError                                # noqa: E402
from src.retriever import glossary                                 # noqa: E402

st.set_page_config(page_title="RAG-IDS · Attack lab", page_icon="🛡️", layout="wide")
ui.inject_css()
state = st.session_state


@st.cache_data
def load_pool(dataset: str):
    return json.loads(dataset_paths(dataset)["pool"].read_text())


# ---------------------------------------------------------------------------
# Sidebar: dataset + assistant settings
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown('<div class="brand"><span class="name">RAG-IDS</span>'
                '<span class="tag">attack lab · IoT intrusion analyst</span></div>', unsafe_allow_html=True)
    datasets = trained_datasets()
    if not datasets:
        st.error("No trained detector yet. Run `python -m src.data_loader`, then `python -m src.detector`.")
        st.stop()
    dataset = st.selectbox("Dataset", datasets, format_func=lambda d: get_dataset_config(d)["dataset_name"])
    cfg = get_dataset_config(dataset)
    pool = load_pool(dataset)

    st.markdown("#### Assistant")
    use_retrieval = st.toggle("Use the threat knowledge base", value=True,
                              help="On: answers may only use the detector output and retrieved MITRE ATT&CK, CAPEC and "
                                   "CVE entries, and must cite them. Off: the model answers from memory.")
    side_by_side = st.toggle("Answer twice: without vs. with it", value=False,
                             help="Every question is answered both ways, so you can see what the knowledge base changes.")
    tool_mode = st.toggle("Let it run the tools itself", value=False, disabled=side_by_side or not use_retrieval,
                          help="Tool calling: the LLM decides when to run the detector and search the knowledge base.")
    st.markdown('<div class="side-note">Answers come from <span class="mono">gpt-oss-120b</span> on Groq. '
                'The free plan allows a few answers per minute, so a reply can take a few seconds.</div>',
                unsafe_allow_html=True)
    with st.expander("Advanced: open a flow by ID"):
        typed = st.text_input("Sample ID", placeholder="sample_00004", label_visibility="collapsed").strip()
        if typed and st.button("Open this flow"):
            state.run = {"label": None, "sample_id": typed, "mystery": False}
            state.view, state.animate, state.messages = "run", True, []
            st.rerun()

state.setdefault("view", "lab")
if state.get("dataset") != dataset:
    state.dataset, state.view = dataset, "lab"


def launch(label=None, mystery=False):
    """Choose a real test flow (of this label, or any flow for a mystery) and start the run."""
    flows = [p["sample_id"] for p in pool if mystery or p["label"] == label]
    state.run = {"label": label, "sample_id": random.choice(flows), "mystery": mystery}
    state.view, state.animate, state.messages = "run", True, []


def back_to_lab():
    state.view = "lab"


# ===========================================================================
# LAB
# ===========================================================================
if state.view == "lab":
    st.markdown("""
<div class="hero">
  <div class="kicker">Attack lab</div>
  <h1>Launch an attack. Watch the detector catch it.</h1>
  <p>Every scenario replays a real network flow from the dataset, one the model never saw while it was trained.
  The detector names it, explains its decision, and then an AI assistant answers your questions using
  MITRE ATT&amp;CK, CAPEC and CVE records as its only sources.</p>
  <div class="steps4"><span><b>1</b>Pick a scenario</span><span><b>2</b>Watch the traffic</span>
  <span><b>3</b>Read the verdict</span><span><b>4</b>Interrogate the assistant</span></div>
</div>""", unsafe_allow_html=True)

    mc1, mc2 = st.columns([3, 1.2], vertical_alignment="center")
    mc1.markdown('<div class="mystery"><div class="t">🎲 Mystery flow</div><div class="d">A random flow from the '
                 'test set, attack or normal. You won\'t be told what it is until the detector gives its verdict.</div></div>',
                 unsafe_allow_html=True)
    mc2.button("Launch a mystery flow", type="primary", width="stretch", on_click=launch, kwargs={"mystery": True})

    by_label = {}
    for p in pool:
        by_label.setdefault(p["label"], p["attack_family"])
    groups = [("Attacks", "Pick one to launch against a simulated IoT device.",
               [l for l, f in by_label.items() if f != "Normal"]),
              ("Normal device traffic", "Harmless traffic. A good detector must leave it alone.",
               [l for l, f in by_label.items() if f == "Normal"])]
    for title, sub, labels in groups:
        if not labels:
            continue
        st.markdown(f'<div class="group-title">{title}</div><div class="group-sub">{sub}</div>', unsafe_allow_html=True)
        order = ["DoS", "Brute force", "Spoofing", "Reconnaissance"]
        labels = sorted(labels, key=lambda l: (order.index(by_label[l]) if by_label[l] in order else 9,
                                               ui.scenario(l, by_label[l])["headline"]))
        for start in range(0, len(labels), 3):
            cols = st.columns(3)
            for col, label in zip(cols, labels[start:start + 3]):
                with col:
                    with st.container(key=f"card-{label}"):
                        st.markdown(ui.card_header(label, by_label[label]), unsafe_allow_html=True)
                        n = sum(1 for p in pool if p["label"] == label)
                        st.button("Launch", key=f"go-{label}", width="stretch", on_click=launch,
                                  kwargs={"label": label}, help=f"{n} real flows of this type in the test set")
    st.stop()

# ===========================================================================
# RUN
# ===========================================================================
run = state.run
row = load_test_sample(run["sample_id"], dataset)
if row is None:
    st.error(f"There is no flow called `{run['sample_id']}`. Sample IDs run from sample_00000 to "
             f"sample_{len(pool) - 1:05d}.")
    st.button("← Back to the lab", on_click=back_to_lab)
    st.stop()
true_label = row[cfg["label_column"]]
true_family = cfg["label_to_family"].get(true_label, "Other")
mystery = run["mystery"]

b1, b2, b3 = st.columns([1.2, 1.2, 4], vertical_alignment="center")
b1.button("← Back to the lab", on_click=back_to_lab, width="stretch")
if run["label"] or mystery:
    b2.button("↻ Launch another", width="stretch", on_click=launch, kwargs={"label": run["label"], "mystery": mystery})
b3.markdown(f'<div class="crumb">flow {run["sample_id"]}</div>', unsafe_allow_html=True)

facts = [("Protocol", f'{row.get("proto", "")}' + (f' · {row["service"]}' if row.get("service", "-") != "-" else "")),
         ("Target port", row.get("id.resp_p", "")),
         ("Duration", ui.fmt_duration(float(row.get("flow_duration", 0)))),
         ("Packets out / back", f'{int(row.get("fwd_pkts_tot", 0))} / {int(row.get("bwd_pkts_tot", 0))}')]
st.markdown(ui.stage(None if mystery else true_label, "" if mystery else true_family, facts, mystery=mystery),
            unsafe_allow_html=True)

n_features = len([c for c in row.index if c not in set(cfg.get("drop_columns", [])) | {cfg["label_column"], "sample_id"}])
n_labels = len(cfg["label_to_family"])
live = bool(state.get("animate"))
state.animate = False
if live:   # a fresh launch starts at the top of the page, where the animation plays
    st.iframe("""<script>
      // Streamlit scrolls different containers depending on the page, so reset whichever is scrolled.
      const reset = () => window.parent.document.querySelectorAll('*').forEach(e => { if (e.scrollTop > 0) e.scrollTop = 0; });
      reset(); setTimeout(reset, 150); setTimeout(reset, 600);
    </script>""", height=1)

st.markdown(ui.tracker(live, n_features, n_labels), unsafe_allow_html=True)

det = detect(row, dataset)
st.markdown(ui.reveal(ui.verdict_card(det, true_label) + ui.why_rows(det, glossary()), live), unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Debrief: chat with the assistant
# ---------------------------------------------------------------------------
st.markdown("### Question the assistant")
st.markdown(ui.CITE_LEGEND, unsafe_allow_html=True)
QUICK = {"What happened?": "What is this traffic, and why did the detector classify it this way?",
         "How do I respond?": "How should I respond to this traffic?",
         "Official references": "Which official ATT&CK technique or CAPEC attack pattern describes this traffic, "
                                "and are there known related vulnerabilities (CVEs)?"}
clicked = None
for col, (label, q) in zip(st.columns(len(QUICK)), QUICK.items()):
    if col.button(label, width="stretch"):
        clicked = q


def render_answer(msg, heading=None):
    if heading:
        st.markdown(f'<div class="vs-head">{heading[0]}</div><div class="vs-sub">{heading[1]}</div>', unsafe_allow_html=True)
    box = "vs-box" if msg.get("allowed") is not None else "vs-box plain"
    # blank lines around the text let Streamlit render the model's markdown (bold, bullets) inside the box
    st.markdown(f'<div class="{box}">\n\n{ui.answer_with_chips(msg["content"], msg.get("allowed"))}\n\n</div>',
                unsafe_allow_html=True)
    flags = ui.id_flags(msg["content"], msg["question"], det["predicted_label"])
    if flags:
        st.markdown(flags, unsafe_allow_html=True)
    st.caption(msg["caption"])
    if msg.get("fallback_reason"):
        st.warning(f"Tool calling failed, so the fixed pipeline answered instead ({msg['fallback_reason']}).")
    for w in msg.get("warnings", []):
        st.warning(w)
    if msg.get("evidence"):
        with st.expander(f"Sources this answer could use ({len(msg['evidence'])} + detector output)"):
            if msg.get("tool_trace"):
                st.markdown("**Tool calls:** " + " → ".join(
                    f"`{t['tool']}({', '.join(map(str, t['arguments'].values()))})`" for t in msg["tool_trace"]))
            st.markdown(ui.source_cards(msg["evidence"]), unsafe_allow_html=True)


def ask(question, retrieval, mode="fixed"):
    out = answer(question, run["sample_id"], dataset, retrieval, mode)
    grounded = out["retrieval"]
    return {"role": "assistant", "question": question, "content": out["answer"],
            "allowed": ui.allowed_tags(out["evidence_chunks"], out["detection"] is not None) if grounded else None,
            "caption": ("grounded in the knowledge base" if grounded else "from the model's memory, no sources")
                       + (" · tool calling" if out["mode"] == "tool" else "")
                       + f" · {out['model']}" + (" · from cache" if out["cached"] else ""),
            "evidence": out["evidence_chunks"], "tool_trace": out["tool_trace"],
            "fallback_reason": out["fallback_reason"], "warnings": out["warnings"]}


if not state.messages:
    st.markdown('<div class="empty">Pick a question above or type your own below. '
                'Turn on <b>Answer twice</b> in the sidebar to see the same question answered without and with the '
                'knowledge base, with every cited ID checked against the official MITRE files.</div>', unsafe_allow_html=True)

for msg in state.messages:
    if msg["role"] == "user":
        with st.chat_message("user", avatar="🧑‍💻"):
            st.markdown(msg["content"])
    elif msg["role"] == "compare":
        with st.chat_message("assistant", avatar="🛡️"):
            c1, c2 = st.columns(2)
            with c1:
                render_answer(msg["plain"], ("Without the knowledge base", "Written from the model's memory."))
            with c2:
                render_answer(msg["grounded"], ("With the knowledge base", "Only the evidence it was given, cited."))
    else:
        with st.chat_message("assistant", avatar="🛡️"):
            render_answer(msg)

question = st.chat_input("Ask about this flow, or about any attack type…") or clicked
if question:
    state.messages.append({"role": "user", "content": question})
    with st.chat_message("user", avatar="🧑‍💻"):
        st.markdown(question)
    with st.chat_message("assistant", avatar="🛡️"):
        try:
            with st.spinner("Reading the evidence and writing an answer…"):
                if side_by_side:
                    msg = {"role": "compare", "plain": ask(question, False), "grounded": ask(question, True)}
                else:
                    msg = ask(question, use_retrieval, "tool" if tool_mode else "fixed")
        except (LLMError, ValueError) as e:
            state.messages.pop()
            st.error(f"No answer: {e}")
            st.stop()
        if msg["role"] == "compare":
            c1, c2 = st.columns(2)
            with c1:
                render_answer(msg["plain"], ("Without the knowledge base", "Written from the model's memory."))
            with c2:
                render_answer(msg["grounded"], ("With the knowledge base", "Only the evidence it was given, cited."))
        else:
            render_answer(msg)
    state.messages.append(msg)
