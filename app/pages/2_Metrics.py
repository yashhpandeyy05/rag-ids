"""Second page of the app: detector and evaluation results, read from the result files."""

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

APP_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(APP_DIR.parent))   # project root, for "src"
sys.path.insert(0, str(APP_DIR))          # app folder, for "ui"

import ui                                                            # noqa: E402
from src.config import dataset_paths, get_dataset_config, trained_datasets  # noqa: E402

st.set_page_config(page_title="RAG-IDS · Results", page_icon="📊", layout="wide")
ui.inject_css()

datasets = trained_datasets()
if not datasets:
    st.error("No trained detector yet. Run `python -m src.detector` first.")
    st.stop()
with st.sidebar:
    st.markdown('<div class="brand"><span class="name">RAG-IDS</span><span class="tag">results</span></div>',
                unsafe_allow_html=True)
    dataset = st.selectbox("Dataset", datasets, format_func=lambda d: get_dataset_config(d)["dataset_name"])
p = dataset_paths(dataset)
rd, pd_dir = p["results_dir"], p["plots_dir"]
m = json.loads((rd / "detector_metrics.json").read_text())
t = m["test"]

st.title("Results")
tab_det, tab_eval = st.tabs(["Detector", "Hallucination evaluation"])

# ---------------------------------------------------------------------------
with tab_det:
    st.markdown(f'<div class="flowline">{m["chosen_model"]} · trained {m["trained_at"][:10]} · '
                f'{m["train_rows"]:,} training flows · {m["test_rows"]:,} test flows (each scored once)</div>',
                unsafe_allow_html=True)
    cols = st.columns(4)
    cards = [("Macro-F1 (headline)", f"{t['macro_f1']:.3f}", "average over the 12 labels, each counted equally"),
             ("Accuracy", f"{t['accuracy']:.1%}", "share of test flows labelled correctly"),
             ("False alarms", f"{t['false_alarm_rate']:.2%}",
              f"{t['false_alarms']} of {t['normal_flows']:,} normal flows called an attack"),
             ("Port leakage check", f"{m['leakage_check']['difference']:+.3f}",
              "change in macro-F1 when the port columns are removed")]
    for col, (k, v, n) in zip(cols, cards):
        col.markdown(ui.kpi(k, v, n), unsafe_allow_html=True)

    st.markdown("#### Per label")
    per = pd.read_csv(rd / "test_per_class.csv")
    per.insert(1, "name", per["label"].map(ui.pretty_label))
    st.dataframe(per, hide_index=True, width="stretch",
                 column_config={"f1": st.column_config.ProgressColumn("test F1", min_value=0, max_value=1, format="%.3f"),
                                "cv_f1": st.column_config.ProgressColumn("CV F1", min_value=0, max_value=1, format="%.3f"),
                                "rows": "test rows", "cv_rows": "CV rows"})
    st.caption("Labels with only a few test rows have noisy test scores; the cross-validation (CV) F1 uses every "
               "training row of that label and is the steadier number.")

    c1, c2 = st.columns([1.15, 1])
    with c1:
        st.markdown("#### Confusion matrix (test set)")
        st.image(str(pd_dir / "confusion_matrix.png"))
    with c2:
        st.markdown("#### Model comparison (5-fold cross-validation)")
        st.dataframe(pd.read_csv(rd / "model_comparison.csv"), hide_index=True, width="stretch")
        st.markdown("#### Duplicates removed before splitting")
        st.dataframe(pd.read_csv(rd / "class_counts.csv")[["label", "rows_before", "rows_after_dedup", "train", "test"]],
                     hide_index=True, width="stretch")

# ---------------------------------------------------------------------------
with tab_eval:
    main_dir = rd / "main"
    if not (main_dir / "summary.csv").exists():
        st.markdown('<div class="empty">No evaluation results yet. Run the stages of '
                    '<span class="mono">eval/run_eval.py</span> (see the README).</div>', unsafe_allow_html=True)
    else:
        summ = pd.read_csv(main_dir / "summary.csv")
        cols = st.columns(len(summ))
        for col, r in zip(cols, summ.itertuples()):
            rate = (r.n_contradicted + r.n_not_in_evidence) / r.claims if r.claims else 0
            col.markdown(ui.kpi(r.condition, f"{rate:.0%}",
                                f"unsupported claims: {r.n_contradicted + r.n_not_in_evidence} of {r.claims} "
                                f"· contradicted: {r.n_contradicted}"), unsafe_allow_html=True)
        st.image(str(pd_dir / "main" / "hallucination_rates.png"))
        st.markdown("#### Full summary")
        st.dataframe(summ[[c for c in summ.columns if not c.startswith("n_")]].set_index("condition").T.astype(str),
                     width="stretch")
        st.markdown("#### By question type")
        st.dataframe(pd.read_csv(main_dir / "by_question_type.csv"), hide_index=True, width="stretch")
        if (main_dir / "agreement.json").exists():
            a = json.loads((main_dir / "agreement.json").read_text())
            st.markdown(f"**Judge vs. you:** {a['agreements']} of {a['items']} claims agree "
                        f"({a['percent_agreement']:.0%}), Cohen's kappa {a['cohens_kappa']:.2f}.")
        if (rd / "comparison.csv").exists():
            st.markdown("#### Two answering models compared")
            st.image(str(pd_dir / "comparison.png"))
