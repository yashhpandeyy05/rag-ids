"""
Configuration for RAG-IDS: project paths, config-file loading and API keys.

Every other module gets paths and settings from here, so that no dataset
name, model name or folder is hard-coded anywhere else.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List

import yaml
from dotenv import load_dotenv

logger = logging.getLogger("config")

# ---------------------------------------------------------------------------
# Project folders
# ---------------------------------------------------------------------------
SRC_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SRC_DIR.parent
CONFIGS_DIR = PROJECT_ROOT / "configs"
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
KB_RAW_DIR = DATA_DIR / "kb_raw"          # official downloads (ATT&CK, CAPEC, NVD)
KB_MANUAL_DIR = DATA_DIR / "kb_manual"    # the two files we wrote ourselves
KB_BUILT_DIR = DATA_DIR / "kb"            # chunk catalogue + ID registry built from the above
CHROMA_DB_DIR = DATA_DIR / "chroma_db"    # vector store
MODELS_DIR = PROJECT_ROOT / "models"
EVAL_DIR = PROJECT_ROOT / "eval"
EVAL_RESULTS_DIR = EVAL_DIR / "results"
EVAL_PLOTS_DIR = EVAL_DIR / "plots"
CACHE_DIR = PROJECT_ROOT / "cache"        # LLM response cache

DEFAULT_DATASET = "ciciot2023"

SHARED_FAMILIES = [
    "Normal", "DoS", "Reconnaissance", "Spoofing",
    "Brute force", "Web attack", "Botnet/Malware", "Other",
]

# API keys come from the .env file, which is never committed.
load_dotenv(PROJECT_ROOT / ".env")


def ensure_directories() -> None:
    """Create the output folders if they do not exist yet."""
    for d in [RAW_DATA_DIR, PROCESSED_DATA_DIR, KB_RAW_DIR, KB_BUILT_DIR,
              CHROMA_DB_DIR, MODELS_DIR, EVAL_RESULTS_DIR, EVAL_PLOTS_DIR, CACHE_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# ---------------------------------------------------------------------------
# Datasets
# ---------------------------------------------------------------------------
def available_datasets() -> List[str]:
    """Every configs/<name>.yaml that describes a dataset (has a label column)."""
    names = []
    for p in sorted(CONFIGS_DIR.glob("*.yaml")):
        if "label_column" in load_yaml(p):
            names.append(p.stem)
    return names


def trained_datasets() -> List[str]:
    """Datasets that already have a trained detector (used by the app's dropdown)."""
    return [d for d in available_datasets() if (dataset_paths(d)["model"]).exists()]


def get_dataset_config(dataset: str = DEFAULT_DATASET) -> Dict[str, Any]:
    cfg = load_yaml(CONFIGS_DIR / f"{dataset}.yaml")
    cfg["key"] = dataset
    bad = {f for f in cfg.get("label_to_family", {}).values() if f not in SHARED_FAMILIES}
    if bad:
        raise ValueError(f"{dataset}.yaml uses unknown attack families {bad}; allowed: {SHARED_FAMILIES}")
    return cfg


def dataset_paths(dataset: str = DEFAULT_DATASET) -> Dict[str, Path]:
    """Where the processed data, sample pool and model files of one dataset live."""
    proc = PROCESSED_DATA_DIR / dataset
    mdl = MODELS_DIR / dataset
    return {
        "processed_dir": proc,
        "train": proc / "train.parquet",
        "test": proc / "test.parquet",
        "pool": proc / "test_samples_pool.json",
        "models_dir": mdl,
        "model": mdl / "detector_xgboost.json",
        "preprocessor": mdl / "preprocessor.joblib",
        "results_dir": EVAL_RESULTS_DIR / dataset,
        "plots_dir": EVAL_PLOTS_DIR / dataset,
    }


def family_of(label: str, dataset: str = DEFAULT_DATASET) -> str:
    """Shared attack family of a label ('Other' if the dataset config does not list it)."""
    return get_dataset_config(dataset).get("label_to_family", {}).get(label, "Other")


# ---------------------------------------------------------------------------
# Attack mapping (labels -> official IDs)
# ---------------------------------------------------------------------------
def get_attack_mapping() -> Dict[str, Dict[str, List[str]]]:
    """Return {label: {"capec": [...], "attack": [...]}} from configs/attack_mapping.yaml."""
    data = load_yaml(CONFIGS_DIR / "attack_mapping.yaml").get("labels", {}) or {}
    return {lbl: {"capec": list(v.get("capec") or []), "attack": list(v.get("attack") or [])}
            for lbl, v in data.items()}


def check_mapping_covers_dataset(dataset: str = DEFAULT_DATASET) -> List[str]:
    """Warn about dataset labels that have no entry in attack_mapping.yaml.
    Such labels still work (semantic search only), so this is a warning, not an error."""
    mapping = get_attack_mapping()
    missing = [l for l in get_dataset_config(dataset)["label_to_family"] if l not in mapping]
    for l in missing:
        logger.warning("Label '%s' has no entry in configs/attack_mapping.yaml; "
                       "the assistant will rely on semantic search alone for it.", l)
    return missing


# ---------------------------------------------------------------------------
# LLM settings and keys
# ---------------------------------------------------------------------------
def get_llm_config() -> Dict[str, Any]:
    return load_yaml(CONFIGS_DIR / "llm.yaml")


def api_key_for(provider: str) -> str:
    env_name = get_llm_config()["providers"][provider]["api_key_env"]
    return os.getenv(env_name, "")


ensure_directories()
