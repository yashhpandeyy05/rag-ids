"""
Milestone 1 - load, clean and split a dataset.

    python -m src.data_loader                 # RT-IoT2022 (default)
    python -m src.data_loader --dataset NAME  # any configs/NAME.yaml

Steps:
 1. Load the raw CSV (downloaded once, then kept in data/raw/).
 2. Drop the columns listed in the config (row number, source port).
 3. Remove exact duplicate rows BEFORE splitting, so the same flow can never
    be in both the training and the test set. Print class counts before/after.
 4. Stratified 80/20 split with a fixed seed. ("Stratified" = every class keeps
    the same share in both parts.)
 5. Give every test row a stable sample ID (sample_00000, ...). The test rows
    are the only traffic the app and the evaluation ever use.
"""

import argparse
import io
import json
import logging
import zipfile

import pandas as pd
import requests
from sklearn.model_selection import train_test_split

from src.config import (DEFAULT_DATASET, PROJECT_ROOT,
                        check_mapping_covers_dataset, dataset_paths, get_dataset_config)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("data_loader")

SMALL_CLASS_WARNING = 20   # warn if a class has fewer rows than this after de-duplication


def load_raw_dataset(config: dict) -> pd.DataFrame:
    """Read the local CSV copy; download it first if it is not there yet."""
    src = config["source"]
    local_csv = PROJECT_ROOT / src["local_csv"]
    if local_csv.exists():
        logger.info("Reading local copy %s", local_csv)
        return pd.read_csv(local_csv)

    local_csv.parent.mkdir(parents=True, exist_ok=True)
    df = None
    if "uci_id" in src:
        try:
            from ucimlrepo import fetch_ucirepo
            logger.info("Downloading UCI dataset id=%s with ucimlrepo ...", src["uci_id"])
            ds = fetch_ucirepo(id=src["uci_id"])
            df = pd.concat([ds.data.features, ds.data.targets], axis=1)
        except Exception as e:  # noqa: BLE001 - any failure -> try the zip instead
            logger.warning("ucimlrepo failed (%s); trying the zip file instead.", e)
    if df is None and "zip_url" not in src:
        raise FileNotFoundError(f"{local_csv} is missing and the config gives no download source. "
                                "Download the data by hand (see the comments in the config file).")
    if df is None:
        logger.info("Downloading %s ...", src["zip_url"])
        resp = requests.get(src["zip_url"], timeout=120)
        resp.raise_for_status()
        z = zipfile.ZipFile(io.BytesIO(resp.content))
        # The RT-IoT2022 zip holds one file without a .csv extension, so take the largest file.
        name = max(z.infolist(), key=lambda i: i.file_size).filename
        df = pd.read_csv(z.open(name))
    df.to_csv(local_csv, index=False)
    logger.info("Saved local copy to %s (%d rows)", local_csv, len(df))
    return df


def clean_and_split(df: pd.DataFrame, config: dict):
    """Drop columns, de-duplicate, split. Returns (train_df, test_df, class_count_table)."""
    label = config["label_column"]
    drop = [c for c in config.get("drop_columns", []) if c in df.columns]
    logger.info("Dropping columns: %s", drop)
    df = df.drop(columns=drop)

    before = df[label].value_counts()
    if config.get("dedup_before_split", True):
        n_dups = int(df.duplicated().sum())
        logger.info("Removing %d exact duplicate rows (%.1f%% of %d)", n_dups, 100 * n_dups / len(df), len(df))
        df = df.drop_duplicates().reset_index(drop=True)
    after = df[label].value_counts()

    table = pd.DataFrame({"rows_before": before, "rows_after_dedup": after}).fillna(0).astype(int)
    table["removed"] = table["rows_before"] - table["rows_after_dedup"]
    table["kept_%"] = (100 * table["rows_after_dedup"] / table["rows_before"]).round(1)
    table = table.sort_values("rows_before", ascending=False)

    # Rows whose 82 feature values are identical but whose label differs: the
    # model cannot possibly get all of them right. Reported, not removed.
    feats = [c for c in df.columns if c != label]
    conflicts = df[df.duplicated(subset=feats, keep=False)]
    if len(conflicts):
        logger.warning("%d rows share identical features with a row of a DIFFERENT label: %s",
                       len(conflicts), conflicts[label].value_counts().to_dict())

    for cls, n in after.items():
        if n < SMALL_CLASS_WARNING:
            logger.warning("Class '%s' has only %d unique rows -> about %d test row(s). "
                           "Its test score will be very noisy; use its cross-validation score.",
                           cls, n, max(1, round(n * config["split"]["test_size"])))

    train_df, test_df = train_test_split(
        df, test_size=config["split"]["test_size"],
        random_state=config["split"]["random_seed"], stratify=df[label])
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)
    test_df.insert(0, "sample_id", [f"sample_{i:05d}" for i in range(len(test_df))])

    table["train"] = train_df[label].value_counts().reindex(table.index).fillna(0).astype(int)
    table["test"] = test_df[label].value_counts().reindex(table.index).fillna(0).astype(int)
    return train_df, test_df, table


def save_outputs(train_df, test_df, table, config) -> None:
    paths = dataset_paths(config["key"])
    paths["processed_dir"].mkdir(parents=True, exist_ok=True)
    paths["results_dir"].mkdir(parents=True, exist_ok=True)
    train_df.to_parquet(paths["train"], index=False)
    test_df.to_parquet(paths["test"], index=False)
    table.to_csv(paths["results_dir"] / "class_counts.csv", index_label="label")

    # A small index of the test pool, so the app can list samples without loading parquet.
    label = config["label_column"]
    fam = config["label_to_family"]
    port = (config.get("port_columns") or [None])[0]
    pool = [{
        "sample_id": r["sample_id"],
        "label": r[label],
        "attack_family": fam.get(r[label], "Other"),
        "proto": str(r.get("proto", "")),
        "service": str(r.get("service", "")),
        "dest_port": int(r[port]) if port and port in r else None,
    } for r in test_df.to_dict("records")]
    with open(paths["pool"], "w", encoding="utf-8") as f:
        json.dump(pool, f, indent=1)
    logger.info("Saved %s, %s and %s", paths["train"], paths["test"], paths["pool"])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=DEFAULT_DATASET)
    args = ap.parse_args()

    config = get_dataset_config(args.dataset)
    check_mapping_covers_dataset(args.dataset)
    raw = load_raw_dataset(config)
    print(f"\nRaw data: {raw.shape[0]:,} rows x {raw.shape[1]} columns, "
          f"{int(raw.isna().sum().sum())} missing values")

    train_df, test_df, table = clean_and_split(raw, config)
    save_outputs(train_df, test_df, table, config)

    print("\nCLASS COUNTS BEFORE / AFTER REMOVING DUPLICATES")
    print(table.to_string())
    print(f"\nTOTAL: {table['rows_before'].sum():,} rows -> {table['rows_after_dedup'].sum():,} unique rows "
          f"-> {len(train_df):,} train / {len(test_df):,} test")
    print(f"Test sample IDs: {test_df['sample_id'].iloc[0]} ... {test_df['sample_id'].iloc[-1]}")


if __name__ == "__main__":
    main()
