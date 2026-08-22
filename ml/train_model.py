"""
ML Trainer — CIC-IDS 2018 Network Intrusion Detection
Reads processed Parquet files from HDFS, trains an XGBClassifier to
detect whether a network flow is benign or an attack (binary classification).

Design notes:
  - Problem type  : Binary classification only (no regression target exists)
  - Class imbalance: IDS-2018 is ~83% Benign / ~17% Attack.
    Handled via scale_pos_weight = n_benign / n_attack inside XGBoost.
  - Data leakage  : `dst_port` is kept as a feature but noted as a
    partial-leakage risk (some attack types consistently target fixed ports).
    All other leaky columns (raw timestamps, flow IDs) are never included.
  - Pipeline      : ColumnTransformer wraps a StandardScaler for all
    numeric features inside a sklearn Pipeline, so scaling is fit only on
    the training split — never on the full dataset.
  - Evaluation    : Accuracy, Precision, Recall, F1, and ROC-AUC are all
    reported on the held-out test set to give an honest performance picture.
"""

import io
import os
import warnings

import joblib
import numpy as np
import pandas as pd
import requests
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HDFS_NAMENODE   = os.getenv("HDFS_NAMENODE",  "http://namenode:9870")
PROCESSED_PATH  = "/ids/processed"
MODELS_DIR      = os.getenv("MODELS_DIR",     "/models")
CSV_FALLBACK    = os.getenv("CSV_FALLBACK",   "/data/raw")   # first CSV found

# Features selected for training:
#   - All numeric, directly measured from the network flow
#   - NOTE: dst_port is included but flagged as a potential partial-leakage
#     source (some attack types always hit the same port). The model may
#     partially memorise port numbers rather than true traffic patterns.
FEATURES = [
    "dst_port",           # ⚠ partial leakage risk — see module docstring
    "protocol",
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "totlen_fwd_pkts",
    "totlen_bwd_pkts",
    "flow_byts_per_s",
    "flow_pkts_per_s",
    "flow_iat_mean",
    "flow_iat_std",
    "fwd_psh_flags",
    "fin_flag_cnt",
    "syn_flag_cnt",
    "rst_flag_cnt",
    "psh_flag_cnt",
    "ack_flag_cnt",
    "init_fwd_win_byts",
    "init_bwd_win_byts",
    "active_mean",
    "idle_mean",
]
TARGET = "is_attack"   # 0 = Benign, 1 = Attack (binarised by Spark)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def load_from_hdfs() -> pd.DataFrame | None:
    """Fetch all Parquet files from HDFS /ids/processed via WebHDFS REST API."""
    list_url = (
        f"{HDFS_NAMENODE}/webhdfs/v1{PROCESSED_PATH}"
        "?op=LISTSTATUS"
    )
    try:
        resp = requests.get(list_url, timeout=10)
        resp.raise_for_status()
    except Exception as exc:
        print(f"[trainer] HDFS listing failed: {exc}")
        return None

    files = resp.json().get("FileStatuses", {}).get("FileStatus", [])
    parquet_files = [f for f in files if f["pathSuffix"].endswith(".parquet")]
    if not parquet_files:
        print("[trainer] No Parquet files found in HDFS.")
        return None

    print(f"[trainer] Reading {len(parquet_files)} Parquet file(s) from HDFS: {PROCESSED_PATH}")
    frames = []
    for pf in parquet_files:
        path = f"{PROCESSED_PATH}/{pf['pathSuffix']}"
        url  = f"{HDFS_NAMENODE}/webhdfs/v1{path}?op=OPEN"
        try:
            r = requests.get(url, timeout=30, allow_redirects=True)
            r.raise_for_status()
            frames.append(pd.read_parquet(io.BytesIO(r.content)))
        except Exception as exc:
            print(f"[trainer]   Skipping {pf['pathSuffix']}: {exc}")

    if not frames:
        return None
    df = pd.concat(frames, ignore_index=True)
    print(f"[trainer] Loaded {len(df):,} rows from HDFS.")
    return df


def load_from_csv_fallback() -> pd.DataFrame | None:
    """Read the first CSV in /data/raw as a fallback when HDFS has no data yet."""
    import glob
    files = sorted(glob.glob(os.path.join(CSV_FALLBACK, "*.csv")))
    if not files:
        print(f"[trainer] No CSV fallback found in {CSV_FALLBACK}.")
        return None

    filepath = files[0]
    print(f"[trainer] CSV fallback: {filepath}")
    chunks = []
    for chunk in pd.read_csv(filepath, chunksize=100_000, low_memory=False,
                              encoding="utf-8", on_bad_lines="skip"):
        # Normalise column names (same logic as producer)
        chunk.columns = (
            chunk.columns
            .str.strip()
            .str.lower()
            .str.replace(r"/s$", "_per_s", regex=True)
            .str.replace("/", "_per_", regex=False)
            .str.replace(" ", "_", regex=False)
            .str.replace(".", "", regex=False)
        )
        # Remove repeated-header rows
        if "label" in chunk.columns:
            chunk = chunk[chunk["label"].str.lower() != "label"]
        chunks.append(chunk)

    df = pd.concat(chunks, ignore_index=True)
    # Binarise label in fallback
    if "label" in df.columns:
        df[TARGET] = (df["label"].str.strip().str.lower() != "benign").astype(int)
    print(f"[trainer] CSV fallback loaded {len(df):,} rows.")
    return df


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train(df: pd.DataFrame) -> None:
    os.makedirs(MODELS_DIR, exist_ok=True)

    # Ensure required columns are present
    missing = [c for c in FEATURES + [TARGET] if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")

    # Convert features and target to numeric, replace inf/-inf with NaN, drop bad rows
    X = df[FEATURES].apply(pd.to_numeric, errors="coerce")
    y = pd.to_numeric(df[TARGET], errors="coerce")

    # Replace Infinity values (common in IDS-2018: flow_byts_per_s = bytes/0)
    X = X.replace([np.inf, -np.inf], np.nan)

    valid = X.notna().all(axis=1) & y.notna()
    X, y = X[valid], y[valid].astype(int)
    print(f"[trainer] Training on {len(X):,} clean rows.")

    # Class distribution
    n_benign = int((y == 0).sum())
    n_attack = int((y == 1).sum())
    print(f"[trainer] Class balance — Benign: {n_benign:,}  Attack: {n_attack:,}")

    if n_attack == 0:
        raise ValueError("No attack samples found — cannot train a binary classifier.")

    scale_pos_weight = n_benign / n_attack
    print(f"[trainer] scale_pos_weight = {scale_pos_weight:.2f}")

    # Stratified train/test split to preserve class ratio
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Build sklearn Pipeline (scaler + XGBClassifier)
    # StandardScaler is fit ONLY on training data inside the pipeline.
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            scale_pos_weight=scale_pos_weight,   # compensate imbalance
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )),
    ])

    print("[trainer] Training XGBClassifier ...")
    pipeline.fit(X_train, y_train)

    # Evaluate on the held-out test set
    y_pred      = pipeline.predict(X_test)
    y_prob      = pipeline.predict_proba(X_test)[:, 1]

    accuracy    = accuracy_score(y_test, y_pred)
    precision   = precision_score(y_test, y_pred, zero_division=0)
    recall      = recall_score(y_test, y_pred, zero_division=0)
    f1          = f1_score(y_test, y_pred, zero_division=0)
    auc         = roc_auc_score(y_test, y_prob)

    print("─" * 50)
    print(f"  Accuracy  : {accuracy  * 100:.2f}%")
    print(f"  Precision : {precision * 100:.2f}%")
    print(f"  Recall    : {recall    * 100:.2f}%")
    print(f"  F1 Score  : {f1        * 100:.2f}%")
    print(f"  ROC-AUC   : {auc       * 100:.2f}%")
    print("─" * 50)
    print(classification_report(y_test, y_pred,
                                target_names=["Benign", "Attack"]))

    # Persist model and metadata
    joblib.dump(pipeline,                            f"{MODELS_DIR}/ids_classifier.joblib")
    joblib.dump({"features": FEATURES, "target": TARGET},
                                                     f"{MODELS_DIR}/model_meta.joblib")
    joblib.dump({"accuracy": accuracy, "precision": precision,
                 "recall": recall, "f1": f1, "auc": auc,
                 "n_train": len(X_train), "n_test": len(X_test),
                 "n_benign": n_benign, "n_attack": n_attack},
                                                     f"{MODELS_DIR}/metrics.joblib")

    print(f"[trainer] Models saved to {MODELS_DIR}", flush=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    df = load_from_hdfs()
    if df is None or len(df) < 100:
        print("[trainer] HDFS data insufficient — using CSV fallback.")
        df = load_from_csv_fallback()

    if df is None or len(df) < 100:
        print("[trainer] No usable data found. Exiting.")
        return

    train(df)


if __name__ == "__main__":
    main()
