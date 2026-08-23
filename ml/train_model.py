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
import json
import os
import time
import warnings
from datetime import datetime, timezone

import joblib
import matplotlib
matplotlib.use("Agg")   # non-interactive backend — must be set before pyplot import
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import requests
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
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
# Training only reads from HDFS — no CSV fallback.
# Run Spark streaming first to populate HDFS before training.

# Features selected for training.
#
# dst_port REMOVED — diagnostic investigation (2026-08-23) showed that
#   in the small initial HDFS batch (10K rows, 96 Benign vs 9,950 Attack)
#   XGBoost used flow_duration as the ONLY split (100% importance) because
#   the class imbalance was extreme enough that a single-feature threshold
#   trivially separated the classes.  dst_port was not the primary cause
#   of the 100%, but it IS a known partial-leakage feature (some attack
#   types consistently target fixed ports, letting the model memorise port
#   numbers rather than learning real traffic patterns).  It is therefore
#   excluded by default to produce more generalisable model weights.
#
# label EXCLUDED — the raw label string ("benign", "ddos attack-hoic", …)
#   is written by Spark to the Parquet schema but is NOT included here.
#   Including it would be perfect target leakage (directly correlated with
#   is_attack). The check is enforced by asserting it is absent from the
#   feature list and never passed to the model.
FEATURES = [
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

# Safety assertion — ensure no leakage columns slipped into FEATURES
_LEAKAGE_COLS = {"label", "dst_port", "src_port", "src_ip", "dst_ip", "timestamp", "flow_id"}
assert not (_LEAKAGE_COLS & set(FEATURES)), \
    f"Leakage column(s) detected in FEATURES: {_LEAKAGE_COLS & set(FEATURES)}"


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


# ---------------------------------------------------------------------------
# Plot generation & metadata
# ---------------------------------------------------------------------------
_DARK_BG = "#1e1e2e"
_AXES_BG = "#282a36"
_GREEN   = "#50fa7b"
_RED     = "#ff5555"
_CYAN    = "#8be9fd"
_TEXT    = "#f8f8f2"


def _apply_dark(fig, ax):
    """Apply a consistent dark theme to a matplotlib figure."""
    fig.patch.set_facecolor(_DARK_BG)
    ax.set_facecolor(_AXES_BG)
    ax.tick_params(colors=_TEXT)
    ax.xaxis.label.set_color(_TEXT)
    ax.yaxis.label.set_color(_TEXT)
    ax.title.set_color(_TEXT)
    for spine in ax.spines.values():
        spine.set_edgecolor("#44475a")


def save_plots(y_test, y_pred, y_prob, pipeline) -> None:
    """Generate and save confusion matrix, ROC curve, and feature importance PNGs."""
    os.makedirs(MODELS_DIR, exist_ok=True)
    plt.rcParams.update({"text.color": _TEXT, "axes.labelcolor": _TEXT})

    # 1. Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["Benign", "Attack"],
        yticklabels=["Benign", "Attack"],
        linewidths=0.5, ax=ax,
        annot_kws={"color": _TEXT},
    )
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("True Label")
    ax.set_title("Confusion Matrix (Test Set)")
    _apply_dark(fig, ax)
    fig.tight_layout()
    fig.savefig(f"{MODELS_DIR}/confusion_matrix.png", dpi=150,
                bbox_inches="tight", facecolor=_DARK_BG)
    plt.close(fig)
    print("[trainer] Saved confusion_matrix.png")

    # 2. ROC Curve
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    auc_val = roc_auc_score(y_test, y_prob)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(fpr, tpr, color=_GREEN, lw=2, label=f"AUC = {auc_val:.4f}")
    ax.plot([0, 1], [0, 1], color=_RED, lw=1, linestyle="--", label="Random")
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve (Test Set)")
    ax.legend(facecolor=_AXES_BG, labelcolor=_TEXT, framealpha=0.8)
    _apply_dark(fig, ax)
    fig.tight_layout()
    fig.savefig(f"{MODELS_DIR}/roc_curve.png", dpi=150,
                bbox_inches="tight", facecolor=_DARK_BG)
    plt.close(fig)
    print("[trainer] Saved roc_curve.png")

    # 3. Feature Importance
    clf         = pipeline.named_steps["clf"]
    importances = clf.feature_importances_
    sorted_idx  = np.argsort(importances)
    feat_names  = [FEATURES[i] for i in sorted_idx]
    feat_vals   = importances[sorted_idx]
    colors      = [_GREEN if v == feat_vals.max() else _CYAN for v in feat_vals]

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.barh(feat_names, feat_vals, color=colors)
    ax.set_xlabel("Feature Importance (gain)")
    ax.set_title("Feature Importance — XGBoost")
    _apply_dark(fig, ax)
    fig.tight_layout()
    fig.savefig(f"{MODELS_DIR}/feature_importance.png", dpi=150,
                bbox_inches="tight", facecolor=_DARK_BG)
    plt.close(fig)
    print("[trainer] Saved feature_importance.png")


def save_metadata(meta: dict) -> None:
    """Write training metadata to model_metadata.json for the API to read."""
    path = f"{MODELS_DIR}/model_metadata.json"
    with open(path, "w") as fh:
        json.dump(meta, fh, indent=2)
    print(f"[trainer] Metadata written to {path}")


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train(df: pd.DataFrame) -> None:
    os.makedirs(MODELS_DIR, exist_ok=True)

    # Ensure required columns are present
    missing = [c for c in FEATURES + [TARGET] if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")

    # Guard: label string must not be present in df columns used for training.
    # Its presence in HDFS Parquet was confirmed by the 2026-08-23 diagnostic —
    # Spark was writing the raw label string alongside is_attack.  It is now
    # dropped by Spark, but this check ensures nothing slips through.
    if "label" in df.columns:
        print("[trainer] WARNING: 'label' column found in HDFS data — dropping it "
              "to prevent target leakage.", flush=True)
        df = df.drop(columns=["label"])

    # Deduplicate BEFORE the train/test split.
    # Spark micro-batch streaming (mode='append') can write the same Kafka
    # offsets to HDFS multiple times across trigger intervals.  If duplicates
    # span the split boundary the model memorises exact rows from the training
    # set and trivially recognises them in the test set, producing 100% metrics.
    n_before = len(df)
    df = df.drop_duplicates()
    n_after  = len(df)
    n_dropped = n_before - n_after
    if n_dropped:
        print(f"[trainer] Removed {n_dropped:,} duplicate rows before split "
              f"({n_dropped/n_before*100:.1f}% of total).", flush=True)

    if len(df) < 100:
        raise ValueError("Too few unique rows after deduplication — collect more data first.")

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
    train_start = time.time()
    pipeline.fit(X_train, y_train)
    train_duration = round(time.time() - train_start, 1)

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

    if accuracy >= 0.995:
        print(
            "[trainer] ⚠  Accuracy >= 99.5% — consider checking for data leakage "
            "(e.g. dst_port memorisation). This warning is recorded in metadata.",
            flush=True,
        )

    # Persist model files
    joblib.dump(pipeline, f"{MODELS_DIR}/ids_classifier.joblib")
    joblib.dump({"features": FEATURES, "target": TARGET},
                f"{MODELS_DIR}/model_meta.joblib")
    joblib.dump({"accuracy": accuracy, "precision": precision,
                 "recall": recall, "f1": f1, "auc": auc,
                 "n_train": len(X_train), "n_test": len(X_test),
                 "n_benign": n_benign, "n_attack": n_attack},
                f"{MODELS_DIR}/metrics.joblib")

    # Generate evaluation plots (PNG files read by the API /model-plot endpoint)
    save_plots(y_test, y_pred, y_prob, pipeline)

    # Write JSON metadata (read by the API /stats and /status endpoints)
    save_metadata({
        "model_version":          "ids_classifier_v2",
        "trained_at":             datetime.now(timezone.utc).isoformat(),
        "training_duration_sec":  train_duration,
        "n_train":                len(X_train),
        "n_test":                 len(X_test),
        "n_benign":               n_benign,
        "n_attack":               n_attack,
        "hdfs_path":              PROCESSED_PATH,
        "features":               FEATURES,
        "leakage_warning":        accuracy >= 0.995,
        "metrics": {
            "accuracy":  round(accuracy,  6),
            "precision": round(precision, 6),
            "recall":    round(recall,    6),
            "f1":        round(f1,        6),
            "auc":       round(auc,       6),
        },
    })

    print(f"[trainer] All artifacts saved to {MODELS_DIR}", flush=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    df = load_from_hdfs()

    if df is None or len(df) < 100:
        print(
            "[trainer] No data found in HDFS at path: "
            f"{PROCESSED_PATH}\n"
            "[trainer] The model will NOT train on raw CSV files.\n"
            "[trainer] Please wait for Spark to process and write "
            "data to HDFS first, then re-run the trainer.",
            flush=True,
        )
        return

    train(df)


if __name__ == "__main__":
    main()
