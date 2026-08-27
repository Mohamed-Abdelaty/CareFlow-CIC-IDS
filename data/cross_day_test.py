import os
import time
import numpy as np
import pandas as pd
from datetime import datetime, timezone
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

RAW_DIR = "/data/raw"
MODELS_DIR = "/models"

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
TARGET = "is_attack"

TRAIN_DAYS = ["02-14-2018.csv", "02-15-2018.csv", "02-16-2018.csv"]
TEST_DAYS  = ["03-02-2018.csv"]

def load_and_clean_raw_day(filename, downsample_limit=200000):
    filepath = os.path.join(RAW_DIR, filename)
    print(f"Loading {filename}...")
    chunks = []
    for chunk in pd.read_csv(filepath, chunksize=100000, low_memory=False, 
                             encoding="utf-8", on_bad_lines="skip"):
        # Normalize column headers
        chunk.columns = (
            chunk.columns
            .str.strip()
            .str.lower()
            .str.replace(r"/s$", "_per_s", regex=True)
            .str.replace("/", "_per_", regex=False)
            .str.replace(" ", "_", regex=False)
            .str.replace(".", "", regex=False)
        )
        if "label" in chunk.columns:
            chunk = chunk[chunk["label"].str.lower() != "label"]
        chunks.append(chunk)
    
    df = pd.concat(chunks, ignore_index=True)
    df = df.drop_duplicates()
    
    # Store raw label for breakdown
    raw_labels = df["label"].str.strip() if "label" in df.columns else pd.Series(["unknown"] * len(df))
    
    if "label" in df.columns:
        df["is_attack"] = (df["label"].str.strip().str.lower() != "benign").astype(int)
        df = df.drop(columns=["label"])
        
    cols_to_keep = [f for f in FEATURES if f in df.columns] + ["is_attack"]
    df = df[cols_to_keep]
    for c in cols_to_keep:
        df[c] = pd.to_numeric(df[c], errors="coerce")
        
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    df["is_attack"] = df["is_attack"].astype(int)
    
    if len(df) > downsample_limit:
        print(f"  Downsampling {filename} from {len(df):,} to {downsample_limit:,} rows")
        df_sampled = df.sample(n=downsample_limit, random_state=42)
        return df_sampled, raw_labels.loc[df_sampled.index]
        
    return df, raw_labels.loc[df.index]

def main():
    print("=== CROSS-DAY GENERALIZATION TEST ===")
    
    # ── 1. Load Train Days ──
    train_frames = []
    train_label_series = []
    for f in TRAIN_DAYS:
        df_day, labels_day = load_and_clean_raw_day(f)
        train_frames.append(df_day)
        train_label_series.append(labels_day)
    df_train = pd.concat(train_frames, ignore_index=True)
    labels_train = pd.concat(train_label_series, ignore_index=True)
    print(f"Total train rows: {len(df_train):,}")
    print("Train attack types distribution:")
    print(labels_train.value_counts())
    
    # ── 2. Load Test Days ──
    test_frames = []
    test_label_series = []
    for f in TEST_DAYS:
        df_day, labels_day = load_and_clean_raw_day(f)
        test_frames.append(df_day)
        test_label_series.append(labels_day)
    df_test = pd.concat(test_frames, ignore_index=True)
    labels_test = pd.concat(test_label_series, ignore_index=True)
    print(f"Total test rows: {len(df_test):,}")
    print("Test attack types distribution:")
    print(labels_test.value_counts())
    
    # ── 3. Train Model ──
    X_train = df_train[FEATURES]
    y_train = df_train[TARGET]
    
    n_benign = int((y_train == 0).sum())
    n_attack = int((y_train == 1).sum())
    scale_pos_weight = n_benign / n_attack if n_attack > 0 else 1.0
    
    print("\nTraining XGBoost pipeline...")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            scale_pos_weight=scale_pos_weight,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )),
    ])
    pipeline.fit(X_train, y_train)
    
    # ── 4. Evaluate on Test Days ──
    X_test = df_test[FEATURES]
    y_test = df_test[TARGET]
    
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_prob)
    
    print("\n=== GENERALIZATION METRICS ===")
    print(f"Accuracy  : {acc*100:.4f}%")
    print(f"Precision : {prec*100:.4f}%")
    print(f"Recall    : {rec*100:.4f}%")
    print(f"F1 Score  : {f1*100:.4f}%")
    print(f"ROC-AUC   : {auc*100:.4f}%")
    
    # ── 5. Confusion Matrix Breakdown by Original Attack Label ──
    cm_df = pd.DataFrame({
        "true_label": labels_test,
        "predicted_binary": y_pred
    })
    print("\nConfusion Matrix Breakdown (Original Labels):")
    # Show how many benign and attack types were predicted as 0 (Benign) vs 1 (Attack)
    breakdown = cm_df.groupby("true_label")["predicted_binary"].value_counts().unstack(fill_value=0)
    breakdown.columns = ["Predicted Benign (0)", "Predicted Attack (1)"]
    print(breakdown)
    
    # ── 6. Save Cross-Day Confusion Matrix Plot ──
    # Normalize confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Oranges",
        xticklabels=["Benign", "Attack"],
        yticklabels=["Benign", "Attack"],
        linewidths=0.5, ax=ax,
        annot_kws={"color": "#f8f8f2"},
    )
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("True Label")
    ax.set_title("Confusion Matrix (Cross-Day Test)")
    
    # Dark theme style
    fig.patch.set_facecolor("#1e1e2e")
    ax.set_facecolor("#282a36")
    ax.tick_params(colors="#f8f8f2")
    ax.xaxis.label.set_color("#f8f8f2")
    ax.yaxis.label.set_color("#f8f8f2")
    ax.title.set_color("#f8f8f2")
    for spine in ax.spines.values():
        spine.set_edgecolor("#44475a")
        
    fig.tight_layout()
    os.makedirs(MODELS_DIR, exist_ok=True)
    fig.savefig(f"{MODELS_DIR}/cross_day_confusion_matrix.png", dpi=150,
                bbox_inches="tight", facecolor="#1e1e2e")
    plt.close(fig)
    print("\nSaved cross_day_confusion_matrix.png")

if __name__ == "__main__":
    main()
