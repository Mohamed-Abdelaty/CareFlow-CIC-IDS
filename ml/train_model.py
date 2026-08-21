"""
ML Training script
Reads processed data (from HDFS Parquet, or a local CSV fallback for quick testing),
trains:
  1. A regression model  -> predicted length of stay       (XGBRegressor)
  2. A classification model -> stay category (Short / Medium / Long) (XGBClassifier)
and saves both as joblib files under /models.

Why XGBoost over Random Forest?
  - Gradient Boosting builds trees sequentially; each tree corrects the errors of the
    previous one, resulting in significantly higher accuracy on tabular medical data.
  - XGBoost uses regularisation (L1/L2) to prevent overfitting.
  - It is faster to train than Random Forest on large datasets when using
    histogram-based tree building (default in modern XGBoost).
"""

import io
import os

import joblib
import pandas as pd
import pyarrow.parquet as pq
from hdfs import InsecureClient
from sklearn.compose import ColumnTransformer
from sklearn.metrics import accuracy_score, mean_absolute_error
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder
from xgboost import XGBClassifier, XGBRegressor

# ── Data sources ───────────────────────────────────────────────────────────────
# Primary: HDFS (written by Spark after cleaning & feature engineering)
HDFS_URL       = os.getenv("HDFS_URL", "http://namenode:9870")
HDFS_PROCESSED = os.getenv("HDFS_PROCESSED_PATH", "/hospital/processed")

# Fallback: local CSV (useful for quick dev / testing without a running HDFS)
CSV_FALLBACK   = os.getenv("PROCESSED_DATA_PATH", "/data/processed/hospital_data.csv")

MODEL_DIR = os.getenv("MODEL_DIR", "/models")

# ── Feature definitions ────────────────────────────────────────────────────────
CATEGORICAL_FEATURES = [
    "age_group",
    "gender",
    "admission_type",
    "diagnosis",
    "severity",
    "risk_of_mortality",
]
NUMERIC_FEATURES  = []           # total_charges removed — it is derived from LOS (data leakage)
TARGET_REGRESSION = "length_of_stay"

# Stay-category label encoding  (XGBClassifier requires integer targets)
LABEL_MAP     = {"Short": 0, "Medium": 1, "Long": 2}
INV_LABEL_MAP = {0: "Short", 1: "Medium", 2: "Long"}


def categorize_stay(days: float) -> str:
    """Map a raw number of days to a clinical stay category."""
    if days <= 3:
        return "Short"
    elif days <= 7:
        return "Medium"
    return "Long"


def build_pipeline(estimator):
    """
    Build a sklearn Pipeline with:
      - OrdinalEncoder for all categorical columns
        (preferred over OneHotEncoder for tree-based models like XGBoost)
      - No numeric features (total_charges removed — data leakage)
    """
    from sklearn.pipeline import make_pipeline
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "cat",
                OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1),
                CATEGORICAL_FEATURES,
            ),
        ],
        remainder="drop",   # drop any remaining columns (none expected)
    )
    return Pipeline(steps=[("preprocess", preprocessor), ("model", estimator)])


# ── Data loading ───────────────────────────────────────────────────────────────
def load_data() -> pd.DataFrame:
    """
    Try to load processed Parquet files from HDFS (the output of Spark's
    cleaning & feature-engineering pipeline). If HDFS is unreachable, fall
    back to the local CSV file.
    """
    # 1. HDFS — primary source
    try:
        client = InsecureClient(HDFS_URL, user="root")
        files = [
            f for f in client.list(HDFS_PROCESSED, status=False)
            if f.endswith(".parquet") or f.endswith(".snappy.parquet")
        ]
        if files:
            print(f"Reading {len(files)} Parquet file(s) from HDFS: {HDFS_PROCESSED}")
            dfs = []
            for fname in files:
                path = f"{HDFS_PROCESSED}/{fname}"
                with client.read(path) as reader:
                    buf = io.BytesIO(reader.read())
                    dfs.append(pq.read_table(buf).to_pandas())
            df = pd.concat(dfs, ignore_index=True)
            print(f"Loaded {len(df)} rows from HDFS.")
            return df
        else:
            print("No Parquet files found on HDFS yet.")
    except Exception as e:
        print(f"Could not read from HDFS ({e}), trying local CSV fallback...")

    # 2. Local CSV — fallback
    if os.path.exists(CSV_FALLBACK):
        print(f"Reading from local CSV: {CSV_FALLBACK}")
        df = pd.read_csv(CSV_FALLBACK)
        print(f"Loaded {len(df)} rows from CSV.")
        return df

    return None


# ── Training ───────────────────────────────────────────────────────────────────
def main():
    df = load_data()
    if df is None:
        print("No data found — neither HDFS nor local CSV. Skipping training.")
        return

    os.makedirs(MODEL_DIR, exist_ok=True)

    # Drop rows that are still missing any required column
    df = df.dropna(subset=CATEGORICAL_FEATURES + NUMERIC_FEATURES + [TARGET_REGRESSION])
    df[TARGET_REGRESSION] = pd.to_numeric(df[TARGET_REGRESSION], errors="coerce")
    df = df.dropna(subset=[TARGET_REGRESSION])

    # Derive stay category and encode to integers for XGBClassifier
    df["stay_category"] = df[TARGET_REGRESSION].apply(categorize_stay)

    features = CATEGORICAL_FEATURES   # total_charges removed (data leakage)
    X        = df[features]
    y_reg    = df[TARGET_REGRESSION]
    y_clf    = df["stay_category"].map(LABEL_MAP)   # "Short"->0, "Medium"->1, "Long"->2

    X_train, X_test, y_reg_train, y_reg_test, y_clf_train, y_clf_test = train_test_split(
        X, y_reg, y_clf, test_size=0.2, random_state=42
    )

    # ── Task 1: Regression — predict exact length of stay ──────────────────────
    print("Training XGBRegressor ...")
    reg_pipeline = build_pipeline(
        XGBRegressor(
            n_estimators=300,       # number of boosting rounds
            max_depth=6,            # tree depth — controls model complexity
            learning_rate=0.1,      # step-size shrinkage to prevent overfitting
            subsample=0.8,          # fraction of training samples used per tree
            colsample_bytree=0.8,   # fraction of features sampled per tree
            random_state=42,
            n_jobs=-1,              # use all available CPU cores
            verbosity=0,
        )
    )
    reg_pipeline.fit(X_train, y_reg_train)
    reg_preds = reg_pipeline.predict(X_test)
    mae = mean_absolute_error(y_reg_test, reg_preds)
    print(f"Regression MAE: {mae:.2f} days")

    # ── Task 2: Classification — predict stay category ─────────────────────────
    print("Training XGBClassifier ...")
    clf_pipeline = build_pipeline(
        XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            n_jobs=-1,
            verbosity=0,
            eval_metric="mlogloss",  # multi-class log loss evaluation metric
        )
    )
    clf_pipeline.fit(X_train, y_clf_train)
    clf_preds = clf_pipeline.predict(X_test)
    acc = accuracy_score(y_clf_test, clf_preds)
    print(f"Classification accuracy: {acc:.2%}")

    # ── Save models & inverse label map ───────────────────────────────────────
    joblib.dump(reg_pipeline,  os.path.join(MODEL_DIR, "los_regressor.joblib"))
    joblib.dump(clf_pipeline,  os.path.join(MODEL_DIR, "stay_classifier.joblib"))
    joblib.dump(INV_LABEL_MAP, os.path.join(MODEL_DIR, "label_map.joblib"))
    print(f"Models saved to {MODEL_DIR}")


if __name__ == "__main__":
    main()
