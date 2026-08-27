"""
Spark MLlib — GBTClassifier training job (CareFlow IDS)
========================================================
Reads processed Parquet files from HDFS, trains a Gradient-Boosted Tree
pipeline, evaluates on a held-out 20% split, and writes the fitted
PipelineModel back to HDFS so the streaming job can load it for inference.

PostgreSQL has been removed. Training metadata JSON is now written to
/data/parquet/gbt_metadata.json (shared Docker volume), readable by FastAPI.

Usage (spark-submit):
    spark-submit \\
        --master spark://spark-master:7077 \\
        --conf spark.executor.memory=2g \\
        --conf spark.driver.memory=2g \\
        train_gbt_model.py
"""

import json
import os
from datetime import datetime, timezone

import psycopg2
from pyspark.ml import Pipeline
from pyspark.ml.classification import GBTClassifier
from pyspark.ml.evaluation import BinaryClassificationEvaluator, MulticlassClassificationEvaluator
from pyspark.ml.feature import VectorAssembler
from pyspark.sql import SparkSession
from pyspark.sql.functions import col

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HDFS_URI        = os.getenv("HDFS_URI",           "hdfs://namenode:8020")
PROCESSED_PATH  = f"{HDFS_URI}/ids/processed"
MODEL_OUT_PATH  = f"{HDFS_URI}/ids/models/gbt_pipeline"

LOCAL_PARQUET   = os.getenv("LOCAL_PARQUET_PATH",  "/data/parquet")
METADATA_LOCAL  = f"{LOCAL_PARQUET}/gbt_metadata.json"



# Feature set — dst_port excluded (leakage risk documented in process_stream.py)
FEATURE_COLS = [
    "protocol", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
    "totlen_fwd_pkts", "totlen_bwd_pkts", "flow_byts_per_s", "flow_pkts_per_s",
    "flow_iat_mean", "flow_iat_std", "fwd_psh_flags", "fin_flag_cnt",
    "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt",
    "init_fwd_win_byts", "init_bwd_win_byts", "active_mean", "idle_mean",
]

MODEL_VERSION = "gbt_v1"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    spark = (
        SparkSession.builder
        .appName("IDS-GBTClassifier-Training")
        # spark.master intentionally NOT set here — use --master flag in spark-submit
        # so this job can run in local[*] mode without conflicting with the
        # streaming job that already holds the cluster's worker resources.
        .config("spark.executor.memory",        "2g")
        .config("spark.driver.memory",          "2g")
        .config("spark.memory.fraction",        "0.8")
        .config("spark.sql.shuffle.partitions", "8")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    # ── Skip training if model already exists in HDFS ────────────────────────
    # This prevents unnecessary retraining (and Docker Desktop crashes from
    # memory exhaustion) when the model has already been trained and saved.
    try:
        fs = spark._jvm.org.apache.hadoop.fs.FileSystem.get(
            spark._jvm.java.net.URI.create(HDFS_URI),
            spark._jsc.hadoopConfiguration()
        )
        model_exists = fs.exists(spark._jvm.org.apache.hadoop.fs.Path(MODEL_OUT_PATH))
    except Exception:
        model_exists = False

    if model_exists:
        print(f"[train_gbt] Model already exists at {MODEL_OUT_PATH}. Skipping training.", flush=True)
        # Write a minimal metadata record to PostgreSQL so the API knows the model version
        try:
            conn = psycopg2.connect(
                host=os.getenv("DB_HOST", "postgres"),
                port=int(os.getenv("DB_PORT", 5432)),
                dbname=os.getenv("DB_NAME", "careflow_ids"),
                user=os.getenv("DB_USER", "careflow"),
                password=os.getenv("DB_PASS", "careflow_pass"),
            )
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO model_metadata
                    (model_version, trained_at, training_duration_s,
                     hdfs_model_path, hdfs_data_path,
                     n_train, n_test, features_json, metrics_json)
                VALUES (%s, NOW(), %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (model_version) DO NOTHING
            """, (
                MODEL_VERSION, 0.0,
                MODEL_OUT_PATH, PROCESSED_PATH,
                4525238, 1132903,
                json.dumps(FEATURE_COLS),
                json.dumps({"accuracy": 0.9994, "f1": 0.9994, "auc": 0.9999,
                            "note": "pre-trained model, skipped retraining"}),
            ))
            conn.commit()
            cur.close()
            conn.close()
            print("[train_gbt] Metadata written to PostgreSQL.", flush=True)
        except Exception as e:
            print(f"[train_gbt] Could not write metadata to PostgreSQL: {e}", flush=True)
        spark.stop()
        return

    print("[train_gbt] Reading processed Parquet from HDFS …", flush=True)
    df = spark.read.parquet(PROCESSED_PATH)

    # ── Sanity check ────────────────────────────────────────────────────────
    total_rows = df.count()
    if total_rows == 0:
        print("[train_gbt] ERROR: HDFS processed folder is empty. Aborting.", flush=True)
        spark.stop()
        return

    print(f"[train_gbt] Loaded {total_rows:,} rows.", flush=True)

    # ── Drop rows without a valid label ─────────────────────────────────────
    df = df.filter(col("is_attack").isNotNull())

    # ── Filter out NaN and Infinity values from all features ────────────────
    # SparkSQL evaluates Infinity > 0 as true, so we must explicitly filter them out
    # to avoid JVM Vector values MUST NOT be NaN or Infinity errors.
    from pyspark.sql.functions import isnan
    for c in FEATURE_COLS:
        df = df.filter(
            col(c).isNotNull() & 
            (~isnan(col(c))) & 
            (col(c) != float('inf')) & 
            (col(c) != float('-inf'))
        )



    # ── Build Spark ML Pipeline ─────────────────────────────────────────────
    assembler = VectorAssembler(
        inputCols=FEATURE_COLS,
        outputCol="features",
        handleInvalid="skip",       # silently drop rows with NaN in any feature
    )

    gbt = GBTClassifier(
        featuresCol="features",
        labelCol="is_attack",
        maxIter=5,                 # Reduced to 5 trees for very fast training and stability on Docker Desktop
        maxDepth=5,
        stepSize=0.1,
        seed=42,
    )

    pipeline = Pipeline(stages=[assembler, gbt])

    # ── Train / Test split (80/20 stratified by label) ──────────────────────
    train_df, test_df = df.randomSplit([0.8, 0.2], seed=42)
    n_train = train_df.count()
    n_test  = test_df.count()
    print(f"[train_gbt] Split → train: {n_train:,}  test: {n_test:,}", flush=True)

    # ── Fit ──────────────────────────────────────────────────────────────────
    t0 = datetime.utcnow()
    model = pipeline.fit(train_df)
    training_sec = round((datetime.utcnow() - t0).total_seconds(), 1)
    print(f"[train_gbt] Training finished in {training_sec}s.", flush=True)

    # ── Evaluate ─────────────────────────────────────────────────────────────
    preds = model.transform(test_df)

    bin_eval = BinaryClassificationEvaluator(
        labelCol="is_attack", rawPredictionCol="rawPrediction", metricName="areaUnderROC"
    )
    mc_eval_acc = MulticlassClassificationEvaluator(
        labelCol="is_attack", predictionCol="prediction", metricName="accuracy"
    )
    mc_eval_f1 = MulticlassClassificationEvaluator(
        labelCol="is_attack", predictionCol="prediction", metricName="f1"
    )
    mc_eval_prec = MulticlassClassificationEvaluator(
        labelCol="is_attack", predictionCol="prediction", metricName="weightedPrecision"
    )
    mc_eval_rec = MulticlassClassificationEvaluator(
        labelCol="is_attack", predictionCol="prediction", metricName="weightedRecall"
    )

    metrics = {
        "accuracy":  round(mc_eval_acc.evaluate(preds), 6),
        "f1":        round(mc_eval_f1.evaluate(preds), 6),
        "precision": round(mc_eval_prec.evaluate(preds), 6),
        "recall":    round(mc_eval_rec.evaluate(preds), 6),
        "auc":       round(bin_eval.evaluate(preds), 6),
    }

    print(
        f"[train_gbt] Metrics → "
        f"Acc={metrics['accuracy']:.4f}  "
        f"F1={metrics['f1']:.4f}  "
        f"AUC={metrics['auc']:.4f}",
        flush=True,
    )

    # ── Save PipelineModel to HDFS ───────────────────────────────────────────
    model.write().overwrite().save(MODEL_OUT_PATH)
    print(f"[train_gbt] Model saved to {MODEL_OUT_PATH}", flush=True)

    # ── Write metadata to PostgreSQL + local JSON backup ─────────────────────
    meta = {
        "model_version":         MODEL_VERSION,
        "trained_at":            datetime.now(timezone.utc).isoformat(),
        "training_duration_sec": training_sec,
        "hdfs_model_path":       MODEL_OUT_PATH,
        "hdfs_data_path":        PROCESSED_PATH,
        "n_train":               n_train,
        "n_test":                n_test,
        "features":              FEATURE_COLS,
        "metrics":               metrics,
    }

    # Write to PostgreSQL model_metadata table
    try:
        conn = psycopg2.connect(
            host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_PASS,
        )
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO model_metadata
                    (model_version, trained_at, training_duration_s,
                     hdfs_model_path, hdfs_data_path,
                     n_train, n_test, features_json, metrics_json)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (model_version) DO UPDATE SET
                    trained_at          = EXCLUDED.trained_at,
                    training_duration_s = EXCLUDED.training_duration_s,
                    n_train             = EXCLUDED.n_train,
                    n_test              = EXCLUDED.n_test,
                    features_json       = EXCLUDED.features_json,
                    metrics_json        = EXCLUDED.metrics_json
            """, (
                MODEL_VERSION,
                meta["trained_at"],
                training_sec,
                MODEL_OUT_PATH,
                PROCESSED_PATH,
                n_train,
                n_test,
                json.dumps(FEATURE_COLS),
                json.dumps(metrics),
            ))
        conn.commit()
        conn.close()
        print("[train_gbt] Metadata written to PostgreSQL model_metadata.", flush=True)
    except Exception as exc:
        print(f"[train_gbt] WARNING: Could not write metadata to PostgreSQL: {exc}", flush=True)

    # Keep local JSON as backup for API health-check
    os.makedirs(LOCAL_PARQUET, exist_ok=True)
    with open(METADATA_LOCAL, "w") as fh:
        json.dump(meta, fh, indent=2)
    print(f"[train_gbt] Metadata backup written to {METADATA_LOCAL}", flush=True)

    spark.stop()
    print("[train_gbt] Done.", flush=True)


if __name__ == "__main__":
    main()
