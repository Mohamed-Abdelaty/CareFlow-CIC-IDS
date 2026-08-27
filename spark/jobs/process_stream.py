"""
Spark Structured Streaming — CareFlow IDS Unified Inference Pipeline
=====================================================================
Reads network-flow JSON messages from Kafka, applies cleaning, runs
GBTClassifier inference from a pre-trained Spark PipelineModel, and
writes all outputs inside a SINGLE foreachBatch call:

    ┌─ HDFS /ids/raw                   — raw Parquet  (SparkSQL source)
    ├─ HDFS /ids/processed             — cleaned + is_attack label (SparkSQL training input)
    ├─ PostgreSQL: network_flows       — inference results (API read source)
    └─ PostgreSQL: flow_submissions    — submission status update

Architecture:
    POST /flows (FastAPI)
      │  generates UUID flow_id, registers 'pending' in PostgreSQL
      ▼
    Kafka topic: network_flows_stream
      │
      ▼
    THIS JOB (Structured Streaming — foreachBatch)
      ├─ parse → clean → watermark → deduplicate
      ├─ write HDFS /ids/raw          (SparkSQL Big Data storage)
      ├─ write HDFS /ids/processed    (SparkSQL Big Data storage — partitioned by ingest_date)
      ├─ GBT inference → write PostgreSQL network_flows  (API serving layer)
      └─ update PostgreSQL flow_submissions → 'done'
"""

import os
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from pyspark.ml import PipelineModel
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    DoubleType,
    LongType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP  = os.getenv("KAFKA_BOOTSTRAP",  "kafka:29092")
TOPIC            = os.getenv("KAFKA_TOPIC",       "network_flows_stream")
HDFS_URI         = os.getenv("HDFS_URI",          "hdfs://namenode:8020")
RAW_PATH         = f"{HDFS_URI}/ids/raw"
PROCESSED_PATH   = f"{HDFS_URI}/ids/processed"
CHECKPOINT_PATH  = f"{HDFS_URI}/ids/checkpoints"
MODEL_PATH       = f"{HDFS_URI}/ids/models/gbt_pipeline"

# PostgreSQL connection (replaces SQLite + DuckDB)
DB_HOST = os.getenv("DB_HOST", "careflow-postgres")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "careflow_ids")
DB_USER = os.getenv("DB_USER", "careflow")
DB_PASS = os.getenv("DB_PASS", "careflow_pass")

JDBC_URL = f"jdbc:postgresql://{DB_HOST}:{DB_PORT}/{DB_NAME}"
JDBC_PROPS = {
    "user":     DB_USER,
    "password": DB_PASS,
    "driver":   "org.postgresql.Driver",
}

MODEL_VERSION = "gbt_v1"

# ---------------------------------------------------------------------------
# Kafka message schema
# ---------------------------------------------------------------------------
SCHEMA = StructType([
    StructField("flow_id",            StringType(), True),
    StructField("kafka_ingest_ts",    StringType(), True),
    StructField("dst_port",           StringType(), True),
    StructField("protocol",           StringType(), True),
    StructField("flow_duration",      StringType(), True),
    StructField("tot_fwd_pkts",       StringType(), True),
    StructField("tot_bwd_pkts",       StringType(), True),
    StructField("totlen_fwd_pkts",    StringType(), True),
    StructField("totlen_bwd_pkts",    StringType(), True),
    StructField("flow_byts_per_s",    StringType(), True),
    StructField("flow_pkts_per_s",    StringType(), True),
    StructField("flow_iat_mean",      StringType(), True),
    StructField("flow_iat_std",       StringType(), True),
    StructField("fwd_psh_flags",      StringType(), True),
    StructField("fin_flag_cnt",       StringType(), True),
    StructField("syn_flag_cnt",       StringType(), True),
    StructField("rst_flag_cnt",       StringType(), True),
    StructField("psh_flag_cnt",       StringType(), True),
    StructField("ack_flag_cnt",       StringType(), True),
    StructField("init_fwd_win_byts",  StringType(), True),
    StructField("init_bwd_win_byts",  StringType(), True),
    StructField("active_mean",        StringType(), True),
    StructField("idle_mean",          StringType(), True),
    StructField("label",              StringType(), True),
])

NUMERIC_COLS = [
    "dst_port", "protocol", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
    "totlen_fwd_pkts", "totlen_bwd_pkts", "flow_byts_per_s", "flow_pkts_per_s",
    "flow_iat_mean", "flow_iat_std", "fwd_psh_flags", "fin_flag_cnt",
    "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt",
    "init_fwd_win_byts", "init_bwd_win_byts", "active_mean", "idle_mean",
]

CRITICAL_COLS = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
    "flow_byts_per_s", "flow_pkts_per_s", "label",
]


# ---------------------------------------------------------------------------
# PostgreSQL helper — psycopg2 connection
# ---------------------------------------------------------------------------
def _pg_conn():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASS,
    )


def _update_submission_status(flow_ids: list, status: str):
    """Bulk-update flow_submissions rows to given status in PostgreSQL."""
    if not flow_ids:
        return
    try:
        completed_at = datetime.now(timezone.utc).isoformat()
        conn = _pg_conn()
        with conn.cursor() as cur:
            psycopg2.extras.execute_batch(
                cur,
                "UPDATE flow_submissions SET status=%s, completed_at=%s WHERE flow_id=%s",
                [(status, completed_at, fid) for fid in flow_ids],
            )
        conn.commit()
        conn.close()
        print(f"[stream] Updated {len(flow_ids)} flow_submissions → '{status}'.", flush=True)
    except Exception as exc:
        print(f"[stream] WARNING: Could not update flow_submissions in PostgreSQL: {exc}", flush=True)


# ---------------------------------------------------------------------------
# Lazy model loader
# ---------------------------------------------------------------------------
_gbt_model = None


def get_gbt_model():
    global _gbt_model
    if _gbt_model is None:
        try:
            _gbt_model = PipelineModel.load(MODEL_PATH)
            print(f"[stream] GBT PipelineModel loaded from {MODEL_PATH}", flush=True)
        except Exception as exc:
            print(f"[stream] WARNING: Could not load GBT model: {exc}. Inference skipped.", flush=True)
    return _gbt_model


# ---------------------------------------------------------------------------
# foreachBatch handler
# ---------------------------------------------------------------------------
def process_batch(batch_df, batch_id):
    if batch_df.isEmpty():
        return

    # ── 1. Parse JSON ─────────────────────────────────────────────────────────
    parsed = (
        batch_df
        .select(F.from_json(F.col("value").cast("string"), SCHEMA).alias("d"))
        .select("d.*")
    )

    # ── 2. Write raw snapshot to HDFS (SparkSQL Big Data storage) ─────────────
    parsed.write.mode("append").parquet(RAW_PATH)

    # ── 3. Parse kafka_ingest_ts string → TimestampType ───────────────────────
    parsed = parsed.withColumn(
        "kafka_ingest_ts",
        F.to_timestamp(F.col("kafka_ingest_ts")),
    )

    # ── 4. Normalise label + drop missing critical fields ─────────────────────
    cleaned = parsed.withColumn("label", F.trim(F.lower(F.col("label"))))
    cleaned = cleaned.dropna(subset=CRITICAL_COLS)

    # ── 5. Cast numerics to Double ────────────────────────────────────────────
    for c in NUMERIC_COLS:
        cleaned = cleaned.withColumn(c, F.col(c).cast(DoubleType()))

    # ── 6. Filter impossible / Infinity values ────────────────────────────────
    cleaned = cleaned.filter(
        (F.col("flow_duration")   >= 0) &
        (F.col("tot_fwd_pkts")    >= 0) &
        (F.col("tot_bwd_pkts")    >= 0) &
        (F.col("flow_byts_per_s").isNotNull()) &
        (F.col("flow_pkts_per_s").isNotNull()) &
        (F.col("flow_byts_per_s") >= 0) &
        (F.col("flow_pkts_per_s") >= 0)
    )

    # ── 7. Binarise label → is_attack ─────────────────────────────────────────
    cleaned = cleaned.withColumn(
        "is_attack",
        F.when(F.col("label") == "benign", 0).otherwise(1).cast(LongType()),
    )

    # ── 8. Watermark-bounded deduplication ────────────────────────────────────
    processed = (
        cleaned
        .withWatermark("kafka_ingest_ts", "10 minutes")
        .dropDuplicates(["flow_id"])
        .withColumn(
            "ingest_date",
            F.date_format(F.col("kafka_ingest_ts"), "yyyy-MM-dd"),
        )
        .drop("label")
    )

    # ── 9. Write cleaned records to HDFS /ids/processed (SparkSQL source) ─────
    (
        processed.write
        .mode("append")
        .partitionBy("ingest_date")
        .parquet(PROCESSED_PATH)
    )

    n_proc = processed.count()
    print(f"[stream] Batch {batch_id}: {n_proc} processed rows → HDFS.", flush=True)

    # ── 10. GBT inference → write results to PostgreSQL ───────────────────────
    model = get_gbt_model()
    if model is not None:
        try:
            predictions = model.transform(processed)

            extract_prob = F.udf(
                lambda v: float(v[1]) if v is not None else None, DoubleType()
            )

            infer_df = predictions.withColumn(
                "attack_probability", extract_prob(F.col("probability"))
            ).withColumn(
                "is_attack_bool", F.col("prediction").cast("boolean")
            )

            result_df = infer_df.select(
                F.col("flow_id").cast("string"),
                F.col("dst_port").cast("integer"),
                F.col("protocol").cast("integer"),
                F.col("flow_duration"),
                F.col("tot_fwd_pkts"),
                F.col("tot_bwd_pkts"),
                F.col("totlen_fwd_pkts"),
                F.col("totlen_bwd_pkts"),
                F.col("flow_byts_per_s"),
                F.col("flow_pkts_per_s"),
                F.col("flow_iat_mean"),
                F.col("flow_iat_std"),
                F.col("fwd_psh_flags"),
                F.col("fin_flag_cnt"),
                F.col("syn_flag_cnt"),
                F.col("rst_flag_cnt"),
                F.col("psh_flag_cnt"),
                F.col("ack_flag_cnt"),
                F.col("init_fwd_win_byts"),
                F.col("init_bwd_win_byts"),
                F.col("active_mean"),
                F.col("idle_mean"),
                F.col("is_attack_bool").alias("is_attack"),
                F.col("attack_probability"),
                F.lit(MODEL_VERSION).alias("model_version"),
                F.col("kafka_ingest_ts"),
            )

            # Write inference results to PostgreSQL via JDBC
            (
                result_df.write
                .mode("append")
                .jdbc(JDBC_URL, "network_flows", properties=JDBC_PROPS)
            )

            n_written = result_df.count()
            print(f"[stream] Batch {batch_id}: {n_written} rows → PostgreSQL network_flows.", flush=True)

            # Update flow_submissions → 'done' in PostgreSQL
            flow_ids = [r["flow_id"] for r in result_df.select("flow_id").collect()]
            _update_submission_status(flow_ids, "done")

        except Exception as exc:
            print(f"[stream] Batch {batch_id}: inference/write ERROR: {exc}", flush=True)
    else:
        print(f"[stream] Batch {batch_id}: GBT model not available — HDFS write only.", flush=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    spark = (
        SparkSession.builder
        .appName("IDS-NetworkFlow-StreamProcessor")
        .config("spark.executor.memory",        "2g")
        .config("spark.driver.memory",          "2g")
        .config("spark.memory.fraction",        "0.8")
        .config("spark.sql.shuffle.partitions", "4")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    raw_stream = (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP)
        .option("subscribe", TOPIC)
        .option("startingOffsets", "earliest")
        .option("maxOffsetsPerTrigger", "500000")
        .option("failOnDataLoss", "false")
        .load()
    )

    (
        raw_stream.writeStream
        .foreachBatch(process_batch)
        .option("checkpointLocation", f"{CHECKPOINT_PATH}/unified")
        .trigger(processingTime="30 seconds")
        .start()
        .awaitTermination()
    )


if __name__ == "__main__":
    main()
