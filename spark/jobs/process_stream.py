"""
Spark Structured Streaming job — CIC-IDS 2018 Network Intrusion Detection
Reads network-flow JSON messages from Kafka, applies a multi-step cleaning
pipeline, writes raw and processed Parquet datasets to HDFS.

Cleaning pipeline:
  1. Parse JSON payload into typed columns
  2. Drop rows missing any critical numeric field
  3. Cast all feature columns to DoubleType
  4. Filter physically impossible values (negative durations, bytes, etc.)
  5. Drop rows where flow_byts_per_s or flow_pkts_per_s is null
     (result of Infinity in source CSV — division-by-zero in CICFlowMeter)
  6. Binarise the label: 'Benign' -> 0, any attack -> 1

NOTE on Dst Port (dst_port):
  Kept as a feature, but it is a known partial-leakage risk in IDS-2018 —
  certain attack types (e.g. DoS GoldenEye) consistently target specific
  ports, so the model may memorise port numbers rather than learning
  true traffic patterns.  This limitation is documented here for awareness.
"""

import os

from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col,
    from_json,
    lower,
    trim,
    when,
)
from pyspark.sql.types import (
    DoubleType,
    LongType,
    StringType,
    StructField,
    StructType,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:29092")
TOPIC           = os.getenv("KAFKA_TOPIC",     "network_flows_stream")
HDFS_URI        = os.getenv("HDFS_URI",        "hdfs://namenode:8020")
RAW_PATH        = f"{HDFS_URI}/ids/raw"
PROCESSED_PATH  = f"{HDFS_URI}/ids/processed"
CHECKPOINT_PATH = f"{HDFS_URI}/ids/checkpoints"

# All columns sent by the producer (string-typed from CSV origin).
# We declare them all as StringType first, then cast the numeric ones.
SCHEMA = StructType([
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

# Columns to cast to Double (all numeric features + target before binarisation)
NUMERIC_COLS = [
    "dst_port", "protocol", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
    "totlen_fwd_pkts", "totlen_bwd_pkts", "flow_byts_per_s", "flow_pkts_per_s",
    "flow_iat_mean", "flow_iat_std", "fwd_psh_flags", "fin_flag_cnt",
    "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt",
    "init_fwd_win_byts", "init_bwd_win_byts", "active_mean", "idle_mean",
]

# Critical fields — rows missing any of these are dropped
CRITICAL_COLS = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
    "flow_byts_per_s", "flow_pkts_per_s", "label",
]


# ---------------------------------------------------------------------------
# Streaming processing function
# ---------------------------------------------------------------------------
def process_batch(batch_df, batch_id):
    if batch_df.isEmpty():
        return

    # ── Step 1: Parse JSON ──────────────────────────────────────────────────
    parsed = (
        batch_df
        .select(from_json(col("value").cast("string"), SCHEMA).alias("d"))
        .select("d.*")
    )

    # ── Step 2: Write raw records to HDFS ───────────────────────────────────
    (
        parsed.write
        .mode("append")
        .parquet(RAW_PATH)
    )

    # ── Step 3: Normalise label text ────────────────────────────────────────
    cleaned = parsed.withColumn("label", trim(lower(col("label"))))

    # ── Step 4: Drop rows missing critical fields ────────────────────────────
    cleaned = cleaned.dropna(subset=CRITICAL_COLS)

    # ── Step 5: Cast all numeric columns to Double ──────────────────────────
    for c in NUMERIC_COLS:
        cleaned = cleaned.withColumn(c, col(c).cast(DoubleType()))

    # ── Step 6: Filter physically impossible / Infinity-derived values ───────
    # Infinity in flow_byts_per_s / flow_pkts_per_s comes from
    # CICFlowMeter dividing by zero when flow_duration == 0.
    # Negative duration or packet counts are also impossible.
    cleaned = cleaned.filter(
        (col("flow_duration")   >= 0) &
        (col("tot_fwd_pkts")    >= 0) &
        (col("tot_bwd_pkts")    >= 0) &
        (col("flow_byts_per_s").isNotNull()) &
        (col("flow_pkts_per_s").isNotNull()) &
        (col("flow_byts_per_s") >= 0) &
        (col("flow_pkts_per_s") >= 0)
    )

    # ── Step 7: Binarise label → 0 = Benign, 1 = Attack ────────────────────
    cleaned = cleaned.withColumn(
        "is_attack",
        when(col("label") == "benign", 0).otherwise(1).cast(LongType()),
    )

    # ── Step 8: Drop the raw label string — it must NOT appear in the
    #   processed output. Keeping it would be a direct target-leakage
    #   column (the string "benign" / attack-type name is perfectly
    #   correlated with is_attack and would trivially give 100% accuracy
    #   if it ever slipped into a feature set).
    # ── Step 9: Deduplicate within the batch before writing.
    #   Spark micro-batch streaming uses mode("append"), so the same
    #   Kafka offsets can be re-processed across trigger intervals
    #   (e.g. on restart or backfill). Without deduplication, identical
    #   rows accumulate in HDFS and can appear in BOTH train and test
    #   splits, letting the model memorise exact rows and report 100%.
    processed = (
        cleaned
        .drop("label")
        .dropDuplicates()
    )

    # ── Step 10: Write cleaned, deduplicated records to HDFS ────────────────
    (
        processed.write
        .mode("append")
        .parquet(PROCESSED_PATH)
    )

    print(
        f"[spark] Batch {batch_id}: "
        f"{processed.count()} processed rows written to HDFS.",
        flush=True,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    spark = (
        SparkSession.builder
        .appName("IDS-NetworkFlow-StreamProcessor")
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
        .option("failOnDataLoss", "false")
        .load()
    )

    (
        raw_stream.writeStream
        .foreachBatch(process_batch)
        .option("checkpointLocation", f"{CHECKPOINT_PATH}/processed")
        .trigger(processingTime="15 seconds")
        .start()
        .awaitTermination()
    )


if __name__ == "__main__":
    main()
