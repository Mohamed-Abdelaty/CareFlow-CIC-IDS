"""
SparkSQL — Historical Attack Analysis (CareFlow IDS)
=====================================================
Reads HDFS processed Parquet files with SparkSQL, computes daily
attack/benign breakdown per protocol, and writes the results to
/data/parquet/daily_summary/ (shared volume, read by FastAPI via DuckDB).

PostgreSQL has been removed — results are stored as Parquet files
partitioned by summary_date.  FastAPI reads them directly with DuckDB.

Usage (spark-submit):
    spark-submit \\
        --master spark://spark-master:7077 \\
        --conf spark.executor.memory=2g \\
        --conf spark.driver.memory=2g \\
        analysis_queries.py
"""

import os
from datetime import date

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HDFS_URI         = os.getenv("HDFS_URI",           "hdfs://namenode:8020")
PROCESSED_PATH   = f"{HDFS_URI}/ids/processed"

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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    # ── Early-exit: skip if daily_summary already populated ─────────────────
    # If PostgreSQL already contains aggregated results, there is no need
    # to re-scan the entire 16.2 M-row HDFS dataset again.
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_PASS,
        )
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM daily_summary;")
        row_count = cur.fetchone()[0]
        cur.close()
        conn.close()
        if row_count > 0:
            print(
                f"[analysis] ✅ daily_summary already has {row_count} rows in PostgreSQL. "
                "Skipping Spark re-scan of HDFS.",
                flush=True,
            )
            return
    except Exception as e:
        print(f"[analysis] Cache check failed ({e}), proceeding with Spark …", flush=True)

    spark = (
        SparkSession.builder
        .appName("IDS-SparkSQL-DailyAnalysis")
        # spark.master intentionally NOT set here — use --master local[*] in spark-submit
        .config("spark.executor.memory",      "2g")
        .config("spark.driver.memory",        "2g")
        .config("spark.memory.fraction",      "0.8")
        .config("spark.sql.shuffle.partitions", "8")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    print("[analysis] Reading processed HDFS Parquet …", flush=True)
    # READS FROM PROCESSED / CLEANED DATA ONLY —
    # do NOT point this at /ids/raw. All rows here have been cleaned,
    # deduplicated, and label-binarised by the streaming foreachBatch job.
    # The path is partitioned by ingest_date; Spark prunes whole day
    # directories when queries are filtered to a specific date.
    df = spark.read.parquet(PROCESSED_PATH)
    total = df.count()

    if total == 0:
        print("[analysis] No data found in HDFS. Skipping.", flush=True)
        spark.stop()
        return

    print(f"[analysis] Loaded {total:,} rows.", flush=True)

    # ── Register as a temporary SQL view ────────────────────────────────────
    # READS FROM PROCESSED / CLEANED DATA ONLY —
    # This view is the sole source for all SparkSQL aggregations.
    # Never substitute this with the /ids/raw path.
    df.createOrReplaceTempView("network_flows_processed")

    # ── SparkSQL: daily per-protocol attack aggregation ──────────────────────
    today = date.today().isoformat()

    summary_df = spark.sql(
        f"""
        SELECT
            CAST('{today}' AS DATE)                AS summary_date,
            CAST(protocol AS INT)                  AS protocol,
            COUNT(*)                               AS total_flows,
            SUM(CAST(is_attack AS INT))            AS attack_count,
            COUNT(*) - SUM(CAST(is_attack AS INT)) AS benign_count,
            ROUND(
                SUM(CAST(is_attack AS INT)) / COUNT(*), 4
            )                                      AS attack_rate,
            ROUND(AVG(flow_byts_per_s), 2)         AS avg_flow_bytes
        FROM network_flows_processed
        WHERE is_attack IS NOT NULL
          AND flow_byts_per_s != CAST('Infinity' AS DOUBLE)
          AND flow_byts_per_s != CAST('-Infinity' AS DOUBLE)
          AND isnan(flow_byts_per_s) = false
        GROUP BY protocol
        ORDER BY protocol
        """
    )

    print("[analysis] SparkSQL aggregation result:", flush=True)
    summary_df.show()

    # ── Write summary to PostgreSQL daily_summary table via JDBC ─────────────
    # Aggregated stats are saved directly to PostgreSQL. We use mode("overwrite")
    # with the option "truncate" = "true" so that the table structure, indices,
    # and constraints are preserved, but all existing historical rows are refreshed.
    (
        summary_df.write
        .mode("overwrite")
        .option("truncate", "true")
        .jdbc(JDBC_URL, "daily_summary", properties=JDBC_PROPS)
    )
    print(f"[analysis] Daily summary updated in PostgreSQL daily_summary table.", flush=True)

    spark.stop()


if __name__ == "__main__":
    main()
