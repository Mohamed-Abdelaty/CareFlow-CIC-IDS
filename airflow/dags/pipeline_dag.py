"""
Airflow DAG — CareFlow IDS Pipeline (Spark MLlib + SparkSQL)
============================================================

Stages (daily schedule):
  1. trigger_kafka_producer  — kicks off streaming ingestion
  2. wait_for_spark_ingestion — waits for the streaming job to accumulate data
  3. train_gbt_model          — spark-submit GBTClassifier training job
  4. run_analysis_queries     — spark-submit SparkSQL daily aggregation job

Notes:
  • ml-trainer container is REMOVED — training is now done via spark-submit
    against the Spark cluster, using Spark MLlib (GBTClassifier).
  • The streaming job (process_stream.py) runs continuously as a separate
    service (spark-processor), NOT scheduled by Airflow.
  • SparkSQL results are written to daily_attack_summary in Postgres.
  • Metastore: Postgres itself serves as the Hive-compatible metastore
    for SparkSQL table metadata (via the JDBC metastore connector).
"""

from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator

default_args = {
    "owner":       "careflow-ids",
    "retries":     1,
    "retry_delay": timedelta(minutes=5),
}

SPARK_SUBMIT = (
    "/home/airflow/.local/bin/spark-submit "
    "--master spark://spark-master:7077 "
    "--conf spark.executor.memory=2g "
    "--conf spark.driver.memory=2g "
    "--conf spark.memory.fraction=0.8 "
    "--conf spark.sql.shuffle.partitions=8 "
)


with DAG(
    dag_id="ids_network_flow_pipeline",
    default_args=default_args,
    description=(
        "End-to-end CareFlow-IDS pipeline: Verify HDFS Data → "
        "Compaction → GBT Training → SparkSQL Analysis (Parquet/DuckDB)"
    ),
    schedule_interval=None,
    start_date=datetime(2026, 8, 25),
    catchup=False,
    tags=["ids", "security", "big-data", "sparkml", "sparksql"],
) as dag:

    # ── 1. Verify HDFS Data exists (Data Quality Check) ──────────────────────────
    # Instead of triggering ingestion (which is 100% complete and should not be rerun),
    # this check verifies that the processed network flow files exist in HDFS.
    verify_hdfs_data = BashOperator(
        task_id="verify_hdfs_data",
        bash_command=(
            "echo 'Checking HDFS for clean processed network flow data…' && "
            "curl -sf 'http://namenode:9870/webhdfs/v1/ids/processed?op=LISTSTATUS' "
            "| python3 -c \"import sys,json; "
            "d=json.load(sys.stdin); "
            "files=d['FileStatuses']['FileStatus']; "
            "sys.exit(0 if len(files)>0 else 1)\" "
            "|| (echo '❌ ERROR: HDFS processed folder is empty. Please verify ingestion.' && exit 1)"
        ),
    )

    # ── 2. Compact small Parquet files for the current day ────────────────────────
    # Reads small streaming micro-batch files and rewrites them into consolidated Parquet files
    # to optimize Spark memory and speed up training.
    compact_parquet = BashOperator(
        task_id="compact_parquet",
        bash_command=(
            f"{SPARK_SUBMIT}"
            "-c \""
            "from pyspark.sql import SparkSession; "
            "from datetime import date; "
            "import subprocess, sys; "
            "spark = SparkSession.builder.appName('Compaction').getOrCreate(); "
            "today = date.today().isoformat(); "
            "path = f'hdfs://namenode:8020/ids/processed/ingest_date={today}'; "
            "try: "
            "    result = subprocess.run(['hdfs','dfs','-count',path], capture_output=True, text=True); "
            "    parts = result.stdout.strip().split(); "
            "    file_count = int(parts[1]) if len(parts)>=2 else 999; "
            "    if file_count <= 4: "
            "        print(f'Already compacted ({file_count} files). Skipping.'); "
            "        spark.stop(); sys.exit(0); "
            "    df = spark.read.parquet(path); "
            "    df.coalesce(4).write.mode('overwrite').parquet(path); "
            "    print('Compaction completed successfully.'); "
            "except Exception as e: "
            "    print(f'Compaction skipped or failed: {e}'); "
            "spark.stop()\" "
            "--master local[2] "
            "--conf spark.executor.memory=2g "
            "--conf spark.driver.memory=2g "
            "|| echo 'Compaction skipped (partition may not exist yet)'"
        ),
    )

    # ── 3. GBTClassifier training (Spark MLlib) ───────────────────────────────
    train_gbt_model = BashOperator(
        task_id="train_gbt_model",
        bash_command=(
            f"{SPARK_SUBMIT} "
            "--master local[2] "
            "/opt/jobs/train_gbt_model.py"
        ),
        env={
            "HDFS_URI":           "hdfs://namenode:8020",
            "LOCAL_PARQUET_PATH": "/data/parquet",
            "DB_HOST":            "careflow-postgres",
            "DB_PORT":            "5432",
            "DB_NAME":            "careflow_ids",
            "DB_USER":            "careflow",
            "DB_PASS":            "careflow_pass",
        },
    )

    # ── 4. SparkSQL daily attack aggregation ──────────────────────────────────
    run_analysis_queries = BashOperator(
        task_id="run_analysis_queries",
        bash_command=(
            f"{SPARK_SUBMIT} "
            "--packages org.postgresql:postgresql:42.7.3 "
            "--master local[2] "
            "/opt/jobs/analysis_queries.py"
        ),
        env={
            "HDFS_URI":           "hdfs://namenode:8020",
            "LOCAL_PARQUET_PATH": "/data/parquet",
            "DB_HOST":            "careflow-postgres",
            "DB_PORT":            "5432",
            "DB_NAME":            "careflow_ids",
            "DB_USER":            "careflow",
            "DB_PASS":            "careflow_pass",
        },
    )


    # ── DAG dependency chain ──────────────────────────────────────────────────
    (
        verify_hdfs_data
        >> compact_parquet
        >> train_gbt_model
        >> run_analysis_queries
    )
