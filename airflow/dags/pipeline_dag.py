"""
Airflow DAG: orchestrates the IDS network flow pipeline.

Stages:
1. trigger_kafka_producer  -> kicks off streaming ingestion
2. wait_for_spark_processing -> waits for Spark to finish writing to HDFS
3. train_model            -> retrains/evaluates the ML model
4. refresh_traffic_metrics -> recomputes aggregate traffic metrics into Postgres
"""

from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.operators.python import PythonOperator

default_args = {
    "owner": "careflow-ids",
    "retries": 1,
    "retry_delay": timedelta(minutes=2),
}

with DAG(
    dag_id="ids_network_flow_pipeline",
    default_args=default_args,
    description="End-to-end pipeline: Kafka -> Spark -> HDFS -> ML -> Postgres",
    schedule_interval="@daily",
    start_date=datetime(2025, 1, 1),
    catchup=False,
    tags=["ids", "security", "big-data", "ml"],
) as dag:

    trigger_kafka_producer = BashOperator(
        task_id="trigger_kafka_producer",
        bash_command="docker start kafka-producer || echo 'producer already ran'",
    )

    wait_for_spark_processing = BashOperator(
        task_id="wait_for_spark_processing",
        bash_command="sleep 60",  # placeholder: replace with a real readiness check
    )

    def train_model_task():
        import subprocess

        subprocess.run(["docker", "start", "-a", "ml-trainer"], check=False)

    train_model = PythonOperator(
        task_id="train_model",
        python_callable=train_model_task,
    )

    refresh_traffic_metrics = BashOperator(
        task_id="refresh_traffic_metrics",
        bash_command=(
            "psql postgresql://hpf:hpf_password@postgres/hospital_flow -c "
            "\"TRUNCATE TABLE traffic_metrics; "
            "INSERT INTO traffic_metrics (protocol, total_flows, attack_count, benign_count, attack_rate) "
            "SELECT f.protocol, COUNT(*), "
            "SUM(CASE WHEN p.is_attack = true THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN p.is_attack = false THEN 1 ELSE 0 END), "
            "AVG(CASE WHEN p.is_attack = true THEN 1.0 ELSE 0.0 END) "
            "FROM network_flows f "
            "LEFT JOIN LATERAL ( "
            "    SELECT is_attack FROM predictions "
            "    WHERE flow_id = f.flow_id "
            "    ORDER BY predicted_at DESC LIMIT 1 "
            ") p ON true "
            "GROUP BY f.protocol;\""
        ),
    )

    trigger_kafka_producer >> wait_for_spark_processing >> train_model >> refresh_traffic_metrics

