"""
Airflow DAG: orchestrates the hospital patient flow pipeline.

Stages:
1. trigger_kafka_producer  -> kicks off streaming ingestion
2. wait_for_spark_processing -> waits for Spark to finish writing to HDFS
3. train_model            -> retrains/evaluates the ML model
4. refresh_hospital_metrics -> recomputes aggregate metrics into Postgres
"""

from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.operators.python import PythonOperator

default_args = {
    "owner": "hospital-patient-flow",
    "retries": 1,
    "retry_delay": timedelta(minutes=2),
}

with DAG(
    dag_id="hospital_patient_flow_pipeline",
    default_args=default_args,
    description="End-to-end pipeline: Kafka -> Spark -> HDFS -> ML -> Postgres",
    schedule_interval="@daily",
    start_date=datetime(2025, 1, 1),
    catchup=False,
    tags=["hospital", "big-data", "ml"],
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

    refresh_hospital_metrics = BashOperator(
        task_id="refresh_hospital_metrics",
        bash_command=(
            "psql postgresql://hpf:hpf_password@postgres/hospital_flow -c "
            "\"INSERT INTO hospital_metrics (hospital_county, avg_los, patient_count, long_stay_rate, emergency_rate) "
            "SELECT hospital_county, AVG(length_of_stay), COUNT(*), "
            "AVG(CASE WHEN length_of_stay >= 8 THEN 1 ELSE 0 END), "
            "AVG(CASE WHEN admission_type = 'Emergency' THEN 1 ELSE 0 END) "
            "FROM patients GROUP BY hospital_county;\""
        ),
    )

    trigger_kafka_producer >> wait_for_spark_processing >> train_model >> refresh_hospital_metrics
