"""
Kafka Producer
Reads patient data (from an API, or from the local SPARCS CSV as a fallback),
renames columns to the snake_case names the rest of the pipeline expects,
and sends it row by row to a Kafka topic called 'patients_stream',
simulating streaming data.
"""

import json
import time
import os

import pandas as pd
from kafka import KafkaProducer

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:29092")
TOPIC = os.getenv("KAFKA_TOPIC", "patients_stream")
SOURCE_CSV = os.getenv("SOURCE_CSV", "/data/raw/hospital_data.csv")
SEND_DELAY = float(os.getenv("SEND_DELAY", "0.05"))  # seconds between messages

# Real SPARCS (NY State) column headers -> snake_case field names used by
# the rest of the pipeline (Spark schema, ML training, API). Only the
# columns the pipeline actually uses are renamed; anything else in the CSV
# is passed through untouched.
COLUMN_RENAME_MAP = {
    "Health Service Area": "health_service_area",
    "Hospital County": "hospital_county",
    "Facility Name": "facility_name",
    "Age Group": "age_group",
    "Gender": "gender",
    "Race": "race",
    "Ethnicity": "ethnicity",
    "Length of Stay": "length_of_stay",
    "Type of Admission": "admission_type",
    "Patient Disposition": "patient_disposition",
    "CCS Diagnosis Description": "diagnosis",
    "CCS Procedure Description": "procedure",
    "APR DRG Description": "apr_drg_description",
    "APR Severity of Illness Description": "severity",
    "APR Risk of Mortality": "risk_of_mortality",
    "APR Medical Surgical Description": "medical_surgical",
    "Payment Typology 1": "payment_typology_1",
    "Total Charges": "total_charges",
    "Total Costs": "total_costs",
}


def build_producer(retries: int = 10, delay: int = 5) -> KafkaProducer:
    for attempt in range(retries):
        try:
            return KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP,
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            )
        except Exception as e:
            print(f"Kafka not ready yet ({e}), retrying {attempt + 1}/{retries}...")
            time.sleep(delay)
    raise RuntimeError("Could not connect to Kafka after retries")


def stream_from_csv(producer: KafkaProducer):
    if not os.path.exists(SOURCE_CSV):
        print(f"No CSV found at {SOURCE_CSV}. Put your dataset there and restart.")
        return

    df = pd.read_csv(SOURCE_CSV, low_memory=False)
    df = df.rename(columns=COLUMN_RENAME_MAP)

    # Length of stay in SPARCS sometimes has a "120 +" style value for
    # top-coded long stays; strip that down to a plain number.
    if "length_of_stay" in df.columns:
        df["length_of_stay"] = (
            df["length_of_stay"].astype(str).str.replace("+", "", regex=False)
        )

    print(f"Streaming {len(df)} rows to topic '{TOPIC}'...")

    for _, row in df.iterrows():
        record = row.to_dict()
        producer.send(TOPIC, value=record)
        time.sleep(SEND_DELAY)

    producer.flush()
    print("Finished streaming all rows.")


def stream_from_api(producer: KafkaProducer, api_url: str):
    import requests

    resp = requests.get(api_url)
    resp.raise_for_status()
    records = resp.json()

    print(f"Streaming {len(records)} records from API to topic '{TOPIC}'...")
    for record in records:
        producer.send(TOPIC, value=record)
        time.sleep(SEND_DELAY)

    producer.flush()
    print("Finished streaming API data.")


if __name__ == "__main__":
    producer = build_producer()

    api_url = os.getenv("API_URL")
    if api_url:
        stream_from_api(producer, api_url)
    else:
        stream_from_csv(producer)
