"""
Kafka Producer — CIC-IDS 2018 Network Intrusion Dataset
Reads all CSV files from /data, normalises column names, filters
repeated-header rows (known IDS-2018 issue), and streams every
network-flow record as a JSON message to the Kafka topic.
"""

import csv
import glob
import json
import math
import os
import time

from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:29092")
TOPIC           = os.getenv("KAFKA_TOPIC",     "network_flows_stream")
DATA_PATH       = os.getenv("DATA_PATH",       "/data")
SEND_DELAY      = float(os.getenv("SEND_DELAY", "0.005"))   # seconds between messages


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_key(raw: str) -> str:
    """Convert a CICFlowMeter column header to a safe, lowercase snake_case key.

    Examples:
        'Flow Byts/s'   -> 'flow_byts_per_s'
        'Init Fwd Win Byts' -> 'init_fwd_win_byts'
        'Dst Port'      -> 'dst_port'
    """
    key = raw.strip()
    key = key.lower()
    key = key.replace("/s", "_per_s")   # e.g. Byts/s -> byts_per_s
    key = key.replace("/", "_per_")
    key = key.replace(" ", "_")
    key = key.replace(".", "")
    return key


def safe_float(value: str):
    """Convert a string to float, returning None for NaN / Infinity."""
    try:
        v = float(value)
        if math.isnan(v) or math.isinf(v):
            return None
        return v
    except (ValueError, TypeError):
        return None


def sanitize_row(raw_row: dict) -> dict:
    """Normalise keys and sanitise values for JSON serialisation."""
    result = {}
    for k, v in raw_row.items():
        if not k or not k.strip():
            continue
        norm_key = normalize_key(k)
        # Try numeric conversion; keep as string if it fails
        num = safe_float(v)
        result[norm_key] = num if num is not None else v.strip()
    return result


def is_repeated_header(row: dict, first_key: str) -> bool:
    """The IDS-2018 CSVs embed header rows in the data body — skip them."""
    raw_first = list(row.values())[0] if row else ""
    # A repeated header row's first value equals the first column name
    return raw_first.strip().lower() == first_key.strip().lower()


def get_csv_files(data_path: str) -> list[str]:
    """Return all CSV files found directly inside data_path or data/raw."""
    patterns = [
        os.path.join(data_path, "*.csv"),
        os.path.join(data_path, "raw", "*.csv"),
    ]
    files = []
    for pattern in patterns:
        files.extend(glob.glob(pattern))
    return sorted(files)


# ---------------------------------------------------------------------------
# Main streaming logic
# ---------------------------------------------------------------------------

def stream(producer: KafkaProducer, files: list[str]) -> None:
    total_sent = 0
    for filepath in files:
        print(f"[producer] Streaming file: {filepath}", flush=True)
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            reader      = csv.DictReader(fh)
            first_col   = (reader.fieldnames or [""])[0]
            file_sent   = 0

            for raw_row in reader:
                # Skip repeated header rows embedded in the CSV body
                if is_repeated_header(raw_row, first_col):
                    continue

                record = sanitize_row(raw_row)
                if not record:
                    continue

                producer.send(TOPIC, value=record)
                total_sent += 1
                file_sent  += 1

                if file_sent % 5_000 == 0:
                    print(f"[producer]   {file_sent:,} rows sent from {os.path.basename(filepath)}", flush=True)

                time.sleep(SEND_DELAY)

        print(f"[producer] Finished {os.path.basename(filepath)}: {file_sent:,} rows", flush=True)

    print(f"[producer] Done. Total flows sent: {total_sent:,}", flush=True)


def main() -> None:
    # Wait for Kafka to be ready
    producer = None
    for attempt in range(1, 11):
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                acks="all",
                retries=5,
            )
            print(f"[producer] Connected to Kafka at {KAFKA_BOOTSTRAP}", flush=True)
            break
        except NoBrokersAvailable as exc:
            print(f"[producer] Attempt {attempt}/10 — Kafka not ready: {exc}", flush=True)
            time.sleep(6)
    else:
        raise RuntimeError("Could not connect to Kafka after 10 attempts.")

    files = get_csv_files(DATA_PATH)
    if not files:
        raise FileNotFoundError(f"No CSV files found in {DATA_PATH}")

    print(f"[producer] Found {len(files)} file(s). Topic: {TOPIC}", flush=True)
    stream(producer, files)
    producer.flush()
    producer.close()


if __name__ == "__main__":
    main()
