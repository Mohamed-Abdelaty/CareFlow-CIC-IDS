# CareFlow IDS — Network Intrusion Detection System

An end-to-end Big Data pipeline for real-time network intrusion detection: Kafka -> Spark -> HDFS -> Airflow -> ML -> API -> Dashboard.

## Architecture

```
Network Flow CSVs
      |
    Kafka  (streaming ingestion)
      |
    Spark  (structured stream cleaning + dedup + GBT inference)
      |
    HDFS   (raw + processed Parquet, partitioned by ingest_date)
      |
  Airflow  (daily: compact Parquet → train GBT → SparkSQL aggregation)
      |
 Postgres  (network_flows + flow_submissions + daily_attack_summary)
      |
  FastAPI  (async Kafka producer + polling endpoints)
      |
 Streamlit (live dashboard — reads exclusively from processed data)
```

## Data Integrity & Visualization Policy

Every chart and table in the Streamlit dashboard reads exclusively from
**processed data** — never from the raw HDFS archive (`/ids/raw`) or
directly from raw Kafka payloads. The raw archive exists only for audit
and replay purposes; it contains uncleaned records including duplicates,
Infinity-derived values, and unstripped label strings that would corrupt
any statistical visualization.

The primary dashboard read path is the `daily_attack_summary` table in
Postgres, populated daily by `analysis_queries.py` which runs SparkSQL
queries on the cleaned, deduplicated Parquet files in `/ids/processed`.
Because `/ids/processed` is **partitioned by `ingest_date`**, SparkSQL
queries filtered to a single day only open that day's directory — Spark's
partition pruning skips all other files, reducing I/O by up to 99% on a
30-day dataset. To prevent thousands of tiny Parquet files accumulating
from the 30-second streaming trigger, a daily Airflow compaction task
(`compact_parquet`) coalesces each day's partition into 4 larger files
before the training job runs, keeping scan times stable over long demos.


## Requirements

- Docker Desktop installed and running
- At least 8 GB RAM allocated to Docker (Settings -> Resources) — this stack runs Kafka, HDFS, Spark, Airflow, and Postgres together.
- Your dataset as CSV files, placed in `data/raw/`. This project targets the [CSE-CIC-IDS2018](https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv) dataset from Kaggle.

## How to run it

1. **Open a terminal in the project folder:**
   ```bash
   cd careflow-IDS
   ```

2. **Download and put your dataset in place:**
   Make sure your downloaded CSV files from the Kaggle IDS dataset are placed inside the `data/raw/` directory (e.g. `02-14-2018.csv`).

3. **Build and start everything:**
   ```bash
   docker compose up --build -d
   ```
   First run will take a while — it pulls images and builds the custom services.

4. **Initialize Airflow (only needed once):**
   The `airflow-init` service creates the admin user automatically. Once it exits successfully, the webserver and scheduler will start.

5. **Check that services are up:**
   | Service            | URL / Port                                        |
   |--------------------|---------------------------------------------------|
   | Kafka broker       | localhost:9092                                    |
   | HDFS NameNode UI   | http://localhost:9870                             |
   | Spark master UI    | http://localhost:8080                             |
   | Airflow UI         | http://localhost:8081 (user: admin / pass: admin) |
   | FastAPI docs       | http://localhost:8000/docs                        |
   | Streamlit dashboard| http://localhost:8501                             |
   | Postgres           | localhost:5432 (user: hpf / pass: hpf_password)   |

6. **Trigger the pipeline:**
   - Open the Airflow UI at http://localhost:8081
   - Turn on and trigger the `ids_network_flow_pipeline` DAG
   - This starts the Kafka producer, waits for Spark to process the stream into HDFS, retrains the ML model, and refreshes traffic metrics in Postgres.

7. **Use the dashboard:**
   Open http://localhost:8501 — the "Live Traffic Overview" tab shows metrics, and "Analyse Flow" lets you run real-time inference on a network flow.

## Stopping / resetting

```bash
docker compose down          # stop everything, keep data
docker compose down -v       # stop everything AND wipe volumes (HDFS, Postgres data)
```

---

## Model Integrity — 100% Accuracy Investigation (2026-08-23)

> **This section is intentionally kept for the graduation defence.**
> An early training run returned 100.00% on all five metrics
> (Accuracy / Precision / Recall / F1 / ROC-AUC) on a 2,010-row test set.
> Below is the full diagnostic, root-cause analysis, and remediation.

### What was observed

The first training run (on the initial Spark micro-batch output, ~10K rows)
returned: **Accuracy 100% · Precision 100% · Recall 100% · F1 100% · AUC 100%**.

### Root causes identified (three compounding issues)

| # | Root cause | Evidence |
|---|-----------|----------|
| **1** | **Model trained on a tiny, unrepresentative batch** — the trainer was triggered when HDFS had only ~10K rows (96 Benign vs 9,950 Attack), an extreme 0.96% Benign / 99.04% Attack split. XGBoost found a single threshold on `flow_duration` that trivially separated the two classes. | Feature importance: `flow_duration` = 100%, all other 20 features = 0% |
| **2** | **30.9% duplicate rows in HDFS** (426,379 / 1,380,249) — Spark Structured Streaming used `mode("append")` without deduplication, so the same Kafka offsets were written to HDFS across multiple trigger intervals. These duplicates crossed the 80/20 train/test split boundary, letting the model memorise exact rows from training and recognise them in the test set. | `df.duplicated().sum()` → 426,379 rows |
| **3** | **Raw `label` string column written to processed Parquet** — Spark was writing the raw text label ("benign", "ddos attack-hoic", …) alongside the binarised `is_attack` column. While it was not in the `FEATURES` list, its presence was a risk vector for accidental inclusion. | Column audit: `['dst_port', ..., 'label', 'is_attack']` |

### Fixes applied

**`spark/jobs/process_stream.py`**
- Added `.drop("label")` before writing — the raw text label is removed from every
  processed Parquet file so it can never be accessed by the trainer.
- Added `.dropDuplicates()` within each micro-batch before writing — prevents the
  same flow record from accumulating in HDFS across multiple Spark trigger intervals.

**`ml/train_model.py`**
- Added `df.drop_duplicates()` **before** the train/test split as a defence-in-depth
  layer (guards against any duplicates that still reach the trainer from old HDFS data).
- Added a runtime guard: if the `label` column is present in loaded data, it is
  dropped with a visible warning before training begins.
- Removed `dst_port` from `FEATURES` — while it was not the primary cause of the
  100% in this specific run, `dst_port` is a known partial-leakage feature
  (some CIC-IDS-2018 attack types consistently target a fixed port, letting the
  model memorise port numbers rather than learning real traffic behaviour).
- Added a `_LEAKAGE_COLS` assertion at module load time that raises immediately
  if any known leakage column (`label`, `dst_port`, `src_port`, `src_ip`,
  `dst_ip`, `timestamp`, `flow_id`) is ever accidentally added back to `FEATURES`.

### Corrected metrics (after all fixes, on 982,249 deduplicated rows)

| Metric | Value | Notes |
|--------|-------|-------|
| **Accuracy** | **99.99%** | Not 100% — rounding artifact of first run |
| **Precision** | **99.99%** | |
| **Recall** | **99.97%** | |
| **F1 Score** | **99.98%** | |
| **ROC-AUC** | **99.9999%** | |
| Train size | 785,799 rows | 80% stratified split, deduplicated |
| Test size | 196,450 rows | 20% stratified split, deduplicated |
| Class balance | 85.2% Benign / 14.8% Attack | After deduplication |

### Why are the corrected metrics still very high?

The CIC-IDS-2018 dataset is labelled from controlled network experiments.
Attack traffic within a single day's session is **genuinely homogeneous** —
the tool that generated the attack flows (e.g. Hulk DoS, FTP-BruteForce) produces
nearly identical packet sequences each time.  XGBoost captures these patterns
with very high fidelity.

The dominant feature is now `init_fwd_win_byts` (initial TCP forward window size,
87% importance) — a legitimate, non-leaking network traffic feature.  Many attack
tools negotiate a non-standard TCP window, making this a real discriminator.

**The remaining ~0.01% error rate is genuine** — it corresponds to real
misclassified flows, not an artefact.

**For a stronger diversity test:** stream all 10 CSV files simultaneously
so the model trains on attacks across all days and attack types.  This will
distribute importance across more features and give more realistic cross-day
generalisation metrics.