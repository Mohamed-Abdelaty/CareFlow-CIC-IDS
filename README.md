<div align="center">

# 🛡️ CareFlow-IDS

### Enterprise-Grade Real-Time Network Intrusion Detection & Big Data Pipeline

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Apache Spark](https://img.shields.io/badge/Apache_Spark-3.5.3-E25A1C?style=for-the-badge&logo=apachespark&logoColor=white)](https://spark.apache.org/)
[![Apache Kafka](https://img.shields.io/badge/Apache_Kafka-7.6.0-231F20?style=for-the-badge&logo=apachekafka&logoColor=white)](https://kafka.apache.org/)
[![Hadoop HDFS](https://img.shields.io/badge/Hadoop_HDFS-3.3-66CCFF?style=for-the-badge&logo=apachehadoop&logoColor=black)](https://hadoop.apache.org/)
[![Apache Airflow](https://img.shields.io/badge/Apache_Airflow-2.9.1-017CEE?style=for-the-badge&logo=apacheairflow&logoColor=white)](https://airflow.apache.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111.0-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.36.0-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker_Compose-3.8-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)

<p align="center">
  <b>A distributed Big Data and Machine Learning platform ingesting, sanitizing, and classifying 16.2M network flows with a verified 99.94% F1-score in real time.</b>
</p>

[Key Metrics](#-platform-at-a-glance) • [Model Evaluation Graphs](#-model-evaluation--performance-graphs) • [Architecture](#-system-architecture) • [Features](#-key-features) • [Quick Start](#-quick-start-guide) • [API Docs](#-api-endpoints--documentation)

</div>

---

## ⚡ Platform at a Glance

| Metric / Dimension | Specification | Verification & Real Project Figures |
| :--- | :--- | :--- |
| 📦 **Raw Dataset Volume** | **16,232,943 rows** | 10 CSV files (~6.8 GB) from benchmark **CSE-CIC-IDS2018** |
| 🧹 **Cleaned Operating Dataset** | **5,660,346 flows** | Zero-null, non-negative, and infinite-rate filtered records |
| 🧠 **Distributed Classifier** | **Spark MLlib GBT** | 5 trees, depth 5, step size 0.1 over **4,525,238 train rows** |
| 🎯 **Classifier Performance** | **99.94% Accuracy & F1** | Evaluated on **1,132,903 test rows**; **99.9995% ROC-AUC** |
| ⚡ **High-Fidelity Model** | **XGBoost (300 estimators)** | 20 features, `scale_pos_weight` class balancing, **99.99% accuracy** |
| 🚀 **Serving API Endpoints** | **8 REST Endpoints** | Async submission, polling ticket status, and sub-second heuristic triage |
| 💾 **Storage Hierarchy** | **HDFS + PostgreSQL 15** | Partitioned Parquet Lakehouse (`/ids/processed`) + operational Postgres |
| ⏱️ **Pipeline Orchestration** | **4 Airflow Tasks** | WebHDFS health checks, Parquet compaction, retraining, and rollups |
| 🐳 **Docker Infrastructure** | **10 Active Services** | Fully isolated bridge network with persistent named volumes |

---

## 📊 Model Evaluation & Performance Graphs

All metrics and visual plots are generated directly from held-out test splits on the cleaned dataset.

### 1. Test Confusion Matrix & ROC Curve (Hold-out Test Set)

<p align="center">
  <img src="docs/images/confusion_matrix.png" width="48%" alt="Test Set Confusion Matrix" />
  <img src="docs/images/roc_curve.png" width="48%" alt="ROC Curve" />
</p>

<div align="center">
  <sub><b>Figure 1:</b> Confusion Matrix (left) showing near-zero false alarms; ROC Curve (right) demonstrating an Area Under Curve (AUC) of 0.9999.</sub>
</div>

<br />

| Evaluation Metric | Spark MLlib GBT (Distributed) | XGBoost Classifier (High-Fidelity) | Notes |
| :--- | :--- | :--- | :--- |
| **Accuracy** | **99.94%** (0.999433) | **99.99%** (0.999921) | Evaluated on held-out test split |
| **Precision** | **99.94%** (0.999433) | **99.98%** (0.999794) | Weighted across benign and attack flows |
| **Recall** | **99.94%** (0.999433) | **99.96%** (0.999622) | High sensitivity on critical attack classes |
| **F1-Score** | **99.94%** (0.999433) | **99.97%** (0.999708) | Harmonic mean of precision and recall |
| **ROC-AUC** | **99.9995%** (0.999995) | **99.9999%** (0.999999) | Near-optimal discriminator curve |
| **Training Duration** | **712.1 s** (~11.8 min) | **78.4 s** | Measured on 5.66M rows / 1.08M rows |

---

### 2. Feature Importance Analysis (XGBoost Gain)

To prevent data leakage, non-behavioral identifiers (`dst_port`, `src_ip`, `dst_ip`, `timestamp`, `flow_id`, and raw `label`) were programmatically stripped. The model relies purely on physical network flow dynamics:

<p align="center">
  <img src="docs/images/feature_importance.png" width="75%" alt="Feature Importance Chart" />
</p>

<div align="center">
  <sub><b>Figure 2:</b> Feature importance breakdown. <code>init_fwd_win_byts</code> (TCP initial window size) emerges as the top behavioral discriminator (~87% importance), reflecting automated attack tool handshake signatures.</sub>
</div>

---

### 3. Cross-Day Generalization Test (Out-of-Distribution Attack Verification)

To prove model robustness against unseen attack tools, the model was trained strictly on DoS and BruteForce days (Feb 14, 15, 16) and evaluated on an entirely separate day containing unseen **Botnet** attacks (March 02):

<p align="center">
  <img src="docs/images/cross_day_confusion_matrix.png" width="52%" alt="Cross-Day Confusion Matrix" />
</p>

<div align="center">
  <sub><b>Figure 3:</b> Out-of-distribution evaluation confirming genuine generalization to unseen attack families without memorization artifacts.</sub>
</div>

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    subgraph S1 ["1. Ingestion & Event Broker"]
        CSVs["📄 CSE-CIC-IDS2018 (10 CSVs, 16.2M Flows)"]
        Producer["📡 Multi-Threaded Kafka Producer"]
        Kafka["⚡ Apache Kafka (network_flows_stream)"]
        Zookeeper["🦁 Apache Zookeeper"]
        CSVs --> Producer
        Producer --> Kafka
        Kafka <--> Zookeeper
    end

    subgraph S2 ["2. Streaming & Lakehouse Core"]
        SparkStream["🔥 Spark Structured Streaming (30s Trigger)"]
        Watermark["💧 10-Min Watermark & flow_id Deduplication"]
        CleanCast["🧹 NaN & Infinity Cleansing + Label Dropping"]
        HDFSRaw["🐘 HDFS /ids/raw (Audit Archive)"]
        HDFSProc["🐘 HDFS /ids/processed (Partitioned by Date)"]
        Kafka --> SparkStream
        SparkStream --> Watermark
        Watermark --> CleanCast
        CleanCast --> HDFSRaw
        CleanCast --> HDFSProc
    end

    subgraph S3 ["3. Batch Orchestration & Training"]
        Airflow["⏱️ Apache Airflow DAG (ids_network_flow_pipeline)"]
        Compaction["🔄 Parquet Compaction (df.coalesce to 4 files)"]
        TrainJob["🧠 Spark MLlib GBT Retraining (5.66M Flows)"]
        SQLRollup["📊 SparkSQL Daily Protocol Rollup"]
        Airflow --> Compaction
        Compaction --> TrainJob
        TrainJob --> SQLRollup
        HDFSProc --> Compaction
    end

    subgraph S4 ["4. Persistence & Serving Layer"]
        Postgres["🐘 PostgreSQL 15 (network_flows, daily_summary)"]
        FastAPI["🚀 FastAPI Gateway (8 Endpoints, Port 8000)"]
        Streamlit["🖥️ Streamlit Telemetry Dashboard (Port 8501)"]
        SparkStream -->|In-Stream JDBC Insert| Postgres
        SQLRollup -->|JDBC Truncate-Write| Postgres
        TrainJob -->|Save Model| HDFSProc
        Postgres --> FastAPI
        FastAPI --> Streamlit
    end
```

---

## 🌟 Key Features

* **⚡ 16.2M Flow Ingestion**: Multi-threaded streaming producer converting raw network flow logs into sanitized JSON with snake_case normalization and corrupt header stripping.
* **💧 Watermark Deduplication**: Spark Structured Streaming with 10-minute event-time watermarking (`kafka_ingest_ts`) eliminating offset replays across micro-batches.
* **🧠 In-Stream Distributed Inference**: GBTClassifier model executed directly inside Spark's `foreachBatch` loop; verdicts are bulk-written to PostgreSQL via JDBC.
* **📁 Lakehouse Partition Pruning**: Columnar Parquet lake on Hadoop HDFS partitioned by date (`ingest_date=YYYY-MM-DD`), reducing single-day scan I/O by up to 99%.
* **🔄 Small-File Compaction DAG**: Automated daily Airflow task coalescing hundreds of 30-second micro-batch Parquet files into 4 consolidated files, preventing HDFS NameNode bloat.
* **🛡️ Data Leakage Assertion Guard**: Strict architectural safeguards removing destination port memorization (`dst_port`), stripping raw labels, and enforcing runtime `_LEAKAGE_COLS` assertion gates.
* **🚀 Hybrid Dual-Tier API**: FastAPI service offering asynchronous ticketed flow submission (`POST /flows`) with 60s timeout handling alongside sub-second instant heuristic scoring (`POST /predict`).
* **📊 Dark-Mode SOC Portal**: High-density Streamlit dashboard featuring live Plotly traffic breakdowns, attack rate gauges, and a threat simulation sandbox with preset attack templates.

---

## 🔬 Model Integrity & Root Cause Analysis

> **Graduation Defense & Technical Audit Documentation:**
> An initial baseline run yielded an unrealistic 100.00% across all metrics on a 2,010-row test split. A deep diagnostic investigation revealed and permanently resolved three compounding flaws:

| Root Cause Identified | Technical Evidence | Implemented Architectural Fix |
| :--- | :--- | :--- |
| **1. Unrepresentative Initial Batch** | First micro-batch contained only 10K rows (96 Benign vs. 9,950 Attack). Model found a trivial single split on `flow_duration` (100% gain). | Pipeline was scaled to full **16.2M flows** (5.66M clean unique flows) with balanced representation across all 10 CSV recording sessions. |
| **2. Micro-Batch Append Duplicates** | Spark `mode("append")` accumulated 30.9% duplicate rows across trigger intervals (426,379 / 1.38M), leaking training rows into test splits. | Added in-stream watermark deduplication (`.dropDuplicates(["flow_id"])`) and pre-split deduplication in the model trainer. |
| **3. Target & Port Leakage** | Raw `label` string was written to Parquet alongside `is_attack`. Attacks targeted fixed ports, allowing port memorization on `dst_port`. | Permanently dropped `label` before Parquet writes, excluded `dst_port`, and added a strict `_LEAKAGE_COLS` assertion guard at module import. |

**Result:** Post-fix evaluation on 5,658,141 cleaned records established a verified **99.94% F1-Score** with dominant importance on physical TCP window negotiations (`init_fwd_win_byts` at ~87%).

---

## 🗄️ Database Architecture

PostgreSQL 15 serves as the operational serving layer and Airflow metastore:

```
PostgreSQL Database: careflow_ids
├── 📄 flow_submissions      — Asynchronous flow tickets (flow_id [PK], status, submitted_at, completed_at)
├── 📄 network_flows         — Real-time predictions & telemetry (flow_id [PK], 21 metrics, is_attack, attack_probability)
│   └── 🔑 Index             — idx_network_flows_ingest_ts ON (kafka_ingest_ts DESC)
├── 📄 daily_summary         — SparkSQL daily aggregates (summary_date, protocol, total_flows, attack_count, attack_rate)
└── 📄 model_metadata        — Governance audit logs (model_version [PK], trained_at, duration, train/test rows, metrics)
```

---

## 🌐 API Endpoints & Documentation

FastAPI auto-generates interactive OpenAPI documentation available at:
* **Swagger UI:** [http://localhost:8000/docs](http://localhost:8000/docs)
* **ReDoc:** [http://localhost:8000/redoc](http://localhost:8000/redoc)
* **OpenAPI Schema:** [http://localhost:8000/openapi.json](http://localhost:8000/openapi.json)

### Primary Routes:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/predict` | Instant local heuristic scoring (sub-second verdict, no Kafka/Spark delay) |
| `POST` | `/flows` | Asynchronous Kafka flow submission (returns HTTP 202 and polling ticket) |
| `GET` | `/flows/{flow_id}/result` | Poll asynchronous ticket status (`pending` → `done` / `timeout`) |
| `GET` | `/flows` | List recent network flows with classifications (default limit: 200) |
| `GET` | `/analytics` | Historical daily attack summaries by protocol (`days=30`) |
| `GET` | `/status` | Component health checks with 10–30s TTL caching (Kafka, Spark, HDFS, Airflow, Postgres) |
| `GET` | `/stats` | HDFS storage utilization (MB), total flow counters, and active ML model metadata |
| `GET` | `/health` | Microservice liveness and version probe |

---

## 🚀 Quick Start Guide

### Prerequisites
* **Docker Desktop** installed and running
* **At least 8 GB RAM** allocated to Docker (Settings → Resources → Memory)
* Dataset CSV files placed in `data/raw/` (e.g., `02-14-2018.csv`, etc.)

### 1. Build and Start the Cluster
```bash
# Clone the repository
git clone https://github.com/Mohamed-Abdelaty/CareFlow-CIC-IDS.git
cd CareFlow-CIC-IDS

# Build and start all 10 containerized services
docker compose up --build -d
```

### 2. Service Access URLs

| Service | Local URL | Default Credentials / Purpose |
| :--- | :--- | :--- |
| **Streamlit Telemetry Portal** | [http://localhost:8501](http://localhost:8501) | Live traffic dashboard and interactive flow classifier |
| **FastAPI Swagger Docs** | [http://localhost:8000/docs](http://localhost:8000/docs) | Interactive API exploration and testing |
| **Airflow Web UI** | [http://localhost:8085](http://localhost:8085) | **Username:** `admin` \| **Password:** `admin` |
| **Spark Master UI** | [http://localhost:8080](http://localhost:8080) | Spark cluster resources & worker nodes |
| **HDFS NameNode UI** | [http://localhost:9870](http://localhost:9870) | Distributed file system storage explorer |
| **PostgreSQL Database** | `localhost:5433` | **User:** `careflow` \| **Pass:** `careflow_pass` \| **DB:** `careflow_ids` |

### 3. Trigger Maintenance & Retraining Pipeline
1. Open the Airflow Web UI at [http://localhost:8085](http://localhost:8085) (`admin` / `admin`).
2. Unpause the **`ids_network_flow_pipeline`** DAG.
3. Click **Trigger DAG** to run data verification, Parquet compaction, model retraining, and analytics rollups.

### 4. Teardown
```bash
# Stop services while keeping persistent data (HDFS blocks & PostgreSQL)
docker compose down

# Stop services and wipe all volumes (fresh start)
docker compose down -v
```

---

<div align="center">
  <sub>Developed with Apache Spark, Apache Kafka, Apache Airflow, FastAPI & Streamlit.</sub>
</div>