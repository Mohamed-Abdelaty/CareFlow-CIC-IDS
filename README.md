# Hospital Patient Flow & Length-of-Stay Optimization

Big data pipeline: Kafka -> Spark -> HDFS -> Airflow -> ML -> API -> Dashboard.

## Architecture

```
Dataset / API
     |
   Kafka  (streaming ingestion)
     |
   Spark  (cleaning + feature engineering)
     |
   HDFS   (raw + processed storage)
     |
 Airflow  (orchestrates the whole pipeline daily)
     |
    ML     (Length-of-Stay regression + stay-category classification)
     |
 Postgres (predictions + hospital metrics)
     |
 FastAPI  (serves predictions + metrics)
     |
Streamlit (dashboard)
```

## Requirements

- Docker Desktop installed and running
- At least 8 GB RAM allocated to Docker (Settings -> Resources) — this stack runs
  Kafka, HDFS, Spark, Airflow and Postgres together, so it's heavy
- Your dataset as CSV, placed at `data/raw/hospital_data.csv` — this project targets
  the [New York Hospital Inpatient Discharges 2014-2017 (SPARCS)](https://www.kaggle.com/datasets/khoongweihao/new-york-hospital-inpatient-discharges-2014to2017)
  dataset from Kaggle. Download it there and save it as `data/raw/hospital_data.csv`.
  The `kafka-producer` service already renames that dataset's real column headers
  (e.g. `"Length of Stay"`, `"Age Group"`, `"APR Severity of Illness Description"`)
  to the snake_case names the rest of the pipeline expects — see
  `COLUMN_RENAME_MAP` in `kafka/producer/producer.py` if your copy has different
  headers.

## How to run it

1. **Open a terminal in the project folder:**
   ```bash
   cd hospital-patient-flow
   ```

2. **Put your dataset in place:**
   Copy your CSV file to `data/raw/hospital_data.csv`. Column names should roughly
   match what's used in `spark/jobs/process_stream.py` and `ml/train_model.py` — adjust
   those files if your dataset's columns differ.

3. **Build and start everything:**
   ```bash
   docker compose up --build
   ```
   First run will take a while — it's pulling Kafka, HDFS, Spark, Airflow and
   Postgres images plus building 5 custom services.

4. **Initialize Airflow (only needed once):**
   The `airflow-init` service creates the admin user automatically. Once it exits
   successfully, the webserver and scheduler will start.

5. **Check that services are up:**
   | Service          | URL / Port              |
   |-------------------|--------------------------|
   | Kafka broker       | localhost:9092          |
   | HDFS NameNode UI   | http://localhost:9870   |
   | Spark master UI    | http://localhost:8080   |
   | Airflow UI         | http://localhost:8081 (user: admin / pass: admin) |
   | FastAPI docs        | http://localhost:8000/docs |
   | Streamlit dashboard | http://localhost:8501   |
   | Postgres            | localhost:5432 (user: hpf / pass: hpf_password) |

6. **Trigger the pipeline:**
   - Open the Airflow UI at http://localhost:8081
   - Turn on and trigger the `hospital_patient_flow_pipeline` DAG
   - This starts the Kafka producer, waits for Spark to process the stream into
     HDFS, retrains the ML model, and refreshes hospital metrics in Postgres

7. **Use the dashboard:**
   Open http://localhost:8501 — the "Hospital Overview" tab shows metrics once
   the pipeline has run at least once, and "Predict Length of Stay" lets you get
   a live prediction from the trained model.

## Stopping / resetting

```bash
docker compose down          # stop everything, keep data
docker compose down -v       # stop everything AND wipe volumes (HDFS, Postgres data)
```

## Notes

- The Kafka producer streams from `data/raw/hospital_data.csv` by default. Set the
  `API_URL` environment variable on the `kafka-producer` service in
  `docker-compose.yml` if you want to pull from a real API instead.
- `spark/jobs/process_stream.py`'s schema and `ml/train_model.py`'s feature list
  already match the SPARCS dataset's columns (after the producer's renaming). If
  your CSV has different or extra columns, adjust `COLUMN_RENAME_MAP` in
  `kafka/producer/producer.py` accordingly.
- This is a scaffold meant to run end-to-end locally; for production use you'd want
  proper secrets management, HDFS replication settings, and Airflow connections
  instead of hardcoded credentials.
