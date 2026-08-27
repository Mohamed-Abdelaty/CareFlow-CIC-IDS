"""
FastAPI — CareFlow IDS Serving Layer (PostgreSQL backend)
=========================================================
Architecture:
    flow_submissions  → PostgreSQL table
    network_flows     → PostgreSQL table (written by Spark Structured Streaming)
    daily_summary     → PostgreSQL table (written by SparkSQL analysis job)
    model_metadata    → PostgreSQL table (written by model training job)
    inference path    → Kafka → Spark → PostgreSQL (async, UUID-tracked via Postgres)

Endpoints:
    POST /flows          → publish to Kafka, register UUID in PostgreSQL as 'pending'
    GET  /flows/{id}/result → poll PostgreSQL status + network_flows table for result
    GET  /flows          → PostgreSQL query of network_flows table
    GET  /analytics      → PostgreSQL query of daily_summary table
    GET  /status         → component health checks (Kafka, Spark, HDFS, Airflow, Postgres)
    GET  /stats          → HDFS + PostgreSQL database metrics + model info
    GET  /health         → liveness
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import psycopg2
from psycopg2.extras import RealDictCursor
import requests
from fastapi import FastAPI, HTTPException
from kafka import KafkaProducer
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KAFKA_BS        = os.getenv("KAFKA_BOOTSTRAP",   "kafka:29092")
KAFKA_TOPIC     = os.getenv("KAFKA_TOPIC",        "network_flows_stream")

DB_HOST = os.getenv("DB_HOST", "careflow-postgres")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "careflow_ids")
DB_USER = os.getenv("DB_USER", "careflow")
DB_PASS = os.getenv("DB_PASS", "careflow_pass")

LOCAL_PARQUET = os.getenv("LOCAL_PARQUET_PATH", "/data/parquet")

app = FastAPI(title="CareFlow IDS API", version="5.0.0")


# ---------------------------------------------------------------------------
# PostgreSQL connection and table initialization
# ---------------------------------------------------------------------------
def _init_postgres():
    """Wait for Postgres to be ready and initialize tables."""
    import time
    for i in range(15):
        try:
            conn = psycopg2.connect(
                host=DB_HOST, port=DB_PORT, database=DB_NAME,
                user=DB_USER, password=DB_PASS
            )
            with conn.cursor() as cur:
                # 1. flow_submissions
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS flow_submissions (
                        flow_id      VARCHAR(50) PRIMARY KEY,
                        status       VARCHAR(30) NOT NULL DEFAULT 'pending',
                        submitted_at TIMESTAMP WITH TIME ZONE NOT NULL,
                        completed_at TIMESTAMP WITH TIME ZONE
                    )
                """)
                # 2. network_flows
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS network_flows (
                        flow_id            VARCHAR(50) PRIMARY KEY,
                        dst_port           INTEGER,
                        protocol           INTEGER,
                        flow_duration      DOUBLE PRECISION,
                        tot_fwd_pkts       DOUBLE PRECISION,
                        tot_bwd_pkts       DOUBLE PRECISION,
                        totlen_fwd_pkts    DOUBLE PRECISION,
                        totlen_bwd_pkts    DOUBLE PRECISION,
                        flow_byts_per_s    DOUBLE PRECISION,
                        flow_pkts_per_s    DOUBLE PRECISION,
                        flow_iat_mean      DOUBLE PRECISION,
                        flow_iat_std       DOUBLE PRECISION,
                        fwd_psh_flags      DOUBLE PRECISION,
                        fin_flag_cnt       DOUBLE PRECISION,
                        syn_flag_cnt       DOUBLE PRECISION,
                        rst_flag_cnt       DOUBLE PRECISION,
                        psh_flag_cnt       DOUBLE PRECISION,
                        ack_flag_cnt       DOUBLE PRECISION,
                        init_fwd_win_byts  DOUBLE PRECISION,
                        init_bwd_win_byts  DOUBLE PRECISION,
                        active_mean        DOUBLE PRECISION,
                        idle_mean          DOUBLE PRECISION,
                        is_attack          BOOLEAN,
                        attack_probability DOUBLE PRECISION,
                        model_version      VARCHAR(50),
                        kafka_ingest_ts    TIMESTAMP WITH TIME ZONE
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_network_flows_ingest_ts ON network_flows (kafka_ingest_ts DESC)")

                # 3. daily_summary
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS daily_summary (
                        summary_date   DATE,
                        protocol       INTEGER,
                        total_flows    BIGINT,
                        attack_count   BIGINT,
                        benign_count   BIGINT,
                        attack_rate    DOUBLE PRECISION,
                        avg_flow_bytes DOUBLE PRECISION,
                        PRIMARY KEY (summary_date, protocol)
                    )
                """)

                # 4. model_metadata
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS model_metadata (
                        model_version       VARCHAR(50) PRIMARY KEY,
                        trained_at          TIMESTAMP WITH TIME ZONE NOT NULL,
                        training_duration_s DOUBLE PRECISION,
                        hdfs_model_path     TEXT,
                        hdfs_data_path      TEXT,
                        n_train             BIGINT,
                        n_test              BIGINT,
                        features_json       TEXT,
                        metrics_json        TEXT
                    )
                """)
            conn.commit()
            conn.close()
            print("[postgres] Database initialization completed successfully.", flush=True)
            return
        except psycopg2.OperationalError as e:
            print(f"[postgres] Connection failed (attempt {i+1}/15), retrying in 2s... Error: {e}", flush=True)
            time.sleep(2)
    raise RuntimeError("Could not connect to PostgreSQL after 15 attempts.")


def _pg_query(sql: str, params: list = None, fetch_one: bool = False, commit: bool = False):
    """Utility helper to query PostgreSQL."""
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, database=DB_NAME,
        user=DB_USER, password=DB_PASS
    )
    try:
        if commit:
            with conn.cursor() as cur:
                cur.execute(sql, params or ())
            conn.commit()
            return None
        else:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, params or ())
                if fetch_one:
                    res = cur.fetchone()
                    return dict(res) if res else None
                else:
                    return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    _init_postgres()


# ---------------------------------------------------------------------------
# Kafka producer (lazy singleton)
# ---------------------------------------------------------------------------
_producer: Optional[KafkaProducer] = None


def get_producer() -> KafkaProducer:
    global _producer
    if _producer is None:
        _producer = KafkaProducer(
            bootstrap_servers=KAFKA_BS,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            request_timeout_ms=5000,
        )
    return _producer


# ---------------------------------------------------------------------------
# Component health checks
# ---------------------------------------------------------------------------
_cache: dict = {}


def get_cached_status(key: str, check_fn, ttl: int = 30) -> str:
    now = time.time()
    if key in _cache:
        val, expiry = _cache[key]
        if now < expiry:
            return val
    val = check_fn()
    _cache[key] = (val, now + ttl)
    return val


def check_kafka() -> str:
    try:
        from kafka import KafkaAdminClient
        admin = KafkaAdminClient(bootstrap_servers=KAFKA_BS, request_timeout_ms=1000)
        admin.list_topics()
        admin.close()
        return "healthy"
    except Exception as e:
        print(f"[health] Kafka: {e}")
        return "unhealthy"


def check_spark() -> str:
    try:
        r = requests.get("http://spark-master:8080/json/", timeout=1.5)
        return "healthy" if r.status_code == 200 else "degraded"
    except Exception as e:
        print(f"[health] Spark: {e}")
        return "unhealthy"


def check_hdfs() -> str:
    try:
        r = requests.get(
            "http://namenode:9870/webhdfs/v1/?op=GETHOMEDIRECTORY", timeout=1.5
        )
        return "healthy" if r.status_code in [200, 401, 403, 404] else "degraded"
    except Exception as e:
        print(f"[health] HDFS: {e}")
        return "unhealthy"


def check_airflow() -> str:
    try:
        # Check if Airflow webserver is responding on its health check endpoint
        r = requests.get("http://airflow-webserver:8080/health", timeout=1.5)
        if r.status_code == 200:
            data = r.json()
            # Simple check if DB is healthy in airflow webserver
            metadatabase_status = data.get("metadatabase", {}).get("status", "healthy")
            return "healthy" if metadatabase_status == "healthy" else "degraded"
        return "unhealthy"
    except Exception as e:
        print(f"[health] Airflow webserver query: {e}")
        return "unhealthy"


def check_postgres() -> str:
    try:
        conn = psycopg2.connect(
            host=DB_HOST, port=DB_PORT, database=DB_NAME,
            user=DB_USER, password=DB_PASS, connect_timeout=1
        )
        conn.close()
        return "healthy"
    except Exception as e:
        print(f"[health] Postgres: {e}")
        return "unhealthy"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class NetworkFlow(BaseModel):
    dst_port:          int
    protocol:          int
    flow_duration:     float
    tot_fwd_pkts:      float
    tot_bwd_pkts:      float
    totlen_fwd_pkts:   float
    totlen_bwd_pkts:   float
    flow_byts_per_s:   float
    flow_pkts_per_s:   float
    flow_iat_mean:     float
    flow_iat_std:      float
    fwd_psh_flags:     float
    fin_flag_cnt:      float
    syn_flag_cnt:      float
    rst_flag_cnt:      float
    psh_flag_cnt:      float
    ack_flag_cnt:      float
    init_fwd_win_byts: float
    init_bwd_win_byts: float
    active_mean:       float
    idle_mean:         float


# ---------------------------------------------------------------------------
# Endpoints — Liveness
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok", "version": "5.0.0", "storage": "HDFS+PostgreSQL"}


# ---------------------------------------------------------------------------
# POST /predict — instant local inference (no Spark / no Kafka)
# ---------------------------------------------------------------------------
@app.post("/predict")
def predict_flow(flow: NetworkFlow):
    """
    Instant prediction using feature-based heuristic scoring aligned with the
    trained GBT model's most important features.
    Returns verdict immediately (no Kafka, no polling needed).
    """
    import math

    f = flow.dict()
    score = 0.0

    # SYN flood / port scan signature (high SYN, no FIN/ACK response)
    if f["syn_flag_cnt"] > 5 and f["ack_flag_cnt"] < 2:
        score += 0.45

    # RST storm (connection reset attacks)
    if f["rst_flag_cnt"] > 3:
        score += 0.30

    # Extremely high packet rate (DDoS indicator)
    if f["flow_pkts_per_s"] > 50000:
        score += 0.35

    # Very short duration with many packets (scanning)
    if f["flow_duration"] < 1000 and (f["tot_fwd_pkts"] + f["tot_bwd_pkts"]) > 20:
        score += 0.25

    # One-directional flow (only forward packets — injection/exfiltration)
    if f["tot_bwd_pkts"] == 0 and f["tot_fwd_pkts"] > 10:
        score += 0.20

    # Abnormal byte rates (Infinity already filtered, but check extremes)
    byts = f["flow_byts_per_s"]
    if not math.isnan(byts) and not math.isinf(byts) and byts > 1_000_000:
        score += 0.15

    # Normal benign signals reduce score
    if f["fin_flag_cnt"] >= 1 and f["ack_flag_cnt"] >= 2:
        score -= 0.10
    if 10 < f["flow_pkts_per_s"] < 5000:
        score -= 0.10

    # Clamp to [0, 1]
    probability = max(0.0, min(1.0, score))
    is_attack   = probability >= 0.4

    return {
        "flow_id":            None,
        "is_attack":          is_attack,
        "attack_probability": round(probability, 4),
        "verdict":            "⚠️ ATTACK DETECTED" if is_attack else "✅ Benign Traffic",
        "model_version":      "gbt_v1_heuristic",
        "inference_mode":     "local_instant",
    }


# ---------------------------------------------------------------------------
# POST /flows — async submission through Kafka
# ---------------------------------------------------------------------------
@app.post("/flows", status_code=202)
def submit_flow(flow: NetworkFlow):
    """
    Publish flow to Kafka, register UUID as 'pending' in PostgreSQL.
    Spark picks it up, runs GBT inference, writes to PostgreSQL, updates status to 'done'.
    """
    flow_id   = str(uuid.uuid4())
    ingest_ts = datetime.now(timezone.utc)
    payload   = flow.dict()
    payload.update({"flow_id": flow_id, "kafka_ingest_ts": ingest_ts.isoformat()})

    # 1. Register in PostgreSQL as 'pending'
    try:
        _pg_query(
            "INSERT INTO flow_submissions (flow_id, status, submitted_at) VALUES (%s, 'pending', %s)",
            [flow_id, ingest_ts],
            commit=True
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Database error registering submission: {exc}"
        )

    # 2. Publish to Kafka
    try:
        producer = get_producer()
        producer.send(KAFKA_TOPIC, value=payload)
        producer.flush()
    except Exception as exc:
        try:
            _pg_query(
                "UPDATE flow_submissions SET status='failed' WHERE flow_id=%s",
                [flow_id],
                commit=True
            )
        except Exception:
            pass
        raise HTTPException(
            status_code=503,
            detail=f"Kafka unavailable — could not submit flow: {exc}",
        )

    return {
        "flow_id":  flow_id,
        "status":   "pending",
        "message":  "Flow submitted. Poll /flows/{flow_id}/result for the GBT result.",
        "poll_url": f"/flows/{flow_id}/result",
    }


# ---------------------------------------------------------------------------
# GET /flows/{flow_id}/result — async polling
# ---------------------------------------------------------------------------
@app.get("/flows/{flow_id}/result")
def get_flow_result(flow_id: str):
    """Poll PostgreSQL for submission status, then retrieve prediction."""
    row = _pg_query(
        "SELECT status, submitted_at, completed_at FROM flow_submissions WHERE flow_id=%s",
        [flow_id],
        fetch_one=True
    )

    if row is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found.")

    status       = row["status"]
    submitted_at = row["submitted_at"]

    # Auto-timeout after 60 s
    if status == "pending" and submitted_at:
        try:
            elapsed = (datetime.now(timezone.utc) - submitted_at).total_seconds()
            if elapsed > 60:
                _pg_query(
                    "UPDATE flow_submissions SET status='processing_timeout' WHERE flow_id=%s",
                    [flow_id],
                    commit=True
                )
                return {"flow_id": flow_id, "status": "processing_timeout",
                        "message": "Spark did not process within 60 s."}
        except Exception:
            pass

    if status != "done":
        return {"flow_id": flow_id, "status": status}

    # Retrieve from PostgreSQL network_flows table
    flow_row = _pg_query(
        "SELECT is_attack, attack_probability, model_version, kafka_ingest_ts FROM network_flows WHERE flow_id=%s LIMIT 1",
        [flow_id],
        fetch_one=True
    )

    if not flow_row:
        return {"flow_id": flow_id, "status": "processing"}

    return {
        "flow_id":            flow_id,
        "status":             "done",
        "is_attack":          flow_row.get("is_attack"),
        "attack_probability": flow_row.get("attack_probability"),
        "verdict": "⚠️ ATTACK DETECTED" if flow_row.get("is_attack") else "✅ Benign Traffic",
        "model_version":      flow_row.get("model_version"),
        "kafka_ingest_ts":    flow_row.get("kafka_ingest_ts").isoformat() if flow_row.get("kafka_ingest_ts") else None,
    }


# ---------------------------------------------------------------------------
# GET /flows — list recent flows from PostgreSQL
# ---------------------------------------------------------------------------
@app.get("/flows")
def list_flows(limit: int = 200):
    """Return recent flows with GBT predictions from PostgreSQL."""
    rows = _pg_query(
        f"""
        SELECT flow_id, dst_port, protocol, flow_duration,
               tot_fwd_pkts, tot_bwd_pkts, flow_byts_per_s, flow_pkts_per_s,
               syn_flag_cnt, rst_flag_cnt, is_attack, attack_probability,
               model_version, kafka_ingest_ts
        FROM network_flows
        ORDER BY kafka_ingest_ts DESC
        LIMIT {int(limit)}
        """
    )
    return [
        {
            "flow_id":           str(r.get("flow_id")),
            "dst_port":          r.get("dst_port"),
            "protocol":          r.get("protocol"),
            "flow_duration":     r.get("flow_duration"),
            "tot_fwd_pkts":      r.get("tot_fwd_pkts"),
            "tot_bwd_pkts":      r.get("tot_bwd_pkts"),
            "flow_byts_per_s":   r.get("flow_byts_per_s"),
            "flow_pkts_per_s":   r.get("flow_pkts_per_s"),
            "syn_flag_cnt":      r.get("syn_flag_cnt"),
            "rst_flag_cnt":      r.get("rst_flag_cnt"),
            "is_attack":         r.get("is_attack"),
            "attack_confidence": r.get("attack_probability"),
            "model_version":     r.get("model_version"),
            "created_at":        r.get("kafka_ingest_ts").isoformat() if r.get("kafka_ingest_ts") else None,
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# GET /analytics — daily_summary from PostgreSQL
# ---------------------------------------------------------------------------
@app.get("/analytics")
def get_analytics(days: int = 30):
    """Return daily attack summary rows written by SparkSQL analysis job to PostgreSQL."""
    rows = _pg_query(
        f"""
        SELECT summary_date, protocol, total_flows, attack_count,
               benign_count, attack_rate, avg_flow_bytes
        FROM daily_summary
        WHERE summary_date >= CURRENT_DATE - INTERVAL '{int(days)} days'
        ORDER BY summary_date DESC, protocol
        """
    )
    return [
        {
            "summary_date":   str(r.get("summary_date")),
            "protocol":       r.get("protocol"),
            "total_flows":    r.get("total_flows"),
            "attack_count":   r.get("attack_count"),
            "benign_count":   r.get("benign_count"),
            "attack_rate":    float(r.get("attack_rate") or 0),
            "avg_flow_bytes": float(r.get("avg_flow_bytes") or 0),
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# GET /status — component health
# ---------------------------------------------------------------------------
@app.get("/status")
def get_system_status():
    return {
        "kafka":    get_cached_status("kafka",    check_kafka,    ttl=10),
        "spark":    get_cached_status("spark",    check_spark,    ttl=10),
        "hdfs":     get_cached_status("hdfs",     check_hdfs,     ttl=30),
        "airflow":  get_cached_status("airflow",  check_airflow,  ttl=30),
        "postgres": get_cached_status("postgres", check_postgres, ttl=10),
    }


# ---------------------------------------------------------------------------
# GET /stats — HDFS + PostgreSQL database metrics + model metadata
# ---------------------------------------------------------------------------
@app.get("/stats")
def get_system_stats():
    # ── HDFS folder sizes ─────────────────────────────────────────────────────
    raw_size_mb  = 0.0
    proc_size_mb = 0.0
    try:
        r = requests.get(
            "http://namenode:9870/webhdfs/v1/ids/raw?op=GETCONTENTSUMMARY", timeout=1.0
        )
        if r.status_code == 200:
            raw_size_mb = round(
                r.json()["ContentSummary"]["spaceConsumed"] / (1024 * 1024), 2
            )
    except Exception:
        pass
    try:
        r = requests.get(
            "http://namenode:9870/webhdfs/v1/ids/processed?op=GETCONTENTSUMMARY",
            timeout=1.0,
        )
        if r.status_code == 200:
            proc_size_mb = round(
                r.json()["ContentSummary"]["spaceConsumed"] / (1024 * 1024), 2
            )
    except Exception:
        pass

    # ── PostgreSQL stats (total and hourly) ───────────────────────────────────
    total_flows = attack_count = benign_count = 0
    attack_last_hour = benign_last_hour = 0
    try:
        rows = _pg_query(
            """
            SELECT is_attack, COUNT(*) as cnt
            FROM network_flows
            GROUP BY is_attack
            """
        )
        for row in rows:
            if row["is_attack"]:
                attack_count = row["cnt"]
            else:
                benign_count = row["cnt"]
        total_flows = attack_count + benign_count
    except Exception as exc:
        print(f"[stats] error querying network_flows totals: {exc}")

    try:
        rows_lh = _pg_query(
            """
            SELECT is_attack, COUNT(*) as cnt
            FROM network_flows
            WHERE kafka_ingest_ts >= NOW() - INTERVAL '1 hour'
            GROUP BY is_attack
            """
        )
        for row in rows_lh:
            if row["is_attack"]:
                attack_last_hour = row["cnt"]
            else:
                benign_last_hour = row["cnt"]
    except Exception as exc:
        print(f"[stats] error querying network_flows hourly: {exc}")

    # ── GBT model metadata ────────────────────────────────────────────────────
    model_meta = None
    try:
        # Try reading from PostgreSQL first
        db_meta = _pg_query(
            """
            SELECT model_version, trained_at, training_duration_s,
                   hdfs_model_path, hdfs_data_path, n_train, n_test,
                   features_json, metrics_json
            FROM model_metadata
            ORDER BY trained_at DESC
            LIMIT 1
            """
        )
        if db_meta:
            m = db_meta[0]
            model_meta = {
                "model_version":         m["model_version"],
                "trained_at":            m["trained_at"].isoformat() if m["trained_at"] else None,
                "training_duration_sec": m["training_duration_s"],
                "hdfs_model_path":       m["hdfs_model_path"],
                "hdfs_data_path":        m["hdfs_data_path"],
                "n_train":               m["n_train"],
                "n_test":                m["n_test"],
                "features":              json.loads(m["features_json"]) if m["features_json"] else [],
                "metrics":               json.loads(m["metrics_json"]) if m["metrics_json"] else {},
            }
    except Exception as exc:
        print(f"[stats] could not query model_metadata from Postgres: {exc}. Trying fallback...")

    # Fallback to local JSON if DB metadata is empty or failed
    if not model_meta:
        meta_path = f"{LOCAL_PARQUET}/gbt_metadata.json"
        if os.path.exists(meta_path):
            try:
                with open(meta_path) as fh:
                    model_meta = json.load(fh)
            except Exception:
                pass

    return {
        "hdfs": {
            "raw_size_mb":       raw_size_mb,
            "processed_size_mb": proc_size_mb,
        },
        "postgres": {
            "total_flows":      total_flows,
            "benign_count":     benign_count,
            "attack_count":     attack_count,
            "benign_last_hour": benign_last_hour,
            "attack_last_hour": attack_last_hour,
        },
        "model_metadata": model_meta,
        "last_dag_run":   None,
    }
