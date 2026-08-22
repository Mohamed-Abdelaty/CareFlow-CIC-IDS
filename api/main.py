"""
FastAPI — CIC-IDS 2018 Network Intrusion Detection Serving Layer
Endpoints:
  POST /flows        — analyse a new network flow, store result in Postgres
  GET  /flows        — list all stored flows with their latest prediction
  PUT  /flows/{id}   — update a flow's fields and re-run inference
"""

import os
from contextlib import contextmanager
from typing import Optional

import joblib
import pandas as pd
import psycopg2
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DB_URL     = os.getenv("DB_URL",     "postgresql://hpf:hpf_password@postgres:5432/hospital_flow")
MODELS_DIR = os.getenv("MODELS_DIR", "/models")

app = FastAPI(title="CareFlow IDS API", version="2.0.0")


# ---------------------------------------------------------------------------
# Model loading (cached after first call)
# ---------------------------------------------------------------------------
_model      = None
_meta       = None
_metrics    = None


def get_model():
    global _model, _meta, _metrics
    if _model is None:
        _model   = joblib.load(f"{MODELS_DIR}/ids_classifier.joblib")
        _meta    = joblib.load(f"{MODELS_DIR}/model_meta.joblib")
        _metrics = joblib.load(f"{MODELS_DIR}/metrics.joblib")
    return _model, _meta, _metrics


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
@contextmanager
def get_db():
    conn = psycopg2.connect(DB_URL)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class NetworkFlow(BaseModel):
    """Input schema — all numeric features measured by a flow collector."""
    dst_port:          int
    protocol:          int        # 0 = HOPOPT, 6 = TCP, 17 = UDP
    flow_duration:     float      # microseconds
    tot_fwd_pkts:      float
    tot_bwd_pkts:      float
    totlen_fwd_pkts:   float      # bytes
    totlen_bwd_pkts:   float
    flow_byts_per_s:   float
    flow_pkts_per_s:   float
    flow_iat_mean:     float      # inter-arrival time mean (μs)
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
# Inference helper
# ---------------------------------------------------------------------------
def run_prediction(flow_dict: dict) -> tuple[bool, float]:
    """Return (is_attack: bool, confidence: float 0-1)."""
    model, meta, _ = get_model()
    features = meta["features"]
    df       = pd.DataFrame([{f: flow_dict.get(f, 0) for f in features}])
    prob     = float(model.predict_proba(df)[0][1])   # P(Attack)
    return prob >= 0.5, round(prob, 6)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/model-metrics")
def model_metrics():
    """Return the latest training evaluation metrics."""
    _, _, metrics = get_model()
    return metrics


@app.post("/flows")
def add_flow(flow: NetworkFlow):
    """Analyse a new network flow, store it and its prediction in Postgres."""
    flow_dict = flow.dict()
    is_attack, confidence = run_prediction(flow_dict)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO network_flows (
                    dst_port, protocol, flow_duration, tot_fwd_pkts,
                    tot_bwd_pkts, totlen_fwd_pkts, totlen_bwd_pkts,
                    flow_byts_per_s, flow_pkts_per_s, flow_iat_mean,
                    flow_iat_std, fwd_psh_flags, fin_flag_cnt, syn_flag_cnt,
                    rst_flag_cnt, psh_flag_cnt, ack_flag_cnt,
                    init_fwd_win_byts, init_bwd_win_byts, active_mean, idle_mean
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                ) RETURNING flow_id
                """,
                (
                    flow.dst_port, flow.protocol, flow.flow_duration,
                    flow.tot_fwd_pkts, flow.tot_bwd_pkts, flow.totlen_fwd_pkts,
                    flow.totlen_bwd_pkts, flow.flow_byts_per_s, flow.flow_pkts_per_s,
                    flow.flow_iat_mean, flow.flow_iat_std, flow.fwd_psh_flags,
                    flow.fin_flag_cnt, flow.syn_flag_cnt, flow.rst_flag_cnt,
                    flow.psh_flag_cnt, flow.ack_flag_cnt, flow.init_fwd_win_byts,
                    flow.init_bwd_win_byts, flow.active_mean, flow.idle_mean,
                ),
            )
            flow_id = cur.fetchone()[0]

            cur.execute(
                """
                INSERT INTO predictions (flow_id, is_attack, attack_confidence, model_version)
                VALUES (%s, %s, %s, %s)
                """,
                (flow_id, is_attack, confidence, "ids_classifier_v2"),
            )

    return {
        "flow_id":      flow_id,
        "is_attack":    is_attack,
        "confidence":   confidence,
        "verdict":      "⚠️ ATTACK DETECTED" if is_attack else "✅ Benign Traffic",
    }


@app.get("/flows")
def list_flows(limit: int = 200):
    """Return all stored flows with their latest prediction."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    f.flow_id, f.dst_port, f.protocol, f.flow_duration,
                    f.tot_fwd_pkts, f.tot_bwd_pkts,
                    f.flow_byts_per_s, f.flow_pkts_per_s,
                    f.syn_flag_cnt, f.rst_flag_cnt, f.created_at,
                    p.is_attack, p.attack_confidence, p.predicted_at
                FROM network_flows f
                LEFT JOIN LATERAL (
                    SELECT is_attack, attack_confidence, predicted_at
                    FROM predictions
                    WHERE flow_id = f.flow_id
                    ORDER BY predicted_at DESC
                    LIMIT 1
                ) p ON true
                ORDER BY f.created_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()

    return [
        {
            "flow_id":          r[0],
            "dst_port":         r[1],
            "protocol":         r[2],
            "flow_duration":    r[3],
            "tot_fwd_pkts":     r[4],
            "tot_bwd_pkts":     r[5],
            "flow_byts_per_s":  r[6],
            "flow_pkts_per_s":  r[7],
            "syn_flag_cnt":     r[8],
            "rst_flag_cnt":     r[9],
            "created_at":       str(r[10]),
            "is_attack":        r[11],
            "attack_confidence": r[12],
            "predicted_at":     str(r[13]),
        }
        for r in rows
    ]


@app.put("/flows/{flow_id}")
def update_flow(flow_id: int, flow: NetworkFlow):
    """Update a flow's features and re-run inference."""
    flow_dict = flow.dict()
    is_attack, confidence = run_prediction(flow_dict)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE network_flows SET
                    dst_port=%s, protocol=%s, flow_duration=%s,
                    tot_fwd_pkts=%s, tot_bwd_pkts=%s,
                    totlen_fwd_pkts=%s, totlen_bwd_pkts=%s,
                    flow_byts_per_s=%s, flow_pkts_per_s=%s,
                    flow_iat_mean=%s, flow_iat_std=%s, fwd_psh_flags=%s,
                    fin_flag_cnt=%s, syn_flag_cnt=%s, rst_flag_cnt=%s,
                    psh_flag_cnt=%s, ack_flag_cnt=%s,
                    init_fwd_win_byts=%s, init_bwd_win_byts=%s,
                    active_mean=%s, idle_mean=%s
                WHERE flow_id=%s
                """,
                (
                    flow.dst_port, flow.protocol, flow.flow_duration,
                    flow.tot_fwd_pkts, flow.tot_bwd_pkts, flow.totlen_fwd_pkts,
                    flow.totlen_bwd_pkts, flow.flow_byts_per_s, flow.flow_pkts_per_s,
                    flow.flow_iat_mean, flow.flow_iat_std, flow.fwd_psh_flags,
                    flow.fin_flag_cnt, flow.syn_flag_cnt, flow.rst_flag_cnt,
                    flow.psh_flag_cnt, flow.ack_flag_cnt, flow.init_fwd_win_byts,
                    flow.init_bwd_win_byts, flow.active_mean, flow.idle_mean,
                    flow_id,
                ),
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found.")

            cur.execute(
                """
                INSERT INTO predictions (flow_id, is_attack, attack_confidence, model_version)
                VALUES (%s, %s, %s, %s)
                """,
                (flow_id, is_attack, confidence, "ids_classifier_v2"),
            )

    return {
        "flow_id":    flow_id,
        "is_attack":  is_attack,
        "confidence": confidence,
        "verdict":    "⚠️ ATTACK DETECTED" if is_attack else "✅ Benign Traffic",
    }
