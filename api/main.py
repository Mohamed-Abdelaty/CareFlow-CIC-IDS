"""
FastAPI service
- POST /predict             -> predicted LOS + stay category (no DB save)
- POST /patients            -> add a new patient + run prediction + save to Postgres
- GET  /patients            -> list all saved patients with their latest prediction
- PUT  /patients/{id}       -> update patient data, re-run prediction, save new record
- GET  /metrics             -> aggregate hospital metrics from Postgres
- GET  /health              -> health check
"""

import os

import joblib
import pandas as pd
import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

MODEL_DIR = os.getenv("MODEL_DIR", "/models")
DB_URL = os.getenv(
    "DATABASE_URL", "postgresql://hpf:hpf_password@postgres:5432/hospital_flow"
)

app = FastAPI(title="Hospital Patient Flow API")

_reg_model = None
_clf_model = None
_label_map = None


def get_models():
    global _reg_model, _clf_model, _label_map
    if _reg_model is None or _clf_model is None:
        reg_path       = os.path.join(MODEL_DIR, "los_regressor.joblib")
        clf_path       = os.path.join(MODEL_DIR, "stay_classifier.joblib")
        label_map_path = os.path.join(MODEL_DIR, "label_map.joblib")
        if not (os.path.exists(reg_path) and os.path.exists(clf_path)):
            raise HTTPException(status_code=503, detail="Models not trained yet")
        _reg_model = joblib.load(reg_path)
        _clf_model = joblib.load(clf_path)
        _label_map = (
            joblib.load(label_map_path)
            if os.path.exists(label_map_path)
            else {0: "Short", 1: "Medium", 2: "Long"}
        )
    return _reg_model, _clf_model, _label_map


def run_prediction(data: dict) -> tuple:
    """Run both regression and classification models on a feature dict."""
    reg_model, clf_model, label_map = get_models()
    df            = pd.DataFrame([data])
    predicted_los = round(float(reg_model.predict(df)[0]), 2)
    raw_category  = int(clf_model.predict(df)[0])
    stay_category = label_map.get(raw_category, str(raw_category))
    return predicted_los, stay_category


# ── Pydantic models ────────────────────────────────────────────────────────────

class PatientInput(BaseModel):
    """Used by /predict — no name or medical ID required."""
    age_group: str
    gender: str
    admission_type: str
    diagnosis: str
    severity: str
    risk_of_mortality: str


class PatientRecord(BaseModel):
    """Used by /patients — includes patient identity fields."""
    patient_name: str
    medical_id: str
    age_group: str
    gender: str
    admission_type: str
    diagnosis: str
    severity: str
    risk_of_mortality: str


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/predict")
def predict(patient: PatientInput):
    """Quick prediction without saving to the database."""
    predicted_los, stay_category = run_prediction(patient.dict())
    return {
        "predicted_length_of_stay_days": predicted_los,
        "stay_category": stay_category,
    }


@app.post("/patients")
def add_patient(patient: PatientRecord):
    """
    Save a new patient to Postgres, run the ML prediction, and
    store the prediction result in the predictions table.
    """
    features = {k: v for k, v in patient.dict().items()
                if k not in ("patient_name", "medical_id")}
    predicted_los, stay_category = run_prediction(features)

    conn = psycopg2.connect(DB_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO patients
                    (patient_name, medical_id, age_group, gender, admission_type,
                     diagnosis, severity, risk_of_mortality)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING patient_id
                """,
                (patient.patient_name, patient.medical_id, patient.age_group,
                 patient.gender, patient.admission_type, patient.diagnosis,
                 patient.severity, patient.risk_of_mortality),
            )
            patient_id = cur.fetchone()[0]

            cur.execute(
                """
                INSERT INTO predictions (patient_id, predicted_los, stay_category, model_version)
                VALUES (%s, %s, %s, %s)
                """,
                (patient_id, predicted_los, stay_category, "xgboost-v1"),
            )
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"Medical ID '{patient.medical_id}' already exists.",
        )
    finally:
        conn.close()

    return {
        "patient_id": patient_id,
        "patient_name": patient.patient_name,
        "medical_id": patient.medical_id,
        "predicted_length_of_stay_days": predicted_los,
        "stay_category": stay_category,
    }


@app.get("/patients")
def list_patients():
    """Return all saved patients with their most recent prediction."""
    conn = psycopg2.connect(DB_URL)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    p.patient_id, p.patient_name, p.medical_id,
                    p.age_group, p.gender, p.admission_type,
                    p.diagnosis, p.severity, p.risk_of_mortality,
                    p.total_charges, p.created_at,
                    pr.predicted_los, pr.stay_category, pr.predicted_at
                FROM patients p
                LEFT JOIN LATERAL (
                    SELECT predicted_los, stay_category, predicted_at
                    FROM predictions
                    WHERE patient_id = p.patient_id
                    ORDER BY predicted_at DESC
                    LIMIT 1
                ) pr ON true
                ORDER BY p.created_at DESC
                """
            )
            rows = cur.fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


@app.put("/patients/{patient_id}")
def update_patient(patient_id: int, patient: PatientRecord):
    """
    Update an existing patient's clinical data, re-run the ML prediction,
    and save the new prediction to the predictions table.
    """
    features = {k: v for k, v in patient.dict().items()
                if k not in ("patient_name", "medical_id")}
    predicted_los, stay_category = run_prediction(features)

    conn = psycopg2.connect(DB_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE patients SET
                    patient_name=%s, medical_id=%s, age_group=%s, gender=%s,
                    admission_type=%s, diagnosis=%s, severity=%s,
                    risk_of_mortality=%s
                WHERE patient_id=%s
                """,
                (patient.patient_name, patient.medical_id, patient.age_group,
                 patient.gender, patient.admission_type, patient.diagnosis,
                 patient.severity, patient.risk_of_mortality,
                 patient_id),
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Patient not found")

            cur.execute(
                """
                INSERT INTO predictions (patient_id, predicted_los, stay_category, model_version)
                VALUES (%s, %s, %s, %s)
                """,
                (patient_id, predicted_los, stay_category, "xgboost-v1"),
            )
        conn.commit()
    finally:
        conn.close()

    return {
        "patient_id": patient_id,
        "patient_name": patient.patient_name,
        "medical_id": patient.medical_id,
        "predicted_length_of_stay_days": predicted_los,
        "stay_category": stay_category,
        "message": "Patient updated and prediction recalculated successfully.",
    }


@app.get("/metrics")
def metrics():
    conn = psycopg2.connect(DB_URL)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT hospital_county, avg_los, patient_count, long_stay_rate, "
                "emergency_rate, computed_at FROM hospital_metrics "
                "ORDER BY computed_at DESC LIMIT 100;"
            )
            rows = cur.fetchall()
        return {"metrics": rows}
    finally:
        conn.close()
