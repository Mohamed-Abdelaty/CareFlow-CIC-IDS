-- Auto-executed by the official postgres image on first startup
-- (mounted into /docker-entrypoint-initdb.d)

CREATE TABLE IF NOT EXISTS patients (
    patient_id      SERIAL PRIMARY KEY,
    patient_name    VARCHAR(100),
    medical_id      VARCHAR(50) UNIQUE,
    age_group       VARCHAR(20),
    gender          VARCHAR(10),
    admission_type  VARCHAR(30),
    diagnosis       VARCHAR(100),
    severity        VARCHAR(20),
    risk_of_mortality VARCHAR(20),
    hospital_county VARCHAR(100),
    total_charges   NUMERIC,
    length_of_stay  NUMERIC,
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS predictions (
    prediction_id SERIAL PRIMARY KEY,
    patient_id INTEGER REFERENCES patients(patient_id),
    predicted_los NUMERIC,
    stay_category VARCHAR(20),
    model_version VARCHAR(50),
    predicted_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS hospital_metrics (
    metric_id SERIAL PRIMARY KEY,
    hospital_county VARCHAR(100),
    avg_los NUMERIC,
    patient_count INTEGER,
    long_stay_rate NUMERIC,
    emergency_rate NUMERIC,
    computed_at TIMESTAMP DEFAULT NOW()
);
