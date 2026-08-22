-- CareFlow IDS — PostgreSQL Schema
-- Network intrusion detection: stores raw flows + inference results

-- ── Network flows table ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS network_flows (
    flow_id             SERIAL PRIMARY KEY,
    dst_port            INTEGER,
    protocol            INTEGER,          -- 0=HOPOPT, 6=TCP, 17=UDP
    flow_duration       NUMERIC,          -- microseconds
    tot_fwd_pkts        NUMERIC,
    tot_bwd_pkts        NUMERIC,
    totlen_fwd_pkts     NUMERIC,          -- bytes
    totlen_bwd_pkts     NUMERIC,
    flow_byts_per_s     NUMERIC,
    flow_pkts_per_s     NUMERIC,
    flow_iat_mean       NUMERIC,          -- inter-arrival time mean (μs)
    flow_iat_std        NUMERIC,
    fwd_psh_flags       NUMERIC,
    fin_flag_cnt        NUMERIC,
    syn_flag_cnt        NUMERIC,
    rst_flag_cnt        NUMERIC,
    psh_flag_cnt        NUMERIC,
    ack_flag_cnt        NUMERIC,
    init_fwd_win_byts   NUMERIC,
    init_bwd_win_byts   NUMERIC,
    active_mean         NUMERIC,
    idle_mean           NUMERIC,
    created_at          TIMESTAMP DEFAULT NOW()
);

-- ── Predictions table ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS predictions (
    prediction_id       SERIAL PRIMARY KEY,
    flow_id             INTEGER REFERENCES network_flows(flow_id) ON DELETE CASCADE,
    is_attack           BOOLEAN,
    attack_confidence   NUMERIC,          -- P(Attack) from XGBClassifier
    model_version       VARCHAR(50),
    predicted_at        TIMESTAMP DEFAULT NOW()
);

-- ── Traffic metrics table (populated by Airflow DAG step) ────────────────────
CREATE TABLE IF NOT EXISTS traffic_metrics (
    metric_id           SERIAL PRIMARY KEY,
    protocol            INTEGER,
    total_flows         INTEGER,
    attack_count        INTEGER,
    benign_count        INTEGER,
    attack_rate         NUMERIC,          -- 0.0 – 1.0
    computed_at         TIMESTAMP DEFAULT NOW()
);

-- ── Indexes for common query patterns ────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_predictions_flow_id   ON predictions(flow_id);
CREATE INDEX IF NOT EXISTS idx_flows_created_at      ON network_flows(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_predictions_predicted ON predictions(predicted_at DESC);
