"""
CareFlow IDS — Streamlit Dashboard
Network Intrusion Detection & Analysis

Tabs:
  1. Overview   — Live KPI cards, flow table, attack/benign distribution chart
  2. Analyse Flow — Submit a new network flow for real-time attack detection
  3. Edit Flow    — Select an existing flow, tweak values, re-run inference
"""

import requests
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from streamlit_autorefresh import st_autorefresh

API_URL = "http://api:8000"

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="CareFlow IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ CareFlow — Network Intrusion Detection System")
st.caption("Real-time network flow analysis powered by XGBoost & Apache Kafka")

# ---------------------------------------------------------------------------
# Helper: safe API call
# ---------------------------------------------------------------------------
def api_get(path: str, **kwargs):
    try:
        r = requests.get(f"{API_URL}{path}", timeout=8, **kwargs)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"API error: {e}")
        return None


def api_post(path: str, payload: dict):
    try:
        r = requests.post(f"{API_URL}{path}", json=payload, timeout=8)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"API error: {e}")
        return None


def api_put(path: str, payload: dict):
    try:
        r = requests.put(f"{API_URL}{path}", json=payload, timeout=8)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"API error: {e}")
        return None


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Overview", 
    "🔍 Analyse Flow", 
    "✏️ Edit Flow", 
    "🛠️ Model & Pipeline Health"
])


# ═══════════════════════════════════════════════════════════════════════════
# TAB 1 — Overview
# ═══════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("Live Traffic Overview")

    flows_data = api_get("/flows", params={"limit": 500})
    metrics_data = api_get("/model-metrics")

    if flows_data:
        df = pd.DataFrame(flows_data)

        # ── KPI Cards ────────────────────────────────────────────────────
        total       = len(df)
        attacks     = int(df["is_attack"].sum()) if "is_attack" in df.columns else 0
        benign      = total - attacks
        attack_rate = (attacks / total * 100) if total > 0 else 0.0

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("🌐 Total Flows Analysed", f"{total:,}")
        c2.metric("✅ Benign Flows",          f"{benign:,}")
        c3.metric("⚠️ Attack Flows",          f"{attacks:,}")
        c4.metric("🔥 Attack Rate",           f"{attack_rate:.1f}%")

        st.divider()

        # ── Model Metrics Card ───────────────────────────────────────────
        if metrics_data:
            st.subheader("🧠 Model Performance (Test Set)")
            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("Accuracy",  f"{metrics_data.get('accuracy',  0)*100:.2f}%")
            m2.metric("Precision", f"{metrics_data.get('precision', 0)*100:.2f}%")
            m3.metric("Recall",    f"{metrics_data.get('recall',    0)*100:.2f}%")
            m4.metric("F1 Score",  f"{metrics_data.get('f1',        0)*100:.2f}%")
            m5.metric("ROC-AUC",   f"{metrics_data.get('auc',       0)*100:.2f}%")
            st.divider()

        # ── Attack / Benign Bar Chart ────────────────────────────────────
        col_chart, col_table = st.columns([1, 2])

        with col_chart:
            st.subheader("Traffic Classification")
            pie_df = pd.DataFrame({
                "Category":  ["Benign", "Attack"],
                "Count":     [benign, attacks],
            })
            fig = px.pie(
                pie_df, names="Category", values="Count",
                color="Category",
                color_discrete_map={"Benign": "#2ecc71", "Attack": "#e74c3c"},
                hole=0.4,
            )
            fig.update_layout(margin=dict(t=0, b=0, l=0, r=0))
            st.plotly_chart(fig, use_container_width=True)

        with col_table:
            st.subheader("Recent Flows")
            display_cols = [
                "flow_id", "dst_port", "protocol", "flow_duration",
                "tot_fwd_pkts", "tot_bwd_pkts", "syn_flag_cnt",
                "is_attack", "attack_confidence", "created_at",
            ]
            available = [c for c in display_cols if c in df.columns]
            display_df = df[available].copy()
            if "is_attack" in display_df.columns:
                display_df["verdict"] = display_df["is_attack"].map(
                    {True: "⚠️ Attack", False: "✅ Benign", 1: "⚠️ Attack", 0: "✅ Benign"}
                )
            st.dataframe(display_df.head(50), use_container_width=True, height=350)

        # ── Confidence histogram ─────────────────────────────────────────
        if "attack_confidence" in df.columns:
            st.subheader("Attack Confidence Distribution")
            fig2 = px.histogram(
                df, x="attack_confidence", nbins=40,
                color="is_attack",
                color_discrete_map={True: "#e74c3c", False: "#2ecc71",
                                    1: "#e74c3c", 0: "#2ecc71"},
                labels={"attack_confidence": "P(Attack)", "is_attack": "Is Attack"},
            )
            st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No flow data yet. Submit a flow in the **Analyse Flow** tab.")


# ═══════════════════════════════════════════════════════════════════════════
# TAB 2 — Analyse New Flow
# ═══════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("🔍 Analyse a Network Flow")
    st.caption(
        "Enter the flow statistics captured by your network sensor. "
        "The model will classify the flow as Benign or an Attack."
    )

    with st.form("add_flow_form"):
        st.markdown("**Connection Identifiers**")
        col1, col2 = st.columns(2)
        dst_port = col1.number_input("Destination Port",    min_value=0,   max_value=65535, value=80)
        protocol = col2.selectbox("Protocol",
                                  options=[0, 6, 17],
                                  format_func=lambda x: {0:"0 - HOPOPT", 6:"6 - TCP", 17:"17 - UDP"}[x])

        st.markdown("**Flow Volume**")
        col3, col4, col5 = st.columns(3)
        flow_duration    = col3.number_input("Flow Duration (μs)",   min_value=0.0, value=100000.0)
        tot_fwd_pkts     = col4.number_input("Total Fwd Packets",    min_value=0.0, value=10.0)
        tot_bwd_pkts     = col5.number_input("Total Bwd Packets",    min_value=0.0, value=8.0)
        col6, col7 = st.columns(2)
        totlen_fwd_pkts  = col6.number_input("Fwd Bytes Total",      min_value=0.0, value=1500.0)
        totlen_bwd_pkts  = col7.number_input("Bwd Bytes Total",      min_value=0.0, value=1200.0)

        st.markdown("**Flow Rates**")
        col8, col9 = st.columns(2)
        flow_byts_per_s  = col8.number_input("Flow Bytes/s",         min_value=0.0, value=15000.0)
        flow_pkts_per_s  = col9.number_input("Flow Packets/s",       min_value=0.0, value=100.0)

        st.markdown("**Inter-Arrival Times**")
        col10, col11 = st.columns(2)
        flow_iat_mean    = col10.number_input("Flow IAT Mean (μs)",  min_value=0.0, value=5000.0)
        flow_iat_std     = col11.number_input("Flow IAT Std (μs)",   min_value=0.0, value=2000.0)

        st.markdown("**TCP Flags**")
        col12, col13, col14, col15, col16, col17 = st.columns(6)
        syn_flag_cnt     = col12.number_input("SYN", min_value=0.0, value=1.0)
        fin_flag_cnt     = col13.number_input("FIN", min_value=0.0, value=1.0)
        rst_flag_cnt     = col14.number_input("RST", min_value=0.0, value=0.0)
        psh_flag_cnt     = col15.number_input("PSH", min_value=0.0, value=2.0)
        ack_flag_cnt     = col16.number_input("ACK", min_value=0.0, value=8.0)
        fwd_psh_flags    = col17.number_input("Fwd PSH", min_value=0.0, value=0.0)

        st.markdown("**Window Sizes & Timing**")
        col18, col19, col20, col21 = st.columns(4)
        init_fwd_win_byts = col18.number_input("Init Fwd Win Bytes", value=65535.0)
        init_bwd_win_byts = col19.number_input("Init Bwd Win Bytes", value=65535.0)
        active_mean       = col20.number_input("Active Mean (μs)",   min_value=0.0, value=0.0)
        idle_mean         = col21.number_input("Idle Mean (μs)",     min_value=0.0, value=0.0)

        submitted = st.form_submit_button("🔍 Analyse & Save Flow", type="primary")

    if submitted:
        payload = {
            "dst_port": dst_port, "protocol": protocol,
            "flow_duration": flow_duration,
            "tot_fwd_pkts": tot_fwd_pkts, "tot_bwd_pkts": tot_bwd_pkts,
            "totlen_fwd_pkts": totlen_fwd_pkts, "totlen_bwd_pkts": totlen_bwd_pkts,
            "flow_byts_per_s": flow_byts_per_s, "flow_pkts_per_s": flow_pkts_per_s,
            "flow_iat_mean": flow_iat_mean, "flow_iat_std": flow_iat_std,
            "fwd_psh_flags": fwd_psh_flags,
            "fin_flag_cnt": fin_flag_cnt, "syn_flag_cnt": syn_flag_cnt,
            "rst_flag_cnt": rst_flag_cnt, "psh_flag_cnt": psh_flag_cnt,
            "ack_flag_cnt": ack_flag_cnt,
            "init_fwd_win_byts": init_fwd_win_byts,
            "init_bwd_win_byts": init_bwd_win_byts,
            "active_mean": active_mean, "idle_mean": idle_mean,
        }
        result = api_post("/flows", payload)
        if result:
            is_attack   = result.get("is_attack")
            confidence  = result.get("confidence", 0)
            verdict     = result.get("verdict", "")
            if is_attack:
                st.error(f"### {verdict}")
                st.metric("Attack Confidence", f"{confidence*100:.2f}%")
            else:
                st.success(f"### {verdict}")
                st.metric("Attack Confidence", f"{confidence*100:.2f}%")
            st.info(f"Flow saved with ID: **{result.get('flow_id')}**")


# ═══════════════════════════════════════════════════════════════════════════
# TAB 3 — Edit Flow
# ═══════════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("✏️ Edit & Re-Analyse a Stored Flow")

    flows_data = api_get("/flows", params={"limit": 200})
    if not flows_data:
        st.info("No flows stored yet.")
    else:
        df_edit = pd.DataFrame(flows_data)
        options = {
            f"Flow #{r['flow_id']}  |  Port {r.get('dst_port','?')}  |  "
            f"{'⚠️ Attack' if r.get('is_attack') else '✅ Benign'}": r
            for r in flows_data
        }
        selected_label = st.selectbox("Select a flow to edit:", list(options.keys()))
        p = options[selected_label]

        with st.form("edit_flow_form"):
            col1, col2 = st.columns(2)
            dst_port  = col1.number_input("Destination Port", min_value=0, max_value=65535,
                                          value=int(p.get("dst_port") or 80))
            protocol  = col2.selectbox("Protocol", options=[0, 6, 17],
                                       index=[0,6,17].index(int(p.get("protocol") or 6)),
                                       format_func=lambda x: {0:"0-HOPOPT",6:"6-TCP",17:"17-UDP"}[x])

            col3, col4, col5 = st.columns(3)
            flow_duration   = col3.number_input("Flow Duration (μs)", min_value=0.0,
                                                value=float(p.get("flow_duration") or 0))
            tot_fwd_pkts    = col4.number_input("Total Fwd Packets",  min_value=0.0,
                                                value=float(p.get("tot_fwd_pkts") or 0))
            tot_bwd_pkts    = col5.number_input("Total Bwd Packets",  min_value=0.0,
                                                value=float(p.get("tot_bwd_pkts") or 0))
            col6, col7 = st.columns(2)
            flow_byts_per_s = col6.number_input("Flow Bytes/s",       min_value=0.0,
                                                value=float(p.get("flow_byts_per_s") or 0))
            flow_pkts_per_s = col7.number_input("Flow Packets/s",     min_value=0.0,
                                                value=float(p.get("flow_pkts_per_s") or 0))
            col8, col9 = st.columns(2)
            syn_flag_cnt    = col8.number_input("SYN Flags", min_value=0.0,
                                                value=float(p.get("syn_flag_cnt") or 0))
            rst_flag_cnt    = col9.number_input("RST Flags", min_value=0.0,
                                                value=float(p.get("rst_flag_cnt") or 0))

            update_submitted = st.form_submit_button("🔄 Update & Re-Analyse", type="primary")

        if update_submitted:
            payload = {
                "dst_port": dst_port, "protocol": protocol,
                "flow_duration": flow_duration,
                "tot_fwd_pkts": tot_fwd_pkts, "tot_bwd_pkts": tot_bwd_pkts,
                "totlen_fwd_pkts": float(p.get("totlen_fwd_pkts") or 0),
                "totlen_bwd_pkts": float(p.get("totlen_bwd_pkts") or 0),
                "flow_byts_per_s": flow_byts_per_s,
                "flow_pkts_per_s": flow_pkts_per_s,
                "flow_iat_mean":   float(p.get("flow_iat_mean") or 0),
                "flow_iat_std":    float(p.get("flow_iat_std")  or 0),
                "fwd_psh_flags":   float(p.get("fwd_psh_flags") or 0),
                "fin_flag_cnt":    float(p.get("fin_flag_cnt")  or 0),
                "syn_flag_cnt":    syn_flag_cnt,
                "rst_flag_cnt":    rst_flag_cnt,
                "psh_flag_cnt":    float(p.get("psh_flag_cnt")  or 0),
                "ack_flag_cnt":    float(p.get("ack_flag_cnt")  or 0),
                "init_fwd_win_byts": float(p.get("init_fwd_win_byts") or 0),
                "init_bwd_win_byts": float(p.get("init_bwd_win_byts") or 0),
                "active_mean":     float(p.get("active_mean")   or 0),
                "idle_mean":       float(p.get("idle_mean")     or 0),
            }
            result = api_put(f"/flows/{p['flow_id']}", payload)
            if result:
                is_attack  = result.get("is_attack")
                confidence = result.get("confidence", 0)
                verdict    = result.get("verdict", "")
                if is_attack:
                    st.error(f"### {verdict}")
                else:
                    st.success(f"### {verdict}")
                st.metric("Updated Attack Confidence", f"{confidence*100:.2f}%")


# ═══════════════════════════════════════════════════════════════════════════
# TAB 4 — Model & Pipeline Health
# ═══════════════════════════════════════════════════════════════════════════
with tab4:
    # ── Auto-refresh: updates the dashboard every 5 seconds for live demos ──
    st_autorefresh(interval=5000, key="ops_dashboard_autorefresh")

    st.subheader("🛠️ Pipeline Health & Ops Control Panel")
    st.caption("Live health checks, data ingestion metrics, and training validation statistics")

    # Fetch status and statistics from API
    status_data = api_get("/status")
    stats_data  = api_get("/stats")

    if not status_data or not stats_data:
        st.warning("⚠️ Waiting for connection to FastAPI serving layer...")
    else:
        # ───────────────────────────────────────────────────────────────────
        # 1. Component Status Strip
        # ───────────────────────────────────────────────────────────────────
        st.markdown("### 🖥️ Component Status")
        col_ka, col_sp, col_hd, col_ai, col_ml = st.columns(5)

        def make_status_card(col, name, state):
            if state == "healthy":
                color = "#2ecc71"
                text  = "HEALTHY"
            elif state == "degraded":
                color = "#f1c40f"
                text  = "DEGRADED"
            else:
                color = "#e74c3c"
                text  = "UNHEALTHY"

            col.markdown(
                f"""
                <div style="
                    background-color: #1e1e2e;
                    padding: 15px;
                    border-radius: 8px;
                    border-left: 5px solid {color};
                    text-align: center;
                    margin-bottom: 20px;
                ">
                    <span style="color: #a6adc8; font-size: 12px; font-weight: bold; text-transform: uppercase;">{name}</span>
                    <h3 style="color: {color}; margin: 5px 0 0 0; font-size: 18px; font-weight: 800;">{text}</h3>
                </div>
                """,
                unsafe_allow_html=True,
            )

        make_status_card(col_ka, "Apache Kafka",    status_data.get("kafka", "unhealthy"))
        make_status_card(col_sp, "Apache Spark",    status_data.get("spark", "unhealthy"))
        make_status_card(col_hd, "Hadoop HDFS",     status_data.get("hdfs", "unhealthy"))
        make_status_card(col_ai, "Apache Airflow",  status_data.get("airflow", "unhealthy"))
        make_status_card(col_ml, "XGBoost Model",   status_data.get("model", "unhealthy"))

        # ───────────────────────────────────────────────────────────────────
        # 2. Model Status & Metadata Card
        # ───────────────────────────────────────────────────────────────────
        st.divider()
        m_meta = stats_data.get("model_metadata")

        c_left, c_right = st.columns(2)

        with c_left:
            st.markdown("### 🧠 Active Model Status")
            if not m_meta:
                st.info("No trained model metadata found. Run the training script first.")
            else:
                st.markdown(
                    f"""
                    <div style="background-color: #1e1e2e; padding: 20px; border-radius: 8px; border: 1px solid #44475a;">
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr>
                                <td style="padding: 8px 0; color: #a6adc8; font-weight: bold;">Model Version</td>
                                <td style="padding: 8px 0; text-align: right; color: #50fa7b; font-family: monospace;">{m_meta.get('model_version', 'N/A')}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; color: #a6adc8; font-weight: bold;">Last Trained</td>
                                <td style="padding: 8px 0; text-align: right; color: #f8f8f2;">{m_meta.get('trained_at', 'N/A')}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; color: #a6adc8; font-weight: bold;">Training Duration</td>
                                <td style="padding: 8px 0; text-align: right; color: #f8f8f2;">{m_meta.get('training_duration_sec', 'N/A')} seconds</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; color: #a6adc8; font-weight: bold;">HDFS Input Path</td>
                                <td style="padding: 8px 0; text-align: right; color: #8be9fd; font-family: monospace;">{m_meta.get('hdfs_path', 'N/A')}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; color: #a6adc8; font-weight: bold;">Training Samples</td>
                                <td style="padding: 8px 0; text-align: right; color: #f1c40f; font-weight: bold;">{m_meta.get('n_train', 0) + m_meta.get('n_test', 0):,} rows</td>
                            </tr>
                        </table>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        with c_right:
            st.markdown("### 🎛️ Orchestration & Storage Stats")
            dag_run = stats_data.get("last_dag_run")
            hdfs_stats = stats_data.get("hdfs", {})

            st.markdown(
                f"""
                <div style="background-color: #1e1e2e; padding: 20px; border-radius: 8px; border: 1px solid #44475a;">
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 8px 0; color: #a6adc8; font-weight: bold;">Airflow Pipeline DAG</td>
                            <td style="padding: 8px 0; text-align: right; color: #8be9fd; font-family: monospace;">ids_network_flow_pipeline</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #a6adc8; font-weight: bold;">Latest DAG Run Status</td>
                            <td style="padding: 8px 0; text-align: right; color: #ffb86c; font-weight: bold;">{dag_run.get('state', 'NO RUNS FOUND') if dag_run else 'NO RUNS FOUND'}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #a6adc8; font-weight: bold;">DAG Run Execution Date</td>
                            <td style="padding: 8px 0; text-align: right; color: #f8f8f2; font-size: 13px;">{dag_run.get('execution_date', 'N/A') if dag_run else 'N/A'}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #a6adc8; font-weight: bold;">HDFS Raw Size</td>
                            <td style="padding: 8px 0; text-align: right; color: #f8f8f2;">{hdfs_stats.get('raw_size_mb', 0.0):,} MB</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #a6adc8; font-weight: bold;">HDFS Processed Size</td>
                            <td style="padding: 8px 0; text-align: right; color: #50fa7b; font-weight: bold;">{hdfs_stats.get('processed_size_mb', 0.0):,} MB</td>
                        </tr>
                    </table>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # ───────────────────────────────────────────────────────────────────
        # 3. Accuracy & Data Leakage Panel
        # ───────────────────────────────────────────────────────────────────
        st.divider()
        st.markdown("### 🎯 Model Accuracy & Validation Metrics")

        if m_meta:
            met = m_meta.get("metrics", {})

            # ⚠ Data Leakage Check Note (High Warning if > 99.5%)
            if m_meta.get("leakage_warning", False) or met.get("accuracy", 0.0) >= 0.995:
                st.warning(
                    "⚠️ **POTENTIAL DATA LEAKAGE DETECTED:** "
                    f"The trained model achieved an accuracy of **{met.get('accuracy', 0.0)*100:.2f}%**. "
                    "In the CIC-IDS 2018 dataset, this is highly indicative of destination port (`dst_port`) memorisation. "
                    "Tree models easily memorise fixed target ports (e.g. DoS targeting port 80). "
                    "Please verify feature relevance in production."
                )

            a1, a2, a3, a4, a5 = st.columns(5)
            a1.metric("Accuracy",  f"{met.get('accuracy',  0.0)*100:.2f}%", help="Correct predictions / total predictions")
            a2.metric("Precision", f"{met.get('precision', 0.0)*100:.2f}%", help="True positive attacks / total predicted attacks")
            a3.metric("Recall",    f"{met.get('recall',    0.0)*100:.2f}%", help="True positive attacks / total actual attacks")
            a4.metric("F1 Score",  f"{met.get('f1',        0.0)*100:.2f}%", help="Harmonic mean of precision and recall")
            a5.metric("ROC-AUC",   f"{met.get('auc',       0.0)*100:.2f}%", help="Area under the Receiver Operating Characteristic curve")

            st.caption(
                f"**Evaluation Context:** Stratified 80/20 train/test split. "
                f"Test set size: **{m_meta.get('n_test', 0):,} rows**."
            )

            # Model evaluation plot images from FastAPI
            st.markdown("#### Evaluation Plots")
            p_col1, p_col2, p_col3 = st.columns(3)
            p_col1.image(f"{API_URL}/model-plot/confusion_matrix",    caption="Confusion Matrix", use_column_width=True)
            p_col2.image(f"{API_URL}/model-plot/roc_curve",           caption="ROC Curve", use_column_width=True)
            p_col3.image(f"{API_URL}/model-plot/feature_importance",  caption="Feature Importance Rankings", use_column_width=True)
        else:
            st.info("Evaluation metrics and plots will load once the model is trained.")

        # ───────────────────────────────────────────────────────────────────
        # 4. Dataset Status Panel (Ingestion & Live Class Balance)
        # ───────────────────────────────────────────────────────────────────
        st.divider()
        st.markdown("### 📊 Live Dataset Ingestion & Class Balance")

        pg_stats = stats_data.get("postgres", {})
        total_ingested = pg_stats.get("total_flows", 0)

        d_col1, d_col2 = st.columns([1, 2])

        with d_col1:
            st.subheader("Postgres Live Database")
            st.markdown(
                f"""
                <div style="background-color: #1e1e2e; padding: 25px; border-radius: 8px; text-align: center; border: 1px solid #44475a;">
                    <span style="color: #a6adc8; font-size: 14px; font-weight: bold;">TOTAL FLOWS INGESTED</span>
                    <h1 style="color: #8be9fd; margin: 10px 0; font-size: 40px; font-weight: 800;">{total_ingested:,}</h1>
                    <span style="color: #a6adc8; font-size: 12px;">Active database records in postgresql</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Rolling counter last hour
            benign_hour = pg_stats.get("benign_last_hour", 0)
            attack_hour = pg_stats.get("attack_last_hour", 0)
            st.markdown(
                f"""
                <div style="background-color: #1e1e2e; padding: 15px; border-radius: 8px; margin-top: 15px; border: 1px solid #44475a;">
                    <span style="color: #a6adc8; font-size: 12px; font-weight: bold; display: block; margin-bottom: 8px;">ROLLING LAST HOUR DETECTION</span>
                    <div style="display: flex; justify-content: space-between;">
                        <span style="color: #2ecc71; font-weight: bold;">✅ Benign: {benign_hour:,}</span>
                        <span style="color: #e74c3c; font-weight: bold;">⚠️ Attack: {attack_hour:,}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with d_col2:
            st.subheader("Database Class Distribution")
            b_cnt = pg_stats.get("benign_count", 0)
            a_cnt = pg_stats.get("attack_count", 0)

            if b_cnt == 0 and a_cnt == 0:
                st.info("No ingested prediction records found in the database yet.")
            else:
                pie_df = pd.DataFrame({
                    "Traffic Class": ["Benign", "Attack"],
                    "Flow Count":    [b_cnt, a_cnt],
                })
                fig = px.pie(
                    pie_df, names="Traffic Class", values="Flow Count",
                    color="Traffic Class",
                    color_discrete_map={"Benign": "#2ecc71", "Attack": "#e74c3c"},
                    hole=0.45,
                )
                fig.update_layout(
                    margin=dict(t=10, b=10, l=10, r=10),
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    legend=dict(font=dict(color=_TEXT)),
                )
                st.plotly_chart(fig, use_container_width=True)

        # ───────────────────────────────────────────────────────────────────
        # 5. Live Activity Feed (Highlighting Attacks in Red)
        # ───────────────────────────────────────────────────────────────────
        st.divider()
        st.markdown("### 📡 Live Network Flow Activity Feed")

        flows_data = api_get("/flows", params={"limit": 50})

        if flows_data:
            df_live = pd.DataFrame(flows_data)

            # Styling function to highlight attacks in soft red
            def highlight_attack(row):
                is_att = row["is_attack"]
                if is_att == 1 or is_att is True or str(is_att).lower() == "true":
                    return ["background-color: rgba(231, 76, 60, 0.25); color: #ff5555; font-weight: bold;"] * len(row)
                return [""] * len(row)

            # Standardise verdict display
            if "is_attack" in df_live.columns:
                df_live["verdict"] = df_live["is_attack"].map(
                    {True: "⚠️ ATTACK", False: "Benign", 1: "⚠️ ATTACK", 0: "Benign"}
                )

            cols_order = [
                "flow_id", "created_at", "dst_port", "protocol", "flow_duration",
                "tot_fwd_pkts", "tot_bwd_pkts", "flow_byts_per_s", "flow_pkts_per_s",
                "attack_confidence", "verdict",
            ]
            available = [c for c in cols_order if c in df_live.columns]

            # Style and display DataFrame
            styled_df = df_live[available].style.apply(highlight_attack, axis=1)
            st.dataframe(styled_df, use_container_width=True, height=400)
        else:
            st.info("Waiting for live network flows to be ingested...")
