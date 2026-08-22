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
tab1, tab2, tab3 = st.tabs(["📊 Overview", "🔍 Analyse Flow", "✏️ Edit Flow"])


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
