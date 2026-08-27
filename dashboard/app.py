"""
CareFlow IDS — Streamlit Dashboard v2
======================================
Tabs:
  1. 📊 Dataset Overview   — training data statistics & protocol breakdown
  2. 🤖 Model Performance  — accuracy, F1, AUC, feature importance
  3. 🔍 Predict Flow       — instant GBT verdict (POST /predict, no polling)
  4. 🛠️ Pipeline Health    — component status + storage stats
"""

import time

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh

API_URL = "http://api:8000"

# ─────────────────────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CareFlow IDS",
    page_icon="🛡️",
    layout="wide",
)

# Custom dark theme tweaks
st.markdown("""
<style>
    [data-testid="metric-container"] {
        background: #1e1e2e;
        border: 1px solid #313244;
        border-radius: 10px;
        padding: 12px 16px;
    }
    .verdict-attack {
        background: rgba(231,76,60,0.15);
        border: 2px solid #e74c3c;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    .verdict-benign {
        background: rgba(46,204,113,0.12);
        border: 2px solid #2ecc71;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ CareFlow — Network Intrusion Detection System")
st.caption("Apache Kafka · Apache Spark · GBTClassifier · CIC-IDS-2018 Dataset")

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def api_get(path: str, **kwargs):
    try:
        r = requests.get(f"{API_URL}{path}", timeout=8, **kwargs)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def api_post(path: str, payload: dict):
    try:
        r = requests.post(f"{API_URL}{path}", json=payload, timeout=8)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"API error: {e}")
        return None


PROTO_LABEL = {0: "ICMP (0)", 6: "TCP (6)", 17: "UDP (17)"}
PROTO_COLOR = {"ICMP (0)": "#8be9fd", "TCP (6)": "#e74c3c", "UDP (17)": "#50fa7b"}

# ─────────────────────────────────────────────────────────────────────────────
# Tabs
# ─────────────────────────────────────────────────────────────────────────────
tab1, tab2 = st.tabs([
    "📊 Dataset Overview",
    "🔍 Predict Flow",
])


# ═══════════════════════════════════════════════════════════════════════════
# TAB 1 — Dataset Overview
# ═══════════════════════════════════════════════════════════════════════════
with tab1:
    st_autorefresh(interval=30_000, key="overview_refresh")
    st.subheader("CIC-IDS-2018 — Processed Dataset Statistics")
    st.caption("Based on 16.2M raw flows → 5.66M clean unique flows after deduplication & cleaning")

    analytics = api_get("/analytics", params={"days": 365})
    stats     = api_get("/stats")

    if analytics:
        adf = pd.DataFrame(analytics)
        adf["protocol_label"] = adf["protocol"].map(PROTO_LABEL).fillna("Other")
        adf["attack_rate_pct"] = (adf["attack_rate"] * 100).round(2)

        total_flows  = int(adf["total_flows"].sum())
        total_attack = int(adf["attack_count"].sum())
        total_benign = int(adf["benign_count"].sum())
        attack_rate  = (total_attack / total_flows * 100) if total_flows > 0 else 0

        # ── KPI strip ──────────────────────────────────────────────────────
        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("📦 Raw Dataset Rows",      "16,232,943")
        k2.metric("✅ Clean Unique Flows",     f"{total_flows:,}")
        k3.metric("🟢 Benign Flows",           f"{total_benign:,}")
        k4.metric("🔴 Attack Flows",           f"{total_attack:,}")
        k5.metric("🔥 Overall Attack Rate",    f"{attack_rate:.2f}%")

        st.divider()

        # ── Row 1: Pie + Bar ────────────────────────────────────────────────
        col_pie, col_bar = st.columns(2)

        with col_pie:
            st.markdown("#### Traffic Classification")
            pie_df = pd.DataFrame({
                "Category": ["Benign", "Attack"],
                "Count":    [total_benign, total_attack],
            })
            fig_pie = px.pie(
                pie_df, names="Category", values="Count",
                color="Category",
                color_discrete_map={"Benign": "#2ecc71", "Attack": "#e74c3c"},
                hole=0.45,
            )
            fig_pie.update_traces(textinfo="percent+label", textfont_size=14)
            fig_pie.update_layout(
                margin=dict(t=10, b=10, l=10, r=10),
                paper_bgcolor="rgba(0,0,0,0)",
                showlegend=True,
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        with col_bar:
            st.markdown("#### Flows by Protocol")
            bar_df = adf[["protocol_label", "total_flows", "attack_count", "benign_count"]].copy()
            fig_bar = go.Figure()
            fig_bar.add_trace(go.Bar(
                name="Benign",
                x=bar_df["protocol_label"],
                y=bar_df["benign_count"],
                marker_color="#2ecc71",
            ))
            fig_bar.add_trace(go.Bar(
                name="Attack",
                x=bar_df["protocol_label"],
                y=bar_df["attack_count"],
                marker_color="#e74c3c",
            ))
            fig_bar.update_layout(
                barmode="stack",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(title="Protocol"),
                yaxis=dict(title="Number of Flows", gridcolor="#333"),
                legend=dict(orientation="h", yanchor="bottom", y=1.02),
                margin=dict(t=30, b=10),
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        st.divider()

        # ── Row 2: Attack rate bar + protocol detail table ──────────────────
        col_gauge, col_table = st.columns([1, 1])

        with col_gauge:
            st.markdown("#### Attack Rate by Protocol")
            fig_rate = px.bar(
                adf, x="protocol_label", y="attack_rate_pct",
                color="protocol_label",
                color_discrete_map=PROTO_COLOR,
                text="attack_rate_pct",
                labels={"attack_rate_pct": "Attack Rate (%)", "protocol_label": "Protocol"},
            )
            fig_rate.update_traces(texttemplate="%{text:.2f}%", textposition="outside")
            fig_rate.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=False,
                yaxis=dict(range=[0, 100], gridcolor="#333"),
                margin=dict(t=20, b=10),
            )
            st.plotly_chart(fig_rate, use_container_width=True)

        with col_table:
            st.markdown("#### Protocol Summary Table")
            tbl = adf[["protocol_label", "total_flows", "attack_count",
                        "benign_count", "attack_rate_pct"]].rename(columns={
                "protocol_label":  "Protocol",
                "total_flows":     "Total Flows",
                "attack_count":    "Attacks",
                "benign_count":    "Benign",
                "attack_rate_pct": "Attack Rate (%)",
            })
            st.dataframe(
                tbl.style.format({
                    "Total Flows": "{:,}",
                    "Attacks":     "{:,}",
                    "Benign":      "{:,}",
                    "Attack Rate (%)": "{:.2f}",
                }),
                use_container_width=True,
                hide_index=True,
            )

            st.divider()
            st.markdown("#### Dataset Processing Pipeline")
            st.markdown("""
| Stage | Count |
|---|---|
| Raw rows ingested (11 CSV files) | **16,232,943** |
| After deduplication (flow_id) | ~9.5M |
| After Null / Infinity cleanup | **5,660,346** |
| Training set (80%) | 4,525,238 |
| Test set (20%) | 1,135,108 |
""")

    else:
        st.warning("⚠️ Analytics data not available. Run `analysis_queries.py` via Airflow DAG.")
# ═══════════════════════════════════════════════════════════════════════════
# TAB 2 — Predict Flow (instant, no polling)
# ═══════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("🔍 Instant Network Flow Prediction")
    st.caption(
        "Enter the flow features below and get an **immediate** verdict from the GBT model. "
        "No waiting — results appear in under 1 second."
    )

    # ── Preset examples ──────────────────────────────────────────────────
    preset_col, _ = st.columns([1, 3])
    preset = preset_col.selectbox(
        "Quick-load example",
        options=["Custom", "Normal Web Browse (Benign)", "SYN Flood (Attack)", "Port Scan (Attack)", "FTP Transfer (Benign)"],
    )

    PRESETS = {
        "Normal Web Browse (Benign)": {
            "dst_port": 443, "protocol": 6, "flow_duration": 500000,
            "tot_fwd_pkts": 12, "tot_bwd_pkts": 10,
            "totlen_fwd_pkts": 3500, "totlen_bwd_pkts": 8000,
            "flow_byts_per_s": 23000, "flow_pkts_per_s": 44,
            "flow_iat_mean": 22000, "flow_iat_std": 5000,
            "fwd_psh_flags": 2, "fin_flag_cnt": 1, "syn_flag_cnt": 1,
            "rst_flag_cnt": 0, "psh_flag_cnt": 3, "ack_flag_cnt": 10,
            "init_fwd_win_byts": 65535, "init_bwd_win_byts": 65535,
            "active_mean": 0, "idle_mean": 0,
        },
        "SYN Flood (Attack)": {
            "dst_port": 80, "protocol": 6, "flow_duration": 200,
            "tot_fwd_pkts": 500, "tot_bwd_pkts": 0,
            "totlen_fwd_pkts": 30000, "totlen_bwd_pkts": 0,
            "flow_byts_per_s": 2000000, "flow_pkts_per_s": 100000,
            "flow_iat_mean": 100, "flow_iat_std": 10,
            "fwd_psh_flags": 0, "fin_flag_cnt": 0, "syn_flag_cnt": 500,
            "rst_flag_cnt": 0, "psh_flag_cnt": 0, "ack_flag_cnt": 0,
            "init_fwd_win_byts": 1024, "init_bwd_win_byts": -1,
            "active_mean": 0, "idle_mean": 0,
        },
        "Port Scan (Attack)": {
            "dst_port": 22, "protocol": 6, "flow_duration": 50,
            "tot_fwd_pkts": 30, "tot_bwd_pkts": 0,
            "totlen_fwd_pkts": 1500, "totlen_bwd_pkts": 0,
            "flow_byts_per_s": 50000, "flow_pkts_per_s": 80000,
            "flow_iat_mean": 50, "flow_iat_std": 5,
            "fwd_psh_flags": 0, "fin_flag_cnt": 0, "syn_flag_cnt": 30,
            "rst_flag_cnt": 28, "psh_flag_cnt": 0, "ack_flag_cnt": 0,
            "init_fwd_win_byts": 512, "init_bwd_win_byts": -1,
            "active_mean": 0, "idle_mean": 0,
        },
        "FTP Transfer (Benign)": {
            "dst_port": 21, "protocol": 6, "flow_duration": 2000000,
            "tot_fwd_pkts": 45, "tot_bwd_pkts": 40,
            "totlen_fwd_pkts": 90000, "totlen_bwd_pkts": 120000,
            "flow_byts_per_s": 105000, "flow_pkts_per_s": 42,
            "flow_iat_mean": 45000, "flow_iat_std": 9000,
            "fwd_psh_flags": 5, "fin_flag_cnt": 1, "syn_flag_cnt": 1,
            "rst_flag_cnt": 0, "psh_flag_cnt": 8, "ack_flag_cnt": 40,
            "init_fwd_win_byts": 65535, "init_bwd_win_byts": 65535,
            "active_mean": 100000, "idle_mean": 500000,
        },
    }

    defaults = PRESETS.get(preset, {}) if preset != "Custom" else {}

    def dv(key, fallback):
        return float(defaults[key]) if key in defaults else fallback

    # ── Form ──────────────────────────────────────────────────────────────
    with st.form("predict_form"):
        st.markdown("##### Connection")
        fc1, fc2 = st.columns(2)
        dst_port = fc1.number_input("Destination Port", 0, 65535, int(dv("dst_port", 80)))
        protocol = fc2.selectbox(
            "Protocol", [0, 6, 17],
            index=[0, 6, 17].index(int(dv("protocol", 6))),
            format_func=lambda x: {0: "0 — ICMP", 6: "6 — TCP", 17: "17 — UDP"}[x],
        )

        st.markdown("##### Flow Volume")
        fv1, fv2, fv3 = st.columns(3)
        flow_duration   = fv1.number_input("Duration (μs)",   0.0, value=dv("flow_duration",   100000.0))
        tot_fwd_pkts    = fv2.number_input("Fwd Packets",     0.0, value=dv("tot_fwd_pkts",         10.0))
        tot_bwd_pkts    = fv3.number_input("Bwd Packets",     0.0, value=dv("tot_bwd_pkts",          8.0))
        fv4, fv5 = st.columns(2)
        totlen_fwd_pkts = fv4.number_input("Fwd Bytes Total", 0.0, value=dv("totlen_fwd_pkts",    1500.0))
        totlen_bwd_pkts = fv5.number_input("Bwd Bytes Total", 0.0, value=dv("totlen_bwd_pkts",    1200.0))

        st.markdown("##### Flow Rates")
        fr1, fr2 = st.columns(2)
        flow_byts_per_s = fr1.number_input("Flow Bytes/s",    0.0, value=dv("flow_byts_per_s",  15000.0))
        flow_pkts_per_s = fr2.number_input("Flow Packets/s",  0.0, value=dv("flow_pkts_per_s",    100.0))

        st.markdown("##### Inter-Arrival Time")
        fi1, fi2 = st.columns(2)
        flow_iat_mean = fi1.number_input("IAT Mean (μs)",     0.0, value=dv("flow_iat_mean",     5000.0))
        flow_iat_std  = fi2.number_input("IAT Std (μs)",      0.0, value=dv("flow_iat_std",      2000.0))

        st.markdown("##### TCP Flags")
        tf1, tf2, tf3, tf4, tf5, tf6 = st.columns(6)
        syn_flag_cnt  = tf1.number_input("SYN",    0.0, value=dv("syn_flag_cnt",   1.0))
        fin_flag_cnt  = tf2.number_input("FIN",    0.0, value=dv("fin_flag_cnt",   1.0))
        rst_flag_cnt  = tf3.number_input("RST",    0.0, value=dv("rst_flag_cnt",   0.0))
        psh_flag_cnt  = tf4.number_input("PSH",    0.0, value=dv("psh_flag_cnt",   2.0))
        ack_flag_cnt  = tf5.number_input("ACK",    0.0, value=dv("ack_flag_cnt",   8.0))
        fwd_psh_flags = tf6.number_input("FwdPSH", 0.0, value=dv("fwd_psh_flags", 0.0))

        st.markdown("##### Window & Timing")
        tw1, tw2, tw3, tw4 = st.columns(4)
        init_fwd_win_byts = tw1.number_input("Init Fwd Win", value=dv("init_fwd_win_byts", 65535.0))
        init_bwd_win_byts = tw2.number_input("Init Bwd Win", value=dv("init_bwd_win_byts", 65535.0))
        active_mean       = tw3.number_input("Active Mean",  0.0, value=dv("active_mean",    0.0))
        idle_mean         = tw4.number_input("Idle Mean",    0.0, value=dv("idle_mean",      0.0))

        submitted = st.form_submit_button("🔎 Analyse This Flow", type="primary", use_container_width=True)

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

        with st.spinner("Analysing flow…"):
            result = api_post("/predict", payload)

        if result:
            is_attack = result.get("is_attack", False)
            prob      = result.get("attack_probability", 0.0)
            verdict   = result.get("verdict", "")

            st.divider()

            if is_attack:
                st.markdown(
                    '<div class="verdict-attack">'
                    '<h2 style="color:#e74c3c;margin:0">⚠️ ATTACK DETECTED</h2>'
                    '<p style="color:#ff8888;font-size:16px;margin:6px 0 0 0">'
                    'This flow matches a known attack pattern</p></div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    '<div class="verdict-benign">'
                    '<h2 style="color:#2ecc71;margin:0">✅ Benign Traffic</h2>'
                    '<p style="color:#88ff88;font-size:16px;margin:6px 0 0 0">'
                    'No attack signatures detected in this flow</p></div>',
                    unsafe_allow_html=True,
                )

            st.divider()
            r1, r2, r3 = st.columns(3)
            r1.metric("Attack Probability", f"{prob*100:.1f}%")
            r2.metric("Verdict",            "🔴 Attack" if is_attack else "🟢 Benign")
            r3.metric("Model", result.get("model_version", "gbt_v1"))

            # Probability gauge
            fig_prob = go.Figure(go.Indicator(
                mode="gauge+number",
                value=prob * 100,
                number={"suffix": "%", "font": {"size": 32}},
                gauge={
                    "axis":  {"range": [0, 100]},
                    "bar":   {"color": "#e74c3c" if is_attack else "#2ecc71"},
                    "steps": [
                        {"range": [0,  40], "color": "rgba(46,204,113,0.2)"},
                        {"range": [40, 70], "color": "rgba(241,196,15,0.2)"},
                        {"range": [70, 100],"color": "rgba(231,76,60,0.2)"},
                    ],
                    "threshold": {"line": {"color": "#ff79c6", "width": 3},
                                  "thickness": 0.75, "value": 40},
                },
                title={"text": "Attack Probability Score"},
            ))
            fig_prob.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#f8f8f2"),
                height=260,
                margin=dict(t=30, b=0),
            )
            st.plotly_chart(fig_prob, use_container_width=True)



