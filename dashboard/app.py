"""
Streamlit dashboard
- Tab 1 | Overview          : summary metrics + table of all saved patients & predictions
- Tab 2 | Add New Patient   : form to enter patient name, medical ID, clinical data,
                              get a prediction, and save it to Postgres
- Tab 3 | Edit Patient      : select an existing patient, edit their data,
                              recalculate prediction, and save the new result
"""

import os

import pandas as pd
import requests
import streamlit as st

API_URL = os.getenv("API_URL", "http://api:8000")

st.set_page_config(page_title="Hospital Patient Flow", page_icon="🏥", layout="wide")
st.title("🏥 Hospital Patient Flow — Length-of-Stay Dashboard")

tab_overview, tab_add, tab_edit = st.tabs(
    ["📊 Overview", "➕ Add New Patient", "✏️ Edit Patient"]
)

# ── Shared dropdown options ────────────────────────────────────────────────────
AGE_GROUPS        = ["0 to 17", "18 to 29", "30 to 49", "50 to 69", "70 or Older"]
GENDERS           = ["M", "F"]
ADMISSION_TYPES   = ["Emergency", "Elective", "Urgent", "Trauma", "Newborn"]
DIAGNOSES         = [
    "Cardiovascular", "Respiratory", "Musculoskeletal", "Oncology",
    "Neurology", "Renal & Urinary", "Gastroenterology",
    "Endocrine & Metabolic", "Infectious Disease",
    "Mental Health", "Obstetrics", "Neonatal", "Other",
]
SEVERITIES        = ["Minor", "Moderate", "Major", "Extreme"]
MORTALITY_RISKS   = ["Minor", "Moderate", "Major", "Extreme"]


def safe_index(options: list, value) -> int:
    """Return the index of value in options, or 0 if not found."""
    try:
        return options.index(str(value))
    except (ValueError, TypeError):
        return 0


# ── Tab 1: Overview ────────────────────────────────────────────────────────────
with tab_overview:
    st.subheader("Saved Patients & Predictions")

    try:
        resp = requests.get(f"{API_URL}/patients", timeout=5)
        resp.raise_for_status()
        patients = resp.json()

        if patients:
            df = pd.DataFrame(patients)

            # Summary KPIs
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Patients", len(df))
            col2.metric(
                "Avg Predicted LOS",
                f"{pd.to_numeric(df['predicted_los'], errors='coerce').mean():.1f} days",
            )
            col3.metric(
                "Long Stay Rate",
                f"{(df['stay_category'] == 'Long').mean():.1%}",
            )
            col4.metric(
                "Short Stay Rate",
                f"{(df['stay_category'] == 'Short').mean():.1%}",
            )

            st.divider()

            # Patient table
            display_cols = {
                "patient_name": "Patient Name",
                "medical_id": "Medical ID",
                "age_group": "Age Group",
                "gender": "Gender",
                "admission_type": "Admission",
                "diagnosis": "Diagnosis",
                "severity": "Severity",
                "predicted_los": "Predicted LOS (days)",
                "stay_category": "Stay Category",
                "predicted_at": "Last Predicted",
            }
            st.dataframe(
                df[[c for c in display_cols if c in df.columns]].rename(
                    columns=display_cols
                ),
                use_container_width=True,
            )

            # Stay-category distribution bar chart
            if "stay_category" in df.columns:
                st.subheader("Stay Category Distribution")
                st.bar_chart(df["stay_category"].value_counts())
        else:
            st.info(
                "No patients saved yet. "
                "Use the **'➕ Add New Patient'** tab to add your first patient."
            )

    except Exception as e:
        st.warning(f"Could not reach the API: {e}")


# ── Tab 2: Add New Patient ─────────────────────────────────────────────────────
with tab_add:
    st.subheader("Add a New Patient & Predict Length of Stay")

    with st.form("add_patient_form", clear_on_submit=True):
        col1, col2 = st.columns(2)

        with col1:
            patient_name     = st.text_input("Patient Full Name *")
            medical_id       = st.text_input("Medical ID Number *")
            age_group        = st.selectbox("Age Group", AGE_GROUPS)
            gender           = st.selectbox("Gender", GENDERS)
            admission_type   = st.selectbox("Admission Type", ADMISSION_TYPES)

        with col2:
            diagnosis        = st.selectbox("Diagnosis Category", DIAGNOSES)
            severity         = st.selectbox("Severity of Illness", SEVERITIES)
            risk_of_mortality = st.selectbox("Risk of Mortality", MORTALITY_RISKS)

        submitted = st.form_submit_button("🔍 Predict & Save Patient")

    if submitted:
        if not patient_name.strip() or not medical_id.strip():
            st.warning("⚠️ Please fill in both **Patient Name** and **Medical ID**.")
        else:
            payload = {
                "patient_name": patient_name.strip(),
                "medical_id": medical_id.strip(),
                "age_group": age_group,
                "gender": gender,
                "admission_type": admission_type,
                "diagnosis": diagnosis,
                "severity": severity,
                "risk_of_mortality": risk_of_mortality,
            }
            try:
                resp = requests.post(f"{API_URL}/patients", json=payload, timeout=10)
                if resp.status_code == 200:
                    result = resp.json()
                    st.success(
                        f"✅ Patient **{patient_name}** (ID: {medical_id}) saved successfully!"
                    )
                    c1, c2 = st.columns(2)
                    c1.metric(
                        "Predicted Length of Stay",
                        f"{result['predicted_length_of_stay_days']} days",
                    )
                    c2.metric("Stay Category", result["stay_category"])
                elif resp.status_code == 409:
                    st.error(
                        f"❌ Medical ID **'{medical_id}'** already exists. "
                        "Please use a unique ID or edit the existing patient."
                    )
                elif resp.status_code == 503:
                    st.error("❌ ML model is not trained yet. Please run the pipeline first.")
                else:
                    st.error(f"Unexpected error: {resp.text}")
            except Exception as e:
                st.error(f"API connection error: {e}")


# ── Tab 3: Edit Patient ────────────────────────────────────────────────────────
with tab_edit:
    st.subheader("Edit Patient Data & Recalculate Prediction")

    try:
        resp = requests.get(f"{API_URL}/patients", timeout=5)
        resp.raise_for_status()
        patients = resp.json()

        if not patients:
            st.info("No patients saved yet. Add patients using the '➕ Add New Patient' tab.")
        else:
            # Patient selector
            options = {
                f"{p['patient_name']}  |  Medical ID: {p['medical_id']}": p
                for p in patients
            }
            selected_label = st.selectbox("Select Patient to Edit", list(options.keys()))
            p = options[selected_label]

            st.info(
                f"**Current prediction:** {p.get('predicted_los', 'N/A')} days "
                f"({p.get('stay_category', 'N/A')} stay) — "
                f"last updated: {p.get('predicted_at', 'N/A')}"
            )

            with st.form("edit_patient_form"):
                col1, col2 = st.columns(2)

                with col1:
                    patient_name = st.text_input(
                        "Patient Full Name", value=p.get("patient_name", "")
                    )
                    medical_id = st.text_input(
                        "Medical ID", value=p.get("medical_id", "")
                    )
                    age_group = st.selectbox(
                        "Age Group", AGE_GROUPS,
                        index=safe_index(AGE_GROUPS, p.get("age_group")),
                    )
                    gender = st.selectbox(
                        "Gender", GENDERS,
                        index=safe_index(GENDERS, p.get("gender")),
                    )
                    admission_type = st.selectbox(
                        "Admission Type", ADMISSION_TYPES,
                        index=safe_index(ADMISSION_TYPES, p.get("admission_type")),
                    )

                with col2:
                    diagnosis = st.selectbox(
                        "Diagnosis Category", DIAGNOSES,
                        index=safe_index(DIAGNOSES, p.get("diagnosis")),
                    )
                    severity = st.selectbox(
                        "Severity of Illness", SEVERITIES,
                        index=safe_index(SEVERITIES, p.get("severity")),
                    )
                    risk_of_mortality = st.selectbox(
                        "Risk of Mortality", MORTALITY_RISKS,
                        index=safe_index(MORTALITY_RISKS, p.get("risk_of_mortality")),
                    )

                update_submitted = st.form_submit_button("🔄 Update & Recalculate Prediction")

            if update_submitted:
                payload = {
                    "patient_name": patient_name.strip(),
                    "medical_id": medical_id.strip(),
                    "age_group": age_group,
                    "gender": gender,
                    "admission_type": admission_type,
                    "diagnosis": diagnosis,
                    "severity": severity,
                    "risk_of_mortality": risk_of_mortality,
                }
                try:
                    resp = requests.put(
                        f"{API_URL}/patients/{p['patient_id']}",
                        json=payload,
                        timeout=10,
                    )
                    if resp.status_code == 200:
                        result = resp.json()
                        st.success(
                            f"✅ Patient **{patient_name}** updated successfully!"
                        )
                        c1, c2 = st.columns(2)
                        c1.metric(
                            "New Predicted LOS",
                            f"{result['predicted_length_of_stay_days']} days",
                        )
                        c2.metric("New Stay Category", result["stay_category"])
                    elif resp.status_code == 404:
                        st.error("❌ Patient not found in database.")
                    elif resp.status_code == 503:
                        st.error("❌ ML model is not trained yet.")
                    else:
                        st.error(f"Update failed: {resp.text}")
                except Exception as e:
                    st.error(f"API connection error: {e}")

    except Exception as e:
        st.warning(f"Could not load patients: {e}")
