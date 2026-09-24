import streamlit as st
import pandas as pd
import requests
from streamlit_autorefresh import st_autorefresh

API_URL = "http://127.0.0.1:8000"


def get_backend_data(endpoint):
    try:
        response = requests.get(
            f"{API_URL}{endpoint}",
            timeout=5
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        st.error(f"Backend connection failed: {e}")
        return None


st.set_page_config(
    page_title="Adaptive AI Network Security Analyst",
    page_icon="🛡️",
    layout="wide"
)


st_autorefresh(
    interval=10000,
    key="dashboard_refresh"
)


# ============================================================
# TITLE
# ============================================================

st.title("🛡️ Adaptive AI Network Security Analyst")

st.write(
    "AI-powered Network Intrusion Detection Dashboard"
)

st.divider()


# ============================================================
# DATASET UPLOAD
# ============================================================

st.subheader("📂 Upload Network Flow Dataset")

uploaded_file = st.file_uploader(
    "Choose a CSV file",
    type=["csv"]
)


if uploaded_file is not None:

    df = pd.read_csv(uploaded_file)

    total_flows = len(df)

    # --------------------------------------------------------
    # Detect suspicious flows
    # --------------------------------------------------------

    if "Prediction" in df.columns:

        threats_df = df[
            df["Prediction"]
            .astype(str)
            .str.upper()
            .str.strip()
            .isin([
                "MALICIOUS",
                "ATTACK",
                "1"
            ])
        ]

    elif "Label" in df.columns:

        # ML dataset format:
        # 0 = BENIGN
        # 1 = ATTACK

        label_values = pd.to_numeric(
            df["Label"],
            errors="coerce"
        )

        threats_df = df[
            label_values == 1
        ]

    else:

        # No prediction information in this CSV
        threats_df = pd.DataFrame()


    threats_count = len(threats_df)


    # --------------------------------------------------------
    # Detect high-risk flows
    # --------------------------------------------------------

    if "Risk" in df.columns:

        high_risk_count = len(
            df[
                df["Risk"]
                .astype(str)
                .str.upper()
                .str.strip()
                == "HIGH"
            ]
        )

    else:

        high_risk_count = 0
        
else:

    df = None

    total_flows = 0
    threats_count = 0
    high_risk_count = 0

    threats_df = pd.DataFrame()


# ============================================================
# DASHBOARD METRICS
# ============================================================

stats = get_backend_data(
    "/dashboard/stats"
)

feedback_summary = get_backend_data(
    "/dashboard/feedback-summary"
)


if stats is not None:

    total_incidents = stats[
        "total_incidents"
    ]

    total_attacks = stats[
        "total_attacks"
    ]

    high_risk = stats[
        "high_risk"
    ]

    average_confidence = stats[
        "average_confidence"
    ]


    if feedback_summary is not None:

        false_positives = feedback_summary[
            "false_positive"
        ]

    else:

        false_positives = 0


    col1, col2, col3, col4 = st.columns(4)


    col1.metric(
        "Total Incidents",
        total_incidents
    )

    col2.metric(
        "Threats",
        total_attacks
    )

    col3.metric(
        "High-Risk Incidents",
        high_risk
    )

    col4.metric(
        "False Positives",
        false_positives
    )


    st.caption(
        f"Average ML Confidence: "
        f"{average_confidence * 100:.2f}%"
    )


st.divider()


# ============================================================
# DATASET PREVIEW
# ============================================================

if df is not None:

    st.success(
        "Dataset uploaded successfully!"
    )

    st.subheader(
        "📊 Dataset Preview"
    )

    st.dataframe(
        df.head(10),
        use_container_width=True
    )

    st.write(
        "Number of rows:",
        df.shape[0]
    )

    st.write(
        "Number of columns:",
        df.shape[1]
    )

else:

    st.info(
        "Upload a network-flow CSV dataset to begin."
    )


st.divider()


# ============================================================
# SUSPICIOUS NETWORK FLOWS
# ============================================================

st.subheader(
    "🚨 Suspicious Network Flows"
)


if df is not None and not threats_df.empty:

    st.dataframe(
        threats_df,
        use_container_width=True
    )


elif df is not None and threats_df.empty:

    st.info(
        "No suspicious network flows detected "
        "in the uploaded dataset."
    )


else:

    sample_data = pd.DataFrame(
        {
            "Time": [
                "10:31",
                "10:32",
                "10:35"
            ],

            "Source": [
                "192.168.1.10",
                "192.168.1.20",
                "192.168.1.15"
            ],

            "Destination": [
                "10.0.0.5",
                "10.0.0.8",
                "10.0.0.10"
            ],

            "Prediction": [
                "ATTACK",
                "BENIGN",
                "ATTACK"
            ],

            "Risk": [
                "HIGH",
                "LOW",
                "HIGH"
            ]
        }
    )


    st.dataframe(
        sample_data,
        use_container_width=True
    )


st.divider()


# ============================================================
# AI INVESTIGATION
# ============================================================

st.subheader(
    "🔍 AI Investigation"
)


incidents = get_backend_data(
    "/dashboard/recent-incidents"
)


if incidents is not None and len(incidents) > 0:

    incident_options = {

        f"Incident #{incident['id']} - "
        f"{incident['attack_type']} - "
        f"{incident['risk']}":

        incident["id"]

        for incident in incidents
    }


    selected_incident = st.selectbox(
        "Select an incident to investigate",
        list(incident_options.keys())
    )


    selected_id = incident_options[
        selected_incident
    ]


    if st.button(
        "🔍 Investigate Selected Alert"
    ):

        incident = get_backend_data(
            f"/incidents/{selected_id}"
        )


        if incident is not None:

            if incident["prediction"] == "1":

                st.warning(
                    "⚠️ ATTACK DETECTED"
                )

            else:

                st.success(
                    "✅ BENIGN FLOW"
                )


            st.write(
                "### ML Confidence"
            )

            st.write(
                f"{incident['confidence'] * 100:.2f}%"
            )


            st.write(
                "### Observed Evidence"
            )

            st.write(
                incident["evidence"]
            )


            st.write(
                "### AI Interpretation"
            )

            st.write(
                incident["explanation"]
            )


            st.write(
                "### Risk"
            )


            if incident["risk"] == "HIGH":

                st.error(
                    "HIGH"
                )

            else:

                st.success(
                    incident["risk"]
                )


            st.write(
                "### Incident ID"
            )

            st.write(
                f"#{incident['id']}"
            )


        else:

            st.error(
                "Unable to retrieve incident details."
            )


else:

    st.info(
        "No incidents available for investigation."
    )


# ============================================================
# ANALYST FEEDBACK SUMMARY
# ============================================================

st.divider()

st.subheader(
    "📊 Analyst Feedback Summary"
)


feedback_summary = get_backend_data(
    "/dashboard/feedback-summary"
)


if feedback_summary is not None:

    col1, col2, col3, col4 = st.columns(4)


    col1.metric(
        "✅ True Positives",
        feedback_summary["true_positive"]
    )


    col2.metric(
        "❌ False Positives",
        feedback_summary["false_positive"]
    )


    col3.metric(
        "❓ Uncertain",
        feedback_summary["uncertain"]
    )


    col4.metric(
        "⏳ No Feedback",
        feedback_summary["no_feedback"]
    )


else:

    st.warning(
        "Unable to load feedback summary."
    )


st.divider()


# ============================================================
# THREAT DISTRIBUTION
# ============================================================

st.subheader(
    "📈 Threat Distribution"
)


distribution = get_backend_data(
    "/dashboard/distribution"
)


if distribution is not None:

    col1, col2 = st.columns(2)


    with col1:

        st.metric(
            "🚨 Attacks",
            distribution["attacks"]
        )


    with col2:

        st.metric(
            "✅ Benign Flows",
            distribution["benign"]
        )


    chart_data = pd.DataFrame(
        {
            "Category": [
                "Attacks",
                "Benign"
            ],

            "Count": [
                distribution["attacks"],
                distribution["benign"]
            ]
        }
    )


    st.bar_chart(
        chart_data.set_index(
            "Category"
        )
    )


else:

    st.warning(
        "Unable to load threat distribution."
    )


# ============================================================
# INCIDENT HISTORY
# ============================================================

st.subheader(
    "📋 Incident History"
)


incidents = get_backend_data(
    "/dashboard/recent-incidents"
)


if incidents is not None and len(incidents) > 0:

    history = pd.DataFrame(
        incidents
    )


    history = history.rename(
        columns={
            "id": "Incident",
            "prediction": "Prediction",
            "confidence": "Confidence",
            "attack_type": "Attack Type",
            "risk": "Risk",
            "explanation": "Explanation"
        }
    )


    history["Confidence"] = (
        history["Confidence"] * 100
    ).round(2).astype(str) + "%"


    st.dataframe(
        history,
        use_container_width=True
    )


else:

    st.info(
        "No incidents found in the backend database."
    )