from pathlib import Path

import joblib
import pandas as pd


# Find the project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Model location
MODEL_PATH = PROJECT_ROOT / "ml" / "random_forest_nids.joblib"


# Load the trained Random Forest model
model = joblib.load(MODEL_PATH)


# These MUST match the features used by Member 1's model
FEATURE_COLUMNS = [
    "L4_SRC_PORT",
    "L4_DST_PORT",
    "PROTOCOL",
    "L7_PROTO",
    "IN_BYTES",
    "IN_PKTS",
    "OUT_BYTES",
    "OUT_PKTS",
    "TCP_FLAGS",
    "CLIENT_TCP_FLAGS",
    "SERVER_TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS",
    "DURATION_IN",
    "DURATION_OUT",
    "MIN_TTL",
    "MAX_TTL",
    "LONGEST_FLOW_PKT",
    "SHORTEST_FLOW_PKT",
    "MIN_IP_PKT_LEN",
    "MAX_IP_PKT_LEN",
    "SRC_TO_DST_SECOND_BYTES",
    "DST_TO_SRC_SECOND_BYTES",
    "RETRANSMITTED_IN_BYTES",
    "RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_BYTES",
    "RETRANSMITTED_OUT_PKTS",
    "SRC_TO_DST_AVG_THROUGHPUT",
    "DST_TO_SRC_AVG_THROUGHPUT",
    "NUM_PKTS_UP_TO_128_BYTES",
    "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES",
    "NUM_PKTS_512_TO_1024_BYTES",
    "NUM_PKTS_1024_TO_1514_BYTES",
    "TCP_WIN_MAX_IN",
    "TCP_WIN_MAX_OUT",
    "ICMP_TYPE",
    "ICMP_IPV4_TYPE",
    "DNS_QUERY_ID",
    "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER",
    "FTP_COMMAND_RET_CODE",
    "SRC_TO_DST_IAT_MIN",
    "SRC_TO_DST_IAT_MAX",
    "SRC_TO_DST_IAT_AVG",
    "SRC_TO_DST_IAT_STDDEV",
    "DST_TO_SRC_IAT_MIN",
    "DST_TO_SRC_IAT_MAX",
    "DST_TO_SRC_IAT_AVG",
    "DST_TO_SRC_IAT_STDDEV",
]


def predict(features: dict):
    """
    Run the Random Forest model on one network-flow record.
    """

    # Convert the dictionary into a one-row DataFrame
    data = pd.DataFrame([features])

    # Check whether any required features are missing
    missing_features = [
        column
        for column in FEATURE_COLUMNS
        if column not in data.columns
    ]

    if missing_features:
        raise ValueError(
            f"Missing features: {missing_features}"
        )

    # IMPORTANT:
    # Put columns in exactly the same order as during training
    data = data[FEATURE_COLUMNS]

    # Get prediction
    prediction = model.predict(data)[0]

    # Get probability for each class
    probabilities = model.predict_proba(data)[0]

    # Highest probability = model confidence
    confidence = float(probabilities.max())

    # Convert 0/1 into meaningful labels
    if int(prediction) == 0:
        label = "BENIGN"
    else:
        label = "ATTACK"

    return {
        "prediction": int(prediction),
        "label": label,
        "confidence": confidence
    }

def get_feature_importance():
    """
    Return the most important features used by the Random Forest model.
    """

    importances = model.feature_importances_

    feature_importance = []

    for feature, importance in zip(FEATURE_COLUMNS, importances):
        feature_importance.append({
            "feature": feature,
            "importance": float(importance)
        })

    feature_importance.sort(
        key=lambda item: item["importance"],
        reverse=True
    )

    return feature_importance