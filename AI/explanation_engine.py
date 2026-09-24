"""
Simple AI investigation and explanation engine.

This module provides human-readable explanations for IDS predictions.
The Random Forest model remains responsible for the actual classification.
"""


def generate_explanation(
    prediction: str,
    confidence: float,
    top_features: list
) -> str:

    if prediction.upper() == "ATTACK":
        result = "The network flow was classified as suspicious."
    else:
        result = "The network flow was classified as benign."

    feature_names = [
        item["feature"]
        for item in top_features[:3]
    ]

    features = ", ".join(feature_names)

    return (
        f"{result} "
        f"The model confidence is {confidence * 100:.2f}%. "
        f"The most important model features for this flow include: "
        f"{features}."
    )