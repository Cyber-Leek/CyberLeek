from fastapi import FastAPI
from sqlalchemy import func

from Backend.Schemas import NetworkFlow, FeedbackRequest
from Backend.Services.ml_service import (
    predict,
    get_feature_importance,
    get_top_features
)
from Backend.Database import SessionLocal, Incident


app = FastAPI(
    title="Explainable Network IDS",
    description="Backend API for the AI-powered Network Intrusion Detection System",
    version="1.0.0"
)


@app.get("/")
def root():
    return {
        "message": "Explainable Network IDS API is running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }

@app.get("/feature-importance")
def feature_importance():
    return get_feature_importance()


@app.post("/predict")
def predict_network_flow(flow: NetworkFlow):
    flow_data = flow.model_dump()

    result = predict(flow_data)

    top_features = get_top_features(flow_data)
    result["top_features"] = top_features

    db = SessionLocal()

    if result["prediction"] == 0:
        attack_type = "BENIGN"
        risk = "LOW"
    else:
        attack_type = "ATTACK"
        risk = "HIGH"

        top_feature_names = [
             item["feature"]
            for item in result["top_features"][:3]
            ]
        explanation = (
            f"The Random Forest model classified this network flow as "
            f"{attack_type} with {result['confidence'] * 100:.2f}% confidence. "
            f"Risk level: {risk}. "
            f"Key model features: {', '.join(top_feature_names)}."
            )

    incident = Incident(
        prediction=result["prediction"],
        confidence=result["confidence"],
        attack_type=attack_type,
        risk=risk,
        evidence="Random Forest model prediction",
        explanation=explanation
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)
    db.close()

    result["incident_id"] = incident.id

    return result

@app.get("/db-test")
def database_test():
    db = SessionLocal()
    db.close()

    return {
        "message": "Database connection successful"
    }

@app.post("/incidents")
def create_incident(
    prediction: int,
    confidence: float,
    attack_type: str,
    risk: str,
    evidence: str,
    explanation: str
):
    db = SessionLocal()

    incident = Incident(
        prediction=prediction,
        confidence=confidence,
        attack_type=attack_type,
        risk=risk,
        evidence=evidence,
        explanation=explanation
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)
    db.close()

    return {
        "message": "Incident saved successfully",
        "incident_id": incident.id
    }

@app.get("/incidents")
def get_incidents():
    db = SessionLocal()

    incidents = db.query(Incident).all()

    result = []

    for incident in incidents:
        result.append({
            "id": incident.id,
            "prediction": incident.prediction,
            "confidence": incident.confidence,
            "attack_type": incident.attack_type,
            "risk": incident.risk,
            "evidence": incident.evidence,
            "explanation": incident.explanation,
            "feedback": incident.feedback
        })

    db.close()

    return result

@app.post("/feedback")
def add_feedback(request: FeedbackRequest):
    db = SessionLocal()

    incident = db.query(Incident).filter(
        Incident.id == request.incident_id
    ).first()

    if incident is None:
        db.close()

        return {
            "message": "Incident not found"
        }

    incident.feedback = request.feedback

    db.commit()
    db.refresh(incident)
    db.close()

    return {
        "message": "Feedback saved successfully",
        "incident_id": incident.id,
        "feedback": incident.feedback
    }

@app.get("/dashboard/stats")
def dashboard_stats():
    db = SessionLocal()

    total_incidents = db.query(Incident).count()

    total_attacks = db.query(Incident).filter(
        Incident.prediction == "1"
    ).count()

    total_benign = db.query(Incident).filter(
        Incident.prediction == "0"
    ).count()

    high_risk = db.query(Incident).filter(
        Incident.risk == "HIGH"
    ).count()

    average_confidence = db.query(
        func.avg(Incident.confidence)
    ).scalar()

    db.close()

    return {
        "total_incidents": total_incidents,
        "total_attacks": total_attacks,
        "total_benign": total_benign,
        "high_risk": high_risk,
        "average_confidence": round(
            float(average_confidence or 0), 4
        )
    }

@app.get("/dashboard/recent-incidents")
def dashboard_recent_incidents():
    db = SessionLocal()

    incidents = (
        db.query(Incident)
        .order_by(Incident.id.desc())
        .limit(20)
        .all()
    )

    db.close()

    return [
        {
            "id": incident.id,
            "prediction": incident.prediction,
            "confidence": incident.confidence,
            "attack_type": incident.attack_type,
            "risk": incident.risk,
            "explanation": incident.explanation
        }
        for incident in reversed(incidents)
    ]

@app.get("/dashboard/distribution")
def dashboard_distribution():
    db = SessionLocal()

    attack_count = db.query(Incident).filter(
        Incident.attack_type == "ATTACK"
    ).count()

    benign_count = db.query(Incident).filter(
        Incident.attack_type == "BENIGN"
    ).count()

    high_risk_count = db.query(Incident).filter(
        Incident.risk == "HIGH"
    ).count()

    low_risk_count = db.query(Incident).filter(
        Incident.risk == "LOW"
    ).count()

    db.close()

    return {
        "attacks": attack_count,
        "benign": benign_count,
        "high_risk": high_risk_count,
        "low_risk": low_risk_count
    }

@app.get("/dashboard/feedback-summary")
def dashboard_feedback_summary():
    db = SessionLocal()

    true_positive = db.query(Incident).filter(
        Incident.feedback == "TRUE_POSITIVE"
    ).count()

    false_positive = db.query(Incident).filter(
        Incident.feedback == "FALSE_POSITIVE"
    ).count()

    uncertain = db.query(Incident).filter(
        Incident.feedback == "UNCERTAIN"
    ).count()

    no_feedback = db.query(Incident).filter(
        Incident.feedback.is_(None)
    ).count()

    db.close()

    return {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "uncertain": uncertain,
        "no_feedback": no_feedback
    }

@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    db = SessionLocal()

    incident = db.query(Incident).filter(
        Incident.id == incident_id
    ).first()

    db.close()

    if incident is None:
        return {
            "message": "Incident not found"
        }

    return {
        "id": incident.id,
        "prediction": incident.prediction,
        "confidence": incident.confidence,
        "attack_type": incident.attack_type,
        "risk": incident.risk,
        "evidence": incident.evidence,
        "explanation": incident.explanation,
        "feedback": incident.feedback
    }
