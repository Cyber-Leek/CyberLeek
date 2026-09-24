from fastapi import FastAPI

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

    incident = Incident(
        prediction=result["prediction"],
        confidence=result["confidence"],
        attack_type=attack_type,
        risk=risk,
        evidence="Random Forest model prediction",
        explanation=(
    f"The Random Forest model classified this network flow as "
    f"{attack_type} with {result['confidence'] * 100:.2f}% confidence. "
    f"Risk level: {risk}."
)
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