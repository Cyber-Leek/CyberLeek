from fastapi import FastAPI

from Backend.Schemas import NetworkFlow
from Backend.Services.ml_service import predict
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


@app.post("/predict")
def predict_network_flow(flow: NetworkFlow):
    result = predict(flow.model_dump())

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
        explanation=f"Model confidence is {result['confidence'] * 100:.2f} percent"
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