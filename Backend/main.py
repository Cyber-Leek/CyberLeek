from fastapi import FastAPI

from backend.Schemas import NetworkFlow
from backend.Services.ml_service import predict


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

    return result