from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="Adaptive AI Network Security Analyst",
    version="1.0.0"
)


class NetworkFlow(BaseModel):
    duration: float
    packets: int
    bytes: int
    protocol: str


@app.get("/")
def home():
    return {
        "message": "AI Network Security Backend is running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/predict")
def predict(flow: NetworkFlow):

    return {
        "message": "Flow received",
        "flow": flow.model_dump()
    }
