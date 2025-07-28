from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="AI Worker", version="0.1.0")

class HealthResponse(BaseModel):
    status: str

@app.get("/health", response_model=HealthResponse, tags=["health"])
async def health() -> HealthResponse:
    """Liveness probe."""
    return HealthResponse(status="ok") 