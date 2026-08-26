"""Health check endpoint."""
from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/api/health")
def health_check():
    return {"status": "ok", "service": "sentientai"}
