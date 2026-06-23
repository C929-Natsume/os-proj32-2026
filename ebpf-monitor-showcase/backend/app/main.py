from __future__ import annotations

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from .service import (
    get_anomalies,
    get_audit_results,
    get_events,
    get_health,
    get_models,
    get_overview,
)

app = FastAPI(title="eBPF Monitor Showcase API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return get_health()


@app.get("/api/models")
def models():
    return {"items": get_models()}


@app.get("/api/overview")
def overview():
    return get_overview()


@app.get("/api/events")
def events(limit: int = Query(default=50, ge=1, le=500)):
    return {"items": get_events(limit)}


@app.get("/api/anomalies")
def anomalies(limit: int = Query(default=50, ge=1, le=500)):
    return {"items": get_anomalies(limit)}


@app.get("/api/audit-results")
def audit_results(limit: int = Query(default=50, ge=1, le=500)):
    return {"items": get_audit_results(limit)}
