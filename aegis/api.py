"""FastAPI service for the AEGIS console.

Run with:  uvicorn aegis.api:app --port 8000
"""

from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import PROJECT_SUBTITLE, PROJECT_TITLE, config, data
from .llm import GeminiLLM
from .runs import ReviewNotAllowed, RunBusy, RunNotFound, RunService


class RunRequest(BaseModel):
    dataset_id: str
    windows: int = Field(10, ge=1, le=200)
    window_size: int = Field(100, ge=10, le=5000)
    sampling: Literal["spread", "sequential"] = "spread"
    start_row: int = Field(0, ge=0)
    mode: Literal["auto", "gemini", "rules"] = "auto"
    operator: str = Field("Operator", max_length=80)


class ReviewRequest(BaseModel):
    decision: Literal["APPROVED", "REJECTED"]
    operator: str = Field("Operator", max_length=80)
    note: str = Field("", max_length=500)


def create_app(service: RunService | None = None) -> FastAPI:
    app = FastAPI(title=f"AEGIS — {PROJECT_TITLE}", description=PROJECT_SUBTITLE, version="2.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.CORS_ORIGINS,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )
    runs = service or RunService()

    @app.get("/api/health")
    def health():
        llm = GeminiLLM()
        return {
            "status": "ok",
            "project": PROJECT_TITLE,
            "gemini": {"configured": llm.configured, "model": llm.model},
            "datasets": len(data.list_datasets()),
        }

    @app.get("/api/datasets")
    def datasets():
        return data.list_datasets()

    @app.get("/api/runs")
    def list_runs():
        return runs.list_runs()

    @app.post("/api/runs", status_code=202)
    def start_run(body: RunRequest):
        try:
            run = runs.start(**body.model_dump())
        except RunBusy as error:
            raise HTTPException(409, str(error)) from error
        except FileNotFoundError as error:
            raise HTTPException(404, str(error)) from error
        except ValueError as error:
            raise HTTPException(422, str(error)) from error
        return {"id": run["id"], "status": run["status"]}

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str):
        try:
            return runs.get(run_id)
        except RunNotFound as error:
            raise HTTPException(404, "Run not found.") from error

    @app.post("/api/runs/{run_id}/windows/{index}/review")
    def review(run_id: str, index: int, body: ReviewRequest):
        try:
            return runs.review(run_id, index, body.decision, body.operator, body.note)
        except RunNotFound as error:
            raise HTTPException(404, "Run or window not found.") from error
        except ReviewNotAllowed as error:
            raise HTTPException(409, str(error)) from error

    @app.get("/api/runs/{run_id}/audit/verify")
    def verify(run_id: str):
        try:
            return runs.verify_audit(run_id)
        except RunNotFound as error:
            raise HTTPException(404, "Run not found.") from error

    return app


app = create_app()
