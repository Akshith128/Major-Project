"""FastAPI service for the AEGIS console.

Run with:  uvicorn aegis.api:app --port 8000

Every endpoint except /api/health and /api/auth/login needs a session token
(`Authorization: Bearer <token>`). Roles are checked here, on the server.
"""

from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import PROJECT_SUBTITLE, PROJECT_TITLE, auth, config, control, data
from .llm import GeminiLLM
from .runs import ReviewNotAllowed, RunBusy, RunNotFound, RunPaused, RunService, actor


class LoginRequest(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class RunRequest(BaseModel):
    dataset_id: str
    windows: int = Field(10, ge=1, le=200)
    window_size: int = Field(100, ge=10, le=5000)
    sampling: Literal["spread", "sequential"] = "spread"
    start_row: int = Field(0, ge=0)
    mode: Literal["auto", "gemini", "rules", "hybrid"] = "auto"
    seed: int | None = Field(None, ge=0)
    detector_baseline: Literal["same-network", "cross-day"] = "same-network"


class ReviewRequest(BaseModel):
    decision: Literal["APPROVED", "REJECTED"]
    note: str = Field("", max_length=500)


class ControlRequest(BaseModel):
    paused: bool
    reason: str = Field("", max_length=300)


def current_user(authorization: str = Header(default="")) -> dict:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "Sign in to use AEGIS.")
    try:
        return auth.read_token(token)
    except auth.AuthError as error:
        raise HTTPException(401, str(error)) from error


def require(permission: str):
    def check(user: dict = Depends(current_user)) -> dict:
        if not auth.can(user["role"], permission):
            raise HTTPException(403, f"Your role ({user['role_label']}) cannot do this.")
        return user

    return check


def create_app(service: RunService | None = None) -> FastAPI:
    app = FastAPI(title=f"AEGIS — {PROJECT_TITLE}", description=PROJECT_SUBTITLE, version="2.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.CORS_ORIGINS,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization"],
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
            "accounts": bool(auth.load_users()),
            "paused": control.is_paused(),
        }

    @app.post("/api/auth/login")
    def login(body: LoginRequest):
        try:
            return auth.issue_token(auth.authenticate(body.username, body.password))
        except auth.AuthError as error:
            raise HTTPException(401, str(error)) from error

    @app.get("/api/auth/me")
    def me(user: dict = Depends(current_user)):
        return {**user, "permissions": sorted(p for p in auth.PERMISSIONS if auth.can(user["role"], p))}

    @app.get("/api/control")
    def get_control(user: dict = Depends(current_user)):
        return control.state()

    @app.post("/api/control")
    def set_control(body: ControlRequest, user: dict = Depends(require("control"))):
        return control.set_paused(body.paused, actor(user), body.reason)

    @app.get("/api/datasets")
    def datasets(user: dict = Depends(current_user)):
        return data.list_datasets()

    @app.get("/api/runs")
    def list_runs(user: dict = Depends(current_user)):
        return runs.list_runs()

    @app.post("/api/runs", status_code=202)
    def start_run(body: RunRequest, user: dict = Depends(require("run"))):
        try:
            run = runs.start(**body.model_dump(), user=user)
        except (RunBusy, RunPaused) as error:
            raise HTTPException(409, str(error)) from error
        except FileNotFoundError as error:
            raise HTTPException(404, str(error)) from error
        except ValueError as error:
            raise HTTPException(422, str(error)) from error
        return {"id": run["id"], "status": run["status"]}

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str, user: dict = Depends(current_user)):
        try:
            return runs.get(run_id)
        except RunNotFound as error:
            raise HTTPException(404, "Run not found.") from error

    @app.post("/api/runs/{run_id}/windows/{index}/review")
    def review(run_id: str, index: int, body: ReviewRequest, user: dict = Depends(require("review"))):
        try:
            return runs.review(run_id, index, body.decision, user, body.note)
        except RunNotFound as error:
            raise HTTPException(404, "Run or window not found.") from error
        except ReviewNotAllowed as error:
            raise HTTPException(409, str(error)) from error

    @app.get("/api/runs/{run_id}/audit/verify")
    def verify(run_id: str, user: dict = Depends(current_user)):
        try:
            return runs.verify_audit(run_id)
        except RunNotFound as error:
            raise HTTPException(404, "Run not found.") from error

    return app


app = create_app()
