"""Runs: push a set of traffic windows through the agent graph, then evaluate,
audit and store the result as JSON (one file per run)."""

import json
import threading
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import anomaly, audit, baselines, config, control, data
from .evaluation import evaluate
from .graph import build_graph
from .llm import GeminiLLM, NoLLM

SYSTEM_ACTOR = "aegis:governance"
DEFAULT_USER = {"username": "cli", "name": "CLI", "role": "analyst"}


class RunBusy(RuntimeError):
    pass


class RunPaused(RuntimeError):
    pass


class RunNotFound(KeyError):
    pass


class ReviewNotAllowed(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def actor(user: dict) -> str:
    return f"user:{user['username']}"


def summarize(windows: list[dict]) -> dict:
    threats = [w for w in windows if w.get("detection", {}).get("threat")]
    decisions = Counter(w["governance"]["decision"] for w in windows)
    sources = Counter(
        w[agent]["source"] for w in windows for agent in ("detection", "response") if agent in w
    )
    return {
        "windows": len(windows),
        "suspicious": sum(w["monitoring"]["suspicious"] for w in windows),
        "threats": len(threats),
        "severity": dict(Counter(w["risk"]["severity"] for w in threats)),
        "attack_types": dict(Counter(w["detection"]["attack_type"] for w in threats)),
        "pending_review": sum(
            w["governance"]["decision"] == "PENDING_REVIEW" and not w.get("review") for w in windows
        ),
        "decisions": dict(decisions),
        "agent_sources": dict(sources),
    }


def analyse_window(graph, window: dict, prior: Counter, baseline: dict | None = None) -> dict:
    """Run one window through the agents, then attach truth and baselines for evaluation."""
    agent_view = {k: window[k] for k in ("index", "row_start", "row_end", "features", "detector") if k in window}
    state = graph.invoke({"window": agent_view, "context": {"prior_incidents": dict(prior)}, "trace": []})
    result = {
        **agent_view,
        **{k: state[k] for k in ("monitoring", "detection", "risk", "response", "governance") if k in state},
        "trace": state["trace"],
        "review": None,
        "truth": window["truth"],  # attached only after the agents ran
    }
    if baseline:
        result["baselines"] = baseline
    if result.get("detection", {}).get("threat"):
        prior[result["detection"]["attack_type"]] += 1
    return result


def baseline_verdicts(
    dataset_id: str, loaded: list[dict], label_threshold: float = 0.5, ablate_tcp_window: bool = False
) -> tuple[list, dict]:
    """Per-window baseline verdicts plus a run-level description of the baselines."""
    scored = baselines.score(dataset_id, loaded, label_threshold, ablate_tcp_window)
    per_window = []
    for i in range(len(loaded)):
        entry = {}
        for name, b in scored.items():
            if b.get("available"):
                entry[name] = b["windows"][i]
        per_window.append(entry or None)
    info = {name: {k: v for k, v in b.items() if k != "windows"} for name, b in scored.items()}
    return per_window, info


class RunService:
    def __init__(self, runs_dir: Path | None = None, llm_factory=None, baselines_enabled: bool = True):
        self.runs_dir = Path(runs_dir or config.RUNS_DIR)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self._llm_factory = llm_factory or (lambda mode: NoLLM() if mode == "rules" else GeminiLLM())
        self._baselines = baselines_enabled
        self._lock = threading.Lock()
        self._active: str | None = None
        self._runs: dict[str, dict] = {}
        for path in self.runs_dir.glob("*.json"):
            run = json.loads(path.read_text(encoding="utf-8"))
            if run.get("status") == "RUNNING":
                run["status"], run["error"] = "FAILED", "Interrupted by a server restart."
            self._runs[run["id"]] = run

    # --- storage -------------------------------------------------------------

    def _save(self, run: dict) -> None:
        path = self.runs_dir / f"{run['id']}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(run, indent=1), encoding="utf-8")
        tmp.replace(path)

    def list_runs(self) -> list[dict]:
        keys = ("id", "created_at", "operator", "status", "config", "llm", "progress", "summary")
        runs = sorted(self._runs.values(), key=lambda r: r["created_at"], reverse=True)
        return [{k: r.get(k) for k in keys} for r in runs]

    def get(self, run_id: str) -> dict:
        try:
            return self._runs[run_id]
        except KeyError:
            raise RunNotFound(run_id) from None

    def _audit(self, run: dict, who: str, action: str, detail: dict) -> None:
        audit.append(run["audit"], who, action, detail, run_id=run["id"])

    # --- execution -----------------------------------------------------------

    def start(
        self,
        dataset_id: str,
        windows: int = 10,
        window_size: int = 100,
        sampling: str = "spread",
        start_row: int = 0,
        mode: str = "auto",
        user: dict | None = None,
        background: bool = True,
        seed: int | None = None,
        detector_baseline: str = "same-network",
    ) -> dict:
        user = user or DEFAULT_USER
        if control.is_paused():
            raise RunPaused("AEGIS is paused by a security manager. Resume it before starting a run.")
        if mode not in ("auto", "gemini", "rules", "hybrid"):
            raise ValueError(f"Unknown mode: {mode}")
        llm = self._llm_factory(mode)
        if not llm.configured and mode == "gemini":
            raise ValueError("Gemini mode needs GOOGLE_API_KEY in .env.")
        if not llm.configured:
            llm = NoLLM()
        if detector_baseline not in anomaly.BASELINES:
            raise ValueError(f"Unknown detector baseline: {detector_baseline}")
        loaded = data.load_windows(
            dataset_id, windows, window_size, sampling, start_row, seed=seed, include_flows=self._baselines
        )

        with self._lock:
            if self._active:
                raise RunBusy("Another run is still executing.")
            run_id = uuid.uuid4().hex[:12]
            self._active = run_id

        note = data.dataset_note(dataset_id)
        run = {
            "id": run_id,
            "created_at": _now(),
            "operator": user["name"],
            "operator_account": {"username": user["username"], "role": user["role"]},
            "status": "RUNNING",
            "config": {
                "dataset_id": dataset_id,
                "windows": windows,
                "window_size": window_size,
                "sampling": sampling,
                "start_row": start_row,
                "mode": mode,
                "seed": seed,
                "label_threshold": 0.5,
                **({"detector_baseline": detector_baseline} if mode == "hybrid" else {}),
            },
            "dataset_caution": note["caution"],
            "llm": {"provider": llm.provider, "model": llm.model},
            "progress": {"done": 0, "total": len(loaded)},
            "windows": [],
            "baselines": None,
            "detector": None,
            "summary": None,
            "evaluation": None,
            "audit": [],
            "error": None,
        }
        self._audit(run, actor(user), "RUN_STARTED", {"run_id": run_id, **run["config"], "llm": run["llm"]})
        self._runs[run_id] = run
        self._save(run)

        if background:
            threading.Thread(target=self._execute, args=(run, llm, loaded), daemon=True).start()
        else:
            self._execute(run, llm, loaded)
        return run

    def _execute(self, run: dict, llm, loaded: list[dict]) -> None:
        graph = build_graph(llm)
        prior: Counter = Counter()
        try:
            per_window = [None] * len(loaded)
            if run["config"]["mode"] == "hybrid":
                evidence, run["detector"] = anomaly.score(
                    run["config"]["dataset_id"], loaded, run["config"]["window_size"], run["config"]["detector_baseline"]
                )
                for window, ev in zip(loaded, evidence):
                    window["detector"] = ev
            if self._baselines:
                per_window, run["baselines"] = baseline_verdicts(run["config"]["dataset_id"], loaded)
                for window in loaded:
                    window.pop("flows", None)  # raw flows never reach the agents or the run file
            for window, baseline in zip(loaded, per_window):
                if control.is_paused():
                    run["status"], run["error"] = "STOPPED", "Stopped by the pause control; nothing was executed."
                    self._audit(run, SYSTEM_ACTOR, "RUN_STOPPED", {"after_window": run["progress"]["done"]})
                    break
                result = analyse_window(graph, window, prior, baseline)
                run["windows"].append(result)
                self._audit(
                    run,
                    SYSTEM_ACTOR,
                    "WINDOW_DECIDED",
                    {
                        "window": window["index"],
                        "decision": result["governance"]["decision"],
                        "threat": bool(result.get("detection", {}).get("threat")),
                        "attack_type": result.get("detection", {}).get("attack_type"),
                        "severity": result.get("risk", {}).get("severity"),
                        "actions": result.get("response", {}).get("actions", []),
                        "detection_source": result.get("detection", {}).get("source"),
                        "model_version": result.get("detection", {}).get("provenance", {}).get("model_version"),
                        "prompt_sha256": result.get("detection", {}).get("provenance", {}).get("prompt_sha256"),
                    },
                )
                run["progress"]["done"] += 1
                self._save(run)
            if run["windows"]:
                run["summary"] = summarize(run["windows"])
                run["evaluation"] = evaluate(run["windows"])
            if run["status"] == "RUNNING":
                run["status"] = "COMPLETED"
                self._audit(run, SYSTEM_ACTOR, "RUN_COMPLETED", {"summary": run["summary"]})
        except Exception as error:  # keep partial results, record the failure
            run["status"], run["error"] = "FAILED", str(error)
            if run["windows"]:
                run["summary"] = summarize(run["windows"])
            self._audit(run, SYSTEM_ACTOR, "RUN_FAILED", {"error": str(error)})
        finally:
            self._save(run)
            with self._lock:
                self._active = None

    # --- human-in-the-loop -----------------------------------------------------

    def review(self, run_id: str, index: int, decision: str, user: dict, note: str = "") -> dict:
        run = self.get(run_id)
        window = next((w for w in run["windows"] if w["index"] == index), None)
        if window is None:
            raise RunNotFound(f"{run_id}/window {index}")
        if decision not in ("APPROVED", "REJECTED"):
            raise ReviewNotAllowed("Decision must be APPROVED or REJECTED.")
        if window["governance"]["decision"] != "PENDING_REVIEW" or window["review"]:
            raise ReviewNotAllowed("This window is not awaiting review.")
        window["review"] = {
            "decision": decision,
            "operator": user["name"],
            "username": user["username"],
            "role": user["role"],
            "note": note,
            "at": _now(),
        }
        self._audit(
            run,
            actor(user),
            f"RESPONSE_{decision}",
            {"window": index, "note": note, "actions": window.get("response", {}).get("actions", [])},
        )
        if run["summary"]:
            run["summary"] = summarize(run["windows"])
        if run["evaluation"]:
            run["evaluation"] = evaluate(run["windows"])
        self._save(run)
        return window

    def verify_audit(self, run_id: str) -> dict:
        return audit.verify(self.get(run_id)["audit"], run_id)
