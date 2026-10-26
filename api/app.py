"""Initial synchronous FastAPI boundary for the existing run service."""

from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Path as ApiPath, status
from fastapi.middleware.cors import CORSMiddleware

from evaluation.evaluator import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_END_ROW,
    DEFAULT_START_ROW,
    MAX_GRAPH_EXECUTIONS,
)
from services.data_loader import find_dataset_files, load_network_data
from services.run_service import RunRequest, RunService
from services.run_store import RunStore

from api.schemas import (
    DatasetColumn,
    DatasetListResponse,
    DatasetSchemaResponse,
    DatasetSummary,
    HealthResponse,
    RunCreateRequest,
    RunResultResponse,
    RunStatusResponse,
)


def create_app(
    run_service: Optional[RunService] = None,
    dataset_directory: Optional[Path] = None,
    run_store_path: Optional[Path] = None,
) -> FastAPI:
    service = run_service or RunService(
        dataset_directory=dataset_directory
        or Path("data/raw")
    )
    app = FastAPI(
        title="Agentic Threat Detection API",
        version="1.0.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type"],
    )
    run_store = RunStore(
        run_store_path or Path("data") / "runs.json"
    )
    records: Dict[str, Dict[str, Any]] = run_store.load()
    for record in records.values():
        if record.get("status") == "RUNNING":
            record.update(
                {
                    "status": "FAILED",
                    "run_status": "FAILED",
                    "error": (
                        "Run was interrupted when the API server stopped "
                        "before a result was persisted."
                    ),
                }
            )
        elif (
            record.get("status") == "COMPLETED"
            and (
                not record.get("run_final_decision_code")
                or record.get("incomplete_window_count", 0) > 0
            )
        ):
            record.update(
                {
                    "status": "INCOMPLETE",
                    "run_status": "INCOMPLETE",
                }
            )
    if records:
        run_store.save(records)
    records_lock = Lock()
    execution_lock = Lock()

    def record_status(run_id: str, **values):
        with records_lock:
            records[run_id].update(values)
            run_store.save(records)

    def get_record(run_id: str) -> Dict[str, Any]:
        with records_lock:
            record = records.get(run_id)
            if record is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        "Run not found. Only runs created by this API instance "
                        "or restored from data/runs.json are available."
                    ),
                )
            return dict(record)

    @app.get(
        "/api/v1/health",
        response_model=HealthResponse,
    )
    def health():
        return {"status": "ok"}

    @app.get(
        "/api/v1/datasets",
        response_model=DatasetListResponse,
    )
    def list_datasets():
        try:
            paths = find_dataset_files(
                str(service.dataset_directory)
            )
            datasets = []
            for dataset_path in paths:
                dataframe = load_network_data(str(dataset_path))
                datasets.append(
                    DatasetSummary(
                        dataset_id=dataset_path.name,
                        format=dataset_path.suffix.lower().lstrip("."),
                        row_count=len(dataframe),
                        has_labels=any(
                            str(column).strip().lower() == "label"
                            for column in dataframe.columns
                        ),
                    )
                )
            return DatasetListResponse(datasets=datasets)
        except (FileNotFoundError, ValueError, KeyError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Dataset listing failed.",
            ) from exc

    @app.get(
        "/api/v1/datasets/{dataset_id}/schema",
        response_model=DatasetSchemaResponse,
    )
    def dataset_schema(
        dataset_id: str = ApiPath(..., min_length=1),
    ):
        try:
            dataset_path = service.resolve_dataset(dataset_id)
            dataframe = load_network_data(str(dataset_path))
            return DatasetSchemaResponse(
                dataset_id=dataset_path.name,
                format=dataset_path.suffix.lower().lstrip("."),
                row_count=len(dataframe),
                columns=[
                    DatasetColumn(
                        name=str(column),
                        dtype=str(dataframe[column].dtype),
                    )
                    for column in dataframe.columns
                ],
                has_labels=any(
                    str(column).strip().lower() == "label"
                    for column in dataframe.columns
                ),
            )
        except FileNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc
        except (ValueError, KeyError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    @app.post(
        "/api/v1/runs",
        response_model=RunStatusResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_run(request: RunCreateRequest):
        if request.end_row <= request.start_row:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="end_row must be greater than start_row.",
            )
        if request.max_graph_executions != MAX_GRAPH_EXECUTIONS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="The pilot allows exactly one graph execution.",
            )
        try:
            service.resolve_dataset(request.dataset_id)
            run_request = RunRequest(
                dataset_identifier=request.dataset_id,
                start_row=request.start_row,
                end_row=request.end_row,
                batch_size=request.batch_size,
                max_graph_executions=request.max_graph_executions,
            )
        except FileNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        if not execution_lock.acquire(blocking=False):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Another run is already executing.",
            )

        run_id = uuid4().hex
        record = {
            "run_id": run_id,
            "status": "RUNNING",
            "run_status": "RUNNING",
            "dataset": request.dataset_id,
        }
        with records_lock:
            records[run_id] = record
            run_store.save(records)

        try:
            result = service.run(run_request)
            report = result.to_dict()
            record_status(
                run_id,
                status=(
                    "INTERRUPTED"
                    if report["run_status"] == "INTERRUPTED"
                    else "INCOMPLETE"
                    if report["run_status"] == "INCOMPLETE"
                    else "COMPLETED"
                ),
                **report,
            )
        except Exception as exc:
            record_status(
                run_id,
                status="FAILED",
                run_status="FAILED",
                error="Run execution failed.",
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Run execution failed.",
            ) from exc
        finally:
            execution_lock.release()

        return RunStatusResponse(**get_record(run_id))

    @app.get(
        "/api/v1/runs/{run_id}",
        response_model=RunStatusResponse,
    )
    def run_status(run_id: str):
        return RunStatusResponse(**get_record(run_id))

    @app.get(
        "/api/v1/runs/{run_id}/result",
        response_model=RunResultResponse,
    )
    def run_result(run_id: str):
        record = get_record(run_id)
        if record["status"] == "FAILED":
            return RunResultResponse(
                run_id=run_id,
                status="FAILED",
                error=record.get("error"),
            )
        if record["status"] == "RUNNING":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Run result is not available yet.",
            )
        report_fields = {
            key: value
            for key, value in record.items()
            if key not in {"run_id", "status"}
        }
        return RunResultResponse(
            run_id=run_id,
            status=record["status"],
            result=report_fields,
        )

    return app


app = create_app()
