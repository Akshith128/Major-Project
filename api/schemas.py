"""Pydantic schemas for the initial run API."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from evaluation.evaluator import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_END_ROW,
    DEFAULT_START_ROW,
    MAX_GRAPH_EXECUTIONS,
)


class HealthResponse(BaseModel):
    status: str


class DatasetSummary(BaseModel):
    dataset_id: str
    format: str
    row_count: int
    has_labels: bool


class DatasetListResponse(BaseModel):
    datasets: List[DatasetSummary]


class DatasetColumn(BaseModel):
    name: str
    dtype: str


class DatasetSchemaResponse(BaseModel):
    dataset_id: str
    format: str
    row_count: int
    columns: List[DatasetColumn]
    has_labels: bool


class RunCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_id: str = Field(min_length=1)
    start_row: int = Field(default=DEFAULT_START_ROW, ge=0)
    end_row: int = Field(default=DEFAULT_END_ROW, gt=0)
    batch_size: int = Field(default=DEFAULT_BATCH_SIZE, gt=0)
    max_graph_executions: int = Field(
        default=MAX_GRAPH_EXECUTIONS,
        ge=1,
    )


class RunStatusResponse(BaseModel):
    run_id: str
    status: str
    run_status: Optional[str] = None
    dataset: Optional[str] = None
    interruption_reason: Optional[str] = None
    error: Optional[str] = None
    graph_executions: Optional[int] = None
    monitoring_window_count: Optional[int] = None
    completed_window_count: Optional[int] = None
    partial_window_count: Optional[int] = None
    incomplete_window_count: Optional[int] = None
    run_final_decision_code: Optional[str] = None


class RunResultResponse(BaseModel):
    run_id: str
    status: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
