"""Streamlit client for the FastAPI threat-detection backend."""

from typing import Any, Callable, Dict, Optional
from urllib.parse import quote

import requests
import streamlit as st


DEFAULT_BACKEND_URL = "http://127.0.0.1:8000"
DEFAULT_START_ROW = 0
DEFAULT_END_ROW = 800
DEFAULT_BATCH_SIZE = 100
REQUEST_TIMEOUT_SECONDS = 30


class BackendError(RuntimeError):
    """An HTTP or transport error returned by the backend."""


class BackendClient:
    """Small HTTP client that keeps the UI independent of backend internals."""

    def __init__(
        self,
        base_url: str,
        request: Callable[..., Any] = requests.request,
        timeout: int = REQUEST_TIMEOUT_SECONDS,
    ):
        self.base_url = base_url.rstrip("/")
        self.request = request
        self.timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> Dict[str, Any]:
        try:
            response = self.request(
                method,
                f"{self.base_url}{path}",
                timeout=self.timeout,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise BackendError(
                f"Backend is unavailable at {self.base_url}: {exc}"
            ) from exc

        try:
            payload = response.json()
        except ValueError:
            payload = {}

        if not response.ok:
            detail = payload.get("detail") or payload.get("error")
            message = detail or f"HTTP {response.status_code}"
            raise BackendError(f"Backend request failed: {message}")

        if not isinstance(payload, dict):
            raise BackendError("Backend returned an invalid response.")
        return payload

    def health(self) -> Dict[str, Any]:
        return self._request("GET", "/api/v1/health")

    def datasets(self) -> Dict[str, Any]:
        return self._request("GET", "/api/v1/datasets")

    def dataset_schema(self, dataset_id: str) -> Dict[str, Any]:
        encoded_id = quote(dataset_id, safe="")
        return self._request(
            "GET",
            f"/api/v1/datasets/{encoded_id}/schema",
        )

    def create_run(
        self,
        dataset_id: str,
        start_row: int,
        end_row: int,
        batch_size: int,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/v1/runs",
            json={
                "dataset_id": dataset_id,
                "start_row": start_row,
                "end_row": end_row,
                "batch_size": batch_size,
                "max_graph_executions": 1,
            },
        )

    def run_status(self, run_id: str) -> Dict[str, Any]:
        encoded_id = quote(run_id, safe="")
        return self._request("GET", f"/api/v1/runs/{encoded_id}")

    def run_result(self, run_id: str) -> Dict[str, Any]:
        encoded_id = quote(run_id, safe="")
        return self._request(
            "GET",
            f"/api/v1/runs/{encoded_id}/result",
        )


def _show_metric_group(title: str, metrics: Optional[Dict[str, Any]]) -> None:
    if not metrics:
        st.info(f"{title}: unavailable.")
        return
    st.subheader(title)
    st.json(metrics)


def _show_run_report(status: Dict[str, Any], result_response: Dict[str, Any]):
    st.subheader("Run status")
    st.write(f"**Run ID:** `{status.get('run_id', 'unknown')}`")
    st.write(f"**Status:** `{status.get('status', 'UNKNOWN')}`")
    st.caption(
        "Data shown here comes from the FastAPI backend. "
        "No demo data is substituted."
    )
    if status.get("interruption_reason"):
        st.warning(
            "Run interrupted: "
            f"{status['interruption_reason']}"
        )

    report = result_response.get("result") or {}
    if not report:
        error = result_response.get("error")
        if error:
            st.error(error)
        return

    decision = report.get("run_final_decision_code")
    st.subheader("Run-level recommendation")
    if decision:
        st.warning(
            f"{decision}. This is a proposed mitigation or classification "
            "outcome, not a confirmed security-response action."
        )
    else:
        st.info(
            "No final decision was recorded. The run is not represented "
            "as successfully mitigated or benign."
        )

    if report.get("run_status") in {"INTERRUPTED", "FAILED"}:
        st.warning(
            "This run did not complete successfully. Its results must not "
            "be interpreted as confirmed mitigation."
        )

    st.subheader("Monitoring windows")
    counts = {
        "Total": report.get("monitoring_window_count"),
        "Completed": report.get("completed_window_count"),
        "Partial": report.get("partial_window_count"),
        "Incomplete": report.get("incomplete_window_count"),
    }
    st.table(
        [
            {"Count": label, "Value": value}
            for label, value in counts.items()
            if value is not None
        ]
    )

    _show_metric_group(
        "Monitoring metrics",
        report.get("monitoring_metrics"),
    )
    _show_metric_group(
        "LLM detection metrics",
        report.get("llm_metrics"),
    )
    _show_metric_group(
        "Pipeline metrics",
        report.get("pipeline_metrics"),
    )

    rows = report.get("rows") or []
    st.subheader("Window-level predictions")
    if rows:
        st.dataframe(rows, use_container_width=True)
    else:
        st.info("No window rows were recorded.")
    st.caption(
        "The final decision above is a run-level outcome. "
        "Window rows contain the independently recorded window predictions."
    )


def main() -> None:
    st.set_page_config(
        page_title="Autonomous Threat Detection",
        page_icon=":shield:",
        layout="wide",
    )
    st.title("Agentic AI for Autonomous Threat Detection and Response")
    st.caption(
        "Synchronous API client. Results and status are available after "
        "the run request completes; this interface does not provide live "
        "progress updates."
    )

    backend_url = st.sidebar.text_input(
        "FastAPI backend URL",
        value=DEFAULT_BACKEND_URL,
    ).strip()
    if not backend_url:
        st.error("Enter a FastAPI backend URL.")
        return

    client = BackendClient(backend_url)
    try:
        health = client.health()
        if health.get("status") == "ok":
            st.sidebar.success("Backend healthy")
        else:
            st.sidebar.warning(
                f"Backend health response: {health.get('status', 'unknown')}"
            )
    except BackendError as exc:
        st.sidebar.error(str(exc))
        st.error(
            "The backend could not be reached. Start FastAPI and try again."
        )
        return

    try:
        dataset_payload = client.datasets()
        datasets = dataset_payload.get("datasets", [])
    except BackendError as exc:
        st.error(str(exc))
        return

    if not datasets:
        st.warning("The backend returned no datasets.")
        return

    dataset_ids = [
        dataset["dataset_id"]
        for dataset in datasets
        if dataset.get("dataset_id")
    ]
    if not dataset_ids:
        st.error("The backend returned datasets without identifiers.")
        return

    st.header("Dataset")
    selected_dataset = st.selectbox("Dataset", dataset_ids)
    selected_summary = next(
        dataset
        for dataset in datasets
        if dataset.get("dataset_id") == selected_dataset
    )
    st.write(
        f"Rows: **{selected_summary.get('row_count', 'unknown')}**  |  "
        f"Format: **{selected_summary.get('format', 'unknown')}**"
    )

    try:
        schema = client.dataset_schema(selected_dataset)
        st.subheader("Schema preview")
        st.dataframe(
            schema.get("columns", []),
            use_container_width=True,
            hide_index=True,
        )
    except BackendError as exc:
        st.error(f"Schema preview unavailable: {exc}")

    st.header("Run configuration")
    start_row = st.number_input(
        "Start row",
        min_value=0,
        value=DEFAULT_START_ROW,
        step=1,
    )
    end_row = st.number_input(
        "End row (exclusive)",
        min_value=1,
        value=DEFAULT_END_ROW,
        step=1,
    )
    batch_size = st.number_input(
        "Batch size",
        min_value=1,
        value=DEFAULT_BATCH_SIZE,
        step=1,
    )

    if st.button("Run evaluation", type="primary"):
        if end_row <= start_row:
            st.error("End row must be greater than start row.")
            return
        try:
            with st.spinner(
                "Running evaluation. This synchronous request may take time."
            ):
                run_status = client.create_run(
                    selected_dataset,
                    int(start_row),
                    int(end_row),
                    int(batch_size),
                )
                run_id = run_status["run_id"]
                result = client.run_result(run_id)
            _show_run_report(run_status, result)
        except (BackendError, KeyError) as exc:
            st.error(f"Run could not be completed: {exc}")


if __name__ == "__main__":
    main()
