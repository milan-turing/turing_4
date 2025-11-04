import time
import threading
from uuid import uuid4
from typing import Dict, Any

from fastapi import APIRouter, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

# simple in-memory metrics; guarded by lock for safety in tests/threads
_metrics_lock = threading.Lock()
_metrics = {
    "total_requests": 0,
    "total_errors": 0,
    "total_latency_ms": 0.0,
    "paths": {},  # path -> count
}


def _record(path: str, duration_ms: float, error: bool = False) -> None:
    with _metrics_lock:
        _metrics["total_requests"] += 1
        if error:
            _metrics["total_errors"] += 1
        _metrics["total_latency_ms"] += duration_ms
        _metrics["paths"].setdefault(path, 0)
        _metrics["paths"][path] += 1


def get_metrics() -> Dict[str, Any]:
    with _metrics_lock:
        total = _metrics["total_requests"]
        avg = (_metrics["total_latency_ms"] / total) if total else 0.0
        return {
            "total_requests": _metrics["total_requests"],
            "total_errors": _metrics["total_errors"],
            "avg_latency_ms": avg,
            "total_latency_ms": _metrics["total_latency_ms"],
            "paths": dict(_metrics["paths"]),
        }


class TraceMetricsMiddleware(BaseHTTPMiddleware):
    """
    Middleware that injects a request id (request.state.request_id and X-Request-ID header)
    and records simple metrics: request count, latency and server error count (5xx).
    """
    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        rid = uuid4().hex
        request.state.request_id = rid
        start = time.perf_counter()
        had_error = False
        try:
            resp = await call_next(request)
        except Exception:
            # treat unhandled exceptions as server errors
            had_error = True
            duration_ms = (time.perf_counter() - start) * 1000.0
            _record(request.url.path, duration_ms, error=True)
            raise
        duration_ms = (time.perf_counter() - start) * 1000.0
        # consider 5xx responses as errors
        if resp.status_code >= 500:
            had_error = True
        _record(request.url.path, duration_ms, error=had_error)
        # expose request id to client
        resp.headers["X-Request-ID"] = rid
        return resp


# Router exposing metrics and a small test-error route used by tests
metrics_router = APIRouter()


@metrics_router.get("/internal/metrics", include_in_schema=False)
def metrics_endpoint():
    return get_metrics()


@metrics_router.get("/internal/test-error", include_in_schema=False)
def metrics_test_error():
    # intentionally raise to produce a 500 for middleware to record
    raise RuntimeError("intentional test error")