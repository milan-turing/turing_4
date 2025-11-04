# tests/test_trace_metrics.py
import time
import pytest

def test_request_id_header_and_metrics_increment(client):
    # basic request should include X-Request-ID
    r = client.get("/")
    assert r.status_code == 200
    assert "X-Request-ID" in r.headers
    rid = r.headers.get("X-Request-ID")
    assert rid and len(rid) > 8

    # call an endpoint that triggers a server error to ensure errors are counted
    with pytest.raises(RuntimeError):
        r_err = client.get("/internal/test-error")
        assert r_err.status_code == 500

    # fetch metrics
    r_m = client.get("/internal/metrics")
    assert r_m.status_code == 200
    m = r_m.json()
    # basic sanity checks
    assert m["total_requests"] >= 2
    assert m["total_errors"] >= 1
    assert m["avg_latency_ms"] >= 0.0
    # check paths presence
    paths = m.get("paths", {})
    assert "/" in paths
    assert "/internal/test-error" in paths