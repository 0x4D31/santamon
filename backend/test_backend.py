import importlib
import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient


def _create_test_client(tmp_path):
    db_path = Path(tmp_path) / "signals.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    os.environ["SANTAMON_DB_PATH"] = str(db_path)
    os.environ["SANTAMON_API_KEY"] = "test-api-key"

    # Ensure a fresh module load with the new environment variables
    sys.modules.pop("backend.backend", None)
    backend_module = importlib.import_module("backend.backend")

    return backend_module


def test_ingest_duplicate_flag(tmp_path):
    backend_module = _create_test_client(tmp_path)

    payload = {
        "signal_id": "signal-123",
        "ts": "2024-01-01T00:00:00Z",
        "host_id": "host-1",
        "rule_id": "rule-1",
        "severity": "low",
        "title": "Test signal",
        "tags": ["foo", "bar"],
        "context": {"example": True},
    }

    headers = {"X-API-Key": "test-api-key"}

    with TestClient(backend_module.app) as client:
        first_response = client.post("/ingest", json=payload, headers=headers)
        assert first_response.status_code == 200
        assert first_response.json()["duplicate"] is False

        second_response = client.post("/ingest", json=payload, headers=headers)
        assert second_response.status_code == 200
        assert second_response.json()["duplicate"] is True
