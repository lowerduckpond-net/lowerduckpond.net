"""Control-plane foundation tests."""

from http import HTTPStatus

from fastapi.testclient import TestClient
from lowerduckpond_control_plane.application import create_application
from lowerduckpond_control_plane.database import Base


def test_health_endpoint_reports_ready_process() -> None:
    client = TestClient(create_application())

    response = client.get("/healthz")

    assert response.status_code == HTTPStatus.OK
    assert response.json() == {"status": "ok"}


def test_foundation_defines_no_application_tables() -> None:
    assert not Base.metadata.tables
