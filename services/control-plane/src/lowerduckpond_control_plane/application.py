"""FastAPI application boundary for the control plane."""

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Stable response returned by the process health endpoint."""

    status: Literal["ok"]


def create_application() -> FastAPI:
    """Create a control-plane application without privileged host access."""
    app = FastAPI(
        title="Lower Duck Pond Hosting control plane",
        version="0.0.0",
    )

    @app.get("/healthz", response_model=HealthResponse, tags=["operations"])
    def health() -> HealthResponse:
        return HealthResponse(status="ok")

    return app


application = create_application()
