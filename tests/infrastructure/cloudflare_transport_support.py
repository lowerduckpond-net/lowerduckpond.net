"""Synthetic responses shared by read-only and mutation client tests."""

from __future__ import annotations

import urllib.request
from collections.abc import Callable

import pytest

from scripts import check_m3_7_production_edge
from scripts.cloudflare_read_diagnostics import ReadDiagnostic


def mock_urlopen(monkeypatch: pytest.MonkeyPatch, opener: Callable[..., object]) -> None:
    def open_request(
        request: urllib.request.Request, *, timeout: int, diagnostic: ReadDiagnostic
    ) -> object:
        return opener(request, timeout=timeout)

    monkeypatch.setattr(check_m3_7_production_edge, "open_request", open_request)
    monkeypatch.setattr(urllib.request, "urlopen", opener)
