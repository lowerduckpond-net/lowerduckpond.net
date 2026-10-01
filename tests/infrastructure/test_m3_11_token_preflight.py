"""Exercise the real token policies with disposable Cloudflare response fixtures."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from scripts import check_m3_10_provider as provider
from scripts import m3_11_token_preflight as preflight
from scripts import qualification_deadline as deadline
from scripts.check_m3_7_production_edge import ProductionEdgePreflightError
from scripts.qualification_budget import MINIMUM_TOKEN_REMAINING, TOKEN_CLEANUP_MARGIN

from .test_m3_10_runtime_token import _ACCOUNT, _SECRETS, TokenFixture

NOW = datetime(2026, 10, 1, tzinfo=UTC)
ENVIRONMENT = {
    "CLOUDFLARE_API_TOKEN": _SECRETS["edge"],
    "CADDY_CLOUDFLARE_API_TOKEN": _SECRETS["caddy"],
    "M3_10_TOKEN_AUDIT_TOKEN": _SECRETS["audit"],
    "M3_10_PAGE_RULES_TOKEN": _SECRETS["pages"],
    "CLOUDFLARE_ZONE_ID": "b" * 32,
    "CLOUDFLARE_TENANT_ZONE_ID": "c" * 32,
}


class Tokens(TokenFixture):
    def __init__(self, role: str, remaining: timedelta) -> None:
        super().__init__(
            None,
            audit_overrides={
                "issued_on": (NOW - timedelta(days=365)).isoformat(),
                "not_before": (NOW - timedelta(days=365)).isoformat(),
                "expires_on": (
                    NOW + (remaining if role == "audit" else timedelta(days=5))
                ).isoformat(),
            },
        )
        self.page_expiry = NOW + (remaining if role == "pages" else timedelta(days=5))

    def response(self, role: str, path: str, query: dict[str, str] | None) -> object:
        if path == "/user/tokens/verify":
            assert role == "pages"
            return {
                "id": "f" * 32,
                "status": "active",
                "not_before": (NOW - timedelta(days=365)).isoformat(),
                "expires_on": self.page_expiry.isoformat(),
            }
        return super().response(role, path, query)


def install(monkeypatch: pytest.MonkeyPatch, fixture: Tokens) -> None:
    monkeypatch.setattr(provider, "CloudflareClient", fixture.client)
    monkeypatch.setattr(preflight, "CloudflareClient", fixture.client)


@pytest.mark.parametrize("role", ["audit", "pages"])
@pytest.mark.parametrize(
    "remaining",
    [
        timedelta(seconds=-1),
        timedelta(),
        timedelta(hours=3),
        timedelta(hours=12, seconds=-1),
        timedelta(hours=12),
        timedelta(days=5),
    ],
)
def test_start_checks_remaining_time_accepting_rolled_original_dates(
    monkeypatch: pytest.MonkeyPatch, role: str, remaining: timedelta
) -> None:
    fixture = Tokens(role, remaining)
    install(monkeypatch, fixture)
    if remaining >= timedelta(hours=12):
        preflight.check(ENVIRONMENT, now=NOW)
        assert ("audit", f"/accounts/{_ACCOUNT}/tokens/verify") in fixture.calls
        assert ("pages", "/user/tokens/verify") in fixture.calls
    else:
        message = "expire within" if remaining <= timedelta() else "at least 12 hours remaining"
        with pytest.raises(ProductionEdgePreflightError, match=message) as caught:
            preflight.check(ENVIRONMENT, now=NOW)
        assert ("token-audit" if role == "audit" else "Page Rules") in str(caught.value)
        assert not any(secret in str(caught.value) for secret in _SECRETS.values())


@pytest.mark.parametrize(("role", "days"), [("audit", 8), ("pages", 91)])
def test_start_keeps_existing_maximum_remaining_validity(
    monkeypatch: pytest.MonkeyPatch, role: str, days: int
) -> None:
    install(monkeypatch, Tokens(role, timedelta(days=days)))
    preflight.check(ENVIRONMENT, now=NOW)
    install(monkeypatch, Tokens(role, timedelta(days=days, seconds=1)))
    with pytest.raises(ProductionEdgePreflightError, match=f"within {days} days from now"):
        preflight.check(ENVIRONMENT, now=NOW)


def test_in_run_policy_checks_do_not_restart_the_full_run_lifetime_requirement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Tokens("audit", timedelta(hours=12))
    fixture.page_expiry = NOW + timedelta(hours=12)
    install(monkeypatch, fixture)
    preflight.check(ENVIRONMENT, now=NOW)
    later = NOW + timedelta(hours=11)
    provider.page_rules_client(ENVIRONMENT, now=later)
    provider.check_caddy_token(ENVIRONMENT, account_id=_ACCOUNT, now=later)
    with pytest.raises(ProductionEdgePreflightError, match="at least 12 hours remaining"):
        preflight.check(ENVIRONMENT, now=later)


def test_token_reserve_covers_the_actual_supervisor_ceiling_and_cleanup_margin() -> None:
    required = timedelta(seconds=deadline.LIVE_SECONDS) + TOKEN_CLEANUP_MARGIN
    assert required == MINIMUM_TOKEN_REMAINING
    assert timedelta(hours=2) == TOKEN_CLEANUP_MARGIN
    shutdown_and_reporting = deadline.REPORT_SECONDS + 4 * deadline.GRACE_SECONDS
    assert TOKEN_CLEANUP_MARGIN.total_seconds() > shutdown_and_reporting


@pytest.mark.parametrize("short", [False, True])
def test_token_command_reports_safe_actionable_outcome(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], short: bool
) -> None:
    install(monkeypatch, Tokens("audit", timedelta(hours=3) if short else timedelta(days=5)))
    for key, value in ENVIRONMENT.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(preflight, "datetime", SimpleNamespace(now=lambda _tz: NOW))
    monkeypatch.setattr(sys, "argv", ["token-preflight"])
    assert preflight.main() == (1 if short else 0)
    output = capsys.readouterr()
    assert "12 hours remaining" in (output.err if short else output.out)
    assert all(value not in output.out + output.err for value in _SECRETS.values())


def test_token_command_does_not_expose_unexpected_provider_exception(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> None:
        raise OSError(_SECRETS["audit"])

    monkeypatch.setattr(preflight, "check", unavailable)
    monkeypatch.setattr(sys, "argv", ["token-preflight"])
    assert preflight.main() == 1
    assert capsys.readouterr().err == "M3.11 qualification token preflight failed: OSError.\n"
