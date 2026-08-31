from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).parents[2]
_CADDY_ROLE = _ROOT / "config/ansible/roles/caddy"


def test_production_unit_executes_only_the_descriptor_pinned_launcher() -> None:
    unit = (_CADDY_ROLE / "templates/caddy-generation.service.j2").read_text(encoding="utf-8")

    assert "OpenFile={{ caddy_publication_lock_path }}:publication-lock" in unit
    assert ":publication-lock:read-write" not in unit
    assert "ExecStart=/usr/local/libexec/lowerduckpond/launch-caddy-generation" in unit
    assert "Restart=on-failure" in unit
    assert "RestartSec=5s" in unit
    assert "StartLimitBurst=3" in unit
    assert "StartLimitIntervalSec=60s" in unit
    assert "/usr/local/bin/caddy" not in unit
    assert "/etc/caddy/Caddyfile" not in unit
    assert "ExecReload=" not in unit


def test_generation_migration_is_stopped_masked_and_defaults_on() -> None:
    defaults = (_CADDY_ROLE / "defaults/main.yml").read_text(encoding="utf-8")
    tasks = (_CADDY_ROLE / "tasks/main.yml").read_text(encoding="utf-8")
    site = (_ROOT / "config/ansible/playbooks/site.yml").read_text(encoding="utf-8")

    assert "caddy_generation_enabled: true" in defaults
    assert "Stop Caddy for the immutable bootstrap transaction" in tasks
    assert "Runtime-mask Caddy for the immutable bootstrap transaction" in tasks
    assert "mask\n      - --runtime\n      - caddy.service" in tasks
    assert "Build, validate, and select the complete platform-only generation" in tasks
    assert "Remove the retired mutable Caddy configuration" in site
    assert "--check" in tasks
    assert site.index("- role: static_host_agent") < site.index("- role: caddy")


def test_frozen_wrappers_enter_only_the_reviewed_host_agent_entrypoints() -> None:
    bootstrap = (_CADDY_ROLE / "files/bootstrap-caddy-generation").read_text(encoding="utf-8")
    launcher = (_CADDY_ROLE / "files/launch-caddy-generation").read_text(encoding="utf-8")

    assert "caddy_bootstrap_main" in bootstrap
    assert "caddy_launcher_main" in launcher
    assert "static-host-agent/{artifact_sha256}/site-packages" in bootstrap
    assert "static-host-agent/{artifact_sha256}/site-packages" in launcher
    assert "current/site-packages" not in bootstrap
    assert "current/site-packages" not in launcher


def test_production_acceptance_and_health_use_the_generation_check() -> None:
    acceptance = (_ROOT / "config/ansible/playbooks/acceptance.yml").read_text(encoding="utf-8")
    health = (_ROOT / "config/ansible/roles/monitoring/templates/health-check.j2").read_text(
        encoding="utf-8"
    )
    check = (_CADDY_ROLE / "templates/check-caddy-generation.j2").read_text(encoding="utf-8")

    assert "check-caddy-generation" in acceptance
    assert "check-caddy-generation" in health
    assert "bootstrap-caddy-generation" in check
    assert "--check" in check
