from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).parents[2]
_CADDY_ROLE = _ROOT / "config/ansible/roles/caddy"


def test_production_web_ingress_uses_only_the_reviewed_cloudflare_ranges() -> None:
    site = (_ROOT / "config/ansible/playbooks/site.yml").read_text(encoding="utf-8")
    production = (
        _ROOT / "config/ansible/inventories/production/group_vars/hosting_nodes.yml"
    ).read_text(encoding="utf-8")

    assert "../../../platform/cloudflare-networks.json" in site
    assert "firewall_web_source_cidrs: >-" in production
    assert "cloudflare_ipv4_cidrs + cloudflare_ipv6_cidrs" in production


def test_production_unit_executes_only_the_descriptor_pinned_launcher() -> None:
    unit = (_CADDY_ROLE / "templates/caddy-generation.service.j2").read_text(encoding="utf-8")

    assert "OpenFile={{ caddy_publication_lock_path }}:publication-lock" in unit
    assert ":publication-lock:read-write" not in unit
    assert (
        "ExecStart=/usr/local/libexec/lowerduckpond/launch-caddy-generation "
        "{{ static_host_agent_artifact_sha256 }} {{ caddy_binary_sha256 }}"
    ) in unit
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
    assert "Inspect the existing Caddy unit before the bootstrap transaction" in tasks
    assert "caddy_generation_existing_unit.stdout | trim == 'loaded'" in tasks
    assert "Remove any immutable-bootstrap runtime mask" in tasks
    assert tasks.index("Build, validate, and select the complete platform-only generation") < (
        tasks.index("Remove any immutable-bootstrap runtime mask")
    )
    assert "Remove the retired mutable Caddy configuration" in site
    assert "--check" in tasks
    assert site.index("- role: static_host_agent") < site.index("- role: caddy")

    host_agent_tasks = (_ROOT / "config/ansible/roles/static_host_agent/tasks/main.yml").read_text(
        encoding="utf-8"
    )
    assert "Create inert Caddy generation storage" in host_agent_tasks
    assert "static_host_agent_caddy_generation_root" in host_agent_tasks


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
    assert "check_exact_output 'Caddy generation is complete and current' unchanged" in health
    assert "bootstrap-caddy-generation" in check
    assert "static_host_agent_artifact_sha256" in check
    assert "--check" in check
