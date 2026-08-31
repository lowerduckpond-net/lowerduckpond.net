from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).parents[2]
_CADDY_ROLE = _ROOT / "config/ansible/roles/caddy"
_PRODUCTION_CERTIFICATE_VARIABLE_COUNT = 2


def test_production_web_ingress_is_not_restricted_before_edge_proxying() -> None:
    production = (
        _ROOT / "config/ansible/inventories/production/group_vars/hosting_nodes.yml"
    ).read_text(encoding="utf-8")

    assert "firewall_web_source_cidrs:" not in production
    assert "CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED" in production
    assert "caddy_origin_pull_enforcement_enabled: false" not in production

    playbook = (_ROOT / "config/ansible/playbooks/site.yml").read_text(encoding="utf-8")
    assert "cloudflare_ipv4_cidrs + cloudflare_ipv6_cidrs" in playbook
    assert "retiring_ipv4_cidrs + retiring_ipv6_cidrs" in playbook
    assert "if caddy_origin_pull_enforcement_enabled | bool" in playbook
    assert 'else ["0.0.0.0/0", "::/0"]' in playbook


def test_edge_policy_is_installed_before_dns_becomes_proxied() -> None:
    module = (_ROOT / "infra/opentofu/modules/cloudflare-public-edge/main.tf").read_text(
        encoding="utf-8"
    )
    dependencies = {
        "cloudflare_zone_setting.ssl",
        "cloudflare_zone_setting.always_online",
        "cloudflare_authenticated_origin_pulls.hostname",
        "cloudflare_authenticated_origin_pulls_settings.zone",
        "cloudflare_ruleset.cache_bypass",
        "cloudflare_ruleset.transform_disable",
        "cloudflare_ruleset.cdn_cgi_block",
    }

    for name in ("apex", "wildcard"):
        match = re.search(
            rf'resource "cloudflare_dns_record" "{name}" \{{(?P<body>.*?)\n\}}',
            module,
            flags=re.DOTALL,
        )
        assert match is not None
        body = match.group("body")
        assert "depends_on = [" in body
        assert all(dependency in body for dependency in dependencies)


def test_selected_origin_pull_leaf_is_associated_with_both_zone_hostnames() -> None:
    module = (_ROOT / "infra/opentofu/modules/cloudflare-public-edge/main.tf").read_text(
        encoding="utf-8"
    )

    assert 'resource "cloudflare_authenticated_origin_pulls" "hostname"' in module
    assert "for_each = local.edge_enabled ? local.origin_pull_hostnames : toset([])" in module
    assert "hostname = each.value" in module
    assert "cert_id  = var.origin_pull_certificate_id" in module
    assert "depends_on = [cloudflare_authenticated_origin_pulls.hostname]" in module


def test_production_accepts_both_cloudflare_certificate_id_forms() -> None:
    production_variables = (
        _ROOT / "infra/opentofu/environments/production/variables.tf"
    ).read_text(encoding="utf-8")
    module_variables = (
        _ROOT / "infra/opentofu/modules/cloudflare-public-edge/variables.tf"
    ).read_text(encoding="utf-8")
    accepted_grammar = "^(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$"

    assert production_variables.count(accepted_grammar) == _PRODUCTION_CERTIFICATE_VARIABLE_COUNT
    assert module_variables.count(accepted_grammar) == 1


def test_generation_bootstrap_binds_the_staged_or_required_origin_pull_mode() -> None:
    tasks = (_CADDY_ROLE / "tasks/main.yml").read_text(encoding="utf-8")
    check = (_CADDY_ROLE / "templates/check-caddy-generation.j2").read_text(encoding="utf-8")

    for source in (tasks, check):
        assert "--origin-pull-staged" in source
        assert "--origin-pull-required" in source
        assert "caddy_origin_pull_enforcement_enabled" in source


def test_disposable_m3_qualification_keeps_its_own_caddy_runtime() -> None:
    playbook = (_ROOT / "config/ansible/playbooks/m3-qualification.yml").read_text(encoding="utf-8")

    assert "caddy_generation_enabled: false" in playbook


def test_production_unit_executes_only_the_descriptor_pinned_launcher() -> None:
    unit = (_CADDY_ROLE / "templates/caddy-generation.service.j2").read_text(encoding="utf-8")

    assert "OpenFile={{ caddy_publication_lock_path }}:publication-lock" in unit
    assert ":publication-lock:read-write" not in unit
    assert (
        "ExecStart=/usr/local/libexec/lowerduckpond/launch-caddy-generation "
        "{{ static_host_agent_artifact_sha256 }}"
    ) in unit
    assert (
        "ExecStartPre=+/usr/local/libexec/lowerduckpond/prepare-caddy-generation-start "
        "{{ static_host_agent_artifact_sha256 }}"
    ) in unit
    assert (
        "ExecStartPost=+/usr/local/libexec/lowerduckpond/verify-caddy-generation-start "
        "{{ static_host_agent_artifact_sha256 }}"
    ) in unit
    assert "OnFailure=caddy-recovery.service" in unit
    assert "After=network-online.target caddy-recovery.service" in unit
    assert "Wants=network-online.target caddy-recovery.service" in unit
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
    for command, entrypoint in (
        ("prepare-caddy-generation-start", "caddy_start_gate_main"),
        ("recover-caddy-generation-start", "caddy_start_recovery_main"),
        ("verify-caddy-generation-start", "caddy_start_verifier_main"),
    ):
        wrapper = (_CADDY_ROLE / f"files/{command}").read_text(encoding="utf-8")
        assert entrypoint in wrapper
        assert "static-host-agent/{artifact_sha256}/site-packages" in wrapper
        assert "current/site-packages" not in wrapper

    recovery = (_CADDY_ROLE / "templates/caddy-recovery.service.j2").read_text(encoding="utf-8")
    assert "Before=caddy.service" in recovery
    assert "Restart=on-failure" in recovery
    assert "StartLimitBurst=3" in recovery
    assert "TimeoutStartSec=2min" in recovery
    assert "OpenFile={{ caddy_publication_lock_path }}:publication-lock" in recovery
    assert (
        "ExecStart=/usr/local/libexec/lowerduckpond/recover-caddy-generation-start "
        "{{ static_host_agent_artifact_sha256 }}"
    ) in recovery


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

    health_unit = (
        _ROOT / "config/ansible/roles/monitoring/templates/lowerduckpond-health.service.j2"
    ).read_text(encoding="utf-8")
    assert "monitoring_caddy_publication_lock_path" in health_unit

    preflight = (_ROOT / "scripts/preflight-m3-6-production").read_text(encoding="utf-8")
    assert "the Caddy startup-intent inventory is not resumable" in preflight
    assert "pending)" in preflight
    assert "the pending Caddy transaction has no durable intent" in preflight
