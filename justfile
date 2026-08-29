set shell := ["bash", "-euo", "pipefail", "-c"]

# List the available project commands.
default:
    @just --list

# Install locked dependencies and local Git hooks.
setup: _sync
    uv run pre-commit install --install-hooks

# Synchronize every workspace package from the committed lockfile.
[private]
_sync:
    uv sync --all-packages --all-groups --frozen

# Apply repository formatters.
format: _sync
    uv run ruff format .
    uv run ruff check --fix .
    tofu fmt -recursive infra/opentofu

# Run every validation required by CI.
check: check-pre-commit check-links check-python check-m3-contract-spine check-m3-qualification check-m3-archive-storage check-cloudflare-networks check-opentofu check-ansible check-actions check-secrets

# Run file hygiene, Markdown, Python, secret, and OpenTofu format hooks.
check-pre-commit: _sync
    git ls-files --cached --others --exclude-standard -z | xargs -0 uv run pre-commit run --show-diff-on-failure --files

# Check external and internal links in Markdown documentation.
check-links:
    lychee --config .lychee.toml "**/*.md" "*.md"

# Format-check, lint, type-check, and test Python workspace packages.
check-python: _sync
    uv run ruff format --check .
    uv run ruff check .
    uv run mypy
    uv run pytest

# Prove the standalone M3.2 contract wheel carries and loads every strict schema.
check-m3-static-contracts: _sync
    repo_root="$PWD"; build_dir="$(mktemp -d)"; trap 'find "$build_dir" -depth -delete' EXIT; uv build --package lowerduckpond-static-contracts --wheel --out-dir "$build_dir" >/dev/null; wheel=("$build_dir"/*.whl); extract_dir="$build_dir/extracted"; mkdir "$extract_dir"; uv run python -m zipfile -e "${wheel[0]}" "$extract_dir"; fixtures="$repo_root/tests/static-publication/fixtures/accepted"; cd "$build_dir"; PYTHONPATH="$extract_dir" uv run --project "$repo_root" --frozen python -c 'import sys; from pathlib import Path; import lowerduckpond_static_contracts as package; from lowerduckpond_static_contracts import ContractKind, decode_contract; assert Path(package.__file__).is_relative_to(Path(sys.argv[1])); decoded = [decode_contract(path.read_bytes()) for path in Path(sys.argv[2]).glob("*.json")]; assert {document["kind"] for document in decoded} == {kind.value for kind in ContractKind}' "$extract_dir" "$fixtures"

# Prove the pure M3.2 root-domain wheel loads with the contract wheel.
check-m3-static-domain: _sync
    repo_root="$PWD"; build_dir="$(mktemp -d)"; trap 'find "$build_dir" -depth -delete' EXIT; uv build --package lowerduckpond-static-contracts --wheel --out-dir "$build_dir" >/dev/null; uv build --package lowerduckpond-static-domain --wheel --out-dir "$build_dir" >/dev/null; extract_dir="$build_dir/extracted"; mkdir "$extract_dir"; for wheel in "$build_dir"/*.whl; do uv run python -m zipfile -e "$wheel" "$extract_dir"; done; cd "$build_dir"; PYTHONPATH="$extract_dir" uv run --project "$repo_root" --frozen python -c 'import sys; from pathlib import Path; import lowerduckpond_static_contracts as contracts; import lowerduckpond_static_domain as domain; root = Path(sys.argv[1]); assert Path(contracts.__file__).is_relative_to(root); assert Path(domain.__file__).is_relative_to(root); assert domain.generate_uuid7(clock=lambda: 0, entropy=lambda length: bytes(length)) == "00000000-0000-7000-8000-000000000000"' "$extract_dir"

# Prove the M3.3 host-agent wheel owns I/O and loads only over the pure lower layers.
check-m3-static-host-agent: _sync
    repo_root="$PWD"; build_dir="$(mktemp -d)"; trap 'find "$build_dir" -depth -delete' EXIT; uv build --package lowerduckpond-static-contracts --wheel --out-dir "$build_dir" >/dev/null; uv build --package lowerduckpond-static-domain --wheel --out-dir "$build_dir" >/dev/null; uv build --package lowerduckpond-static-host-agent --wheel --out-dir "$build_dir" >/dev/null; extract_dir="$build_dir/extracted"; mkdir "$extract_dir"; for wheel in "$build_dir"/*.whl; do uv run python -m zipfile -e "$wheel" "$extract_dir"; done; cd "$build_dir"; PYTHONPATH="$extract_dir" uv run --project "$repo_root" --frozen python -c 'import sys; from pathlib import Path; import lowerduckpond_static_contracts as contracts; import lowerduckpond_static_domain as domain; import lowerduckpond_static_host_agent as agent; root = Path(sys.argv[1]); assert all(Path(package.__file__).is_relative_to(root) for package in (contracts, domain, agent)); assert [lock.name for lock in agent.LockName] == ["INTAKE", "EXPORT", "PUBLICATION", "TENANT_STATE"]' "$extract_dir"

# Run every independently packaged M3 static-publication proof obligation.
check-m3-contract-spine: check-m3-static-contracts check-m3-static-domain check-m3-static-host-agent

# Exercise the local, no-cloud portion of the exact, no-skip M3.0 gate.
check-m3-qualification: _sync
    evidence_dir="$(mktemp -d)"; trap 'find "$evidence_dir" -depth -delete' EXIT; uv run ldp-m3-qualify libraries --run-id 0198d17f-6f4a-7000-8000-000000000001 --source-revision 0000000000000000000000000000000000000000 --output "$evidence_dir/libraries.json"
    bash -n scripts/m3-qualification config/ansible/roles/m3_qualification/files/m3-caddy-hook
    uv run python -m py_compile scripts/assert_m3_qualification_plan.py config/ansible/roles/m3_qualification/files/m3-caddy-generation config/ansible/roles/m3_qualification/files/m3-qualification-tmpfs config/ansible/roles/m3_qualification/files/m3-qualification-uuid
    scripts/check-m3-browser-boundary

# Exercise M3.1 versions, delete markers, pagination, and multipart accounting.
check-m3-archive-storage: _sync
    scripts/check-m3-archive-storage

# Run the live M3.1 storage gate from a trusted workstation.
m3-archive-qualification: _sync
    scripts/m3-archive-qualification

# Independently exercise the cookie boundary in stock Firefox and Chrome.
check-m3-stock-browsers: _sync
    scripts/check-m3-stock-browsers

# Compare the committed firewall allowlist with Cloudflare's published proxy ranges.
check-cloudflare-networks: _sync
    uv run python scripts/check_cloudflare_networks.py

# Run one trusted-workstation M3.0 action (see the operations guide).
m3-qualification action *arguments: _sync
    scripts/m3-qualification "{{ action }}" {{ arguments }}

# Select the primary M3.0 authenticated-origin-pull generation.
m3-use-primary:
    scripts/set-m3-origin-pull-generation primary

# Select the replacement M3.0 authenticated-origin-pull generation.
m3-use-replacement:
    scripts/set-m3-origin-pull-generation replacement

# Format, validate, lint, and security-scan every OpenTofu root and module.
check-opentofu:
    tofu fmt -check -recursive infra/opentofu
    validation_dir="$(mktemp -d)"; trap 'find "$validation_dir" -depth -delete' EXIT; git ls-files --cached --others --exclude-standard -z -- infra/opentofu platform/cloudflare-networks.json | tar --null -cf - -T - | tar -xf - -C "$validation_dir"; for root in "$validation_dir"/infra/opentofu/bootstrap-state "$validation_dir"/infra/opentofu/environments/*; do TF_VAR_state_encryption_passphrase=ci-only-example-passphrase-0000000000 tofu -chdir="$root" init -backend=false -input=false; TF_VAR_state_encryption_passphrase=ci-only-example-passphrase-0000000000 tofu -chdir="$root" validate; tflint --chdir="$root" --config="$(pwd)/.tflint.hcl"; done
    trivy config --exit-code 1 --severity HIGH,CRITICAL infra/opentofu

# Lint, syntax-check, and acceptance-test the Ansible configuration.
check-ansible: _sync
    bash -n scripts/configure-production
    bash -n scripts/check-production-inventory
    bash -n config/ansible/roles/caddy/files/caddy-validate
    scripts/check-production-inventory
    uv run ansible-galaxy collection install --no-deps --requirements-file config/ansible/requirements.yml
    ANSIBLE_CONFIG=config/ansible/ansible.cfg uv run ansible-lint config/ansible
    ANSIBLE_CONFIG=config/ansible/ansible.cfg uv run ansible-playbook --inventory config/ansible/inventories/development/hosts.yml --syntax-check config/ansible/playbooks/site.yml
    ANSIBLE_CONFIG=config/ansible/ansible.cfg uv run ansible-playbook --inventory config/ansible/inventories/development/hosts.yml --syntax-check config/ansible/playbooks/acceptance.yml
    M3_QUALIFICATION_EXPECTED_IPV4=192.0.2.1 M3_QUALIFICATION_EXPECTED_DROPLET_ID=123456789 M3_QUALIFICATION_EXPECTED_RUN_ID=0198d17f-6f4a-7000-8000-000000000001 M3_QUALIFICATION_EXPECTED_SOURCE_REVISION=0000000000000000000000000000000000000000 M3_QUALIFICATION_EXPECTED_ADMIN_SOURCE_CIDRS_JSON='["192.0.2.1/32"]' M3_QUALIFICATION_CLOUDFLARE_API_TOKEN=syntax-only-placeholder-token M3_QUALIFICATION_ORIGIN_PULL_TRUST=dual M3_QUALIFICATION_PRIMARY_CA_PATH=/tmp/primary-ca.pem M3_QUALIFICATION_REPLACEMENT_CA_PATH=/tmp/replacement-ca.pem ANSIBLE_CONFIG=config/ansible/ansible.cfg uv run ansible-playbook --inventory config/ansible/inventories/qualification/hosts.yml --syntax-check config/ansible/playbooks/m3-qualification.yml
    cd config/ansible && ANSIBLE_CONFIG="$(pwd)/ansible.cfg" uv run molecule test --scenario-name default

# Converge production twice and run host acceptance and restore checks.
configure-production: _sync
    scripts/configure-production

# Validate GitHub Actions workflow syntax and expressions.
check-actions:
    actionlint

# Scan the complete Git history and every working-tree file for credentials.
check-secrets:
    gitleaks git --redact --no-banner --verbose .
    gitleaks dir --redact --no-banner --verbose .
