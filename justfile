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
check: check-pre-commit check-links check-python check-opentofu check-ansible check-actions check-secrets

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

# Format, validate, lint, and security-scan every OpenTofu root and module.
check-opentofu:
    tofu fmt -check -recursive infra/opentofu
    validation_dir="$(mktemp -d)"; trap 'find "$validation_dir" -depth -delete' EXIT; git ls-files infra/opentofu | tar -cf - -T - | tar -xf - -C "$validation_dir"; for root in "$validation_dir"/infra/opentofu/bootstrap-state "$validation_dir"/infra/opentofu/environments/*; do TF_VAR_state_encryption_passphrase=ci-only-example-passphrase-0000000000 tofu -chdir="$root" init -backend=false -input=false; TF_VAR_state_encryption_passphrase=ci-only-example-passphrase-0000000000 tofu -chdir="$root" validate; tflint --chdir="$root" --config="$(pwd)/.tflint.hcl"; done
    trivy config --exit-code 1 --severity HIGH,CRITICAL infra/opentofu

# Lint the Ansible tree and syntax-check its foundation playbook.
check-ansible: _sync
    ANSIBLE_CONFIG=config/ansible/ansible.cfg uv run ansible-lint config/ansible
    ANSIBLE_CONFIG=config/ansible/ansible.cfg uv run ansible-playbook --inventory config/ansible/inventories/development/hosts.yml --syntax-check config/ansible/playbooks/site.yml

# Validate GitHub Actions workflow syntax and expressions.
check-actions:
    actionlint

# Scan the complete Git history and every working-tree file for credentials.
check-secrets:
    gitleaks git --redact --no-banner --verbose .
    gitleaks dir --redact --no-banner --verbose .
