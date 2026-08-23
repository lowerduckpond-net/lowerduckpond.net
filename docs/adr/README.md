# Architecture decision records

ADRs capture decisions that shape multiple components or are expensive to
reverse. Copy [`0000-template.md`](0000-template.md), assign the next number, and
submit it with the change that implements the decision.

Accepted decisions:

- [0001: Use OpenTofu](0001-use-opentofu.md)
- [0002: Use Ansible for durable host configuration](0002-use-ansible.md)
- [0003: Use Caddy and Cloudflare DNS-01](0003-caddy-cloudflare-dns.md)
- [0004: Make static hosting the default](0004-static-first.md)
- [0005: Isolate dynamic workloads with rootless Podman](0005-rootless-podman-quadlet.md)
- [0006: Separate the control plane and provisioner](0006-separate-control-plane-provisioner.md)
- [0007: Use MariaDB for tenant SQL](0007-use-mariadb.md)
- [0008: Support archive upload before Git deployment](0008-archive-upload-first.md)
- [0009: Require pilot approval](0009-pilot-administrative-approval.md)
- [0010: Serialize OpenTofu state changes](0010-state-and-serialization.md)
- [0011: License original code under Apache-2.0](0011-apache-2-license.md)
- [0012: Use FastAPI, SQLAlchemy, and uv](0012-python-application-stack.md)
- [0013: Standardize the developer workflow](0013-developer-tooling.md)
- [0014: Use Ubuntu 26.04 LTS initially](0014-ubuntu-host-baseline.md)
- [0015: Start small and preserve resize reversibility](0015-start-small-and-preserve-resize-reversibility.md)
- [0016: Model static publication as an untrusted boundary](0016-model-static-publication-threats.md)
- [0017: Atomically activate immutable static releases](0017-atomically-activate-static-releases.md)
- [0018: Version the static tenant manifest contract](0018-version-static-tenant-manifests.md)
- [0019: Constrain static archives and exports](0019-constrain-static-archives-and-exports.md)
- [0020: Use a trusted-workstation static operator interface](0020-use-a-trusted-workstation-static-operator-interface.md)
- [0021: Define static tenant lifecycle semantics](0021-define-static-tenant-lifecycle-semantics.md)
- [0022: Test static publication as a security boundary](0022-test-static-publication-as-a-security-boundary.md)
- [0023: Separate reusable slugs from immutable tenant origins](0023-separate-reusable-slugs-from-tenant-origins.md)
- [0024: Use lowerduckpond.net as the tenant public suffix](0024-use-lowerduckpond-net-as-the-tenant-public-suffix.md)
- [0025: Separate tenant archives from platform backups](0025-separate-tenant-archives-from-platform-backups.md)
- [0026: Separate static operation from host administration](0026-separate-static-operation-from-host-administration.md)
- [0027: Gate production static publication](0027-gate-production-static-publication.md)
