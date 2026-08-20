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
