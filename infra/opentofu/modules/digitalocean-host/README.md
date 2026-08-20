# DigitalOcean host module

Creates the replaceable hosting node and its network boundary: a VPC, SSH key,
Basic Droplet, retained reserved IPv4 address, and Cloud Firewall. The Droplet's
disk is deliberately not enlarged during vertical resizes so CPU and memory
changes remain reversible.

Destroying the Droplet does not destroy the reserved address. Removing the
reserved address requires first removing its `prevent_destroy` lifecycle guard
in a separately reviewed change.
