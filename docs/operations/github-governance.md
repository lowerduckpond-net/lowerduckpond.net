# GitHub governance

Status: accepted for the community pilot

## Ownership and access

The `lowerduckpond-net` GitHub organization owns platform repositories. A
personal account must administer the organization, but repositories and public
project identity remain under the organization namespace.

During the single-maintainer phase:

- one organization owner retains administrative and recovery access;
- the visible `maintainers` team receives `Maintain`, not `Admin`, on project
  repositories;
- ordinary contributors use forks and pull requests without organization
  membership;
- organization membership may remain private;
- organization-wide paid controls are not required.

Add a second trusted owner when one is available. Review access whenever a
member joins, changes responsibility, or leaves.

## Repository protections

For each public repository:

- protect `main` with a repository ruleset;
- require pull requests, successful CI, and resolved conversations;
- block force pushes and branch deletion;
- give administrative repository access only to organization owners;
- enable the dependency graph, vulnerability alerts, secret scanning, push
  protection, and private vulnerability reporting;
- allow squash merging and delete merged branches.

An approving review is not required while there is only one maintainer. Add the
requirement before granting a second maintainer merge access.

## Publication checklist

Keep a new repository private until it contains a license, contribution guide,
security policy, CODEOWNERS file, issue templates, passing CI, and a protected
default branch. Enable private vulnerability reporting before making it public.

## Continuity

Organization recovery codes and account recovery material must be stored
offline. Do not put them in a repository, password shared through an issue, or
tenant backup. A handoff should appoint another owner, verify their recovery
access, transfer operational credentials separately, and only then remove the
departing owner.

## Upgrade triggers

Reconsider GitHub Team when the organization has multiple members, sensitive
private repositories, delegated administrators, or enough repositories that
organization-wide policy enforcement materially reduces risk or maintenance.
