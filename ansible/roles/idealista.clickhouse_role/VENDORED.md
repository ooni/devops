# Vendored role: idealista.clickhouse_role

This directory is vendored from
[idealista/clickhouse_role](https://github.com/idealista/clickhouse_role) tag `3.5.2`
(`5ca82f11c0bd554c4b52045a57cb0e0bc6addb61`, upstream `main` HEAD as of vendoring),
rather than pulled from Galaxy/git at `ansible-galaxy install` time.

Apache License 2.0 — see `LICENSE` in this directory, unchanged from upstream.

## Why vendor instead of leaving it on Galaxy

1. `check_ansible.yml` never runs `ansible-galaxy install` — it only `apt install`s
   Ansible itself, then runs `ansible-playbook playbook.yml --check --diff` directly.
   `playbook.yml → deploy-tier0.yml → deploy-clickhouse.yml` pulls in
   `idealista.clickhouse_role`, so it's never actually been resolvable in CI, the same
   failure class as the recurring `[ERROR]: the role 'geerlingguy.docker' was not found`
   visible throughout this repo's PR history. Vendoring fixes CI's ability to actually
   check-mode-validate changes to this path for the first time.
2. Upstream is slow: [PR #80](https://github.com/idealista/clickhouse_role/pull/80), a
   basic Debian 12+/13 compatibility fix, has been open since March 2026 with no review.
   The last actual merge to upstream `main` was December 2024.

The commits that follow this one apply specific fixes on top of the unmodified upstream
code vendored here; see each commit's own message, and the rest of this file (extended
commit by commit) for detail.

## Pruning

Standalone-repo scaffolding with no purpose once vendored was removed: `.github/`
(issue/PR templates, CI config for the old standalone repo), `.travis.yml`, `.yamllint`,
`.ansible-lint`, `.gitattributes`, `.gitignore`, `Pipfile[.lock]` and
`test-requirements.txt` (molecule/Travis test env deps), `molecule/` (standalone
Docker-based role tests), `logo.gif` (project branding). Kept: `LICENSE`, `README.md`,
`CHANGELOG.md` (required/useful for attribution and history), plus the actual functional
role content (`defaults/`, `handlers/`, `meta/`, `tasks/`, `templates/`) untouched.

## Resolution

No other changes were needed anywhere else in this repo.
`ansible/roles/oonidata_clickhouse/tasks/main.yml`'s
`include_role: name: idealista.clickhouse_role` resolves the vendored copy automatically
— Ansible's default role search includes `<playbook-relative>/roles/`, and the vendored
role lives right there next to every other role in this repo. Verified directly: a
throwaway `include_role` test playbook placed outside `ansible/` (no sibling `roles/`)
fails with `role not found`; the identical playbook placed inside `ansible/` resolves the
role cleanly.

## Updating this role

Edit files directly in this directory and commit normally — it's just a regular part of
this repo now, no special process needed.
