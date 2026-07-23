# Audit plan (example)

Put this file next to credentials as `inventory/<ClientName>/PLAN.md`.
At intake **scope** (framework choice), the auditor loads it and prefers these
host → framework pairs over auto-detection. Credentials stay in `INVENTORY.md`.

You can also **paste** the same table in chat at the scope step.

## Host → frameworks

| Host / IP | Frameworks / checks |
|-----------|---------------------|
| 10.0.0.10 | postgres_cis, ubuntu_cis_24_l2 |
| 10.0.0.20 | it_audit |

Framework ids must match `agents/*.md` (`id:` frontmatter).

### Bullet form (also supported)

- 10.0.0.10: postgres_cis, ubuntu_cis_24_l2
- 10.0.0.20: it_audit
