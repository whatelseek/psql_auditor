# Converting CIS / Nessus `.audit` files

CIS WorkBench and Nessus export benchmarks as `.audit` (not Markdown).
This repo’s agent only loads `agents/*.md` checklists, so convert first.

## Convert

```bash
python scripts/convert_cis_audit.py \
  agents/vendor/CIS_Ubuntu_24.04_LTS_v1.0.0_L2_Server.audit \
  --framework-id ubuntu_cis_24_l2 \
  --out-md agents/ubuntu_cis_24_l2.md \
  --out-playbook agents/playbooks/ubuntu_cis_24_l2.yaml
```

Produces:

- `agents/<id>.md` — `REQ-NNN` checklist with CIS IDs, verify hints, remediation
- `agents/playbooks/<id>.yaml` — preferred `ssh_run` commands per REQ

`agents/` is bind-mounted into the agent container; no image rebuild is required
for new frameworks (restart optional if the process cached discovery).

## Notes

- Only controls whose `description` starts with a CIS id (`1.1.1.6 Ensure …`)
  become REQs. Helper probes without ids are folded into composite `<report>` controls.
- The sample Ubuntu 24.04 L2 export in `agents/vendor/` yields **61** controls
  (partial chapter set in that file, not the entire published benchmark).
- Prefer `ubuntu_cis_24_l2` for auto host detect; scaffold `ubuntu_cis` has no `detect:`.
