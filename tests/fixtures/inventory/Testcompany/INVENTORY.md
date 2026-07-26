# Inventory — Testcompany

## Credentials & Access

| Access | Host / URL | Port | Username | Secret Reference | Database |
|---|---|---:|---|---|---|
| SSH | 10.200.29.71 | 22 | audit_user | vault://client/ssh/host01 | |
| SSH | 10.200.29.72 | 22 | audit_user | vault://client/ssh/host02 | |
| PostgreSQL | 10.200.29.72 | 5432 | auditor_ro | vault://client/pg/host02 | application_db |
| SSH | 10.200.29.73 | 22 | audit_user | vault://client/ssh/host03 | |
| SSH | 10.200.29.74 | 22 | audit_user | vault://client/ssh/host04 | |
| PostgreSQL | 10.200.29.74 | 5432 | auditor_ro | vault://client/pg/host04 | application_db |
| WinRM | 10.200.29.75 | 5985 | audit_user | vault://client/winrm/host05 | transport=ntlm |

## In-scope hosts

| Host | Operating System | Discovered Services | IP | Access |
|---|---|---|---|---|
| host-01 | Ubuntu | SSH | 10.200.29.71 | SSH |
| host-02 | Ubuntu | SSH, PostgreSQL | 10.200.29.72 | SSH |
| host-03 | Ubuntu | SSH | 10.200.29.73 | SSH |
| host-04 | Ubuntu | SSH, PostgreSQL | 10.200.29.74 | SSH |
| host-05 | Windows Server | WinRM | 10.200.29.75 | WinRM |
