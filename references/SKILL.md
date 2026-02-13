---
name: stig-hardening
description: >
  DISA STIG and SRG compliance automation for system hardening across Windows, Linux,
  Active Directory (AD, ADCS, ADFS), web/application servers (Tomcat, Apache httpd,
  ActiveMQ, Keycloak), middleware and data services (Apache Solr, OpenSearch, Apache
  ZooKeeper), Java runtimes, and databases (PostgreSQL, MariaDB, SQL Server).
  Includes pre-hardening backup/rollback patterns (AMIs, RDS snapshots), tailoring
  guidance for operational exceptions, and automated compliance scanning. Use this skill
  when the user mentions STIG, SRG, DISA, system hardening, compliance, CIS benchmarks,
  security baselines, security technical implementation guides, CAT I/II/III findings,
  SCAP, POA&M, ATO, RMF, or any of the specific technologies listed. Also trigger on
  phrases like "harden my server", "lock down the database", "harden Solr", "secure
  OpenSearch", "ZooKeeper security", "security compliance", "audit findings", or
  "make this STIG compliant".
---

# STIG Hardening & Compliance Skill

Automated system hardening aligned with DISA Security Technical Implementation Guides
(STIGs) and Security Requirements Guides (SRGs), with pre-hardening snapshots for
safe rollback and a structured tailoring process for operational exceptions.

## Core Principles

1. **Snapshot before hardening** — Always create an AMI (EC2) or RDS snapshot before
   applying any STIG changes. Every hardening script begins with a backup step and
   validates the backup succeeded before proceeding. See `references/backup-rollback.md`.
2. **Idempotency** — All hardening scripts check current state before making changes.
   Running them twice produces the same result. No blind overwrites.
3. **Tailoring over blind compliance** — Not every STIG control applies to every system.
   Document exceptions in a tailoring file with finding ID, justification, risk acceptance,
   and compensating controls. See `references/tailoring.md`.
4. **CAT I first** — Prioritize findings by severity: CAT I (critical, immediate risk),
   then CAT II (medium), then CAT III (low). CAT I findings are showstoppers for ATO.
5. **Test in lower environments** — Harden dev/staging first, validate applications
   still work, then promote to production.
6. **Automation over manual remediation** — Use Ansible, PowerShell, Bash, and Python
   to implement controls so they are repeatable and auditable.
7. **Scan → Fix → Scan** — Use SCAP/STIG Viewer to scan, remediate, then re-scan
   to verify. Never assume a fix worked without validation.

## STIG Quick Reference

| Technology | STIG ID | Automation Tool | Reference File |
|------------|---------|-----------------|---------------|
| RHEL 8/9 / Amazon Linux | RHEL 8/9 STIG | Ansible, Bash | `references/os-linux.md` |
| Windows Server 2019/2022 | WN19/WN22 STIG | PowerShell, GPO | `references/os-windows.md` |
| Active Directory Domain Services | AD DS STIG | PowerShell | `references/active-directory.md` |
| AD Certificate Services | ADCS STIG | PowerShell | `references/active-directory.md` |
| AD Federation Services | ADFS STIG | PowerShell | `references/active-directory.md` |
| Apache Tomcat 9/10 | TCAT STIG | Ansible, Bash | `references/web-app-servers.md` |
| Apache HTTP Server 2.4 | APACHE STIG | Ansible, Bash | `references/web-app-servers.md` |
| ActiveMQ Classic/Artemis | App Server SRG | Bash, Ansible | `references/middleware-data-services.md` |
| Apache Solr | App Server SRG | Bash, Ansible | `references/middleware-data-services.md` |
| OpenSearch (self-managed & AWS) | App Server SRG | Bash, Python/Boto3 | `references/middleware-data-services.md` |
| Apache ZooKeeper | App Server SRG | Bash, Ansible | `references/middleware-data-services.md` |
| Keycloak | App Server SRG | Bash, Python | `references/web-app-servers.md` |
| Java Runtime (JRE/JDK) | JRE 8 STIG | Bash, Python | `references/java-runtime.md` |
| PostgreSQL 12+ | PGS STIG | Ansible, Bash, SQL | `references/databases.md` |
| MariaDB / MySQL | MySQL 8 STIG | Bash, SQL | `references/databases.md` |
| SQL Server 2019+ | SQL Server STIG | PowerShell, T-SQL | `references/databases.md` |

## Decision Tree

```
User request
│
├─ "Harden a Linux server" / RHEL / Amazon Linux
│  ├─ Read: references/backup-rollback.md (AMI snapshot first)
│  └─ Read: references/os-linux.md
│
├─ "Harden a Windows server" / Windows Server
│  ├─ Read: references/backup-rollback.md (AMI snapshot first)
│  └─ Read: references/os-windows.md
│
├─ "Harden Active Directory" / AD / ADCS / ADFS
│  ├─ Read: references/backup-rollback.md (AMI snapshots of DCs)
│  └─ Read: references/active-directory.md
│
├─ "Harden web/app servers" / Tomcat / Apache / Keycloak
│  ├─ Read: references/backup-rollback.md
│  └─ Read: references/web-app-servers.md
│
├─ "Harden middleware" / Solr / OpenSearch / ActiveMQ / ZooKeeper
│  ├─ Read: references/backup-rollback.md
│  ├─ Read: references/middleware-data-services.md
│  └─ Also read: references/java-runtime.md (all are JVM-based)
│
├─ "Harden Java" / JRE / JDK
│  └─ Read: references/java-runtime.md
│
├─ "Harden a database" / PostgreSQL / MariaDB / SQL Server
│  ├─ Read: references/backup-rollback.md (RDS snapshot or data dump)
│  └─ Read: references/databases.md
│
├─ "Document exceptions" / tailoring / POA&M / waiver
│  └─ Read: references/tailoring.md
│
├─ "Rollback" / "Restore from snapshot" / something broke
│  └─ Read: references/backup-rollback.md
│
└─ Mixed / full-stack hardening
   └─ Read references/backup-rollback.md first, then each relevant file
```

**Critical rule**: Always read `references/backup-rollback.md` first when any
hardening work is involved. Snapshots before changes. No exceptions.

## Preferred Automation Tools

| Priority | Tool | Use Case |
|----------|------|----------|
| 1 | Ansible | Linux hardening at scale, multi-host, declarative playbooks |
| 2 | PowerShell | Windows/AD/SQL Server hardening, GPO management |
| 3 | Bash | Single-server Linux fixes, user-data hardening scripts |
| 4 | Python (Boto3) | AWS-level operations: AMIs, snapshots, SSM Run Command |

## Severity Categories

| Category | Impact | SLA | Example |
|----------|--------|-----|---------|
| **CAT I** | High — direct exploit, data loss, system compromise | Fix immediately | Default admin passwords, unpatched critical CVE, no audit logging |
| **CAT II** | Medium — increases attack surface | Fix within 30 days | Weak password policies, missing banners, excess permissions |
| **CAT III** | Low — defense-in-depth | Fix within 90 days | Informational banners, cosmetic policy settings |

## Workflow for Any Hardening Task

1. **Scope** — Identify target systems, OS versions, installed software.
2. **Backup** — Create AMI / RDS snapshot / filesystem backup. Verify it.
3. **Scan** — Run SCAP scan or STIG Viewer checklist to get baseline findings.
4. **Prioritize** — Sort by CAT I → II → III. Identify which findings apply.
5. **Tailor** — Document exceptions for controls that break application functionality
   (see `references/tailoring.md`).
6. **Remediate** — Apply hardening scripts from the relevant reference file.
7. **Validate** — Re-scan. Verify application still works. Run health checks.
8. **Document** — Update tailoring file, export STIG Viewer .ckl, archive scan results.
9. **Promote** — Repeat in staging → production with same scripts.

## Reference Files

| File | When to Read |
|------|-------------|
| `references/backup-rollback.md` | **Always first** — AMI, RDS snapshot, rollback procedures |
| `references/os-linux.md` | RHEL, Amazon Linux, CentOS — OS-level STIG automation |
| `references/os-windows.md` | Windows Server 2019/2022 — OS-level STIG via PowerShell/GPO |
| `references/active-directory.md` | AD DS, ADCS, ADFS STIGs — domain controller hardening |
| `references/web-app-servers.md` | Tomcat, Apache httpd, Keycloak hardening |
| `references/middleware-data-services.md` | Solr, OpenSearch, ActiveMQ (expanded), ZooKeeper — cluster-aware hardening |
| `references/java-runtime.md` | JRE/JDK STIG — crypto, TLS, permissions |
| `references/databases.md` | PostgreSQL, MariaDB, SQL Server STIG automation |
| `references/tailoring.md` | Exception documentation, POA&M, risk acceptance |
