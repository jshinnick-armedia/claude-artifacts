# STIG Tailoring & Exception Documentation

When a STIG control cannot be applied because it breaks application functionality,
conflicts with operational requirements, or is not applicable to the environment,
you must document the exception formally. This file covers the tailoring process,
exception formats, POA&M (Plan of Action & Milestones), and risk acceptance.

## Table of Contents

1. [When to Tailor](#when-to-tailor)
2. [Tailoring File Format](#tailoring-file-format)
3. [JSON Schema for Automation](#json-schema)
4. [POA&M Entry Format](#poam-format)
5. [Risk Acceptance Levels](#risk-acceptance-levels)
6. [Compensating Controls](#compensating-controls)
7. [Tailoring Review Workflow](#review-workflow)
8. [Common Exceptions by Technology](#common-exceptions)
9. [Generating Tailoring Reports](#generating-reports)

---

## When to Tailor

Tailoring is appropriate when:

- **Technical conflict**: Applying the control breaks the application (e.g., FIPS mode
  disables an algorithm the app requires).
- **Not applicable**: The control doesn't apply (e.g., "disable Bluetooth" on a
  headless cloud server that has no Bluetooth hardware).
- **Operational conflict**: The control interferes with required operations (e.g.,
  IP forwarding disabled but the host is a NAT gateway).
- **Compensating control exists**: An alternative control provides equivalent or
  better protection (e.g., CloudWatch logging instead of local audit HALT on disk full).

Tailoring is **NOT** appropriate when:

- The control is inconvenient but not technically impossible.
- You haven't tested whether the control actually breaks anything.
- You want to skip it because it's "too much work."

---

## Tailoring File Format

Each system or system group gets a tailoring file in YAML format that documents
every exception. Store these alongside your hardening automation.

### YAML Tailoring File

```yaml
# tailoring.yml — STIG exceptions for [system/application name]
metadata:
  system_name: "web-tier-prod"
  stig_name: "RHEL 9 STIG"
  stig_version: "V1R2"
  date_created: "2026-01-15"
  last_reviewed: "2026-01-15"
  reviewed_by: "J. Smith, ISSO"
  approved_by: "M. Johnson, AO"
  environment: "production"
  next_review_date: "2026-07-15"

exceptions:
  - finding_id: "RHEL-09-253010"
    title: "IP forwarding must be disabled"
    severity: "CAT II"
    status: "tailored"             # tailored | poam | risk_accepted | not_applicable
    current_value: "net.ipv4.ip_forward = 1"
    stig_required_value: "net.ipv4.ip_forward = 0"
    justification: >
      This host serves as a NAT gateway for private subnets. IP forwarding
      is required for its primary function.
    compensating_controls:
      - "Security groups restrict forwarding to VPC CIDR only"
      - "Network ACLs limit traffic to approved ports"
      - "VPC Flow Logs enabled for all traffic"
    risk_level: "low"
    approved_date: "2026-01-15"
    review_date: "2026-07-15"
    owner: "Platform Team"

  - finding_id: "RHEL-09-671010"
    title: "FIPS mode must be enabled"
    severity: "CAT I"
    status: "poam"                 # Will be fixed, not yet
    current_value: "FIPS disabled"
    stig_required_value: "FIPS enabled"
    justification: >
      Application uses Bouncy Castle crypto provider with algorithms not
      available in FIPS mode. Migration to FIPS-compliant provider is underway.
    poam:
      milestone: "Migrate to FIPS-compliant crypto provider"
      estimated_completion: "2026-06-30"
      resources_needed: "Developer time — 2 sprints"
      current_progress: "Provider evaluation complete, implementation in Q2"
    compensating_controls:
      - "TLS 1.2+ enforced at load balancer"
      - "Application encrypts data at rest using AES-256"
      - "Network restricted to private subnets"
    risk_level: "medium"
    approved_date: "2026-01-15"
    owner: "Application Team"

  - finding_id: "RHEL-09-291020"
    title: "Bluetooth service must be disabled"
    severity: "CAT II"
    status: "not_applicable"
    justification: >
      EC2 instances do not have Bluetooth hardware. Service does not exist.
    risk_level: "none"
```

---

## JSON Schema

For automated tooling, use JSON format with the same structure:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "metadata": {
      "type": "object",
      "properties": {
        "system_name": { "type": "string" },
        "stig_name": { "type": "string" },
        "stig_version": { "type": "string" },
        "date_created": { "type": "string", "format": "date" },
        "last_reviewed": { "type": "string", "format": "date" },
        "reviewed_by": { "type": "string" },
        "approved_by": { "type": "string" },
        "environment": { "type": "string", "enum": ["dev", "staging", "production"] },
        "next_review_date": { "type": "string", "format": "date" }
      },
      "required": ["system_name", "stig_name", "environment"]
    },
    "exceptions": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "finding_id": { "type": "string" },
          "title": { "type": "string" },
          "severity": { "type": "string", "enum": ["CAT I", "CAT II", "CAT III"] },
          "status": {
            "type": "string",
            "enum": ["tailored", "poam", "risk_accepted", "not_applicable"]
          },
          "current_value": { "type": "string" },
          "stig_required_value": { "type": "string" },
          "justification": { "type": "string" },
          "compensating_controls": {
            "type": "array",
            "items": { "type": "string" }
          },
          "risk_level": {
            "type": "string",
            "enum": ["none", "low", "medium", "high", "critical"]
          },
          "poam": {
            "type": "object",
            "properties": {
              "milestone": { "type": "string" },
              "estimated_completion": { "type": "string", "format": "date" },
              "resources_needed": { "type": "string" },
              "current_progress": { "type": "string" }
            }
          },
          "approved_date": { "type": "string", "format": "date" },
          "review_date": { "type": "string", "format": "date" },
          "owner": { "type": "string" }
        },
        "required": ["finding_id", "severity", "status", "justification"]
      }
    }
  }
}
```

---

## POA&M Format

A POA&M (Plan of Action & Milestones) is required for findings that will be fixed
but not immediately. It differs from a permanent tailoring exception.

### Required Fields

| Field | Description | Example |
|-------|------------|---------|
| Finding ID | STIG finding identifier | RHEL-09-671010 |
| Weakness | Description of the gap | FIPS mode not enabled |
| Severity | CAT I / II / III | CAT I |
| Responsible POC | Who owns the fix | App Team Lead |
| Milestone | What will be done | Migrate to FIPS-compliant provider |
| Milestone Date | When it will be done | 2026-06-30 |
| Resources | What's needed | 2 developer sprints |
| Status | Current progress | In progress — 40% complete |
| Compensating Controls | Interim mitigations | TLS 1.2 enforced, AES-256 at rest |

### POA&M CSV for Import into eMASS or Xacta

```csv
"POA&M ID","Finding ID","Weakness","Severity","Responsible","Milestone","Milestone Date","Resources","Status","Compensating Controls"
"POAM-001","RHEL-09-671010","FIPS mode not enabled","CAT I","App Team","Migrate crypto provider","2026-06-30","2 dev sprints","In Progress","TLS 1.2+, AES-256 at rest"
"POAM-002","SQL6-D0-001500","xp_cmdshell enabled","CAT II","DBA Team","Refactor stored procedures","2026-04-30","1 dev sprint","Not Started","Proxy account, restricted role"
```

---

## Risk Acceptance Levels

| Level | Definition | Who Approves | Max Duration |
|-------|-----------|-------------|-------------|
| **None** | Not applicable — no risk | ISSM | Permanent |
| **Low** | Minimal additional risk, strong compensating controls | ISSM | 1 year, then re-review |
| **Medium** | Moderate risk, compensating controls reduce but don't eliminate | ISSO + AO | 6 months |
| **High** | Significant risk, limited compensating controls | AO | 90 days (must have POA&M) |
| **Critical** | CAT I with no compensating controls — should not be accepted | AO + CIO | 30 days emergency only |

---

## Compensating Controls

Good compensating controls are specific, measurable, and address the same threat
as the original STIG control.

### Strong Compensating Controls

| Original Control | Compensating Control | Why It Works |
|-----------------|---------------------|-------------|
| FIPS mode | TLS 1.2+ enforced, AES-256 at rest | Same crypto strength via different mechanism |
| Audit HALT on disk full | CloudWatch Logs agent + alarm | Logs preserved offsite, alert on failure |
| Disable IP forwarding | Security groups + NACLs + flow logs | Network-level equivalent restriction |
| Account lockout never auto-unlock | MFA + CloudWatch alarm on lockout events | Stronger auth + monitoring |

### Weak Compensating Controls (Avoid)

| Original Control | Weak Substitute | Why It's Weak |
|-----------------|----------------|-------------|
| Disable SMBv1 | "We have a firewall" | Doesn't prevent lateral movement inside the firewall |
| Password complexity | "Users promise to use good passwords" | Not enforceable |
| Disable root SSH | "We trust our admins" | Trust is not a control |
| Enable audit logging | "We review logs monthly" | Too infrequent to detect active compromise |

---

## Review Workflow

```
1. Engineer identifies STIG control that can't be applied
   │
2. Engineer documents in tailoring.yml with:
   ├─ Finding ID, severity, justification
   ├─ Compensating controls (specific and measurable)
   └─ Risk level assessment
   │
3. ISSO reviews:
   ├─ Are compensating controls adequate?
   ├─ Is the justification valid (tested, not just assumed)?
   └─ Can a POA&M fix this eventually?
   │
4. If CAT I or high risk → AO must approve
   │
5. Exception entered in:
   ├─ tailoring.yml (automation reference)
   ├─ STIG Viewer .ckl (mark as Not a Finding with comment, or Open with POA&M)
   └─ eMASS/Xacta POA&M (if required)
   │
6. Re-review at next_review_date
   ├─ Is the exception still needed?
   ├─ Has the POA&M been completed?
   └─ Are compensating controls still in place?
```

---

## Common Exceptions by Technology

Consolidated from individual reference files. Each entry here has full details in
the corresponding technology reference file.

### Linux (os-linux.md)
- IP forwarding enabled — NAT/Docker/K8s hosts
- SELinux permissive — custom app (create policy module instead)
- FIPS disabled — legacy crypto dependencies
- Audit HALT → SYSLOG — high availability
- Account lockout auto-unlock — no 24/7 admin

### Windows (os-windows.md)
- Print Spooler enabled — print servers
- WinRM enabled — Ansible/PowerShell remoting
- SMBv1 — legacy device (isolated VLAN)

### Active Directory (active-directory.md)
- Kerberos DES — legacy application
- Unconstrained delegation — specific servers
- WS-Trust endpoints (ADFS) — legacy SAML clients

### Web/App Servers (web-app-servers.md)
- Tomcat Manager kept — CI/CD (localhost-only)
- HTTP enabled (Keycloak) — behind TLS ALB
- ActiveMQ web console — network-accessible with auth

### Java (java-runtime.md)
- TLS 1.0 enabled — legacy backend
- OCSP/CRL disabled — air-gapped network
- FIPS provider disabled — Bouncy Castle dependency

### Databases (databases.md)
- PostgreSQL MD5 — legacy app SCRAM incompatible
- MariaDB local_infile — ETL pipeline
- SQL Server sa enabled — break-glass access
- SQL Server xp_cmdshell — legacy stored proc

---

## Generating Reports

### Python Script: Tailoring Summary Report

```python
#!/usr/bin/env python3
"""Generate a summary report from tailoring YAML files."""

import yaml
import sys
from pathlib import Path
from collections import Counter


def generate_tailoring_report(tailoring_dir: str) -> None:
    """Read all tailoring.yml files and produce a summary."""
    tailoring_dir = Path(tailoring_dir)
    all_exceptions = []

    for yml_file in tailoring_dir.rglob("tailoring.yml"):
        with open(yml_file) as f:
            data = yaml.safe_load(f)
        system = data.get("metadata", {}).get("system_name", yml_file.stem)
        for exc in data.get("exceptions", []):
            exc["_system"] = system
            exc["_file"] = str(yml_file)
            all_exceptions.append(exc)

    if not all_exceptions:
        print("No tailoring files found.")
        return

    # Summary counts
    by_severity = Counter(e["severity"] for e in all_exceptions)
    by_status = Counter(e["status"] for e in all_exceptions)
    by_risk = Counter(e.get("risk_level", "unknown") for e in all_exceptions)

    print("=" * 60)
    print("STIG TAILORING SUMMARY REPORT")
    print("=" * 60)
    print(f"\nTotal exceptions: {len(all_exceptions)}")

    print("\nBy Severity:")
    for sev in ["CAT I", "CAT II", "CAT III"]:
        print(f"  {sev}: {by_severity.get(sev, 0)}")

    print("\nBy Status:")
    for status in ["tailored", "poam", "risk_accepted", "not_applicable"]:
        print(f"  {status}: {by_status.get(status, 0)}")

    print("\nBy Risk Level:")
    for risk in ["none", "low", "medium", "high", "critical"]:
        print(f"  {risk}: {by_risk.get(risk, 0)}")

    # Flag high-risk items
    high_risk = [e for e in all_exceptions if e.get("risk_level") in ("high", "critical")]
    if high_risk:
        print(f"\n⚠ HIGH/CRITICAL RISK EXCEPTIONS ({len(high_risk)}):")
        for e in high_risk:
            print(f"  [{e['severity']}] {e['finding_id']} — {e['_system']}")
            print(f"    Status: {e['status']}, Risk: {e.get('risk_level')}")
            if e.get("poam"):
                print(f"    POA&M target: {e['poam'].get('estimated_completion', 'TBD')}")

    # Overdue POA&Ms
    from datetime import date
    overdue = []
    for e in all_exceptions:
        if e.get("status") == "poam" and e.get("poam", {}).get("estimated_completion"):
            try:
                target = date.fromisoformat(e["poam"]["estimated_completion"])
                if target < date.today():
                    overdue.append(e)
            except ValueError:
                pass
    if overdue:
        print(f"\n❌ OVERDUE POA&Ms ({len(overdue)}):")
        for e in overdue:
            print(f"  {e['finding_id']} — {e['_system']}")
            print(f"    Due: {e['poam']['estimated_completion']}")

    # Exceptions needing review
    from datetime import date as dt_date
    needs_review = [
        e for e in all_exceptions
        if e.get("review_date")
        and dt_date.fromisoformat(e["review_date"]) <= dt_date.today()
    ]
    if needs_review:
        print(f"\n🔄 EXCEPTIONS NEEDING REVIEW ({len(needs_review)}):")
        for e in needs_review:
            print(f"  {e['finding_id']} — {e['_system']} (due: {e['review_date']})")


if __name__ == "__main__":
    generate_tailoring_report(sys.argv[1] if len(sys.argv) > 1 else ".")
```

### Bash: Quick Exception Count

```bash
#!/usr/bin/env bash
# count_exceptions.sh — Quick summary from tailoring files
set -euo pipefail

DIR="${1:-.}"

echo "=== STIG Tailoring Quick Summary ==="
echo ""

for f in $(find "${DIR}" -name "tailoring.yml" -type f); do
    system=$(grep "system_name:" "$f" | head -1 | awk -F: '{print $2}' | xargs)
    total=$(grep -c "finding_id:" "$f" || echo 0)
    cat1=$(grep -A1 "finding_id:" "$f" | grep -c "CAT I" || echo 0)
    poam=$(grep -c 'status: "poam"\|status: poam' "$f" || echo 0)
    echo "  ${system}: ${total} exceptions (${cat1} CAT I, ${poam} POA&M)"
done
```
