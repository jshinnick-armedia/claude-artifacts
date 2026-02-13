# Backup & Rollback for STIG Hardening

**Read this file FIRST before any hardening work.** Every hardening operation must
be preceded by a recoverable backup. This file covers AMIs for EC2, RDS snapshots
for databases, and filesystem-level backups for non-AWS workloads.

## Table of Contents

1. [Pre-Hardening Checklist](#pre-hardening-checklist)
2. [EC2 AMI Snapshots (Python)](#ec2-ami-snapshots)
3. [RDS Snapshots (Python)](#rds-snapshots)
4. [Filesystem Backup (Bash)](#filesystem-backup)
5. [Active Directory Backup (PowerShell)](#active-directory-backup)
6. [SQL Server Backup (T-SQL / PowerShell)](#sql-server-backup)
7. [Rollback Procedures](#rollback-procedures)
8. [Verification After Rollback](#verification-after-rollback)

---

## Pre-Hardening Checklist

Before running any hardening script, confirm all of these:

```
□ Backup created (AMI / RDS snapshot / filesystem)
□ Backup verified (status = "available" / "completed")
□ Backup tagged with: Purpose=pre-stig-hardening, Date, TargetSTIG, Environment
□ Application health check passing before changes
□ Rollback procedure documented and tested in lower environment
□ Change window approved (if production)
□ Team notified
```

---

## EC2 AMI Snapshots

### Create Pre-Hardening AMI (Idempotent Python)

```python
import boto3
import datetime


def create_pre_hardening_ami(
    instance_id: str, stig_name: str, environment: str,
    no_reboot: bool = True, region: str = "us-east-1"
) -> str:
    """Create an AMI before STIG hardening. Skip if one already exists today.

    Args:
        instance_id: EC2 instance to snapshot.
        stig_name: e.g. "rhel9-stig", "win2022-stig", "tomcat-stig"
        no_reboot: If True, don't reboot instance (faster but less consistent).
                   Set False for production systems with heavy I/O.
    Returns:
        AMI ID.
    """
    ec2 = boto3.client("ec2", region_name=region)
    today = datetime.date.today().isoformat()
    ami_name = f"pre-stig-{stig_name}-{instance_id}-{today}"

    # Check if AMI already created today
    existing = ec2.describe_images(
        Owners=["self"],
        Filters=[{"Name": "name", "Values": [ami_name]}],
    )["Images"]
    if existing:
        ami_id = existing[0]["ImageId"]
        print(f"  ✓ Pre-hardening AMI already exists: {ami_id}")
        return ami_id

    # Create AMI
    response = ec2.create_image(
        InstanceId=instance_id,
        Name=ami_name,
        Description=f"Pre-STIG hardening snapshot for {stig_name}",
        NoReboot=no_reboot,
        TagSpecifications=[{
            "ResourceType": "image",
            "Tags": [
                {"Key": "Name", "Value": ami_name},
                {"Key": "Purpose", "Value": "pre-stig-hardening"},
                {"Key": "STIG", "Value": stig_name},
                {"Key": "SourceInstance", "Value": instance_id},
                {"Key": "Environment", "Value": environment},
                {"Key": "Date", "Value": today},
            ],
        }],
    )
    ami_id = response["ImageId"]
    print(f"  ⏳ Creating AMI {ami_id} — waiting for completion...")

    ec2.get_waiter("image_available").wait(
        ImageIds=[ami_id],
        WaiterConfig={"Delay": 30, "MaxAttempts": 60},  # Up to 30 min
    )
    print(f"  ✓ Pre-hardening AMI ready: {ami_id}")
    return ami_id
```

### Batch AMI for Multiple Instances

```python
def create_batch_pre_hardening_amis(
    instance_ids: list[str], stig_name: str, environment: str,
    region: str = "us-east-1"
) -> dict[str, str]:
    """Create AMIs for multiple instances, then wait for all to complete."""
    ec2 = boto3.client("ec2", region_name=region)
    today = datetime.date.today().isoformat()
    ami_map = {}

    # Kick off all AMIs first (don't wait individually)
    for inst_id in instance_ids:
        ami_name = f"pre-stig-{stig_name}-{inst_id}-{today}"
        existing = ec2.describe_images(
            Owners=["self"], Filters=[{"Name": "name", "Values": [ami_name]}]
        )["Images"]
        if existing:
            ami_map[inst_id] = existing[0]["ImageId"]
            print(f"  ✓ AMI exists for {inst_id}: {ami_map[inst_id]}")
            continue

        response = ec2.create_image(
            InstanceId=inst_id, Name=ami_name, NoReboot=True,
            Description=f"Pre-STIG hardening snapshot",
            TagSpecifications=[{
                "ResourceType": "image",
                "Tags": [
                    {"Key": "Name", "Value": ami_name},
                    {"Key": "Purpose", "Value": "pre-stig-hardening"},
                    {"Key": "STIG", "Value": stig_name},
                    {"Key": "SourceInstance", "Value": inst_id},
                    {"Key": "Environment", "Value": environment},
                    {"Key": "Date", "Value": today},
                ],
            }],
        )
        ami_map[inst_id] = response["ImageId"]
        print(f"  ⏳ AMI started for {inst_id}: {ami_map[inst_id]}")

    # Wait for all pending AMIs
    pending = [aid for aid in ami_map.values()]
    if pending:
        print(f"  ⏳ Waiting for {len(pending)} AMIs to complete...")
        ec2.get_waiter("image_available").wait(
            ImageIds=pending,
            WaiterConfig={"Delay": 30, "MaxAttempts": 60},
        )
    print(f"  ✓ All {len(ami_map)} pre-hardening AMIs ready")
    return ami_map
```

---

## RDS Snapshots

### Create Pre-Hardening RDS Snapshot (Idempotent)

```python
def create_pre_hardening_rds_snapshot(
    db_identifier: str, stig_name: str, environment: str,
    region: str = "us-east-1"
) -> str:
    """Create an RDS snapshot before database STIG hardening.

    For RDS, STIG settings are applied via parameter groups and SQL commands.
    Snapshot ensures you can restore the entire database if changes break things.
    """
    rds = boto3.client("rds", region_name=region)
    today = datetime.date.today().isoformat()
    snap_id = f"pre-stig-{stig_name}-{db_identifier}-{today}"

    # Check if snapshot exists
    try:
        snap = rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"]
        if snap:
            print(f"  ✓ RDS snapshot exists: {snap_id} (status: {snap[0]['Status']})")
            return snap_id
    except rds.exceptions.DBSnapshotNotFoundFault:
        pass

    rds.create_db_snapshot(
        DBInstanceIdentifier=db_identifier,
        DBSnapshotIdentifier=snap_id,
        Tags=[
            {"Key": "Purpose", "Value": "pre-stig-hardening"},
            {"Key": "STIG", "Value": stig_name},
            {"Key": "Environment", "Value": environment},
            {"Key": "Date", "Value": today},
        ],
    )
    print(f"  ⏳ Creating RDS snapshot {snap_id}...")

    rds.get_waiter("db_snapshot_available").wait(
        DBSnapshotIdentifier=snap_id,
        WaiterConfig={"Delay": 30, "MaxAttempts": 120},  # Up to 60 min
    )
    print(f"  ✓ RDS snapshot ready: {snap_id}")
    return snap_id
```

### Aurora Cluster Snapshot

```python
def create_pre_hardening_aurora_snapshot(
    cluster_id: str, stig_name: str, environment: str,
    region: str = "us-east-1"
) -> str:
    rds = boto3.client("rds", region_name=region)
    today = datetime.date.today().isoformat()
    snap_id = f"pre-stig-{stig_name}-{cluster_id}-{today}"

    try:
        snap = rds.describe_db_cluster_snapshots(
            DBClusterSnapshotIdentifier=snap_id
        )["DBClusterSnapshots"]
        if snap:
            print(f"  ✓ Aurora snapshot exists: {snap_id}")
            return snap_id
    except rds.exceptions.DBClusterSnapshotNotFoundFault:
        pass

    rds.create_db_cluster_snapshot(
        DBClusterIdentifier=cluster_id,
        DBClusterSnapshotIdentifier=snap_id,
        Tags=[
            {"Key": "Purpose", "Value": "pre-stig-hardening"},
            {"Key": "STIG", "Value": stig_name},
            {"Key": "Environment", "Value": environment},
        ],
    )
    print(f"  ⏳ Creating Aurora cluster snapshot {snap_id}...")
    rds.get_waiter("db_cluster_snapshot_available").wait(
        DBClusterSnapshotIdentifier=snap_id,
    )
    print(f"  ✓ Aurora snapshot ready: {snap_id}")
    return snap_id
```

---

## Filesystem Backup

For non-AWS or self-managed servers where an AMI isn't available.

### Tar-Based Config Backup (Bash)

```bash
#!/usr/bin/env bash
# backup_configs.sh — Run before STIG hardening on Linux
set -euo pipefail

BACKUP_DIR="/var/backups/pre-stig"
DATE=$(date +%Y-%m-%d)
ARCHIVE="${BACKUP_DIR}/pre-stig-${DATE}.tar.gz"

if [[ -f "${ARCHIVE}" ]]; then
    echo "✓ Backup already exists: ${ARCHIVE}"
    exit 0
fi

mkdir -p "${BACKUP_DIR}"

# Capture critical config files that STIG scripts modify
tar -czf "${ARCHIVE}" \
    /etc/ssh/sshd_config \
    /etc/pam.d/ \
    /etc/security/limits.conf \
    /etc/security/pwquality.conf \
    /etc/audit/auditd.conf \
    /etc/audit/rules.d/ \
    /etc/sysctl.conf \
    /etc/sysctl.d/ \
    /etc/fstab \
    /etc/login.defs \
    /etc/profile.d/ \
    /etc/modprobe.d/ \
    /etc/rsyslog.conf \
    /etc/chrony.conf \
    /etc/aide.conf \
    /etc/selinux/config \
    /etc/sudoers /etc/sudoers.d/ \
    /etc/systemd/ \
    /etc/firewalld/ \
    2>/dev/null || true

echo "✓ Config backup created: ${ARCHIVE} ($(du -h "${ARCHIVE}" | cut -f1))"
```

---

## Active Directory Backup

### AD System State Backup (PowerShell)

```powershell
# Backup-ADPreHardening.ps1 — Run on each domain controller before STIG work
[CmdletBinding()]
param(
    [string]$BackupPath = "C:\Backups\PreSTIG",
    [string]$StigName   = "ad-ds-stig"
)

$date = Get-Date -Format "yyyy-MM-dd"
$backupDir = Join-Path $BackupPath "$StigName-$date"

if (Test-Path $backupDir) {
    Write-Host "✓ Backup already exists: $backupDir" -ForegroundColor Green
    exit 0
}

New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# Windows Server Backup (wbadmin) — system state includes AD database
Write-Host "⏳ Creating system state backup..."
$wbResult = wbadmin start systemstatebackup -backuptarget:$backupDir -quiet
if ($LASTEXITCODE -ne 0) {
    Write-Error "System state backup failed"
    exit 1
}

# Also export current GPOs for easy comparison
Write-Host "⏳ Exporting Group Policy Objects..."
$gpoDir = Join-Path $backupDir "GPO-Export"
New-Item -ItemType Directory -Path $gpoDir -Force | Out-Null
Get-GPO -All | ForEach-Object {
    $_ | Backup-GPO -Path $gpoDir -Comment "Pre-STIG export $date"
}

# Export current security policy
secedit /export /cfg (Join-Path $backupDir "secpol-before.inf") /quiet

# Export certificate templates (if ADCS)
if (Get-Service -Name CertSvc -ErrorAction SilentlyContinue) {
    certutil -catemplates > (Join-Path $backupDir "cert-templates-before.txt")
    certutil -getreg CA > (Join-Path $backupDir "ca-registry-before.txt")
}

Write-Host "✓ AD backup complete: $backupDir" -ForegroundColor Green
```

---

## SQL Server Backup

### Full Database Backup Before Hardening (T-SQL + PowerShell)

```powershell
# Backup-SQLPreHardening.ps1
[CmdletBinding()]
param(
    [string]$SqlInstance  = "localhost",
    [string]$BackupPath   = "C:\Backups\PreSTIG",
    [string[]]$Databases  = @()  # Empty = all user databases
)

$date = Get-Date -Format "yyyy-MM-dd"
$backupDir = Join-Path $BackupPath "sql-stig-$date"

if (Test-Path $backupDir) {
    Write-Host "✓ SQL backup directory exists: $backupDir" -ForegroundColor Green
    exit 0
}
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# Get databases to back up
if (-not $Databases) {
    $Databases = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
        SELECT name FROM sys.databases
        WHERE database_id > 4 AND state_desc = 'ONLINE'
    " | Select-Object -ExpandProperty name
}

foreach ($db in $Databases) {
    $bakFile = Join-Path $backupDir "$db.bak"
    if (Test-Path $bakFile) {
        Write-Host "  ✓ Backup exists: $db" -ForegroundColor Green
        continue
    }
    Write-Host "  ⏳ Backing up $db..."
    Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
        BACKUP DATABASE [$db]
        TO DISK = N'$bakFile'
        WITH FORMAT, COMPRESSION,
             NAME = N'Pre-STIG backup $date',
             STATS = 10;
    "
    Write-Host "  ✓ Backed up: $db → $bakFile" -ForegroundColor Green
}

# Also export server-level security settings
Write-Host "⏳ Exporting server configuration..."
Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
    SELECT name, value_in_use FROM sys.configurations ORDER BY name
" | Export-Csv (Join-Path $backupDir "server-config-before.csv") -NoTypeInformation

Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
    SELECT * FROM sys.server_principals WHERE type IN ('S','U','G')
" | Export-Csv (Join-Path $backupDir "server-principals-before.csv") -NoTypeInformation

Write-Host "✓ SQL Server backup complete: $backupDir" -ForegroundColor Green
```

---

## Rollback Procedures

### Rollback EC2 from AMI

```python
def rollback_from_ami(
    ami_id: str, instance_id: str, subnet_id: str,
    security_group_ids: list[str], instance_type: str = "",
    region: str = "us-east-1"
) -> str:
    """Launch a replacement instance from the pre-hardening AMI.

    This does NOT terminate the hardened instance — the user must verify the
    replacement works before decommissioning the original.
    """
    ec2 = boto3.client("ec2", region_name=region)

    # Determine instance type from original if not specified
    if not instance_type:
        inst = ec2.describe_instances(InstanceIds=[instance_id])
        instance_type = inst["Reservations"][0]["Instances"][0]["InstanceType"]

    result = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        SubnetId=subnet_id,
        SecurityGroupIds=security_group_ids,
        MinCount=1, MaxCount=1,
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [
                {"Key": "Name", "Value": f"rollback-from-{instance_id}"},
                {"Key": "Purpose", "Value": "stig-rollback"},
                {"Key": "SourceAMI", "Value": ami_id},
            ],
        }],
    )
    new_id = result["Instances"][0]["InstanceId"]
    ec2.get_waiter("instance_running").wait(InstanceIds=[new_id])
    print(f"  ✓ Rollback instance running: {new_id}")
    print(f"    Verify it works, then terminate the old instance {instance_id}")
    return new_id
```

### Rollback RDS from Snapshot

```python
def rollback_rds_from_snapshot(
    snapshot_id: str, new_db_identifier: str,
    db_instance_class: str = "", region: str = "us-east-1"
) -> str:
    """Restore an RDS instance from a pre-hardening snapshot.

    The restored instance gets a NEW identifier to avoid conflicts.
    After verifying it works, rename or update your application config.
    """
    rds = boto3.client("rds", region_name=region)

    # Check if restored instance already exists
    try:
        existing = rds.describe_db_instances(
            DBInstanceIdentifier=new_db_identifier
        )["DBInstances"]
        if existing:
            print(f"  ✓ Restored instance exists: {new_db_identifier}")
            return new_db_identifier
    except rds.exceptions.DBInstanceNotFoundFault:
        pass

    kwargs = {
        "DBInstanceIdentifier": new_db_identifier,
        "DBSnapshotIdentifier": snapshot_id,
    }
    if db_instance_class:
        kwargs["DBInstanceClass"] = db_instance_class

    rds.restore_db_instance_from_db_snapshot(**kwargs)
    print(f"  ⏳ Restoring {new_db_identifier} from {snapshot_id}...")

    rds.get_waiter("db_instance_available").wait(
        DBInstanceIdentifier=new_db_identifier,
        WaiterConfig={"Delay": 30, "MaxAttempts": 120},
    )
    print(f"  ✓ Restored: {new_db_identifier}")
    return new_db_identifier
```

### Rollback Linux Configs (Bash)

```bash
#!/usr/bin/env bash
# rollback_configs.sh — Restore from tar backup
set -euo pipefail

ARCHIVE="${1:?Usage: rollback_configs.sh /var/backups/pre-stig/pre-stig-YYYY-MM-DD.tar.gz}"

if [[ ! -f "${ARCHIVE}" ]]; then
    echo "ERROR: Backup not found: ${ARCHIVE}"
    exit 1
fi

echo "⚠ Restoring config files from ${ARCHIVE}"
echo "  This will overwrite current configs. Press Ctrl+C to abort."
read -rp "  Continue? (yes/no) " CONFIRM
if [[ "${CONFIRM}" != "yes" ]]; then
    echo "Aborted."
    exit 0
fi

tar -xzf "${ARCHIVE}" -C / --overwrite
echo "✓ Configs restored. Restart affected services:"
echo "  systemctl restart sshd auditd rsyslog chronyd"
```

---

## Verification After Rollback

After any rollback, verify the system is functional:

```bash
#!/usr/bin/env bash
# verify_rollback.sh
set -euo pipefail

echo "=== Post-Rollback Verification ==="

# 1. System services
echo "[1/4] Checking critical services..."
for svc in sshd auditd rsyslog chronyd; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        echo "  ✓ ${svc} is running"
    else
        echo "  ✗ ${svc} is NOT running — attempting restart"
        systemctl start "${svc}" || echo "  ❌ Failed to start ${svc}"
    fi
done

# 2. Network connectivity
echo "[2/4] Checking network..."
if curl -sf --max-time 5 http://169.254.169.254/latest/meta-data/ >/dev/null; then
    echo "  ✓ IMDS reachable"
else
    echo "  ✗ IMDS not reachable"
fi

# 3. Application health (customize per app)
echo "[3/4] Checking application health..."
if curl -sf --max-time 10 http://localhost:8080/health >/dev/null 2>&1; then
    echo "  ✓ Application health check passed"
else
    echo "  ⚠ Application health check failed or no endpoint"
fi

# 4. SSH access
echo "[4/4] Checking SSH config..."
sshd -t && echo "  ✓ sshd config valid" || echo "  ✗ sshd config invalid"

echo "=== Verification complete ==="
```
