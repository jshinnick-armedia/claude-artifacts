# Database STIG Hardening

Covers PostgreSQL 12+, MariaDB/MySQL 8, and SQL Server 2019+. For RDS-managed
databases, some controls are handled by AWS (OS-level, patching) — focus on
parameter group and SQL-level controls. For self-managed databases on EC2,
apply both OS-level and database-level STIGs.

## Table of Contents

1. [RDS vs Self-Managed Scope](#rds-vs-self-managed)
2. [PostgreSQL](#postgresql)
3. [MariaDB / MySQL](#mariadb--mysql)
4. [SQL Server](#sql-server)
5. [Common Tailoring Exceptions](#common-tailoring-exceptions)

---

## RDS vs Self-Managed

| Control Area | RDS | Self-Managed (EC2) |
|-------------|-----|-------------------|
| OS hardening | AWS responsibility | You — see `references/os-linux.md` or `os-windows.md` |
| Patching | Minor: auto; Major: you schedule | You — OS and DB |
| Encryption at rest | Enable at creation (KMS) | You — configure TDE or dm-crypt |
| Encryption in transit | Parameter group: `rds.force_ssl=1` | You — configure TLS certs |
| Audit logging | Parameter group + CloudWatch | You — configure native audit |
| Network isolation | Security groups, private subnets | You — firewall, bind address |
| Backup | Automated snapshots + manual | You — see `references/backup-rollback.md` |
| User/role management | You — SQL commands | You — SQL commands |

**For RDS**: Always snapshot before STIG work. Use `references/backup-rollback.md`
for the `create_pre_hardening_rds_snapshot()` function.

---

## PostgreSQL

### STIG Coverage Map (PGS STIG)

| Finding | Severity | Requirement | Where |
|---------|----------|------------|-------|
| PGS9-00-000100 | CAT I | Encrypt passwords (scram-sha-256) | postgresql.conf, pg_hba.conf |
| PGS9-00-000200 | CAT I | Enforce TLS for connections | postgresql.conf |
| PGS9-00-000300 | CAT II | Enable audit logging (pgaudit) | postgresql.conf |
| PGS9-00-000400 | CAT II | Log connections and disconnections | postgresql.conf |
| PGS9-00-000700 | CAT II | Set connection timeout | postgresql.conf |
| PGS9-00-000800 | CAT II | Limit superuser access | SQL |
| PGS9-00-001000 | CAT II | Revoke public schema privileges | SQL |
| PGS9-00-001200 | CAT II | File permissions on data directory | filesystem |

### postgresql.conf Hardening (Ansible)

```yaml
# roles/stig_postgresql/tasks/main.yml
- name: PGS STIG | Harden postgresql.conf
  ansible.builtin.lineinfile:
    path: "{{ pg_data_dir }}/postgresql.conf"
    regexp: "^#?{{ item.key }}\\s*="
    line: "{{ item.key }} = {{ item.value }}"
    backup: true
  loop:
    # CAT I — Enforce TLS
    - { key: ssl,                    value: "on" }
    - { key: ssl_min_protocol_version, value: "'TLSv1.2'" }
    - { key: ssl_cert_file,          value: "'/etc/ssl/certs/pg-server.crt'" }
    - { key: ssl_key_file,           value: "'/etc/ssl/private/pg-server.key'" }

    # CAT I — SCRAM-SHA-256 password hashing (replaces MD5)
    - { key: password_encryption,    value: "scram-sha-256" }

    # CAT II — Audit logging
    - { key: logging_collector,      value: "on" }
    - { key: log_destination,        value: "'stderr'" }
    - { key: log_directory,          value: "'log'" }
    - { key: log_filename,           value: "'postgresql-%Y-%m-%d.log'" }
    - { key: log_rotation_age,       value: "1d" }
    - { key: log_rotation_size,      value: "100MB" }
    - { key: log_connections,        value: "on" }
    - { key: log_disconnections,     value: "on" }
    - { key: log_line_prefix,        value: "'%m [%p] %u@%d '" }
    - { key: log_statement,          value: "'ddl'" }      # Log all DDL

    # CAT II — pgaudit extension (if installed)
    - { key: shared_preload_libraries, value: "'pgaudit'" }
    - { key: "pgaudit.log",         value: "'write, ddl, role'" }

    # CAT II — Connection limits
    - { key: statement_timeout,      value: "60000" }      # 60 sec
    - { key: idle_in_transaction_session_timeout, value: "600000" }  # 10 min

    # CAT II — Restrict listen address
    - { key: listen_addresses,       value: "'*'" }        # Use pg_hba.conf for access control
  notify: restart postgresql
```

### pg_hba.conf Hardening

```bash
#!/usr/bin/env bash
# harden_pg_hba.sh — Enforce SCRAM-SHA-256 and TLS
set -euo pipefail

PG_HBA="${PG_DATA_DIR:-/var/lib/pgsql/data}/pg_hba.conf"

if [[ ! -f "${PG_HBA}" ]]; then
    echo "ERROR: pg_hba.conf not found at ${PG_HBA}"
    exit 1
fi

# Backup
BACKUP="${PG_HBA}.pre-stig.bak"
[[ -f "${BACKUP}" ]] || cp "${PG_HBA}" "${BACKUP}"

# Replace md5 with scram-sha-256 (CAT I)
if grep -q "md5" "${PG_HBA}"; then
    sed -i 's/md5/scram-sha-256/g' "${PG_HBA}"
    echo "  ✓ Replaced md5 → scram-sha-256"
fi

# Replace trust with scram-sha-256 (except local socket for postgres user)
if grep -qE "trust\s*$" "${PG_HBA}"; then
    # Keep trust only for local postgres (for maintenance)
    sed -i '/^local.*all.*postgres.*trust$/!s/trust$/scram-sha-256/' "${PG_HBA}"
    echo "  ✓ Replaced trust → scram-sha-256 (except local postgres)"
fi

# Enforce hostssl (reject plain host connections) — CAT I
if grep -q "^host\b" "${PG_HBA}"; then
    sed -i 's/^host\b/hostssl/' "${PG_HBA}"
    echo "  ✓ Enforced hostssl for all remote connections"
fi

echo "✓ pg_hba.conf hardened — reload with: pg_ctl reload"
```

### SQL-Level Hardening

```sql
-- stig_postgresql.sql — Run as superuser, idempotent

-- CAT II: Revoke public schema CREATE from PUBLIC
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.role_table_grants
        WHERE grantee = 'PUBLIC' AND table_schema = 'public'
    ) THEN
        REVOKE CREATE ON SCHEMA public FROM PUBLIC;
        RAISE NOTICE '✓ Revoked CREATE on public schema from PUBLIC';
    END IF;
END $$;

-- CAT II: Ensure no superuser roles besides postgres
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT rolname FROM pg_roles
             WHERE rolsuper AND rolname NOT IN ('postgres', 'rdsadmin', 'rds_superuser')
    LOOP
        RAISE WARNING '⚠ Unexpected superuser: % — review and remove', r.rolname;
    END LOOP;
END $$;

-- CAT II: Revoke default execute on public functions from PUBLIC
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

-- CAT II: Set default privileges for new objects
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC;

-- CAT II: Enable pgaudit if extension is available
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- CAT II: Verify password encryption is scram-sha-256
DO $$
BEGIN
    IF current_setting('password_encryption') != 'scram-sha-256' THEN
        RAISE WARNING '⚠ password_encryption is not scram-sha-256';
    ELSE
        RAISE NOTICE '✓ password_encryption = scram-sha-256';
    END IF;
END $$;
```

### RDS Parameter Group (Python/Boto3)

```python
import boto3


def harden_rds_postgres_params(
    db_identifier: str, region: str = "us-east-1"
) -> None:
    """Apply STIG-aligned parameters to an RDS PostgreSQL parameter group.

    Idempotent — only modifies parameters that differ from desired state.
    """
    rds = boto3.client("rds", region_name=region)

    # Get current parameter group
    instance = rds.describe_db_instances(
        DBInstanceIdentifier=db_identifier
    )["DBInstances"][0]
    pg_name = instance["DBParameterGroups"][0]["DBParameterGroupName"]

    stig_params = {
        "rds.force_ssl": "1",                    # CAT I — Force TLS
        "password_encryption": "scram-sha-256",   # CAT I
        "log_connections": "on",                  # CAT II
        "log_disconnections": "on",               # CAT II
        "log_statement": "ddl",                   # CAT II
        "log_min_duration_statement": "1000",     # Log slow queries > 1s
        "shared_preload_libraries": "pgaudit",    # CAT II — audit extension
        "pgaudit.log": "write,ddl,role",          # CAT II
        "idle_in_transaction_session_timeout": "600000",  # 10 min
        "statement_timeout": "60000",             # 60 sec
        "ssl_min_protocol_version": "TLSv1.2",   # CAT I
    }

    # Get current values
    current = {}
    paginator = rds.get_paginator("describe_db_parameters")
    for page in paginator.paginate(DBParameterGroupName=pg_name):
        for param in page["Parameters"]:
            if param["ParameterName"] in stig_params:
                current[param["ParameterName"]] = param.get("ParameterValue")

    # Build list of changes
    changes = []
    for name, desired in stig_params.items():
        if current.get(name) != desired:
            changes.append({
                "ParameterName": name,
                "ParameterValue": desired,
                "ApplyMethod": "pending-reboot",
            })

    if not changes:
        print("  ✓ RDS PostgreSQL parameters already compliant")
        return

    # Apply in batches of 20 (API limit)
    for i in range(0, len(changes), 20):
        rds.modify_db_parameter_group(
            DBParameterGroupName=pg_name,
            Parameters=changes[i:i+20],
        )

    print(f"  ✓ Modified {len(changes)} parameters — reboot required to apply")
    pending = [c["ParameterName"] for c in changes]
    print(f"    Changed: {', '.join(pending)}")
```

---

## MariaDB / MySQL

### STIG Coverage Map (MySQL 8 STIG)

| Finding | Severity | Requirement | Where |
|---------|----------|------------|-------|
| MYS8-00-000100 | CAT I | Remove test database | SQL |
| MYS8-00-000200 | CAT I | Enforce TLS for client connections | my.cnf |
| MYS8-00-000300 | CAT I | No blank passwords | SQL |
| MYS8-00-001000 | CAT II | Enable audit logging | my.cnf |
| MYS8-00-001100 | CAT II | Error log configuration | my.cnf |
| MYS8-00-001300 | CAT II | Restrict FILE privilege | SQL |
| MYS8-00-001500 | CAT II | Disable symbolic links | my.cnf |
| MYS8-00-002000 | CAT II | Set connection timeout | my.cnf |

### Hardening Script (Bash)

```bash
#!/usr/bin/env bash
# harden_mariadb.sh — Idempotent MariaDB/MySQL STIG hardening
set -euo pipefail

MY_CNF="/etc/my.cnf.d/stig-hardening.cnf"
MYSQL_CMD="mysql"  # or mariadb

echo "=== MariaDB/MySQL STIG Hardening ==="

# --- Server config file hardening ---
cat > "${MY_CNF}" << 'EOF'
# STIG Hardening — managed by automation
[mysqld]
# CAT I — Enforce TLS
require_secure_transport = ON
tls_version = TLSv1.2,TLSv1.3
ssl_cert = /etc/ssl/certs/mysql-server.crt
ssl_key = /etc/ssl/private/mysql-server.key

# CAT II — Disable symbolic links
symbolic-links = 0

# CAT II — Error and general logging
log_error = /var/log/mysql/error.log
general_log = OFF
general_log_file = /var/log/mysql/general.log

# CAT II — Slow query log
slow_query_log = ON
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2

# CAT II — Connection timeouts
wait_timeout = 600
interactive_timeout = 600
connect_timeout = 10

# CAT II — Restrict local file loading
local_infile = OFF

# Security
skip_name_resolve = ON
max_connect_errors = 10

# CAT II — Audit plugin (MariaDB server_audit or MySQL Enterprise Audit)
# MariaDB:
plugin_load_add = server_audit
server_audit_logging = ON
server_audit_events = CONNECT,QUERY_DDL,QUERY_DML_NO_SELECT
server_audit_output_type = FILE
server_audit_file_path = /var/log/mysql/audit.log
server_audit_file_rotate_size = 100000000
server_audit_file_rotations = 10
EOF

echo "  ✓ Config written: ${MY_CNF}"

# --- SQL-level hardening ---
echo "  Running SQL hardening..."

${MYSQL_CMD} -e "
-- CAT I: Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- CAT I: Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- CAT I: Remove users with no password
SELECT User, Host FROM mysql.user WHERE
    (authentication_string = '' OR authentication_string IS NULL)
    AND User != 'mariadb.sys'
    AND User != 'mysql.sys';

-- CAT II: Revoke FILE privilege from non-admin users
-- (Review output and revoke manually as FILE can't be partially revoked)
SELECT User, Host FROM mysql.global_priv
WHERE JSON_CONTAINS(Priv, '\"Y\"', '$.File_priv')
   OR User IN (SELECT User FROM mysql.user WHERE File_priv = 'Y');

FLUSH PRIVILEGES;
" 2>/dev/null || echo "  ⚠ Some SQL commands may require manual review"

echo "✓ MariaDB/MySQL STIG hardening complete — restart with: systemctl restart mariadb"
```

### RDS MariaDB/MySQL Parameter Group

```python
def harden_rds_mysql_params(
    db_identifier: str, region: str = "us-east-1"
) -> None:
    """Apply STIG settings to RDS MySQL/MariaDB parameter group."""
    rds = boto3.client("rds", region_name=region)

    instance = rds.describe_db_instances(
        DBInstanceIdentifier=db_identifier
    )["DBInstances"][0]
    pg_name = instance["DBParameterGroups"][0]["DBParameterGroupName"]

    stig_params = {
        "require_secure_transport": "ON",           # CAT I — Force TLS
        "tls_version": "TLSv1.2,TLSv1.3",          # CAT I
        "local_infile": "0",                         # CAT II
        "wait_timeout": "600",                       # CAT II
        "interactive_timeout": "600",                # CAT II
        "log_output": "FILE",                        # CAT II
        "slow_query_log": "1",                       # CAT II
        "long_query_time": "2",                      # CAT II
        "skip_name_resolve": "ON",                   # Security
        "max_connect_errors": "10",                  # Security
    }

    current = {}
    paginator = rds.get_paginator("describe_db_parameters")
    for page in paginator.paginate(DBParameterGroupName=pg_name):
        for param in page["Parameters"]:
            if param["ParameterName"] in stig_params:
                current[param["ParameterName"]] = param.get("ParameterValue")

    changes = [
        {"ParameterName": k, "ParameterValue": v, "ApplyMethod": "pending-reboot"}
        for k, v in stig_params.items()
        if current.get(k) != v
    ]

    if not changes:
        print("  ✓ RDS MySQL parameters already compliant")
        return

    for i in range(0, len(changes), 20):
        rds.modify_db_parameter_group(
            DBParameterGroupName=pg_name, Parameters=changes[i:i+20]
        )
    print(f"  ✓ Modified {len(changes)} parameters — reboot required")
```

---

## SQL Server

### STIG Coverage Map (SQL Server 2019 STIG)

| Finding | Severity | Requirement | Where |
|---------|----------|------------|-------|
| SQL6-D0-000100 | CAT I | Disable sa account | T-SQL |
| SQL6-D0-000200 | CAT I | Enforce TLS for connections | SQL Config Manager |
| SQL6-D0-000400 | CAT I | Use Windows Authentication mode | T-SQL / registry |
| SQL6-D0-001000 | CAT II | Enable C2 / Common Criteria audit | T-SQL |
| SQL6-D0-001100 | CAT II | Configure login auditing | T-SQL |
| SQL6-D0-001500 | CAT II | Disable xp_cmdshell | T-SQL |
| SQL6-D0-002000 | CAT II | Disable CLR integration (if unused) | T-SQL |
| SQL6-D0-002500 | CAT II | Restrict public role permissions | T-SQL |

### Hardening Script (PowerShell + T-SQL)

```powershell
# Harden-SQLServer.ps1
[CmdletBinding()]
param(
    [string]$SqlInstance = "localhost"
)

Write-Host "`n=== SQL Server STIG Hardening ===" -ForegroundColor Cyan

# --- CAT I: Disable the sa account ---
$saStatus = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
    SELECT is_disabled FROM sys.server_principals WHERE name = 'sa'
"
if ($saStatus -and -not $saStatus.is_disabled) {
    Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "ALTER LOGIN [sa] DISABLE"
    Write-Host "  ✓ sa account disabled" -ForegroundColor Green
} else {
    Write-Host "  ✓ sa account already disabled" -ForegroundColor Green
}

# --- CAT I: Rename sa account ---
Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
    IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'sa')
        ALTER LOGIN [sa] WITH NAME = [disabled_sa]
" -ErrorAction SilentlyContinue

# --- CAT II: Disable xp_cmdshell ---
$xpCmd = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
    SELECT CAST(value_in_use AS INT) AS val
    FROM sys.configurations WHERE name = 'xp_cmdshell'
"
if ($xpCmd.val -ne 0) {
    Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
        EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
        EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
    "
    Write-Host "  ✓ xp_cmdshell disabled" -ForegroundColor Green
}

# --- CAT II: Disable CLR integration (if not used) ---
$clr = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
    SELECT CAST(value_in_use AS INT) AS val
    FROM sys.configurations WHERE name = 'clr enabled'
"
if ($clr.val -ne 0) {
    Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
        EXEC sp_configure 'clr enabled', 0; RECONFIGURE;
    "
    Write-Host "  ✓ CLR disabled" -ForegroundColor Green
}

# --- CAT II: Disable Ole Automation ---
$oleAuto = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
    SELECT CAST(value_in_use AS INT) AS val
    FROM sys.configurations WHERE name = 'Ole Automation Procedures'
"
if ($oleAuto.val -ne 0) {
    Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
        EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;
    "
    Write-Host "  ✓ Ole Automation disabled" -ForegroundColor Green
}

# --- CAT II: Disable remote access ---
Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
    EXEC sp_configure 'remote access', 0; RECONFIGURE;
    EXEC sp_configure 'remote admin connections', 0; RECONFIGURE;
" -ErrorAction SilentlyContinue

# --- CAT II: Enable login auditing (failed + successful) ---
Set-StigRegistry -Path "HKLM:\SOFTWARE\Microsoft\MSSQLServer\MSSQLServer" `
    -Name "AuditLevel" -Value 3   # 3 = Both failed and successful logins

# --- CAT II: Enable Common Criteria compliance ---
$cc = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
    SELECT CAST(value_in_use AS INT) AS val
    FROM sys.configurations WHERE name = 'common criteria compliance enabled'
"
if ($cc.val -ne 1) {
    Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
        EXEC sp_configure 'common criteria compliance enabled', 1; RECONFIGURE;
    "
    Write-Host "  ✓ Common Criteria compliance enabled (restart required)" -ForegroundColor Green
}

# --- CAT II: Restrict guest user in all databases ---
$databases = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
    SELECT name FROM sys.databases
    WHERE database_id > 4 AND state_desc = 'ONLINE'
    AND name NOT IN ('msdb')
"
foreach ($db in $databases) {
    Invoke-Sqlcmd -ServerInstance $SqlInstance -Database $db.name -Query "
        IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'guest')
        BEGIN
            REVOKE CONNECT FROM guest
        END
    " -ErrorAction SilentlyContinue
}
Write-Host "  ✓ Guest connect revoked in user databases" -ForegroundColor Green

# --- CAT II: Restrict public role ---
Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
    REVOKE VIEW ANY DATABASE FROM [public];
" -ErrorAction SilentlyContinue

# --- CAT II: Configure SQL Server audit ---
$auditExists = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
    SELECT name FROM sys.server_audits WHERE name = 'STIG_Audit'
"
if (-not $auditExists) {
    Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
        CREATE SERVER AUDIT [STIG_Audit]
        TO FILE (
            FILEPATH = N'C:\SQLAudit\',
            MAXSIZE = 200 MB,
            MAX_ROLLOVER_FILES = 50,
            RESERVE_DISK_SPACE = OFF
        )
        WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);

        ALTER SERVER AUDIT [STIG_Audit] WITH (STATE = ON);

        CREATE SERVER AUDIT SPECIFICATION [STIG_AuditSpec]
        FOR SERVER AUDIT [STIG_Audit]
        ADD (FAILED_LOGIN_GROUP),
        ADD (SUCCESSFUL_LOGIN_GROUP),
        ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),
        ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
        ADD (AUDIT_CHANGE_GROUP),
        ADD (SERVER_OBJECT_CHANGE_GROUP),
        ADD (DATABASE_CHANGE_GROUP),
        ADD (SCHEMA_OBJECT_CHANGE_GROUP),
        ADD (SERVER_PERMISSION_CHANGE_GROUP),
        ADD (DATABASE_PERMISSION_CHANGE_GROUP)
        WITH (STATE = ON);
    "
    Write-Host "  ✓ SQL Server audit created and enabled" -ForegroundColor Green
} else {
    Write-Host "  ✓ SQL Server audit already exists" -ForegroundColor Green
}

Write-Host "`n✓ SQL Server STIG hardening complete" -ForegroundColor Green
Write-Host "  ⚠ Common Criteria requires SQL Server restart" -ForegroundColor Yellow
```

### TLS for SQL Server (PowerShell)

```powershell
# Configure TLS certificate for SQL Server connections
# Requires a valid certificate in the computer's Personal cert store
[CmdletBinding()]
param(
    [string]$CertThumbprint   # Thumbprint of the TLS cert
)

if ($CertThumbprint) {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer\SuperSocketNetLib"
    Set-StigRegistry -Path $regPath -Name "Certificate" -Value $CertThumbprint -Type String
    Set-StigRegistry -Path $regPath -Name "ForceEncryption" -Value 1   # CAT I

    Write-Host "  ✓ TLS forced with cert $CertThumbprint — restart SQL Server to apply"
}
```

---

## Common Tailoring Exceptions

| DB | Finding | Default | Tailored | Reason | Compensating Control |
|----|---------|---------|----------|--------|---------------------|
| PostgreSQL | SCRAM-SHA-256 | Required | MD5 allowed | Legacy app can't use SCRAM | App upgrade plan, network encryption |
| PostgreSQL | pgaudit | Enabled | Disabled | Performance on high-throughput DB | CloudWatch log insights, RDS audit |
| PostgreSQL | statement_timeout | 60s | 300s | Long-running reports | Separate read replica for reports |
| MariaDB | require_secure_transport | ON | OFF | Legacy app without TLS driver | Private subnet, no internet exposure |
| MariaDB | local_infile | OFF | ON | ETL bulk loading | Restrict to specific user, audit logging |
| SQL Server | sa disabled | Disabled | Enabled (renamed) | Break-glass emergency access | Renamed, strong password, audit alerts |
| SQL Server | xp_cmdshell | Disabled | Enabled | Legacy stored proc dependency | Proxy account, restricted executor role |
| SQL Server | CLR | Disabled | Enabled | Custom .NET assemblies in use | SAFE assemblies only, code review |
| All | Authentication mode | Windows-only | Mixed | Application service accounts | Strong passwords, audit, rotation policy |
