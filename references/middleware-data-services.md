# Middleware & Data Services SRG Hardening

Covers Apache Solr, OpenSearch, Apache ActiveMQ (expanded), and Apache ZooKeeper.
None of these have dedicated STIGs — they map to the **Application Server SRG**
(SRG-APP-000001 through SRG-APP-000516) and, where they expose HTTP interfaces,
the **Web Server SRG**. These services frequently run together as a stack (e.g.,
Solr + ZooKeeper, OpenSearch + its coordinating nodes), so hardening should be
coordinated across the cluster.

## Table of Contents

1. [Shared Concerns](#shared-concerns)
2. [Apache Solr](#apache-solr)
3. [OpenSearch](#opensearch)
4. [Apache ActiveMQ](#apache-activemq)
5. [Apache ZooKeeper](#apache-zookeeper)
6. [Cluster-Wide Hardening Checklist](#cluster-wide-checklist)
7. [Common Tailoring Exceptions](#common-tailoring-exceptions)

---

## Shared Concerns

These four services share common hardening patterns that map to the same SRG controls.

| SRG Control | Requirement | Applies To |
|-------------|------------|-----------|
| SRG-APP-000014 | Encrypt traffic in transit (TLS) | All four |
| SRG-APP-000033 | Run as non-root dedicated user | All four |
| SRG-APP-000065 | Enforce authentication | All four |
| SRG-APP-000092 | Remove/change default credentials | All four |
| SRG-APP-000095 | Enable audit logging | All four |
| SRG-APP-000142 | Restrict admin interfaces | All four |
| SRG-APP-000172 | Authenticate before access | All four |
| SRG-APP-000317 | Enforce session/connection timeouts | All four |
| SRG-APP-000378 | Principle of least privilege | All four |
| SRG-APP-000516 | Secure file permissions | All four |

### Shared Bash Helpers

```bash
#!/usr/bin/env bash
# stig_helpers.sh — Common functions for middleware hardening
# Source this file from other hardening scripts.

set -euo pipefail

# Idempotent properties file setting (Java .properties or similar)
set_property() {
    local file="$1" key="$2" value="$3"
    if grep -q "^${key}\s*=" "$file" 2>/dev/null; then
        sed -i "s|^${key}\s*=.*|${key}=${value}|" "$file"
    elif grep -q "^#\s*${key}\s*=" "$file" 2>/dev/null; then
        sed -i "s|^#\s*${key}\s*=.*|${key}=${value}|" "$file"
    else
        echo "${key}=${value}" >> "$file"
    fi
}

# Idempotent YAML setting (top-level key only — for deeper nesting use Python)
set_yaml_value() {
    local file="$1" key="$2" value="$3"
    if grep -q "^${key}:" "$file" 2>/dev/null; then
        sed -i "s|^${key}:.*|${key}: ${value}|" "$file"
    elif grep -q "^#${key}:" "$file" 2>/dev/null; then
        sed -i "s|^#${key}:.*|${key}: ${value}|" "$file"
    else
        echo "${key}: ${value}" >> "$file"
    fi
}

# Ensure a dedicated service user exists
ensure_service_user() {
    local username="$1" home_dir="$2"
    if ! id "${username}" &>/dev/null; then
        useradd --system --shell /sbin/nologin --home-dir "${home_dir}" --create-home "${username}"
        echo "  ✓ Created service user: ${username}"
    fi
}

# Set standard file permissions for a service home directory
secure_service_dir() {
    local dir="$1" user="$2"
    chown -R "${user}:${user}" "${dir}"
    find "${dir}" -type d -exec chmod 750 {} \;
    find "${dir}" -type f -exec chmod 640 {} \;
    find "${dir}/bin" -type f -exec chmod 750 {} \; 2>/dev/null || true
    echo "  ✓ Permissions set: ${dir} (owner: ${user})"
}

# Backup a config file before modification (idempotent)
backup_config() {
    local file="$1"
    local backup="${file}.pre-stig.bak"
    if [[ -f "$file" && ! -f "$backup" ]]; then
        cp "$file" "$backup"
        echo "  ✓ Backup: ${backup}"
    fi
}
```

---

## Apache Solr

Solr is a search platform built on Lucene. It exposes an HTTP API and admin UI,
often runs in SolrCloud mode with ZooKeeper, and stores indexed data on disk.

### SRG Control Mapping

| SRG Control | Solr Implementation | Config File / Method |
|-------------|-------------------|---------------------|
| SRG-APP-000014 | Enable TLS for all HTTP traffic | solr.in.sh, solr.xml |
| SRG-APP-000033 | Run as `solr` user, never root | systemd unit |
| SRG-APP-000065 | Enable Authentication plugin | security.json |
| SRG-APP-000092 | Change default admin password | security.json |
| SRG-APP-000095 | Enable audit logging | solr.xml / log4j2 |
| SRG-APP-000142 | Restrict admin UI access | firewall / reverse proxy |
| SRG-APP-000172 | Enable Authorization plugin | security.json |
| SRG-APP-000317 | Connection/request timeouts | solr.xml |
| SRG-APP-000516 | File permissions on SOLR_HOME | filesystem |

### Hardening Script (Bash)

```bash
#!/usr/bin/env bash
# harden_solr.sh — Idempotent Apache Solr SRG hardening
set -euo pipefail

source "$(dirname "$0")/stig_helpers.sh" 2>/dev/null || true

SOLR_HOME="${SOLR_HOME:-/opt/solr}"
SOLR_VAR="${SOLR_VAR:-/var/solr}"
SOLR_USER="${SOLR_USER:-solr}"
SOLR_INCLUDE="${SOLR_HOME}/bin/solr.in.sh"

echo "=== Apache Solr SRG Hardening ==="

# ----------------------------------------------------------------
# SRG-APP-000033: Run as non-root dedicated user
# ----------------------------------------------------------------
if ! id "${SOLR_USER}" &>/dev/null; then
    useradd --system --shell /sbin/nologin --home-dir "${SOLR_VAR}" "${SOLR_USER}"
    echo "  ✓ Created user: ${SOLR_USER}"
fi

if [[ -f /etc/systemd/system/solr.service ]]; then
    if ! grep -q "User=${SOLR_USER}" /etc/systemd/system/solr.service; then
        echo "  ⚠ systemd unit should specify User=${SOLR_USER}"
    else
        echo "  ✓ Running as ${SOLR_USER}"
    fi
fi

# ----------------------------------------------------------------
# SRG-APP-000014: Enable TLS
# ----------------------------------------------------------------
backup_config "${SOLR_INCLUDE}" 2>/dev/null || true

# Configure TLS in solr.in.sh
SOLR_SSL_SETTINGS=(
    "SOLR_SSL_ENABLED=true"
    "SOLR_SSL_KEY_STORE=/etc/solr/ssl/solr-keystore.p12"
    "SOLR_SSL_KEY_STORE_PASSWORD=\${SOLR_SSL_KEY_STORE_PASSWORD}"
    "SOLR_SSL_KEY_STORE_TYPE=PKCS12"
    "SOLR_SSL_TRUST_STORE=/etc/solr/ssl/solr-truststore.p12"
    "SOLR_SSL_TRUST_STORE_PASSWORD=\${SOLR_SSL_TRUST_STORE_PASSWORD}"
    "SOLR_SSL_TRUST_STORE_TYPE=PKCS12"
    "SOLR_SSL_NEED_CLIENT_AUTH=false"
    "SOLR_SSL_WANT_CLIENT_AUTH=false"
    "SOLR_SSL_CLIENT_KEY_STORE=/etc/solr/ssl/solr-keystore.p12"
    "SOLR_SSL_CLIENT_KEY_STORE_PASSWORD=\${SOLR_SSL_KEY_STORE_PASSWORD}"
    "SOLR_SSL_CLIENT_TRUST_STORE=/etc/solr/ssl/solr-truststore.p12"
    "SOLR_SSL_CLIENT_TRUST_STORE_PASSWORD=\${SOLR_SSL_TRUST_STORE_PASSWORD}"
)

for setting in "${SOLR_SSL_SETTINGS[@]}"; do
    key="${setting%%=*}"
    if ! grep -q "^${key}=" "${SOLR_INCLUDE}" 2>/dev/null; then
        echo "${setting}" >> "${SOLR_INCLUDE}"
    fi
done
echo "  ✓ TLS settings configured in solr.in.sh"
echo "  ℹ Ensure keystores exist at /etc/solr/ssl/ before starting Solr"

# ----------------------------------------------------------------
# SRG-APP-000065/092/172: Authentication & Authorization
# ----------------------------------------------------------------
# security.json is uploaded to ZooKeeper (SolrCloud) or placed in SOLR_HOME (standalone)
SECURITY_JSON="${SOLR_VAR}/data/security.json"
if [[ ! -f "${SECURITY_JSON}" ]]; then
    cat > "${SECURITY_JSON}" << 'SECJSON'
{
  "authentication": {
    "class": "solr.BasicAuthPlugin",
    "blockUnknown": true,
    "forwardCredentials": false,
    "credentials": {
      "solr-admin": "IV0EHq1OnNrj6gvRCwvFwTrZ1+z1oBbnQdiVC3otuq0= Ndd7LKvVBAaZIF0QAVi1ekCfAJXr1GGfLtRUXhgrF8c="
    }
  },
  "authorization": {
    "class": "solr.RuleBasedAuthorizationPlugin",
    "permissions": [
      { "name": "security-edit", "role": "admin" },
      { "name": "security-read", "role": "admin" },
      { "name": "schema-edit",   "role": "admin" },
      { "name": "config-edit",   "role": "admin" },
      { "name": "collection-admin-edit", "role": "admin" },
      { "name": "core-admin-edit",       "role": "admin" },
      { "name": "read",  "role": ["admin", "reader"] },
      { "name": "update","role": ["admin", "writer"] },
      { "name": "all",   "role": "admin" }
    ],
    "user-role": {
      "solr-admin": "admin"
    }
  }
}
SECJSON
    echo "  ✓ security.json created — CHANGE DEFAULT PASSWORD IMMEDIATELY"
    echo "    Use: curl -u solr-admin:SolrRocks https://localhost:8983/api/cluster/security/authentication"
    echo "    To set new password via API after first start"
else
    echo "  ✓ security.json exists"
    # Verify blockUnknown is true
    if ! grep -q '"blockUnknown".*true' "${SECURITY_JSON}"; then
        echo "  ⚠ blockUnknown is not true — anonymous access may be allowed (CAT I)"
    fi
fi

# ----------------------------------------------------------------
# SRG-APP-000095: Audit logging
# ----------------------------------------------------------------
# Enable Solr audit logging via solr.xml or log4j2.xml
LOG4J_CONF="${SOLR_HOME}/server/resources/log4j2.xml"
if [[ -f "${LOG4J_CONF}" ]]; then
    if ! grep -q "AuditLogger\|audit" "${LOG4J_CONF}"; then
        echo "  ⚠ Audit logging not configured in log4j2.xml"
        echo "    Add an AuditLogger appender to capture auth events"
    else
        echo "  ✓ Audit logging present in log4j2.xml"
    fi
fi

# ----------------------------------------------------------------
# SRG-APP-000142: Restrict admin UI
# ----------------------------------------------------------------
# Solr admin UI is always on — restrict via network controls
echo "  ℹ Solr Admin UI: restrict via security group / firewall to admin IPs only"
echo "    Or place behind a reverse proxy with additional auth"

# ----------------------------------------------------------------
# SRG-APP-000317: Timeouts
# ----------------------------------------------------------------
SOLR_XML="${SOLR_VAR}/data/solr.xml"
if [[ -f "${SOLR_XML}" ]]; then
    # Check/set socket timeout and connection timeout
    if ! grep -q "socketTimeout" "${SOLR_XML}"; then
        echo "  ⚠ Consider setting socketTimeout and connTimeout in solr.xml"
        echo "    <int name=\"socketTimeout\">600000</int>"
        echo "    <int name=\"connTimeout\">60000</int>"
    fi
fi

# ----------------------------------------------------------------
# SRG-APP-000516: File permissions
# ----------------------------------------------------------------
chown -R "${SOLR_USER}:${SOLR_USER}" "${SOLR_HOME}" "${SOLR_VAR}"
find "${SOLR_HOME}" -type d -exec chmod 750 {} \;
find "${SOLR_HOME}" -type f -exec chmod 640 {} \;
find "${SOLR_HOME}/bin" -type f -exec chmod 750 {} \;
chmod 750 "${SOLR_HOME}/server/scripts"/* 2>/dev/null || true
echo "  ✓ File permissions secured"

# ----------------------------------------------------------------
# Additional: Disable Remote Streaming (CAT I equivalent)
# ----------------------------------------------------------------
# Remote streaming allows Solr to fetch arbitrary URLs — major SSRF risk
echo "  ℹ Verify enableRemoteStreaming=false in solrconfig.xml for each collection"
echo "    This is false by default in Solr 8.6+, but verify explicitly"

echo "✓ Solr SRG hardening complete"
```

### Solr SolrCloud + ZooKeeper Auth

When running SolrCloud, security.json is stored in ZooKeeper. Upload it securely:

```bash
# Upload security.json to ZooKeeper for SolrCloud
# Requires ZooKeeper to already have Solr's chroot

SOLR_ZK_HOST="${SOLR_ZK_HOST:-zk1:2181,zk2:2181,zk3:2181/solr}"

# Check if security.json already exists in ZK
existing=$(${SOLR_HOME}/bin/solr zk ls /security.json -z "${SOLR_ZK_HOST}" 2>&1 || true)
if echo "$existing" | grep -q "NoNode"; then
    ${SOLR_HOME}/bin/solr zk cp file:${SECURITY_JSON} zk:/security.json -z "${SOLR_ZK_HOST}"
    echo "  ✓ security.json uploaded to ZooKeeper"
else
    echo "  ✓ security.json already in ZooKeeper"
fi
```

### Ansible Tasks (Key Controls)

```yaml
- name: Solr SRG | Ensure dedicated user
  ansible.builtin.user:
    name: "{{ solr_user }}"
    system: true
    shell: /sbin/nologin
    home: "{{ solr_var_dir }}"

- name: Solr SRG | Deploy TLS settings in solr.in.sh
  ansible.builtin.blockinfile:
    path: "{{ solr_home }}/bin/solr.in.sh"
    marker: "# {mark} STIG TLS SETTINGS"
    block: |
      SOLR_SSL_ENABLED=true
      SOLR_SSL_KEY_STORE={{ solr_keystore_path }}
      SOLR_SSL_KEY_STORE_PASSWORD={{ solr_keystore_password }}
      SOLR_SSL_KEY_STORE_TYPE=PKCS12
      SOLR_SSL_TRUST_STORE={{ solr_truststore_path }}
      SOLR_SSL_TRUST_STORE_PASSWORD={{ solr_truststore_password }}
      SOLR_SSL_TRUST_STORE_TYPE=PKCS12
    backup: true

- name: Solr SRG | Deploy security.json
  ansible.builtin.template:
    src: security.json.j2
    dest: "{{ solr_var_dir }}/data/security.json"
    owner: "{{ solr_user }}"
    mode: "0640"

- name: Solr SRG | Secure file permissions
  ansible.builtin.file:
    path: "{{ solr_home }}"
    owner: "{{ solr_user }}"
    group: "{{ solr_user }}"
    recurse: true
```

---

## OpenSearch

OpenSearch (AWS-backed Elasticsearch fork) has a built-in security plugin. For
AWS-managed OpenSearch Service, many OS-level controls are handled by AWS — focus
on cluster settings, roles, and TLS. For self-managed OpenSearch, apply both OS-level
and service-level hardening.

### SRG Control Mapping

| SRG Control | OpenSearch Implementation | Config File / Method |
|-------------|-------------------------|---------------------|
| SRG-APP-000014 | TLS for transport and HTTP | opensearch.yml |
| SRG-APP-000033 | Run as `opensearch` user | systemd unit |
| SRG-APP-000065 | Security plugin authentication | opensearch-security config |
| SRG-APP-000092 | Change default admin password | internal_users.yml |
| SRG-APP-000095 | Enable audit logging | opensearch.yml |
| SRG-APP-000142 | Restrict Dashboards access | opensearch_dashboards.yml |
| SRG-APP-000172 | Role-based access control | roles.yml, roles_mapping.yml |
| SRG-APP-000317 | Search/scroll timeouts | opensearch.yml |
| SRG-APP-000378 | Principle of least privilege | Fine-grained roles |
| SRG-APP-000516 | File permissions | filesystem |

### Hardening Script (Bash) — Self-Managed

```bash
#!/usr/bin/env bash
# harden_opensearch.sh — Idempotent OpenSearch SRG hardening
set -euo pipefail

source "$(dirname "$0")/stig_helpers.sh" 2>/dev/null || true

OS_HOME="${OS_HOME:-/usr/share/opensearch}"
OS_CONF="${OS_CONF:-/etc/opensearch}"
OS_USER="${OS_USER:-opensearch}"
OS_YML="${OS_CONF}/opensearch.yml"
SECURITY_DIR="${OS_CONF}/opensearch-security"

echo "=== OpenSearch SRG Hardening ==="

# ----------------------------------------------------------------
# SRG-APP-000033: Run as non-root
# ----------------------------------------------------------------
if ! id "${OS_USER}" &>/dev/null; then
    useradd --system --shell /sbin/nologin --home-dir "${OS_HOME}" "${OS_USER}"
    echo "  ✓ Created user: ${OS_USER}"
fi

# ----------------------------------------------------------------
# SRG-APP-000014: TLS for transport and HTTP layers
# ----------------------------------------------------------------
backup_config "${OS_YML}" 2>/dev/null || true

declare -A OS_SETTINGS=(
    # --- TLS: Transport layer (node-to-node) ---
    ["plugins.security.ssl.transport.enabled"]="true"
    ["plugins.security.ssl.transport.pemcert_filepath"]="certs/node.pem"
    ["plugins.security.ssl.transport.pemkey_filepath"]="certs/node-key.pem"
    ["plugins.security.ssl.transport.pemtrustedcas_filepath"]="certs/root-ca.pem"
    ["plugins.security.ssl.transport.enforce_hostname_verification"]="true"

    # --- TLS: HTTP layer (client-to-node) ---
    ["plugins.security.ssl.http.enabled"]="true"
    ["plugins.security.ssl.http.pemcert_filepath"]="certs/node-http.pem"
    ["plugins.security.ssl.http.pemkey_filepath"]="certs/node-http-key.pem"
    ["plugins.security.ssl.http.pemtrustedcas_filepath"]="certs/root-ca.pem"

    # --- TLS: Protocol restrictions ---
    ["plugins.security.ssl.http.enabled_protocols"]="[TLSv1.2, TLSv1.3]"
    ["plugins.security.ssl.transport.enabled_protocols"]="[TLSv1.2, TLSv1.3]"

    # --- Security plugin core ---
    ["plugins.security.disabled"]="false"
    ["plugins.security.allow_default_init_securityindex"]="true"

    # --- SRG-APP-000095: Audit logging ---
    ["plugins.security.audit.type"]="internal_opensearch"
    ["plugins.security.audit.config.log_request_body"]="true"
    ["plugins.security.audit.config.resolve_indices"]="true"
    ["plugins.security.audit.config.enable_rest"]="true"
    ["plugins.security.audit.config.enable_transport"]="true"
    ["plugins.security.audit.config.disabled_rest_categories"]="NONE"
    ["plugins.security.audit.config.disabled_transport_categories"]="NONE"

    # --- SRG-APP-000317: Timeouts ---
    ["search.default_search_timeout"]="60s"
    ["search.max_open_scroll_context"]="500"

    # --- Disable dangerous features ---
    ["action.destructive_requires_name"]="true"
    ["plugins.security.ssl.http.clientauth_mode"]="OPTIONAL"
)

for key in "${!OS_SETTINGS[@]}"; do
    value="${OS_SETTINGS[$key]}"
    if grep -q "^${key}:" "${OS_YML}" 2>/dev/null; then
        sed -i "s|^${key}:.*|${key}: ${value}|" "${OS_YML}"
    elif grep -q "^#${key}:" "${OS_YML}" 2>/dev/null; then
        sed -i "s|^#${key}:.*|${key}: ${value}|" "${OS_YML}"
    else
        echo "${key}: ${value}" >> "${OS_YML}"
    fi
done
echo "  ✓ opensearch.yml TLS and security settings applied"

# ----------------------------------------------------------------
# SRG-APP-000092: Change default credentials
# ----------------------------------------------------------------
INTERNAL_USERS="${SECURITY_DIR}/internal_users.yml"
if [[ -f "${INTERNAL_USERS}" ]]; then
    if grep -q "hash:.*\"\$2a\$12\$VcCDgh2NDk07JGN0rjGbM" "${INTERNAL_USERS}" 2>/dev/null; then
        echo "  ⚠ DEFAULT PASSWORD HASHES DETECTED in internal_users.yml (CAT I)"
        echo "    Generate new hashes: ${OS_HOME}/plugins/opensearch-security/tools/hash.sh"
        echo "    Then run securityadmin.sh to apply"
    fi
else
    echo "  ⚠ internal_users.yml not found — security plugin may not be configured"
fi

# ----------------------------------------------------------------
# SRG-APP-000172: Role-based access control
# ----------------------------------------------------------------
ROLES_MAPPING="${SECURITY_DIR}/roles_mapping.yml"
if [[ -f "${ROLES_MAPPING}" ]]; then
    echo "  ✓ roles_mapping.yml exists — verify least-privilege assignments"
else
    echo "  ⚠ roles_mapping.yml not found — RBAC not configured"
fi

# ----------------------------------------------------------------
# SRG-APP-000516: File permissions
# ----------------------------------------------------------------
chown -R "${OS_USER}:${OS_USER}" "${OS_CONF}" "${OS_HOME}"
chmod 750 "${OS_CONF}"
chmod 640 "${OS_YML}"
chmod -R 640 "${SECURITY_DIR}"/*.yml 2>/dev/null || true
chmod 750 "${SECURITY_DIR}" 2>/dev/null || true
# Cert keys must be read-only by opensearch user
find "${OS_CONF}/certs" -name "*-key.pem" -exec chmod 600 {} \; 2>/dev/null || true
echo "  ✓ File permissions secured"

# ----------------------------------------------------------------
# Disable unnecessary features
# ----------------------------------------------------------------
# Disable script execution if not needed (prevents RCE via Painless scripts)
if ! grep -q "script.allowed_types" "${OS_YML}"; then
    echo "  ℹ Consider restricting script.allowed_types if inline scripts are not needed"
fi

echo ""
echo "✓ OpenSearch SRG hardening complete"
echo "  ⚠ After config changes, run securityadmin.sh to push security config:"
echo "    ${OS_HOME}/plugins/opensearch-security/tools/securityadmin.sh \\"
echo "      -cd ${SECURITY_DIR} -icl -nhnv \\"
echo "      -cacert ${OS_CONF}/certs/root-ca.pem \\"
echo "      -cert ${OS_CONF}/certs/admin.pem \\"
echo "      -key ${OS_CONF}/certs/admin-key.pem"
```

### AWS OpenSearch Service (Managed) — Python/Boto3

```python
import boto3
import json


def harden_aws_opensearch_domain(
    domain_name: str, region: str = "us-east-1"
) -> None:
    """Apply SRG-aligned settings to an AWS OpenSearch Service domain.

    For managed OpenSearch, AWS handles OS-level hardening, TLS certs, and patching.
    We configure: encryption, fine-grained access control, audit logging, and
    access policies.

    Idempotent — reads current config and only modifies what differs.
    """
    client = boto3.client("opensearch", region_name=region)

    domain = client.describe_domain(DomainName=domain_name)["DomainStatus"]

    updates = {}

    # SRG-APP-000014: Enforce HTTPS (node-to-node + HTTPS endpoint)
    if not domain.get("NodeToNodeEncryptionOptions", {}).get("Enabled"):
        updates["NodeToNodeEncryptionOptions"] = {"Enabled": True}

    dpp = domain.get("DomainEndpointOptions", {})
    if not dpp.get("EnforceHTTPS") or dpp.get("TLSSecurityPolicy") != "Policy-Min-TLS-1-2-PFS-2023-10":
        updates["DomainEndpointOptions"] = {
            "EnforceHTTPS": True,
            "TLSSecurityPolicy": "Policy-Min-TLS-1-2-PFS-2023-10",
        }

    # SRG-APP-000014: Encryption at rest
    if not domain.get("EncryptionAtRestOptions", {}).get("Enabled"):
        updates["EncryptionAtRestOptions"] = {"Enabled": True}

    # SRG-APP-000065/172: Fine-grained access control
    afac = domain.get("AdvancedSecurityOptions", {})
    if not afac.get("Enabled") or not afac.get("InternalUserDatabaseEnabled"):
        updates["AdvancedSecurityOptions"] = {
            "Enabled": True,
            "InternalUserDatabaseEnabled": True,
        }

    # SRG-APP-000095: Audit logging
    log_opts = domain.get("LogPublishingOptions", {})
    if "AUDIT_LOGS" not in log_opts:
        # Requires a CloudWatch log group
        updates["LogPublishingOptions"] = {
            "AUDIT_LOGS": {
                "CloudWatchLogsLogGroupArn": f"arn:aws:logs:{region}:*:log-group:/aws/opensearch/{domain_name}/audit-logs",
                "Enabled": True,
            },
            "INDEX_SLOW_LOGS": {
                "CloudWatchLogsLogGroupArn": f"arn:aws:logs:{region}:*:log-group:/aws/opensearch/{domain_name}/index-slow-logs",
                "Enabled": True,
            },
            "SEARCH_SLOW_LOGS": {
                "CloudWatchLogsLogGroupArn": f"arn:aws:logs:{region}:*:log-group:/aws/opensearch/{domain_name}/search-slow-logs",
                "Enabled": True,
            },
        }

    if not updates:
        print(f"  ✓ OpenSearch domain '{domain_name}' already compliant")
        return

    client.update_domain_config(DomainName=domain_name, **updates)
    changed = list(updates.keys())
    print(f"  ✓ OpenSearch domain '{domain_name}' updated: {changed}")
    print(f"    ⚠ Some changes (encryption at rest, FGAC) require blue/green deployment")
```

### OpenSearch Dashboards Hardening

```yaml
# opensearch_dashboards.yml — SRG-aligned settings
server.ssl.enabled: true
server.ssl.certificate: /etc/opensearch-dashboards/certs/dashboards.pem
server.ssl.key: /etc/opensearch-dashboards/certs/dashboards-key.pem

# SRG-APP-000317: Session timeout
opensearch_security.session.ttl: 3600000       # 1 hour
opensearch_security.session.keepalive: false
opensearch_security.cookie.secure: true
opensearch_security.cookie.isSameSite: Strict

# SRG-APP-000065: Authentication via OpenSearch Security
opensearch.username: dashboards_internal
opensearch.password: "${DASHBOARDS_PASSWORD}"
opensearch.ssl.verificationMode: full

# Disable telemetry
telemetry.enabled: false
telemetry.optIn: false
```

---

## Apache ActiveMQ

Expanded hardening for ActiveMQ Classic and ActiveMQ Artemis. The basic web console
and auth checks from `references/web-app-servers.md` are included here with deeper
coverage of broker transport, message-level security, and clustering.

### SRG Control Mapping

| SRG Control | ActiveMQ Implementation | Config File |
|-------------|------------------------|------------|
| SRG-APP-000014 | TLS for transport connectors (OpenWire, AMQP, STOMP, MQTT) | activemq.xml / broker.xml |
| SRG-APP-000033 | Dedicated non-root user | systemd unit |
| SRG-APP-000065 | JAAS or simple authentication plugin | activemq.xml, login.config |
| SRG-APP-000092 | Remove default admin/admin credentials | users.properties |
| SRG-APP-000095 | Enable audit logging | log4j2.properties |
| SRG-APP-000142 | Restrict web console to localhost or disable | jetty.xml |
| SRG-APP-000172 | Authorization plugin (per-destination ACLs) | activemq.xml |
| SRG-APP-000317 | Wire format timeouts, inactive connection cleanup | activemq.xml |
| SRG-APP-000378 | Per-queue/topic permissions | activemq.xml |
| SRG-APP-000516 | File permissions | filesystem |

### Hardening Script — ActiveMQ Classic (Bash)

```bash
#!/usr/bin/env bash
# harden_activemq_classic.sh — Full ActiveMQ Classic SRG hardening
set -euo pipefail

source "$(dirname "$0")/stig_helpers.sh" 2>/dev/null || true

AMQ_HOME="${AMQ_HOME:-/opt/activemq}"
AMQ_USER="${AMQ_USER:-activemq}"
AMQ_CONF="${AMQ_HOME}/conf"
AMQ_XML="${AMQ_CONF}/activemq.xml"
JETTY_XML="${AMQ_CONF}/jetty.xml"
USERS_PROPS="${AMQ_CONF}/users.properties"
GROUPS_PROPS="${AMQ_CONF}/groups.properties"

echo "=== ActiveMQ Classic SRG Hardening ==="

# ----------------------------------------------------------------
# SRG-APP-000033: Non-root user
# ----------------------------------------------------------------
if ! id "${AMQ_USER}" &>/dev/null; then
    useradd --system --shell /sbin/nologin --home-dir "${AMQ_HOME}" "${AMQ_USER}"
    echo "  ✓ Created user: ${AMQ_USER}"
fi

# ----------------------------------------------------------------
# SRG-APP-000092: Default credentials (CAT I equivalent)
# ----------------------------------------------------------------
backup_config "${USERS_PROPS}" 2>/dev/null || true
if [[ -f "${USERS_PROPS}" ]]; then
    if grep -qE "^admin=admin$" "${USERS_PROPS}"; then
        echo "  ❌ DEFAULT CREDENTIALS: admin=admin in users.properties — CHANGE IMMEDIATELY"
    else
        echo "  ✓ No default admin=admin found"
    fi
    if grep -qE "^user=password$" "${USERS_PROPS}"; then
        echo "  ❌ DEFAULT CREDENTIALS: user=password in users.properties — CHANGE IMMEDIATELY"
    fi
    if grep -qE "^guest=" "${USERS_PROPS}"; then
        # Remove guest user
        sed -i '/^guest=/d' "${USERS_PROPS}"
        echo "  ✓ Removed guest user from users.properties"
    fi
fi

# ----------------------------------------------------------------
# SRG-APP-000014: TLS on transport connectors
# ----------------------------------------------------------------
backup_config "${AMQ_XML}" 2>/dev/null || true

# Check for plain TCP connectors
if grep -q 'uri="tcp://0.0.0.0' "${AMQ_XML}" 2>/dev/null; then
    echo "  ⚠ Plain TCP connector found. Convert to SSL:"
    echo "    <transportConnector name=\"ssl\" uri=\"ssl://0.0.0.0:61617?needClientAuth=false\"/>"
    echo "    Add <sslContext> to broker with keyStore and trustStore"
fi

# Ensure sslContext block exists
if ! grep -q '<sslContext>' "${AMQ_XML}" 2>/dev/null; then
    echo "  ⚠ No <sslContext> found in activemq.xml. Add:"
    echo '    <sslContext>'
    echo '      <sslContext keyStore="/etc/activemq/ssl/broker.ks"'
    echo '                  keyStorePassword="${AMQ_KEYSTORE_PASS}"'
    echo '                  trustStore="/etc/activemq/ssl/broker.ts"'
    echo '                  trustStorePassword="${AMQ_TRUSTSTORE_PASS}"/>'
    echo '    </sslContext>'
fi

# Check for unencrypted AMQP/STOMP/MQTT connectors
for proto in amqp stomp mqtt; do
    if grep -q "uri=\"${proto}://0.0.0.0" "${AMQ_XML}" 2>/dev/null; then
        echo "  ⚠ Unencrypted ${proto} connector found — convert to ${proto}+ssl"
    fi
done

# ----------------------------------------------------------------
# SRG-APP-000065/172: Authentication + Authorization
# ----------------------------------------------------------------
# Verify authentication plugin is configured
if ! grep -q 'simpleAuthenticationPlugin\|jaasAuthenticationPlugin' "${AMQ_XML}" 2>/dev/null; then
    echo "  ⚠ No authentication plugin in activemq.xml — add one:"
    echo '    <plugins>'
    echo '      <jaasAuthenticationPlugin configuration="activemq" />'
    echo '      <authorizationPlugin>'
    echo '        <map>'
    echo '          <authorizationMap>'
    echo '            <authorizationEntries>'
    echo '              <authorizationEntry queue=">" read="admins" write="admins" admin="admins"/>'
    echo '              <authorizationEntry topic=">" read="admins" write="admins" admin="admins"/>'
    echo '              <authorizationEntry topic="ActiveMQ.Advisory.>" read="admins,users" write="admins,users" admin="admins,users"/>'
    echo '            </authorizationEntries>'
    echo '          </authorizationMap>'
    echo '        </map>'
    echo '      </authorizationPlugin>'
    echo '    </plugins>'
else
    echo "  ✓ Authentication plugin configured"
    # Verify authorization is also present
    if ! grep -q 'authorizationPlugin' "${AMQ_XML}" 2>/dev/null; then
        echo "  ⚠ Auth but no authorization — all authenticated users have full access"
    else
        echo "  ✓ Authorization plugin configured"
    fi
fi

# ----------------------------------------------------------------
# SRG-APP-000142: Restrict web console
# ----------------------------------------------------------------
backup_config "${JETTY_XML}" 2>/dev/null || true
if [[ -f "${JETTY_XML}" ]]; then
    if grep -q '0\.0\.0\.0' "${JETTY_XML}"; then
        sed -i 's/0\.0\.0\.0/127.0.0.1/g' "${JETTY_XML}"
        echo "  ✓ Web console restricted to localhost"
    else
        echo "  ✓ Web console already localhost-bound or disabled"
    fi
fi

# Enable console auth if jetty-realm.properties has defaults
JETTY_REALM="${AMQ_CONF}/jetty-realm.properties"
if [[ -f "${JETTY_REALM}" ]]; then
    if grep -q "admin: admin" "${JETTY_REALM}"; then
        echo "  ❌ DEFAULT WEB CONSOLE CREDENTIALS in jetty-realm.properties — CHANGE"
    fi
fi

# ----------------------------------------------------------------
# SRG-APP-000095: Audit logging
# ----------------------------------------------------------------
LOG4J_PROPS="${AMQ_CONF}/log4j2.properties"
if [[ -f "${LOG4J_PROPS}" ]]; then
    if ! grep -qE "audit|Audit" "${LOG4J_PROPS}"; then
        cat >> "${LOG4J_PROPS}" << 'AUDITEOF'

# STIG Audit Logging
appender.audit_file.type = RollingFile
appender.audit_file.name = AuditFile
appender.audit_file.fileName = ${sys:activemq.data}/audit.log
appender.audit_file.filePattern = ${sys:activemq.data}/audit.log.%i
appender.audit_file.layout.type = PatternLayout
appender.audit_file.layout.pattern = %-5p | %m | %t%n
appender.audit_file.policies.type = Policies
appender.audit_file.policies.size.type = SizeBasedTriggeringPolicy
appender.audit_file.policies.size.size = 100MB
appender.audit_file.strategy.type = DefaultRolloverStrategy
appender.audit_file.strategy.max = 10

logger.audit.name = org.apache.activemq.audit
logger.audit.level = INFO
logger.audit.appenderRef.audit.ref = AuditFile
AUDITEOF
        echo "  ✓ Audit logging configured in log4j2.properties"
    else
        echo "  ✓ Audit logging already configured"
    fi
fi

# ----------------------------------------------------------------
# SRG-APP-000317: Timeouts and limits
# ----------------------------------------------------------------
# Wire format max inactivity duration (default 30s — acceptable)
# Set maxFrameSize to prevent memory exhaustion
if ! grep -q 'wireFormat.maxFrameSize' "${AMQ_XML}" 2>/dev/null; then
    echo "  ℹ Consider adding wireFormat.maxFrameSize=104857600 (100MB) to transport URIs"
fi

# ----------------------------------------------------------------
# SRG-APP-000516: File permissions
# ----------------------------------------------------------------
chown -R "${AMQ_USER}:${AMQ_USER}" "${AMQ_HOME}"
chmod 750 "${AMQ_CONF}"
chmod 640 "${AMQ_CONF}"/*.xml "${AMQ_CONF}"/*.properties 2>/dev/null || true
chmod 750 "${AMQ_HOME}/bin"
chmod 750 "${AMQ_HOME}/bin"/* 2>/dev/null || true
echo "  ✓ File permissions secured"

echo "✓ ActiveMQ Classic SRG hardening complete"
```

### ActiveMQ Artemis Differences

```bash
# Key Artemis config differences from Classic:
#
# Config file: broker.xml (not activemq.xml)
# Security:    Built-in JAAS (login.config), properties or LDAP
# TLS:         <acceptor> elements in broker.xml
# Web console: bootstrap.xml / jolokia-access.xml
#
# Example TLS acceptor:
#   <acceptor name="amqp-ssl">
#     tcp://0.0.0.0:5671?sslEnabled=true;keyStorePath=/etc/artemis/ssl/broker.ks;
#     keyStorePassword=ENC(xxxx);protocols=AMQP;enabledProtocols=TLSv1.2,TLSv1.3
#   </acceptor>
#
# Restrict web console in bootstrap.xml:
#   <web bind="https://127.0.0.1:8161" path="web"
#        keyStorePath="/etc/artemis/ssl/broker.ks"
#        keyStorePassword="ENC(xxxx)">
```

---

## Apache ZooKeeper

ZooKeeper is the coordination backbone for Solr, Kafka, and many distributed
systems. A compromised ZooKeeper can cascade to every service that depends on it.

### SRG Control Mapping

| SRG Control | ZooKeeper Implementation | Config File |
|-------------|------------------------|------------|
| SRG-APP-000014 | TLS for client and quorum communication | zoo.cfg |
| SRG-APP-000033 | Dedicated non-root user | systemd unit |
| SRG-APP-000065 | SASL/Kerberos or Digest authentication | zoo.cfg, jaas.conf |
| SRG-APP-000092 | Change/set authentication credentials | jaas.conf |
| SRG-APP-000095 | Enable audit logging | zoo.cfg, log4j |
| SRG-APP-000142 | Restrict AdminServer (Four Letter Words) | zoo.cfg |
| SRG-APP-000172 | ACLs on znodes | Application-level |
| SRG-APP-000317 | Session and tick timeouts | zoo.cfg |
| SRG-APP-000516 | File permissions on dataDir | filesystem |

### Hardening Script (Bash)

```bash
#!/usr/bin/env bash
# harden_zookeeper.sh — Idempotent ZooKeeper SRG hardening
set -euo pipefail

source "$(dirname "$0")/stig_helpers.sh" 2>/dev/null || true

ZK_HOME="${ZK_HOME:-/opt/zookeeper}"
ZK_CONF="${ZK_CONF:-${ZK_HOME}/conf}"
ZK_USER="${ZK_USER:-zookeeper}"
ZOO_CFG="${ZK_CONF}/zoo.cfg"
ZK_DATA="${ZK_DATA:-/var/lib/zookeeper}"

echo "=== Apache ZooKeeper SRG Hardening ==="

# ----------------------------------------------------------------
# SRG-APP-000033: Non-root user
# ----------------------------------------------------------------
if ! id "${ZK_USER}" &>/dev/null; then
    useradd --system --shell /sbin/nologin --home-dir "${ZK_DATA}" "${ZK_USER}"
    echo "  ✓ Created user: ${ZK_USER}"
fi

# ----------------------------------------------------------------
# SRG-APP-000014: TLS for client connections
# ----------------------------------------------------------------
backup_config "${ZOO_CFG}" 2>/dev/null || true

declare -A ZK_TLS_SETTINGS=(
    # Client-to-ZK TLS
    ["secureClientPort"]="2281"
    ["ssl.keyStore.location"]="/etc/zookeeper/ssl/zk-keystore.p12"
    ["ssl.keyStore.password"]="\${ZK_KEYSTORE_PASS}"
    ["ssl.keyStore.type"]="PKCS12"
    ["ssl.trustStore.location"]="/etc/zookeeper/ssl/zk-truststore.p12"
    ["ssl.trustStore.password"]="\${ZK_TRUSTSTORE_PASS}"
    ["ssl.trustStore.type"]="PKCS12"
    ["ssl.protocol"]="TLSv1.2"

    # Quorum TLS (ZK node-to-node)
    ["sslQuorum"]="true"
    ["ssl.quorum.keyStore.location"]="/etc/zookeeper/ssl/zk-keystore.p12"
    ["ssl.quorum.keyStore.password"]="\${ZK_KEYSTORE_PASS}"
    ["ssl.quorum.trustStore.location"]="/etc/zookeeper/ssl/zk-truststore.p12"
    ["ssl.quorum.trustStore.password"]="\${ZK_TRUSTSTORE_PASS}"

    # Disable plaintext client port (after confirming TLS works!)
    # ["clientPort"]="0"   # Uncomment AFTER testing secureClientPort
)

for key in "${!ZK_TLS_SETTINGS[@]}"; do
    value="${ZK_TLS_SETTINGS[$key]}"
    if grep -q "^${key}=" "${ZOO_CFG}" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${value}|" "${ZOO_CFG}"
    elif grep -q "^#${key}=" "${ZOO_CFG}" 2>/dev/null; then
        sed -i "s|^#${key}=.*|${key}=${value}|" "${ZOO_CFG}"
    else
        echo "${key}=${value}" >> "${ZOO_CFG}"
    fi
done
echo "  ✓ TLS configured for client and quorum connections"
echo "  ⚠ Keep clientPort=2181 active until all clients migrate to secureClientPort=2281"
echo "    Then set clientPort=0 to disable plaintext"

# ----------------------------------------------------------------
# SRG-APP-000065/092: Authentication (SASL Digest)
# ----------------------------------------------------------------
JAAS_CONF="${ZK_CONF}/zookeeper-jaas.conf"
if [[ ! -f "${JAAS_CONF}" ]]; then
    cat > "${JAAS_CONF}" << 'JAASEOF'
// ZooKeeper server JAAS configuration
// SRG-APP-000065: Require authentication for all connections

Server {
    org.apache.zookeeper.server.auth.DigestLoginModule required
    user_admin="CHANGE_THIS_PASSWORD"
    user_solr="CHANGE_THIS_PASSWORD"
    user_kafka="CHANGE_THIS_PASSWORD";
};

// Quorum auth (ZK node-to-node)
QuorumServer {
    org.apache.zookeeper.server.auth.DigestLoginModule required
    user_zk="CHANGE_QUORUM_PASSWORD";
};

QuorumLearner {
    org.apache.zookeeper.server.auth.DigestLoginModule required
    username="zk"
    password="CHANGE_QUORUM_PASSWORD";
};
JAASEOF
    echo "  ✓ JAAS config created — CHANGE ALL PASSWORDS before starting"
    echo "    File: ${JAAS_CONF}"
else
    echo "  ✓ JAAS config exists"
    if grep -q "CHANGE_THIS_PASSWORD\|password1\|admin123" "${JAAS_CONF}" 2>/dev/null; then
        echo "  ❌ DEFAULT/PLACEHOLDER PASSWORDS in JAAS config — CHANGE IMMEDIATELY"
    fi
fi

# Configure ZK to use JAAS
if ! grep -q "authProvider" "${ZOO_CFG}" 2>/dev/null; then
    cat >> "${ZOO_CFG}" << 'AUTHEOF'

# SRG-APP-000065: SASL authentication
authProvider.1=org.apache.zookeeper.server.auth.SASLAuthenticationProvider
requireClientAuthScheme=sasl
enforce.auth.enabled=true
enforce.auth.schemes=sasl
AUTHEOF
    echo "  ✓ SASL auth provider configured in zoo.cfg"
fi

# JVM arg to point to JAAS config — add to zookeeper-env.sh
ZK_ENV="${ZK_CONF}/zookeeper-env.sh"
if [[ -f "${ZK_ENV}" ]]; then
    if ! grep -q "java.security.auth.login.config" "${ZK_ENV}"; then
        echo "export SERVER_JVMFLAGS=\"\${SERVER_JVMFLAGS:-} -Djava.security.auth.login.config=${JAAS_CONF}\"" >> "${ZK_ENV}"
        echo "  ✓ JAAS JVM flag added to zookeeper-env.sh"
    fi
else
    cat > "${ZK_ENV}" << ENVEOF
#!/usr/bin/env bash
export SERVER_JVMFLAGS="\${SERVER_JVMFLAGS:-} -Djava.security.auth.login.config=${JAAS_CONF}"
ENVEOF
    chmod 750 "${ZK_ENV}"
    echo "  ✓ Created zookeeper-env.sh with JAAS JVM flag"
fi

# ----------------------------------------------------------------
# SRG-APP-000142: Restrict AdminServer (Four Letter Words)
# ----------------------------------------------------------------
# ZK 3.5+ has an embedded AdminServer on port 8080 — restrict or disable
declare -A ZK_ADMIN_SETTINGS=(
    ["admin.enableServer"]="false"           # Disable entirely; or:
    # ["admin.serverPort"]="8080"            # If needed, bind to localhost
    # ["admin.serverAddress"]="127.0.0.1"
    ["4lw.commands.whitelist"]="ruok, stat"  # Only allow safe commands
)

for key in "${!ZK_ADMIN_SETTINGS[@]}"; do
    value="${ZK_ADMIN_SETTINGS[$key]}"
    if grep -q "^${key}=" "${ZOO_CFG}" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${value}|" "${ZOO_CFG}"
    else
        echo "${key}=${value}" >> "${ZOO_CFG}"
    fi
done
echo "  ✓ AdminServer disabled, Four Letter Words restricted to ruok + stat"

# ----------------------------------------------------------------
# SRG-APP-000095: Audit logging
# ----------------------------------------------------------------
# ZK 3.6+ has built-in audit logging
if ! grep -q "audit.enable" "${ZOO_CFG}" 2>/dev/null; then
    cat >> "${ZOO_CFG}" << 'AUDITEOF'

# SRG-APP-000095: Audit logging (ZK 3.6+)
audit.enable=true
audit.impl.class=org.apache.zookeeper.audit.Log4jAuditLogger
AUDITEOF
    echo "  ✓ ZooKeeper audit logging enabled"
fi

# ----------------------------------------------------------------
# SRG-APP-000317: Session and tick timeouts
# ----------------------------------------------------------------
# Ensure reasonable tick/session settings
declare -A ZK_TIMEOUT_SETTINGS=(
    ["tickTime"]="2000"              # Base time unit (ms)
    ["minSessionTimeout"]="4000"     # 2 * tickTime minimum
    ["maxSessionTimeout"]="60000"    # 60 sec max session
    ["initLimit"]="10"               # Ticks for initial sync
    ["syncLimit"]="5"                # Ticks for sync during operation
    ["maxClientCnxns"]="60"          # Max connections per IP
)

for key in "${!ZK_TIMEOUT_SETTINGS[@]}"; do
    value="${ZK_TIMEOUT_SETTINGS[$key]}"
    if grep -q "^${key}=" "${ZOO_CFG}" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${value}|" "${ZOO_CFG}"
    elif ! grep -q "^${key}=" "${ZOO_CFG}" 2>/dev/null; then
        echo "${key}=${value}" >> "${ZOO_CFG}"
    fi
done
echo "  ✓ Session/timeout settings configured"

# ----------------------------------------------------------------
# SRG-APP-000516: File permissions
# ----------------------------------------------------------------
chown -R "${ZK_USER}:${ZK_USER}" "${ZK_HOME}" "${ZK_DATA}"
chmod 750 "${ZK_CONF}" "${ZK_DATA}"
chmod 640 "${ZOO_CFG}" "${JAAS_CONF}" 2>/dev/null || true
chmod 700 "${ZK_DATA}/version-2" 2>/dev/null || true  # Transaction logs
# Protect snapshot directory
find "${ZK_DATA}" -name "snapshot.*" -exec chmod 600 {} \; 2>/dev/null || true
find "${ZK_DATA}" -name "log.*" -exec chmod 600 {} \; 2>/dev/null || true
echo "  ✓ File permissions secured"

echo ""
echo "✓ ZooKeeper SRG hardening complete"
echo "  ⚠ Rolling restart required — update one ZK node at a time to maintain quorum"
```

### ZooKeeper Ansible Tasks

```yaml
# roles/stig_zookeeper/tasks/main.yml
- name: ZK SRG | Ensure dedicated user
  ansible.builtin.user:
    name: "{{ zk_user }}"
    system: true
    shell: /sbin/nologin
    home: "{{ zk_data_dir }}"

- name: ZK SRG | Deploy hardened zoo.cfg
  ansible.builtin.template:
    src: zoo.cfg.j2
    dest: "{{ zk_conf_dir }}/zoo.cfg"
    owner: "{{ zk_user }}"
    group: "{{ zk_user }}"
    mode: "0640"
    backup: true
  notify: restart zookeeper

- name: ZK SRG | Deploy JAAS config
  ansible.builtin.template:
    src: zookeeper-jaas.conf.j2
    dest: "{{ zk_conf_dir }}/zookeeper-jaas.conf"
    owner: "{{ zk_user }}"
    group: "{{ zk_user }}"
    mode: "0640"
  notify: restart zookeeper
  no_log: true    # Contains passwords

- name: ZK SRG | Configure JAAS JVM flag
  ansible.builtin.lineinfile:
    path: "{{ zk_conf_dir }}/zookeeper-env.sh"
    regexp: "java.security.auth.login.config"
    line: 'export SERVER_JVMFLAGS="${SERVER_JVMFLAGS:-} -Djava.security.auth.login.config={{ zk_conf_dir }}/zookeeper-jaas.conf"'
    create: true
    owner: "{{ zk_user }}"
    mode: "0750"

- name: ZK SRG | Secure data directory
  ansible.builtin.file:
    path: "{{ zk_data_dir }}"
    owner: "{{ zk_user }}"
    group: "{{ zk_user }}"
    mode: "0750"
    recurse: true
```

---

## Cluster-Wide Hardening Checklist

When these services run together (common stacks), coordinate hardening in this order:

### Stack: Solr + ZooKeeper

```
1. Snapshot all EC2 instances (AMIs)
2. Harden ZooKeeper FIRST (Solr depends on it)
   a. TLS for quorum (rolling restart, one node at a time)
   b. TLS for client port (secureClientPort)
   c. SASL authentication
   d. Keep plaintext clientPort active until Solr is reconfigured
3. Reconfigure Solr to use ZK secureClientPort + SASL
4. Harden Solr (TLS, auth, security.json)
5. Disable ZK plaintext clientPort (set clientPort=0)
6. Validate: Solr queries work, admin UI accessible, replication OK
```

### Stack: OpenSearch Cluster

```
1. Snapshot all data nodes
2. Harden one master-eligible node, verify cluster health = green
3. Rolling restart remaining masters
4. Rolling restart data nodes (one at a time, wait for shard relocation)
5. Apply security plugin config via securityadmin.sh
6. Reconfigure OpenSearch Dashboards for TLS + auth
7. Validate: Index/search operations, Dashboards login, audit logs flowing
```

### Stack: ActiveMQ + ZooKeeper (Replicated LevelDB)

```
1. Snapshot all broker instances
2. Harden ZooKeeper first (see above)
3. Reconfigure ActiveMQ ZK connection string for TLS
4. Harden ActiveMQ (TLS connectors, auth, authorization)
5. Verify: Message production/consumption, failover, web console
```

---

## Common Tailoring Exceptions

| Service | Finding | Default | Tailored | Reason | Compensating Control |
|---------|---------|---------|----------|--------|---------------------|
| Solr | TLS on HTTP | Enabled | Disabled | Behind TLS-terminating ALB | ALB handles TLS, private subnet, SG restricted |
| Solr | blockUnknown auth | true | false | Public read-only search endpoint | Read-only role, network ACL, write requires auth |
| Solr | Remote streaming | Disabled | Enabled | Content extraction pipeline | Restricted source IPs via firewall, non-public facing |
| OpenSearch | HTTP TLS | Enabled | Disabled | Behind TLS ALB in VPC | Private subnet, SG-restricted, ALB cert |
| OpenSearch | Audit logging | Internal index | CloudWatch only | Index size concerns | CloudWatch log group with retention policy |
| OpenSearch | Script execution | Restricted | Allowed | Application uses Painless scripts | Script allowlist, index-level permissions |
| ActiveMQ | Web console | Localhost-only | Network-accessible | Remote ops monitoring | TLS + auth + IP ACL in jetty.xml |
| ActiveMQ | Plain TCP | Disabled | Enabled alongside SSL | Legacy client migration | Parallel listener, client upgrade timeline, network segmented |
| ActiveMQ | Authorization | Per-destination | Open to authenticated | Small trusted app set | All producers/consumers authenticated, audit logging |
| ZooKeeper | AdminServer | Disabled | Enabled (localhost) | Health check integration | Bind 127.0.0.1, 4lw whitelist = ruok only |
| ZooKeeper | Plaintext port | Disabled | Enabled alongside TLS | Client migration period | Firewall restricts to known Solr/Kafka IPs |
| ZooKeeper | maxClientCnxns | 60 | 200 | Large Solr/Kafka cluster | Per-IP limit still enforced, total monitored |
