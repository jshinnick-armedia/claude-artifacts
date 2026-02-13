# Web & Application Server STIG Hardening

Covers Apache Tomcat 9/10, Apache HTTP Server 2.4, ActiveMQ, and Keycloak. Tomcat
and Apache have dedicated STIGs; ActiveMQ and Keycloak map to the Application Server
SRG (Security Requirements Guide).

## Table of Contents

1. [Apache Tomcat](#apache-tomcat)
2. [Apache HTTP Server](#apache-http-server)
3. [ActiveMQ](#activemq)
4. [Keycloak](#keycloak)
5. [Common Tailoring Exceptions](#common-tailoring-exceptions)

---

## Apache Tomcat

### Key STIG Controls (TCAT-AS)

| Finding | Severity | Requirement | Config Location |
|---------|----------|------------|-----------------|
| TCAT-AS-000010 | CAT I | Remove default apps (ROOT, examples, docs) | webapps/ |
| TCAT-AS-000030 | CAT I | Disable unused connectors | server.xml |
| TCAT-AS-000060 | CAT I | Use TLS for all connectors | server.xml |
| TCAT-AS-000090 | CAT II | Run as non-root, dedicated user | systemd unit |
| TCAT-AS-000110 | CAT II | File permissions on CATALINA_HOME | filesystem |
| TCAT-AS-000150 | CAT II | Enable access logging | server.xml |
| TCAT-AS-000200 | CAT II | Error pages must not reveal stack traces | web.xml |
| TCAT-AS-000240 | CAT II | Shutdown port disabled | server.xml |
| TCAT-AS-000260 | CAT II | Secure session cookies | web.xml / context.xml |
| TCAT-AS-000340 | CAT III | Remove server version from headers | server.xml |

### Hardening Script (Bash)

```bash
#!/usr/bin/env bash
# harden_tomcat.sh — Idempotent Tomcat STIG hardening
set -euo pipefail

CATALINA_HOME="${CATALINA_HOME:-/opt/tomcat}"
TOMCAT_USER="${TOMCAT_USER:-tomcat}"

echo "=== Tomcat STIG Hardening: ${CATALINA_HOME} ==="

# --- CAT I: Remove default apps ---
for app in ROOT examples docs host-manager; do
    if [[ -d "${CATALINA_HOME}/webapps/${app}" ]]; then
        rm -rf "${CATALINA_HOME}/webapps/${app}"
        echo "  ✓ Removed default app: ${app}"
    fi
done

# --- CAT I: Disable shutdown port ---
if grep -q 'port="8005"' "${CATALINA_HOME}/conf/server.xml" 2>/dev/null; then
    sed -i 's/port="8005"/port="-1"/' "${CATALINA_HOME}/conf/server.xml"
    echo "  ✓ Shutdown port disabled"
fi

# --- CAT II: Remove server version from responses ---
SERVER_XML="${CATALINA_HOME}/conf/server.xml"
if ! grep -q 'server=" "' "${SERVER_XML}" 2>/dev/null; then
    # Add server=" " attribute to Connector elements
    sed -i '/<Connector/s/>/ server=" ">/' "${SERVER_XML}" 2>/dev/null || true
    echo "  ✓ Server header blanked"
fi

# --- CAT II: Enable secure session cookies in context.xml ---
CONTEXT_XML="${CATALINA_HOME}/conf/context.xml"
if ! grep -q 'useHttpOnly="true"' "${CONTEXT_XML}" 2>/dev/null; then
    sed -i 's|<Context>|<Context>\n    <CookieProcessor className="org.apache.tomcat.util.http.Rfc6265CookieProcessor" sameSiteCookies="strict" />|' "${CONTEXT_XML}"
    echo "  ✓ Secure cookie processor added"
fi

# --- CAT II: Custom error pages (no stack traces) ---
WEB_XML="${CATALINA_HOME}/conf/web.xml"
if ! grep -q '<error-page>' "${WEB_XML}" 2>/dev/null; then
    # Insert before closing </web-app>
    sed -i '/<\/web-app>/i \
    <error-page><error-code>404</error-code><location>/error.html</location></error-page>\
    <error-page><error-code>500</error-code><location>/error.html</location></error-page>\
    <error-page><exception-type>java.lang.Throwable</exception-type><location>/error.html</location></error-page>' "${WEB_XML}"
    echo "  ✓ Custom error pages configured"
fi

# --- CAT II: File permissions ---
chown -R "${TOMCAT_USER}:${TOMCAT_USER}" "${CATALINA_HOME}"
chmod -R 750 "${CATALINA_HOME}/bin"
chmod -R 640 "${CATALINA_HOME}/conf"
chmod 750 "${CATALINA_HOME}/conf"
chmod -R 750 "${CATALINA_HOME}/logs"
chmod -R 750 "${CATALINA_HOME}/webapps"
echo "  ✓ File permissions set (owner: ${TOMCAT_USER})"

# --- CAT II: Ensure running as non-root ---
if [[ -f /etc/systemd/system/tomcat.service ]]; then
    if ! grep -q "User=${TOMCAT_USER}" /etc/systemd/system/tomcat.service; then
        echo "  ⚠ systemd unit does not specify User=${TOMCAT_USER} — fix the unit file"
    else
        echo "  ✓ Running as ${TOMCAT_USER}"
    fi
fi

echo "✓ Tomcat STIG hardening complete"
```

### Ansible Equivalent (Key Tasks)

```yaml
- name: TCAT | Remove default webapps
  ansible.builtin.file:
    path: "{{ catalina_home }}/webapps/{{ item }}"
    state: absent
  loop: [ROOT, examples, docs, host-manager]

- name: TCAT | Disable shutdown port
  ansible.builtin.replace:
    path: "{{ catalina_home }}/conf/server.xml"
    regexp: 'port="8005"'
    replace: 'port="-1"'
    backup: true

- name: TCAT | Set file ownership
  ansible.builtin.file:
    path: "{{ catalina_home }}"
    owner: "{{ tomcat_user }}"
    group: "{{ tomcat_user }}"
    recurse: true
```

---

## Apache HTTP Server

### Key STIG Controls (APACHE-2.4)

| Finding | Severity | Requirement | Config Location |
|---------|----------|------------|-----------------|
| AS24-U1-000010 | CAT I | Disable TRACE method | httpd.conf |
| AS24-U1-000030 | CAT I | Use TLS 1.2+ | ssl.conf |
| AS24-U1-000060 | CAT II | Disable directory listing | httpd.conf |
| AS24-U1-000090 | CAT II | Remove server version | httpd.conf |
| AS24-U1-000120 | CAT II | Access logging enabled | httpd.conf |
| AS24-U1-000180 | CAT II | Limit request size | httpd.conf |
| AS24-U1-000210 | CAT II | Timeout settings | httpd.conf |
| AS24-U1-000270 | CAT II | Run as non-root user | httpd.conf |

### Hardening Script (Bash)

```bash
#!/usr/bin/env bash
# harden_apache.sh — Idempotent Apache httpd STIG hardening
set -euo pipefail

HTTPD_CONF="${HTTPD_CONF:-/etc/httpd/conf/httpd.conf}"
SSL_CONF="${SSL_CONF:-/etc/httpd/conf.d/ssl.conf}"
STIG_CONF="/etc/httpd/conf.d/stig-hardening.conf"

echo "=== Apache httpd STIG Hardening ==="

# Use a dedicated config file for STIG overrides so we don't fight with package updates
cat > "${STIG_CONF}" << 'STIGEOF'
# STIG Hardening — managed by automation
# AS24-U1-000090 — Hide server version
ServerTokens Prod
ServerSignature Off

# AS24-U1-000010 — Disable TRACE
TraceEnable Off

# AS24-U1-000180 — Limit request body
LimitRequestBody 10485760

# AS24-U1-000210 — Timeouts
Timeout 60
KeepAliveTimeout 5
MaxKeepAliveRequests 100

# AS24-U1-000060 — Disable directory listing
<Directory />
    Options -Indexes -FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>

# Security headers
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always unset X-Powered-By
STIGEOF

echo "  ✓ STIG config written: ${STIG_CONF}"

# --- CAT I: TLS hardening in ssl.conf ---
if [[ -f "${SSL_CONF}" ]]; then
    # Enforce TLS 1.2+
    if grep -q "^SSLProtocol" "${SSL_CONF}"; then
        sed -i 's/^SSLProtocol.*/SSLProtocol -all +TLSv1.2 +TLSv1.3/' "${SSL_CONF}"
    else
        echo "SSLProtocol -all +TLSv1.2 +TLSv1.3" >> "${SSL_CONF}"
    fi

    # Strong cipher suite
    if grep -q "^SSLCipherSuite" "${SSL_CONF}"; then
        sed -i 's/^SSLCipherSuite.*/SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4:!DES:!EXPORT/' "${SSL_CONF}"
    else
        echo "SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4:!DES:!EXPORT" >> "${SSL_CONF}"
    fi
    echo "  ✓ TLS 1.2+ enforced, weak ciphers disabled"
fi

# Validate config
httpd -t 2>&1 && echo "  ✓ Config syntax valid" || echo "  ✗ Config syntax error"

echo "✓ Apache STIG hardening complete — reload with: systemctl reload httpd"
```

---

## ActiveMQ

ActiveMQ doesn't have a dedicated STIG but maps to the **Application Server SRG**
(SRG-APP-000001 through SRG-APP-000516). Key controls below; for expanded coverage
including TLS transport connectors, JAAS authentication, per-destination authorization,
Artemis differences, and cluster-wide hardening order, see
`references/middleware-data-services.md`.

### Hardening Script (Bash)

```bash
#!/usr/bin/env bash
# harden_activemq.sh
set -euo pipefail

AMQ_HOME="${AMQ_HOME:-/opt/activemq}"
AMQ_USER="${AMQ_USER:-activemq}"
AMQ_CONF="${AMQ_HOME}/conf"

echo "=== ActiveMQ SRG Hardening ==="

# --- SRG-APP-000033: Run as non-root ---
if [[ -f /etc/systemd/system/activemq.service ]]; then
    if ! grep -q "User=${AMQ_USER}" /etc/systemd/system/activemq.service; then
        echo "  ⚠ systemd unit should specify User=${AMQ_USER}"
    fi
fi

# --- SRG-APP-000142: Disable web console or restrict access ---
JETTY_XML="${AMQ_CONF}/jetty.xml"
if [[ -f "${JETTY_XML}" ]]; then
    # Bind web console to localhost only
    if grep -q '0.0.0.0' "${JETTY_XML}"; then
        sed -i 's/0\.0\.0\.0/127.0.0.1/g' "${JETTY_XML}"
        echo "  ✓ Web console restricted to localhost"
    fi
fi

# --- SRG-APP-000172: Require authentication for all connections ---
# Ensure activemq.xml has authentication plugin
ACTIVEMQ_XML="${AMQ_CONF}/activemq.xml"
if ! grep -q 'simpleAuthenticationPlugin\|jaasAuthenticationPlugin' "${ACTIVEMQ_XML}" 2>/dev/null; then
    echo "  ⚠ No authentication plugin found in activemq.xml — add one"
fi

# --- SRG-APP-000014: Use TLS for transport connectors ---
if grep -q 'tcp://0.0.0.0:61616' "${ACTIVEMQ_XML}" 2>/dev/null; then
    echo "  ⚠ Plain TCP connector found — should use ssl://0.0.0.0:61617 with keystoreFile"
fi

# --- SRG-APP-000516: File permissions ---
chown -R "${AMQ_USER}:${AMQ_USER}" "${AMQ_HOME}"
chmod 750 "${AMQ_CONF}"
chmod 640 "${AMQ_CONF}"/*.xml
chmod 640 "${AMQ_CONF}"/*.properties 2>/dev/null || true
echo "  ✓ File permissions set"

# --- SRG-APP-000092: Remove default credentials ---
USERS_PROPS="${AMQ_CONF}/users.properties"
if [[ -f "${USERS_PROPS}" ]] && grep -q "^admin=admin$" "${USERS_PROPS}"; then
    echo "  ⚠ DEFAULT CREDENTIALS FOUND in users.properties — change immediately (CAT I)"
fi

# --- SRG-APP-000095: Enable audit logging ---
LOG4J_PROPS="${AMQ_CONF}/log4j2.properties"
if [[ -f "${LOG4J_PROPS}" ]]; then
    if ! grep -q "audit" "${LOG4J_PROPS}"; then
        echo "  ⚠ Audit logging not configured in log4j2.properties"
    fi
fi

echo "✓ ActiveMQ SRG hardening complete"
```

---

## Keycloak

Keycloak also maps to the **Application Server SRG**. Additional controls from the
**Web Server SRG** apply to its embedded HTTP server.

### Hardening Script (Bash)

```bash
#!/usr/bin/env bash
# harden_keycloak.sh
set -euo pipefail

KC_HOME="${KC_HOME:-/opt/keycloak}"
KC_USER="${KC_USER:-keycloak}"
KC_CONF="${KC_HOME}/conf/keycloak.conf"

echo "=== Keycloak SRG Hardening ==="

# --- SRG-APP-000033: Run as non-root ---
if [[ -f /etc/systemd/system/keycloak.service ]]; then
    if ! grep -q "User=${KC_USER}" /etc/systemd/system/keycloak.service; then
        echo "  ⚠ systemd unit should specify User=${KC_USER}"
    fi
fi

# --- SRG-APP-000014: HTTPS required ---
apply_kc_setting() {
    local key="$1" value="$2"
    if grep -q "^${key}=" "${KC_CONF}" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${value}|" "${KC_CONF}"
    elif grep -q "^#${key}=" "${KC_CONF}" 2>/dev/null; then
        sed -i "s|^#${key}=.*|${key}=${value}|" "${KC_CONF}"
    else
        echo "${key}=${value}" >> "${KC_CONF}"
    fi
}

apply_kc_setting "https-port" "8443"
apply_kc_setting "http-enabled" "false"
echo "  ✓ HTTP disabled, HTTPS on 8443"

# --- SRG-APP-000172: Enforce strong TLS ---
apply_kc_setting "https-protocols" "TLSv1.3,TLSv1.2"
echo "  ✓ TLS 1.2+ enforced"

# --- SRG-APP-000317: Session timeout ---
# Default Keycloak realm SSO session idle = 30 min, max = 10 hr
# STIG typically wants 15 min idle for admin sessions
echo "  ℹ Session timeouts configured per-realm in Keycloak admin console"
echo "    Recommended: SSO Session Idle = 15 min, SSO Session Max = 8 hr"

# --- SRG-APP-000092: Remove/change default admin credentials ---
# Keycloak 21+ uses 'kc.sh' bootstrap admin — verify no default admin/admin
echo "  ℹ Verify admin credentials are not default (admin/admin)"

# --- SRG-APP-000095: Enable event logging ---
# Keycloak event logging is configured per-realm
echo "  ℹ Enable Login Events and Admin Events in each realm's Events settings"

# --- File permissions ---
chown -R "${KC_USER}:${KC_USER}" "${KC_HOME}"
chmod 750 "${KC_HOME}/conf"
chmod 640 "${KC_CONF}"
echo "  ✓ File permissions set"

echo "✓ Keycloak SRG hardening complete"
```

### Keycloak Realm-Level Hardening (Python — Keycloak Admin API)

```python
import requests


def harden_keycloak_realm(
    base_url: str, realm: str, admin_token: str,
    session_idle_min: int = 15, session_max_hr: int = 8,
    brute_force_max: int = 5
):
    """Apply STIG-aligned settings to a Keycloak realm via Admin REST API.

    Idempotent — reads current settings and only updates if different.
    """
    headers = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}
    realm_url = f"{base_url}/admin/realms/{realm}"

    current = requests.get(realm_url, headers=headers).json()

    updates = {}

    # SRG-APP-000317: Session timeouts
    desired_idle = session_idle_min * 60
    desired_max = session_max_hr * 3600
    if current.get("ssoSessionIdleTimeout") != desired_idle:
        updates["ssoSessionIdleTimeout"] = desired_idle
    if current.get("ssoSessionMaxLifespan") != desired_max:
        updates["ssoSessionMaxLifespan"] = desired_max

    # SRG-APP-000065: Brute force protection
    if not current.get("bruteForceProtected"):
        updates["bruteForceProtected"] = True
        updates["maxFailureWaitSeconds"] = 900
        updates["failureFactor"] = brute_force_max
        updates["permanentLockout"] = False
        updates["waitIncrementSeconds"] = 60

    # SRG-APP-000095: Event logging
    if not current.get("eventsEnabled"):
        updates["eventsEnabled"] = True
        updates["eventsExpiration"] = 7776000  # 90 days
        updates["adminEventsEnabled"] = True
        updates["adminEventsDetailsEnabled"] = True

    if updates:
        requests.put(realm_url, headers=headers, json=updates)
        print(f"  ✓ Realm '{realm}' updated: {list(updates.keys())}")
    else:
        print(f"  ✓ Realm '{realm}' already compliant")
```

---

## Common Tailoring Exceptions

| App | Finding | Default | Tailored | Reason |
|-----|---------|---------|----------|--------|
| Tomcat | Manager app removed | Removed | Kept (localhost-only) | CI/CD deploy via manager | IP-restricted, TLS, separate credentials |
| Tomcat | AJP connector | Disabled | Enabled | Apache mod_proxy_ajp frontend | secretRequired, address=127.0.0.1 |
| Apache | TRACE disabled | Off | On | Debugging in dev | Dev-only, disabled in prod |
| ActiveMQ | Web console | Localhost-only | Network-accessible | Remote monitoring | TLS, auth required, ACL by source IP |
| Keycloak | HTTP | Disabled | Enabled on :8080 | Behind TLS-terminating ALB | ALB handles TLS, private subnet only |
| All | SELinux | Enforcing | Custom policy | Non-standard paths | `audit2allow -M appname` policy module |
