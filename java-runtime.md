# Java Runtime STIG Hardening

STIG automation for Java Runtime Environment (JRE 8+) and JDK installations. The
JRE STIG applies to every system that runs Java — including Tomcat, ActiveMQ,
Keycloak, and any Java-based application. Apply this BEFORE hardening individual
Java applications.

## Table of Contents

1. [STIG Coverage Map](#stig-coverage-map)
2. [Locate Java Installations](#locate-java-installations)
3. [java.security Hardening](#javasecurity-hardening)
4. [deployment.properties (Client JRE)](#deploymentproperties)
5. [TLS & Certificate Configuration](#tls--certificate-configuration)
6. [File Permissions](#file-permissions)
7. [FIPS Mode for Java](#fips-mode-for-java)
8. [Ansible Playbook](#ansible-playbook)
9. [Common Tailoring Exceptions](#common-tailoring-exceptions)

---

## STIG Coverage Map

| Finding | Severity | Requirement | Config File |
|---------|----------|------------|-------------|
| JRE8-UX-000010 | CAT I | Remove outdated JRE versions | filesystem |
| JRE8-UX-000020 | CAT I | Disable TLS 1.0/1.1 | java.security |
| JRE8-UX-000060 | CAT II | Restrict crypto algorithms | java.security |
| JRE8-UX-000080 | CAT II | Enable certificate revocation checking | java.security |
| JRE8-UX-000090 | CAT II | Lock down deployment.properties | deployment.properties |
| JRE8-UX-000120 | CAT II | File permissions on JRE | filesystem |
| JRE8-UX-000150 | CAT II | Disable unsigned/self-signed applets | deployment.properties |
| JRE8-UX-000170 | CAT III | Banner/consent for Java Web Start | deployment.properties |

---

## Locate Java Installations

### Discovery Script (Bash)

```bash
#!/usr/bin/env bash
# find_java.sh — Find all Java installations on the system
set -euo pipefail

echo "=== Java Installation Discovery ==="

# Method 1: Known paths
KNOWN_PATHS=(
    /usr/lib/jvm
    /usr/java
    /opt/java
    /opt/jdk*
    /opt/jre*
    /usr/local/java
    "$JAVA_HOME"
)

for path in "${KNOWN_PATHS[@]}"; do
    if [[ -d "$path" ]] 2>/dev/null; then
        echo "  Found: $path"
        # Show version if possible
        if [[ -x "$path/bin/java" ]]; then
            echo "    Version: $("$path/bin/java" -version 2>&1 | head -1)"
        fi
    fi
done

# Method 2: Find all java binaries
echo ""
echo "  All java binaries:"
find / -name "java" -type f -executable 2>/dev/null | while read -r jbin; do
    version=$("$jbin" -version 2>&1 | head -1)
    echo "    $jbin → $version"
done

# Method 3: alternatives system
echo ""
echo "  Alternatives:"
alternatives --display java 2>/dev/null || update-alternatives --display java 2>/dev/null || true
```

### Discovery Script (Python)

```python
import subprocess
import os
from pathlib import Path


def find_java_installations() -> list[dict]:
    """Find all Java installations on the system."""
    installations = []
    search_paths = [
        "/usr/lib/jvm", "/usr/java", "/opt/java", "/opt/jdk*",
        "/opt/jre*", "/usr/local/java",
    ]
    java_home = os.environ.get("JAVA_HOME", "")
    if java_home:
        search_paths.append(java_home)

    seen = set()
    for pattern in search_paths:
        for path in Path("/").glob(pattern.lstrip("/")):
            java_bin = path / "bin" / "java"
            if java_bin.exists() and str(path) not in seen:
                seen.add(str(path))
                try:
                    result = subprocess.run(
                        [str(java_bin), "-version"],
                        capture_output=True, text=True, timeout=5
                    )
                    version = result.stderr.split("\n")[0]
                except Exception:
                    version = "unknown"

                sec_file = path / "conf" / "security" / "java.security"
                if not sec_file.exists():
                    sec_file = path / "lib" / "security" / "java.security"

                installations.append({
                    "path": str(path),
                    "version": version,
                    "java_security": str(sec_file) if sec_file.exists() else None,
                })
                print(f"  Found: {path} — {version}")

    return installations
```

---

## java.security Hardening

The `java.security` file is the primary security configuration for the JRE. Location
depends on version:
- JDK 9+: `$JAVA_HOME/conf/security/java.security`
- JDK 8: `$JAVA_HOME/jre/lib/security/java.security`

### Hardening Script (Bash)

```bash
#!/usr/bin/env bash
# harden_java_security.sh — Idempotent java.security hardening
set -euo pipefail

JAVA_HOME="${JAVA_HOME:?Set JAVA_HOME}"

# Determine java.security location
if [[ -f "${JAVA_HOME}/conf/security/java.security" ]]; then
    JAVA_SEC="${JAVA_HOME}/conf/security/java.security"
elif [[ -f "${JAVA_HOME}/jre/lib/security/java.security" ]]; then
    JAVA_SEC="${JAVA_HOME}/jre/lib/security/java.security"
else
    echo "ERROR: java.security not found"
    exit 1
fi

echo "=== Hardening: ${JAVA_SEC} ==="

# Backup
BACKUP="${JAVA_SEC}.pre-stig.bak"
if [[ ! -f "${BACKUP}" ]]; then
    cp "${JAVA_SEC}" "${BACKUP}"
    echo "  ✓ Backup: ${BACKUP}"
fi

apply_setting() {
    local key="$1" value="$2"
    if grep -q "^${key}=" "${JAVA_SEC}"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "${JAVA_SEC}"
    elif grep -q "^#${key}=" "${JAVA_SEC}"; then
        sed -i "s|^#${key}=.*|${key}=${value}|" "${JAVA_SEC}"
    else
        echo "${key}=${value}" >> "${JAVA_SEC}"
    fi
}

# --- CAT I: Disable weak TLS protocols ---
# jdk.tls.disabledAlgorithms — add SSLv3, TLSv1, TLSv1.1
CURRENT_TLS_DISABLED=$(grep "^jdk.tls.disabledAlgorithms=" "${JAVA_SEC}" | cut -d= -f2-)
DESIRED_TLS="SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, DH keySize < 2048, EC keySize < 224, 3DES_EDE_CBC, anon, NULL"
apply_setting "jdk.tls.disabledAlgorithms" "${DESIRED_TLS}"
echo "  ✓ Weak TLS protocols and ciphers disabled"

# --- CAT II: Disable weak crypto algorithms ---
DESIRED_CRYPTO="MD5, MD2, SHA1 jdkCA & usage SignedJAR & denyAfter 2019-01-01, RC4, DES, DESede, RSA keySize < 2048, DSA keySize < 2048, EC keySize < 224"
apply_setting "jdk.certpath.disabledAlgorithms" "${DESIRED_CRYPTO}"
echo "  ✓ Weak certificate path algorithms disabled"

# --- CAT II: Enable certificate revocation checking ---
apply_setting "com.sun.security.enableCRLDP" "true"
apply_setting "ocsp.enable" "true"
echo "  ✓ CRL/OCSP revocation checking enabled"

# --- CAT II: Enable crypto policy restrictions ---
apply_setting "crypto.policy" "unlimited"
echo "  ✓ Crypto policy set"

# --- CAT II: Disable insecure random ---
# Ensure strong SecureRandom source
if ! grep -q "securerandom.strongAlgorithms" "${JAVA_SEC}"; then
    echo "securerandom.strongAlgorithms=NativePRNGBlocking:SUN" >> "${JAVA_SEC}"
fi

echo "✓ java.security hardening complete"
```

### Hardening Script (Python)

```python
import re
import shutil
from pathlib import Path


def harden_java_security(java_home: str) -> None:
    """Apply STIG-compliant settings to java.security. Idempotent."""
    java_home_p = Path(java_home)
    candidates = [
        java_home_p / "conf" / "security" / "java.security",
        java_home_p / "jre" / "lib" / "security" / "java.security",
    ]
    sec_file = next((c for c in candidates if c.exists()), None)
    if not sec_file:
        raise FileNotFoundError(f"java.security not found in {java_home}")

    # Backup
    backup = sec_file.with_suffix(".pre-stig.bak")
    if not backup.exists():
        shutil.copy2(sec_file, backup)
        print(f"  ✓ Backup: {backup}")

    content = sec_file.read_text()

    settings = {
        "jdk.tls.disabledAlgorithms": (
            "SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, "
            "DH keySize < 2048, EC keySize < 224, 3DES_EDE_CBC, anon, NULL"
        ),
        "jdk.certpath.disabledAlgorithms": (
            "MD5, MD2, SHA1 jdkCA & usage SignedJAR & denyAfter 2019-01-01, "
            "RC4, DES, DESede, RSA keySize < 2048, DSA keySize < 2048, EC keySize < 224"
        ),
        "com.sun.security.enableCRLDP": "true",
        "ocsp.enable": "true",
        "crypto.policy": "unlimited",
    }

    for key, value in settings.items():
        pattern = rf"^#?{re.escape(key)}=.*$"
        replacement = f"{key}={value}"
        if re.search(pattern, content, re.MULTILINE):
            content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
        else:
            content += f"\n{replacement}"

    sec_file.write_text(content)
    print(f"  ✓ java.security hardened: {sec_file}")
```

---

## deployment.properties

Applies only to systems with Java Web Start or browser plugin (rare on servers but
common on workstations). Skip on headless servers.

```bash
# /etc/.java/deployment/deployment.properties
# (system-wide; user-level is ~/.java/deployment/deployment.properties)

deployment.security.level=VERY_HIGH
deployment.security.askgrantdialog.show=true
deployment.security.validation.crl=true
deployment.security.validation.ocsp=true
deployment.security.TLSv1=false
deployment.security.TLSv1.1=false
deployment.security.TLSv1.2=true
deployment.security.TLSv1.3=true
deployment.insecure.jres=PROMPT
deployment.security.sandbox.awtwarningwindow=true
deployment.security.notinca.warning=true
```

```bash
# Lock it so users can't override
# /etc/.java/deployment/deployment.config
deployment.system.config=file:///etc/.java/deployment/deployment.properties
deployment.system.config.mandatory=true
```

---

## TLS & Certificate Configuration

### Configure Trusted CA Certificates

```bash
#!/usr/bin/env bash
# import_dod_certs.sh — Import DoD root CAs into Java truststore
set -euo pipefail

JAVA_HOME="${JAVA_HOME:?Set JAVA_HOME}"
KEYTOOL="${JAVA_HOME}/bin/keytool"
TRUSTSTORE="${JAVA_HOME}/lib/security/cacerts"
TRUSTSTORE_PASS="${TRUSTSTORE_PASS:-changeit}"

CERT_DIR="${1:?Usage: import_dod_certs.sh /path/to/dod-certs/}"

echo "=== Importing DoD CAs into Java Truststore ==="

for cert in "${CERT_DIR}"/*.cer "${CERT_DIR}"/*.crt "${CERT_DIR}"/*.pem; do
    [[ -f "$cert" ]] || continue
    alias=$(basename "$cert" | sed 's/\.[^.]*$//' | tr '[:upper:]' '[:lower:]' | tr ' ' '-')

    # Check if already imported
    if "${KEYTOOL}" -list -keystore "${TRUSTSTORE}" -storepass "${TRUSTSTORE_PASS}" \
        -alias "${alias}" >/dev/null 2>&1; then
        echo "  ✓ Already imported: ${alias}"
        continue
    fi

    "${KEYTOOL}" -importcert -keystore "${TRUSTSTORE}" -storepass "${TRUSTSTORE_PASS}" \
        -alias "${alias}" -file "${cert}" -noprompt
    echo "  ✓ Imported: ${alias}"
done

echo "✓ DoD CA import complete"
```

---

## File Permissions

```bash
#!/usr/bin/env bash
# fix_java_permissions.sh
set -euo pipefail

JAVA_HOME="${JAVA_HOME:?Set JAVA_HOME}"

echo "=== Java File Permissions ==="

# JRE should be owned by root, not writable by group/other
chown -R root:root "${JAVA_HOME}"
find "${JAVA_HOME}" -type d -exec chmod 755 {} \;
find "${JAVA_HOME}" -type f -exec chmod 644 {} \;
find "${JAVA_HOME}/bin" -type f -exec chmod 755 {} \;

# Restrict security config files
chmod 644 "${JAVA_HOME}/conf/security/java.security" 2>/dev/null || \
chmod 644 "${JAVA_HOME}/jre/lib/security/java.security" 2>/dev/null || true

chmod 644 "${JAVA_HOME}/lib/security/cacerts" 2>/dev/null || \
chmod 644 "${JAVA_HOME}/jre/lib/security/cacerts" 2>/dev/null || true

echo "✓ Java permissions set"
```

---

## FIPS Mode for Java

When the OS is in FIPS mode (see `references/os-linux.md`), Java must also be
configured for FIPS-compliant operation.

```bash
# Append to java.security for FIPS mode
# This configures NSS as the FIPS provider

# Check if OS is in FIPS mode first
if fips-mode-setup --check 2>/dev/null | grep -q "is enabled"; then
    JAVA_SEC="${JAVA_HOME}/conf/security/java.security"

    # Prepend SunPKCS11 as security provider #1
    # Create NSS config
    cat > "${JAVA_HOME}/conf/security/nss.fips.cfg" << 'EOF'
name = NSS-FIPS
nssLibraryDirectory = /usr/lib64
nssSecmodDirectory = /etc/pki/nssdb
nssDbMode = readOnly
nssModule = fips
EOF

    echo "  ✓ FIPS NSS provider configured"
    echo "  ℹ Applications must be tested — FIPS restricts available algorithms"
fi
```

> **Tailoring**: FIPS mode disables many algorithms. Applications using MD5 digests,
> non-FIPS TLS cipher suites, or custom crypto providers will fail. Common victims:
> older JDBC drivers (PostgreSQL MD5 auth), legacy SAML libraries, and custom
> keystores. Test each application individually.

---

## Ansible Playbook

```yaml
# roles/stig_java/tasks/main.yml
- name: JRE STIG | Find Java installations
  ansible.builtin.find:
    paths:
      - /usr/lib/jvm
      - /opt
      - /usr/local
    patterns: "java.security"
    recurse: true
    file_type: file
  register: java_security_files

- name: JRE STIG | Backup java.security
  ansible.builtin.copy:
    src: "{{ item.path }}"
    dest: "{{ item.path }}.pre-stig.bak"
    remote_src: true
    force: false    # Don't overwrite existing backup
  loop: "{{ java_security_files.files }}"

- name: JRE STIG | Disable weak TLS protocols
  ansible.builtin.lineinfile:
    path: "{{ item.path }}"
    regexp: "^jdk.tls.disabledAlgorithms="
    line: "jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, DH keySize < 2048, EC keySize < 224, 3DES_EDE_CBC, anon, NULL"
    backup: true
  loop: "{{ java_security_files.files }}"

- name: JRE STIG | Disable weak certpath algorithms
  ansible.builtin.lineinfile:
    path: "{{ item.path }}"
    regexp: "^jdk.certpath.disabledAlgorithms="
    line: "jdk.certpath.disabledAlgorithms=MD5, MD2, SHA1 jdkCA & usage SignedJAR & denyAfter 2019-01-01, RC4, DES, DESede, RSA keySize < 2048, DSA keySize < 2048, EC keySize < 224"
    backup: true
  loop: "{{ java_security_files.files }}"

- name: JRE STIG | Enable CRL checking
  ansible.builtin.lineinfile:
    path: "{{ item.path }}"
    regexp: "^com.sun.security.enableCRLDP="
    line: "com.sun.security.enableCRLDP=true"
  loop: "{{ java_security_files.files }}"

- name: JRE STIG | Enable OCSP
  ansible.builtin.lineinfile:
    path: "{{ item.path }}"
    regexp: "^ocsp.enable="
    line: "ocsp.enable=true"
  loop: "{{ java_security_files.files }}"

- name: JRE STIG | Set file permissions
  ansible.builtin.file:
    path: "{{ item.path }}"
    owner: root
    group: root
    mode: "0644"
  loop: "{{ java_security_files.files }}"
```

---

## Common Tailoring Exceptions

| Finding | Default | Tailored | Reason | Compensating Control |
|---------|---------|----------|--------|---------------------|
| TLS 1.0/1.1 disabled | Disabled | Enabled for TLSv1.2 fallback | Legacy backend service | Upgrade plan, network segmentation |
| OCSP/CRL enabled | Enabled | Disabled | Air-gapped network, no CRL endpoint | Local CRL distribution, short-lived certs |
| FIPS provider | Enabled | Disabled | App uses non-FIPS crypto (e.g., Bouncy Castle) | App-level encryption audit, upgrade timeline |
| 3DES disabled | Disabled | Enabled | Legacy smartcard middleware | Isolated workstation, upgrade scheduled |
| RSA < 2048 disabled | Disabled | Allowed for internal CA | Legacy internal PKI | CA migration plan, 1-year expiry |
