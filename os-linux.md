# Linux OS STIG Hardening

STIG automation for RHEL 8/9 and Amazon Linux 2023. Controls organized by category
with Ansible tasks, Bash equivalents, and tailoring notes for common exceptions.

## Table of Contents

1. [STIG Coverage Map](#stig-coverage-map)
2. [Authentication & Password Policy](#authentication--password-policy)
3. [SSH Hardening](#ssh-hardening)
4. [Audit & Logging](#audit--logging)
5. [Filesystem & Permissions](#filesystem--permissions)
6. [Kernel & Network Hardening](#kernel--network-hardening)
7. [Service Minimization](#service-minimization)
8. [SELinux](#selinux)
9. [FIPS 140-2 Mode](#fips-mode)
10. [Banner & Login Warnings](#banner--login-warnings)
11. [Ansible Playbook Structure](#ansible-playbook-structure)
12. [Common Tailoring Exceptions](#common-tailoring-exceptions)

---

## STIG Coverage Map

| Category | Severity | Key Findings (RHEL 9 representative) | Automated? |
|----------|----------|---------------------------------------|-----------|
| FIPS mode | CAT I | RHEL-09-671010 | ✅ |
| SSH root login | CAT I | RHEL-09-255040 | ✅ |
| Password complexity | CAT II | RHEL-09-611070–611120 | ✅ |
| Account lockout | CAT II | RHEL-09-411075 | ✅ |
| Audit log config | CAT II | RHEL-09-653010–653120 | ✅ |
| Kernel parameters | CAT II | RHEL-09-253010–253060 | ✅ |
| File permissions | CAT II | RHEL-09-232010–232260 | ✅ |
| SELinux enforcing | CAT II | RHEL-09-431010 | ✅ |
| Login banner | CAT III | RHEL-09-271010 | ✅ |
| Unnecessary services | CAT II | RHEL-09-291010 | ✅ |

---

## Authentication & Password Policy

### Password Quality (pam_pwquality)

```yaml
# Ansible task
- name: STIG | Password quality settings
  ansible.builtin.lineinfile:
    path: /etc/security/pwquality.conf
    regexp: "^{{ item.key }}\\s*="
    line: "{{ item.key }} = {{ item.value }}"
    backup: true
  loop:
    - { key: minlen,         value: "15" }    # CAT II — DoD 15+ chars
    - { key: dcredit,        value: "-1" }    # At least 1 digit
    - { key: ucredit,        value: "-1" }    # At least 1 uppercase
    - { key: lcredit,        value: "-1" }    # At least 1 lowercase
    - { key: ocredit,        value: "-1" }    # At least 1 special
    - { key: difok,          value: "8" }     # 8 chars different from previous
    - { key: maxrepeat,      value: "3" }     # No 3+ consecutive identical
    - { key: maxclassrepeat, value: "4" }
    - { key: dictcheck,      value: "1" }
```

```bash
# Bash equivalent — idempotent
#!/usr/bin/env bash
set -euo pipefail
CONF="/etc/security/pwquality.conf"

apply() {
    local key="$1" val="$2"
    if grep -q "^${key}\s*=" "${CONF}" 2>/dev/null; then
        sed -i "s/^${key}\s*=.*/${key} = ${val}/" "${CONF}"
    else
        echo "${key} = ${val}" >> "${CONF}"
    fi
}

apply minlen 15; apply dcredit -1; apply ucredit -1; apply lcredit -1
apply ocredit -1; apply difok 8; apply maxrepeat 3; apply dictcheck 1
echo "✓ Password quality configured"
```

### Account Lockout (pam_faillock)

```yaml
- name: STIG | Account lockout via faillock
  ansible.builtin.lineinfile:
    path: /etc/security/faillock.conf
    regexp: "^{{ item.key }}\\s*="
    line: "{{ item.key }} = {{ item.value }}"
    backup: true
  loop:
    - { key: deny,          value: "3" }     # Lock after 3 failures
    - { key: fail_interval, value: "900" }   # Within 15 min window
    - { key: unlock_time,   value: "0" }     # Admin must unlock (STIG default)
```

> **Tailoring**: `unlock_time = 0` (never auto-unlock) can lock admins out permanently.
> Consider `unlock_time = 900` (15 min) for environments without 24/7 admin coverage,
> and document the exception.

### Password Aging (login.defs)

```yaml
- name: STIG | Password max age 60 days
  ansible.builtin.lineinfile:
    path: /etc/login.defs
    regexp: "^PASS_MAX_DAYS"
    line: "PASS_MAX_DAYS   60"
    backup: true

- name: STIG | Password min age 1 day
  ansible.builtin.lineinfile:
    path: /etc/login.defs
    regexp: "^PASS_MIN_DAYS"
    line: "PASS_MIN_DAYS   1"
    backup: true

- name: STIG | Password min length in login.defs
  ansible.builtin.lineinfile:
    path: /etc/login.defs
    regexp: "^PASS_MIN_LEN"
    line: "PASS_MIN_LEN    15"
    backup: true
```

---

## SSH Hardening

### Key STIG Settings for sshd_config

```yaml
- name: STIG | SSH — Apply hardened settings
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    regexp: "^#?{{ item.key }}\\s"
    line: "{{ item.key }} {{ item.value }}"
    backup: true
    validate: "sshd -t -f %s"
  loop:
    # CAT I
    - { key: PermitRootLogin,           value: "no" }
    - { key: PermitEmptyPasswords,      value: "no" }
    # CAT II — FIPS-approved ciphers only
    - { key: Ciphers, value: "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr" }
    - { key: MACs,    value: "hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" }
    - { key: KexAlgorithms, value: "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512" }
    # Session timeout
    - { key: ClientAliveInterval,       value: "600" }
    - { key: ClientAliveCountMax,       value: "0" }
    # Misc hardening
    - { key: X11Forwarding,             value: "no" }
    - { key: HostbasedAuthentication,   value: "no" }
    - { key: MaxAuthTries,              value: "4" }
    - { key: Banner,                    value: "/etc/issue.net" }
    - { key: LogLevel,                  value: "VERBOSE" }
    - { key: GSSAPIAuthentication,      value: "no" }
  notify: restart sshd
```

> **Tailoring**: `PermitRootLogin no` — Ensure a sudo-capable user exists before
> applying. If using SSM Session Manager, this is safe since SSM bypasses SSH entirely.

---

## Audit & Logging

### Auditd Configuration

```yaml
- name: STIG | Auditd config
  ansible.builtin.lineinfile:
    path: /etc/audit/auditd.conf
    regexp: "^{{ item.key }}\\s*="
    line: "{{ item.key }} = {{ item.value }}"
    backup: true
  loop:
    - { key: log_format,              value: ENRICHED }
    - { key: max_log_file,            value: "25" }
    - { key: max_log_file_action,     value: ROTATE }
    - { key: num_logs,                value: "5" }
    - { key: space_left_action,       value: email }
    - { key: admin_space_left_action, value: HALT }     # Stop if audit full
    - { key: disk_full_action,        value: HALT }
  notify: restart auditd
```

### STIG Audit Rules

```bash
# /etc/audit/rules.d/99-stig.rules
# Identity changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# Login events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Privilege escalation
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid

# Permission changes
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Unauthorized access
-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules

# Time changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-w /etc/localtime -p wa -k time-change

# Make rules immutable (last rule)
-e 2
```

> **Tailoring**: `admin_space_left_action = HALT` stops the system when audit logs
> fill up. For high-availability systems, use `SYSLOG` or `ROTATE` and set up external
> log shipping (CloudWatch, rsyslog) so you don't lose audit data while keeping the
> system running. Document the compensating control.

---

## Filesystem & Permissions

### Mount Options

```yaml
- name: STIG | Secure /tmp mount options
  ansible.posix.mount:
    path: /tmp
    src: tmpfs
    fstype: tmpfs
    opts: "defaults,nodev,nosuid,noexec,size=2G"
    state: mounted

- name: STIG | Secure /dev/shm mount options
  ansible.posix.mount:
    path: /dev/shm
    src: tmpfs
    fstype: tmpfs
    opts: "defaults,nodev,nosuid,noexec"
    state: mounted
```

### Critical File Permissions

```bash
#!/usr/bin/env bash
set -euo pipefail

fix() {
    local file="$1" owner="$2" mode="$3"
    [[ -e "$file" ]] || return 0
    current=$(stat -c "%U:%G %a" "$file")
    if [[ "$current" != "$owner $mode" ]]; then
        chown "${owner}" "$file"; chmod "$mode" "$file"
        echo "  ✓ Fixed: $file → $mode $owner"
    fi
}

fix /etc/passwd   root:root 644
fix /etc/shadow   root:root 000
fix /etc/group    root:root 644
fix /etc/gshadow  root:root 000
fix /etc/ssh/sshd_config root:root 600
fix /etc/audit/auditd.conf root:root 640
echo "✓ File permissions verified"
```

---

## Kernel & Network Hardening

```yaml
- name: STIG | Sysctl hardening
  ansible.posix.sysctl:
    name: "{{ item.key }}"
    value: "{{ item.value }}"
    sysctl_set: true
    state: present
    reload: true
  loop: "{{ stig_sysctl | dict2items }}"
  vars:
    stig_sysctl:
      net.ipv4.ip_forward: "{{ '1' if stig_ip_forwarding else '0' }}"
      net.ipv4.conf.all.accept_source_route: 0
      net.ipv4.conf.default.accept_source_route: 0
      net.ipv6.conf.all.accept_source_route: 0
      net.ipv4.conf.all.accept_redirects: 0
      net.ipv4.conf.default.accept_redirects: 0
      net.ipv6.conf.all.accept_redirects: 0
      net.ipv4.conf.all.send_redirects: 0
      net.ipv4.conf.default.send_redirects: 0
      net.ipv4.conf.all.rp_filter: 1
      net.ipv4.conf.default.rp_filter: 1
      net.ipv4.icmp_ignore_bogus_error_responses: 1
      net.ipv4.tcp_syncookies: 1
      kernel.randomize_va_space: 2          # ASLR
      fs.suid_dumpable: 0                   # No core dumps for setuid
      kernel.kptr_restrict: 1               # Hide kernel pointers
      kernel.dmesg_restrict: 1              # Restrict dmesg
```

> **Tailoring**: Set `stig_ip_forwarding: true` for NAT gateways, Docker hosts,
> Kubernetes nodes, or VPN servers. Document in tailoring file.

---

## Service Minimization

```yaml
- name: STIG | Stop and mask unnecessary services
  ansible.builtin.systemd:
    name: "{{ item }}"
    state: stopped
    enabled: false
    masked: true
  loop:
    - rpcbind
    - avahi-daemon
    - cups
    - bluetooth
    - rsh.socket
    - rlogin.socket
    - vsftpd
    - telnet.socket
    - tftp.socket
  failed_when: false    # Don't fail if service doesn't exist

- name: STIG | Remove unnecessary packages
  ansible.builtin.dnf:
    name: [rsh, telnet, tftp, ypbind, talk]
    state: absent
```

---

## SELinux

```yaml
- name: STIG | SELinux enforcing
  ansible.builtin.lineinfile:
    path: /etc/selinux/config
    regexp: "^SELINUX="
    line: "SELINUX=enforcing"
    backup: true

- name: STIG | Set enforcing at runtime
  ansible.builtin.command: setenforce 1
  when: ansible_selinux.mode != "enforcing"
  changed_when: true
  failed_when: false
```

> **Tailoring**: Applications like Tomcat, ActiveMQ, and Keycloak may need custom
> SELinux policy modules. Use `audit2allow -M myapp` rather than disabling SELinux.
> See `references/web-app-servers.md` for per-app guidance.

---

## FIPS Mode

```yaml
- name: STIG | Check FIPS status
  ansible.builtin.command: fips-mode-setup --check
  register: fips_check
  changed_when: false
  failed_when: false

- name: STIG | Enable FIPS 140-2 mode (CAT I)
  ansible.builtin.command: fips-mode-setup --enable
  when: "'is enabled' not in fips_check.stdout"
  notify: reboot required
```

> **Tailoring**: FIPS disables non-compliant algorithms. Test all applications in
> staging first. Common breakages: Java apps with non-FIPS providers, PostgreSQL
> MD5 auth, legacy TLS clients. See `references/databases.md` and
> `references/java-runtime.md` for FIPS-specific guidance.

---

## Banner & Login Warnings

```yaml
- name: STIG | Deploy DoD login banner
  ansible.builtin.copy:
    content: |
      You are accessing a U.S. Government (USG) Information System (IS) that is
      provided for USG-authorized use only. By using this IS (which includes any
      device attached to this IS), you consent to the following conditions:
      -The USG routinely intercepts and monitors communications on this IS for
      purposes including, but not limited to, penetration testing, COMSEC monitoring,
      network operations and defense, personnel misconduct (PM), law enforcement (LE),
      and counterintelligence (CI) investigations.
      -At any time, the USG may inspect and seize data stored on this IS.
      -Communications using, or data stored on, this IS are not private, are subject
      to routine monitoring, interception, and search, and may be disclosed or used
      for any USG-authorized purpose.
      -This IS includes security measures (e.g., authentication and access controls)
      to protect USG interests--not for your personal benefit or privacy.
      -Notwithstanding the above, using this IS does not constitute consent to PM, LE
      or CI investigative searching or monitoring of the content of privileged
      communications, or work product, related to personal representation or services
      by attorneys, psychotherapists, or clergy, and their assistants. Such
      communications and work product are private and confidential.
    dest: "{{ item }}"
    owner: root
    group: root
    mode: "0644"
  loop:
    - /etc/issue
    - /etc/issue.net
```

---

## Ansible Playbook Structure

```
stig-linux/
├── site.yml                    # Main entry point
├── inventory/
│   ├── dev.ini
│   └── prod.ini
├── group_vars/
│   └── all.yml                 # Default STIG vars
├── host_vars/
│   └── webserver01.yml         # Per-host tailoring overrides
└── roles/
    └── stig_linux/
        ├── tasks/main.yml      # Imports all task files
        ├── templates/
        ├── files/
        │   └── 99-stig.rules   # Audit rules
        ├── defaults/main.yml   # Default variable values
        └── handlers/main.yml   # restart sshd, auditd, etc.
```

### Main Playbook

```yaml
# site.yml
- hosts: linux_servers
  become: true
  vars:
    stig_skip_fips: false
    stig_skip_selinux: false
    stig_ip_forwarding: false
  roles:
    - stig_linux
```

### Role Main Task (Tags for Selective Runs)

```yaml
# roles/stig_linux/tasks/main.yml
- import_tasks: password_policy.yml
  tags: [passwords, cat2]

- import_tasks: ssh.yml
  tags: [ssh, cat1]

- import_tasks: audit.yml
  tags: [audit, cat2]

- import_tasks: filesystem.yml
  tags: [filesystem, cat2]

- import_tasks: sysctl.yml
  tags: [kernel, cat2]

- import_tasks: services.yml
  tags: [services, cat2]

- import_tasks: selinux.yml
  when: not stig_skip_selinux
  tags: [selinux, cat2]

- import_tasks: fips.yml
  when: not stig_skip_fips
  tags: [fips, cat1]

- import_tasks: banner.yml
  tags: [banner, cat3]
```

### Handlers

```yaml
# roles/stig_linux/handlers/main.yml
- name: restart sshd
  ansible.builtin.systemd:
    name: sshd
    state: restarted

- name: restart auditd
  ansible.builtin.command: service auditd restart
  # auditd doesn't support systemctl restart — must use service command

- name: reload auditd
  ansible.builtin.command: augenrules --load

- name: reboot required
  ansible.builtin.debug:
    msg: "⚠ REBOOT REQUIRED for FIPS mode. Schedule a maintenance window."
```

---

## Common Tailoring Exceptions

| Finding | Default | Tailored Value | Reason | Compensating Control |
|---------|---------|---------------|--------|---------------------|
| IP forwarding | 0 (off) | 1 (on) | Docker/K8s host, NAT GW | Network ACLs, SG rules |
| SELinux | enforcing | permissive | Custom app incompatible | App-specific policy module, `audit2allow` |
| FIPS mode | enabled | disabled | Legacy app uses MD5/RC4 | Application-layer encryption, TLS 1.2+ |
| Account lockout unlock | 0 (never) | 900 (15 min) | No 24/7 admin coverage | MFA, CloudWatch alarm on lockout |
| Audit disk full action | HALT | SYSLOG | HA requirement | CloudWatch Logs agent for offsite logging |
| SSH root login | no | prohibit-password | Emergency key-only root access | MFA, audit trail, SSM Session Manager |

See `references/tailoring.md` for the full tailoring documentation process.
