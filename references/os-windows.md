# Windows Server STIG Hardening

STIG automation for Windows Server 2019/2022 using PowerShell and Group Policy.
Covers OS-level security settings, local policy, registry hardening, and Windows
Defender/Firewall configuration.

## Table of Contents

1. [STIG Coverage Map](#stig-coverage-map)
2. [PowerShell Execution Patterns](#powershell-patterns)
3. [Account & Password Policy](#account--password-policy)
4. [Audit Policy](#audit-policy)
5. [User Rights Assignment](#user-rights-assignment)
6. [Security Options (Registry)](#security-options)
7. [Windows Firewall](#windows-firewall)
8. [Windows Defender & Updates](#windows-defender--updates)
9. [SMB Hardening](#smb-hardening)
10. [TLS & Cryptography](#tls--cryptography)
11. [Service Hardening](#service-hardening)
12. [Banner & Legal Notice](#banner--legal-notice)
13. [GPO Export/Import Workflow](#gpo-workflow)
14. [Common Tailoring Exceptions](#common-tailoring-exceptions)

---

## STIG Coverage Map

| Category | Severity | Key Requirements | Automated? |
|----------|----------|-----------------|-----------|
| Reversible encryption | CAT I | Must be disabled | ✅ |
| Guest account | CAT I | Must be disabled | ✅ |
| Anonymous SID/Name translation | CAT I | Must be disabled | ✅ |
| Password policy (length, age, complexity) | CAT II | 15+ chars, 60d max | ✅ |
| Account lockout | CAT II | 3 attempts, 15 min | ✅ |
| Audit policy | CAT II | Success/failure logging | ✅ |
| SMB signing | CAT II | Required on both sides | ✅ |
| TLS/cipher order | CAT II | FIPS-compliant ciphers | ✅ |
| Windows Firewall | CAT II | Enabled, inbound blocked | ✅ |
| Legal banner | CAT III | DoD notice before login | ✅ |

---

## PowerShell Patterns

### Idempotent Registry Setting

```powershell
function Set-StigRegistry {
    <#
    .SYNOPSIS Sets a registry value only if it differs from the desired state.
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord"
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    $current = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $current -or $current.$Name -ne $Value) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
        Write-Host "  ✓ Set $Path\$Name = $Value" -ForegroundColor Green
    }
}
```

### Idempotent Security Policy (secedit)

```powershell
function Set-StigSecurityPolicy {
    <#
    .SYNOPSIS Exports current security policy, modifies a setting, and re-imports.
    Idempotent — skips if already correct.
    #>
    [CmdletBinding()]
    param(
        [string]$Section,   # e.g. "System Access"
        [string]$Key,       # e.g. "MinimumPasswordLength"
        [string]$Value      # e.g. "15"
    )

    $tempCfg = "$env:TEMP\secedit-export.cfg"
    $tempDb  = "$env:TEMP\secedit-temp.sdb"

    secedit /export /cfg $tempCfg /quiet

    $content = Get-Content $tempCfg
    $pattern = "^${Key}\s*=\s*(.*)$"
    $match = $content | Select-String -Pattern $pattern

    if ($match -and $match.Matches.Groups[1].Value.Trim() -eq $Value) {
        return  # Already correct
    }

    if ($match) {
        $content = $content -replace $pattern, "$Key = $Value"
    } else {
        # Insert into the correct section
        $sectionIdx = ($content | Select-String -Pattern "^\[$Section\]").LineNumber
        $content = $content[0..($sectionIdx-1)] + "$Key = $Value" + $content[$sectionIdx..($content.Count-1)]
    }

    $content | Set-Content $tempCfg
    secedit /configure /db $tempDb /cfg $tempCfg /quiet
    Write-Host "  ✓ Security policy: $Key = $Value" -ForegroundColor Green

    Remove-Item $tempCfg, $tempDb -Force -ErrorAction SilentlyContinue
}
```

---

## Account & Password Policy

```powershell
# Harden-PasswordPolicy.ps1
[CmdletBinding()]
param()

Write-Host "`n=== Password & Account Policy ===" -ForegroundColor Cyan

# CAT II — Password length, age, complexity
Set-StigSecurityPolicy -Section "System Access" -Key "MinimumPasswordLength" -Value "15"
Set-StigSecurityPolicy -Section "System Access" -Key "MaximumPasswordAge" -Value "60"
Set-StigSecurityPolicy -Section "System Access" -Key "MinimumPasswordAge" -Value "1"
Set-StigSecurityPolicy -Section "System Access" -Key "PasswordComplexity" -Value "1"
Set-StigSecurityPolicy -Section "System Access" -Key "PasswordHistorySize" -Value "24"
Set-StigSecurityPolicy -Section "System Access" -Key "ClearTextPassword" -Value "0"  # CAT I

# CAT II — Account lockout
Set-StigSecurityPolicy -Section "System Access" -Key "LockoutBadCount" -Value "3"
Set-StigSecurityPolicy -Section "System Access" -Key "ResetLockoutCount" -Value "15"
Set-StigSecurityPolicy -Section "System Access" -Key "LockoutDuration" -Value "0"  # Admin unlock

# CAT I — Disable guest account
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest -and $guest.Enabled) {
    Disable-LocalUser -Name "Guest"
    Write-Host "  ✓ Guest account disabled" -ForegroundColor Green
}

# Rename Administrator account (CAT II)
$admin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
if ($admin) {
    # Only rename if still the default name
    Rename-LocalUser -Name "Administrator" -NewName "LocalAdmin" -ErrorAction SilentlyContinue
    Write-Host "  ✓ Administrator renamed" -ForegroundColor Green
}

Write-Host "✓ Password & account policy complete" -ForegroundColor Green
```

---

## Audit Policy

```powershell
# Harden-AuditPolicy.ps1
[CmdletBinding()]
param()

Write-Host "`n=== Audit Policy ===" -ForegroundColor Cyan

# Apply advanced audit policy via auditpol
$policies = @(
    @{ Sub="Credential Validation";        Setting="Success and Failure" }
    @{ Sub="Security Group Management";    Setting="Success" }
    @{ Sub="User Account Management";      Setting="Success and Failure" }
    @{ Sub="Process Creation";             Setting="Success" }
    @{ Sub="Account Lockout";              Setting="Failure" }
    @{ Sub="Logon";                        Setting="Success and Failure" }
    @{ Sub="Logoff";                       Setting="Success" }
    @{ Sub="Special Logon";                Setting="Success" }
    @{ Sub="Removable Storage";            Setting="Success and Failure" }
    @{ Sub="Audit Policy Change";          Setting="Success and Failure" }
    @{ Sub="Authentication Policy Change"; Setting="Success" }
    @{ Sub="Security State Change";        Setting="Success" }
    @{ Sub="Security System Extension";    Setting="Success" }
    @{ Sub="System Integrity";             Setting="Success and Failure" }
    @{ Sub="Sensitive Privilege Use";       Setting="Success and Failure" }
    @{ Sub="Other Object Access Events";   Setting="Success and Failure" }
)

foreach ($p in $policies) {
    $current = auditpol /get /subcategory:"$($p.Sub)" 2>&1
    if ($current -notmatch $p.Setting) {
        auditpol /set /subcategory:"$($p.Sub)" /success:enable /failure:enable 2>$null
        Write-Host "  ✓ $($p.Sub) → $($p.Setting)" -ForegroundColor Green
    }
}

# Ensure audit log size and retention
Set-StigRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" `
    -Name "MaxSize" -Value 1024000 -Type DWord   # ~1 GB

Write-Host "✓ Audit policy complete" -ForegroundColor Green
```

---

## Security Options

```powershell
# Harden-SecurityOptions.ps1
[CmdletBinding()]
param()

Write-Host "`n=== Security Options (Registry) ===" -ForegroundColor Cyan

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

# CAT I — Anonymous SID/Name translation
Set-StigRegistry -Path $lsaPath -Name "TurnOffAnonymousBlock" -Value 1

# CAT II — Restrict anonymous enumeration of shares
Set-StigRegistry -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 1
Set-StigRegistry -Path $lsaPath -Name "RestrictAnonymous" -Value 1

# CAT II — Do not store LAN Manager hash
Set-StigRegistry -Path $lsaPath -Name "NoLMHash" -Value 1

# CAT II — LAN Manager authentication level (NTLMv2 only)
Set-StigRegistry -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5

# CAT II — LDAP client signing
Set-StigRegistry -Path $lsaPath -Name "LDAPClientIntegrity" -Value 1

# CAT II — Secure channel signing/sealing
$netlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
Set-StigRegistry -Path $netlogonPath -Name "RequireSignOrSeal" -Value 1
Set-StigRegistry -Path $netlogonPath -Name "SealSecureChannel" -Value 1
Set-StigRegistry -Path $netlogonPath -Name "SignSecureChannel" -Value 1

# CAT II — Disable autorun
$explorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
Set-StigRegistry -Path $explorerPath -Name "NoDriveTypeAutoRun" -Value 255
Set-StigRegistry -Path $explorerPath -Name "NoAutorun" -Value 1

# CAT II — UAC settings
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-StigRegistry -Path $uacPath -Name "EnableLUA" -Value 1
Set-StigRegistry -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2  # Prompt on secure desktop
Set-StigRegistry -Path $uacPath -Name "FilterAdministratorToken" -Value 1
Set-StigRegistry -Path $uacPath -Name "EnableInstallerDetection" -Value 1

# CAT II — Disable remote registry path access
Set-StigRegistry -Path $uacPath -Name "LocalAccountTokenFilterPolicy" -Value 0

Write-Host "✓ Security options complete" -ForegroundColor Green
```

---

## Windows Firewall

```powershell
# Harden-Firewall.ps1
[CmdletBinding()]
param()

Write-Host "`n=== Windows Firewall ===" -ForegroundColor Cyan

# Enable all profiles, block inbound by default, allow outbound
$profiles = @("Domain", "Public", "Private")
foreach ($profile in $profiles) {
    $fw = Get-NetFirewallProfile -Name $profile
    if (-not $fw.Enabled -or $fw.DefaultInboundAction -ne "Block") {
        Set-NetFirewallProfile -Name $profile `
            -Enabled True `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Allow `
            -LogAllowed True `
            -LogBlocked True `
            -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" `
            -LogMaxSizeKilobytes 16384
        Write-Host "  ✓ $profile profile: enabled, inbound=block" -ForegroundColor Green
    }
}

Write-Host "✓ Windows Firewall hardened" -ForegroundColor Green
```

---

## SMB Hardening

```powershell
# Harden-SMB.ps1
[CmdletBinding()]
param()

Write-Host "`n=== SMB Hardening ===" -ForegroundColor Cyan

# CAT II — Require SMB signing (server)
$smbServerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Set-StigRegistry -Path $smbServerPath -Name "RequireSecuritySignature" -Value 1
Set-StigRegistry -Path $smbServerPath -Name "EnableSecuritySignature" -Value 1

# CAT II — Require SMB signing (client)
$smbClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
Set-StigRegistry -Path $smbClientPath -Name "RequireSecuritySignature" -Value 1
Set-StigRegistry -Path $smbClientPath -Name "EnableSecuritySignature" -Value 1

# CAT II — Disable SMBv1
$smb1 = Get-WindowsFeature -Name FS-SMB1 -ErrorAction SilentlyContinue
if ($smb1 -and $smb1.Installed) {
    Remove-WindowsFeature -Name FS-SMB1
    Write-Host "  ✓ SMBv1 removed" -ForegroundColor Green
} else {
    Set-StigRegistry -Path $smbServerPath -Name "SMB1" -Value 0
}

# Disable SMBv1 client
$smbClientFeature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
if ($smbClientFeature -and $smbClientFeature.State -eq "Enabled") {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Write-Host "  ✓ SMBv1 client disabled" -ForegroundColor Green
}

Write-Host "✓ SMB hardened" -ForegroundColor Green
```

---

## TLS & Cryptography

```powershell
# Harden-TLS.ps1 — Disable weak protocols and ciphers
[CmdletBinding()]
param()

Write-Host "`n=== TLS & Crypto Hardening ===" -ForegroundColor Cyan

$schannelBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

# Disable SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1 (CAT II)
$disableProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($proto in $disableProtocols) {
    foreach ($side in @("Server", "Client")) {
        $path = "$schannelBase\Protocols\$proto\$side"
        Set-StigRegistry -Path $path -Name "Enabled" -Value 0
        Set-StigRegistry -Path $path -Name "DisabledByDefault" -Value 1
    }
}

# Enable TLS 1.2 and TLS 1.3
foreach ($proto in @("TLS 1.2", "TLS 1.3")) {
    foreach ($side in @("Server", "Client")) {
        $path = "$schannelBase\Protocols\$proto\$side"
        Set-StigRegistry -Path $path -Name "Enabled" -Value 1
        Set-StigRegistry -Path $path -Name "DisabledByDefault" -Value 0
    }
}

# Disable weak ciphers
$weakCiphers = @("DES 56/56", "RC2 40/128", "RC2 56/128", "RC2 128/128", "RC4 40/128",
                  "RC4 56/128", "RC4 64/128", "RC4 128/128", "Triple DES 168", "NULL")
foreach ($cipher in $weakCiphers) {
    $path = "$schannelBase\Ciphers\$cipher"
    Set-StigRegistry -Path $path -Name "Enabled" -Value 0
}

Write-Host "✓ TLS/cipher hardening complete" -ForegroundColor Green
```

---

## Service Hardening

```powershell
# Harden-Services.ps1 — Disable unnecessary services
[CmdletBinding()]
param()

Write-Host "`n=== Service Minimization ===" -ForegroundColor Cyan

$disableServices = @(
    "XblAuthManager",     # Xbox Live (CAT II if present)
    "XblGameSave",
    "MapsBroker",         # Downloaded Maps Manager
    "lfsvc",              # Geolocation Service
    "SharedAccess",       # Internet Connection Sharing
    "lltdsvc",            # Link-Layer Topology Discovery
    "MSiSCSI",            # iSCSI Initiator (unless needed)
    "PNRPsvc",            # Peer Networking
    "p2psvc",
    "p2pimsvc",
    "PNRPAutoReg",
    "Spooler",            # Print Spooler (disable on non-print servers!)
    "WinRM"               # Disable if using SSM only
)

foreach ($svc in $disableServices) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s -and $s.StartType -ne "Disabled") {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled
        Write-Host "  ✓ Disabled: $svc" -ForegroundColor Green
    }
}

Write-Host "✓ Service hardening complete" -ForegroundColor Green
```

> **Tailoring**: Keep `Spooler` enabled on print servers, `WinRM` enabled if using
> Ansible/PowerShell remoting, `MSiSCSI` enabled for iSCSI storage.

---

## Banner & Legal Notice

```powershell
# Harden-Banner.ps1 — CAT II
[CmdletBinding()]
param()

$bannerTitle = "US Department of Defense Warning Statement"
$bannerText = @"
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
"@

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-StigRegistry -Path $regPath -Name "LegalNoticeCaption" -Value $bannerTitle -Type String
Set-StigRegistry -Path $regPath -Name "LegalNoticeText" -Value $bannerText -Type String

Write-Host "✓ Login banner configured" -ForegroundColor Green
```

---

## GPO Workflow

For domain-joined servers, deploy STIG settings via GPO rather than local scripts.

### Export a Hardened GPO

```powershell
# Export GPO for reuse across environments
$gpoName = "STIG-WinServer2022-Baseline"
$exportPath = "C:\GPOExports\$gpoName"

if (-not (Test-Path $exportPath)) {
    New-Item -ItemType Directory -Path $exportPath -Force | Out-Null
}

$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if ($gpo) {
    Backup-GPO -Name $gpoName -Path $exportPath
    Write-Host "✓ GPO exported: $exportPath"
}
```

### Import GPO to New Domain

```powershell
$importPath = "C:\GPOExports\STIG-WinServer2022-Baseline"
$targetGPO  = "STIG-WinServer2022-Baseline"

$existing = Get-GPO -Name $targetGPO -ErrorAction SilentlyContinue
if (-not $existing) {
    New-GPO -Name $targetGPO | Out-Null
}

$backupId = (Get-ChildItem "$importPath\*\bkupInfo.xml" | Select-Object -First 1 |
    Select-Xml -XPath "//BackupInst/ID" | Select-Object -ExpandProperty Node).InnerText

Import-GPO -BackupId $backupId -Path $importPath -TargetName $targetGPO
Write-Host "✓ GPO imported: $targetGPO"
```

---

## Common Tailoring Exceptions

| Finding | Default | Tailored | Reason | Compensating Control |
|---------|---------|----------|--------|---------------------|
| Print Spooler | Disabled | Enabled | Print server role | Restrict driver installation via GPO |
| WinRM | Disabled | Enabled | Ansible/PowerShell remoting | TLS, trusted hosts only |
| Account lockout | Admin unlock (0) | 15 min auto-unlock | No 24/7 admin | MFA, CloudWatch alarm |
| NTLM v2-only | Level 5 | Level 3 | Legacy app needs NTLMv1 | Network segmentation, app upgrade plan |
| SMBv1 | Removed | Kept | Legacy scanner/printer | Isolated VLAN, firewall ACL |
