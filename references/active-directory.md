# Active Directory STIG Hardening

Covers AD Domain Services (AD DS), AD Certificate Services (ADCS), and AD Federation
Services (ADFS). All automation uses PowerShell. Always snapshot domain controllers
before making changes (see `references/backup-rollback.md`).

## Table of Contents

1. [Pre-Hardening Warnings](#pre-hardening-warnings)
2. [AD DS — Domain Services](#ad-ds)
3. [ADCS — Certificate Services](#adcs)
4. [ADFS — Federation Services](#adfs)
5. [Common Tailoring Exceptions](#common-tailoring-exceptions)

---

## Pre-Hardening Warnings

**Active Directory changes can break authentication for the entire domain.** Follow
this sequence strictly:

1. **Snapshot ALL domain controllers** before any changes.
2. Harden one DC first. Wait 2 replication cycles. Verify auth still works.
3. Then harden remaining DCs.
4. Never harden ADCS/ADFS until AD DS is stable.
5. Keep a non-hardened DC in DSRM-bootable state as emergency fallback.

---

## AD DS

### Domain Functional Level & Schema

```powershell
# Verify functional level — STIG requires 2016+ for modern features
$forest = Get-ADForest
$domain = Get-ADDomain

Write-Host "Forest level : $($forest.ForestMode)"
Write-Host "Domain level : $($domain.DomainMode)"

if ($domain.DomainMode -lt "Windows2016Domain") {
    Write-Warning "Domain functional level below 2016 — some STIG controls unavailable"
}
```

### Privileged Account Protections

```powershell
# Harden-ADDS-Accounts.ps1
[CmdletBinding()]
param()

Write-Host "`n=== AD DS Account Hardening ===" -ForegroundColor Cyan

# CAT I — Protected Users group: add privileged accounts
# Members get: no NTLM auth, no delegation, no DES/RC4, Kerberos TGT lifetime 4 hrs
$protectedGroup = Get-ADGroup "Protected Users"
$adminAccounts = @("Domain Admins", "Enterprise Admins", "Schema Admins") | ForEach-Object {
    Get-ADGroupMember -Identity $_ -ErrorAction SilentlyContinue
} | Select-Object -ExpandProperty SamAccountName -Unique

foreach ($account in $adminAccounts) {
    $user = Get-ADUser -Identity $account -Properties MemberOf -ErrorAction SilentlyContinue
    if ($user -and ($user.MemberOf -notcontains $protectedGroup.DistinguishedName)) {
        Add-ADGroupMember -Identity "Protected Users" -Members $account
        Write-Host "  ✓ Added $account to Protected Users" -ForegroundColor Green
    }
}

# CAT II — Disable Kerberos DES encryption types
$domainDN = (Get-ADDomain).DistinguishedName
$currentPolicy = Get-ADObject -Identity $domainDN -Properties "msDS-SupportedEncryptionTypes"
# Value 0x18 = AES128 + AES256 only (no DES, no RC4)
$desiredValue = 24
if ($currentPolicy."msDS-SupportedEncryptionTypes" -ne $desiredValue) {
    Set-ADObject -Identity $domainDN -Replace @{"msDS-SupportedEncryptionTypes" = $desiredValue}
    Write-Host "  ✓ Kerberos encryption restricted to AES only" -ForegroundColor Green
}

# CAT II — Ensure krbtgt password was changed within 180 days
$krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet
$daysSinceChange = ((Get-Date) - $krbtgt.PasswordLastSet).Days
if ($daysSinceChange -gt 180) {
    Write-Warning "  ⚠ krbtgt password is $daysSinceChange days old (max 180)"
    Write-Warning "    Reset it carefully — requires TWO resets with replication between each"
}

Write-Host "✓ AD DS account hardening complete" -ForegroundColor Green
```

### Fine-Grained Password Policy

```powershell
# CAT II — Create STIG-compliant fine-grained password policy for admins
$psoName = "STIG-Admin-PSO"
$existingPso = Get-ADFineGrainedPasswordPolicy -Identity $psoName -ErrorAction SilentlyContinue

if (-not $existingPso) {
    New-ADFineGrainedPasswordPolicy -Name $psoName `
        -Precedence 10 `
        -MinPasswordLength 15 `
        -MaxPasswordAge "60.00:00:00" `
        -MinPasswordAge "1.00:00:00" `
        -PasswordHistoryCount 24 `
        -ComplexityEnabled $true `
        -ReversibleEncryptionEnabled $false `
        -LockoutThreshold 3 `
        -LockoutDuration "00:00:00" `        # Admin must unlock
        -LockoutObservationWindow "00:15:00"
    Write-Host "  ✓ Created PSO: $psoName" -ForegroundColor Green
}

# Apply to Domain Admins
Add-ADFineGrainedPasswordPolicySubject -Identity $psoName `
    -Subjects "Domain Admins" -ErrorAction SilentlyContinue
```

### Delegation & Tiered Access

```powershell
# CAT II — Deny logon to workstations for Tier 0 accounts
# Use GPO: "Deny log on locally" and "Deny log on through Remote Desktop"
# for Domain Admins on member servers and workstations

# Audit delegation permissions — CAT II
Write-Host "  Scanning for unconstrained delegation..."
$unconstrainedComputers = Get-ADComputer -Filter {
    TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516
} -Properties TrustedForDelegation

foreach ($computer in $unconstrainedComputers) {
    Write-Warning "  ⚠ Unconstrained delegation: $($computer.Name) — should be constrained or removed"
}

# Scan for AdminSDHolder orphans
$orphans = Get-ADUser -Filter {AdminCount -eq 1} -Properties MemberOf | Where-Object {
    $protectedGroups = @("Domain Admins","Enterprise Admins","Schema Admins",
                         "Administrators","Account Operators","Backup Operators",
                         "Server Operators","Print Operators")
    $isMember = $false
    foreach ($pg in $protectedGroups) {
        $members = Get-ADGroupMember -Identity $pg -ErrorAction SilentlyContinue |
                   Select-Object -ExpandProperty SamAccountName
        if ($_.SamAccountName -in $members) { $isMember = $true; break }
    }
    -not $isMember
}
foreach ($orphan in $orphans) {
    Write-Warning "  ⚠ AdminSDHolder orphan: $($orphan.SamAccountName) — review and clear AdminCount"
}
```

### LDAP Signing & Channel Binding

```powershell
# CAT II — Require LDAP signing on DCs
Set-StigRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity" -Value 2   # 2 = Require signing

# CAT II — LDAP channel binding
Set-StigRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LdapEnforceChannelBinding" -Value 2  # 2 = Always
```

---

## ADCS

### Certificate Authority Hardening

```powershell
# Harden-ADCS.ps1
[CmdletBinding()]
param()

Write-Host "`n=== ADCS Hardening ===" -ForegroundColor Cyan

# Verify ADCS is installed
if (-not (Get-Service -Name CertSvc -ErrorAction SilentlyContinue)) {
    Write-Host "  ⏭ ADCS not installed — skipping" -ForegroundColor Yellow
    return
}

# CAT I — Audit object access on CA
$caName = (certutil -getreg CA\CommonName | Select-String "CommonName REG_SZ =").ToString().Split("=")[1].Trim()
Write-Host "  CA Name: $caName"

# CAT II — Enforce certificate manager approval for all templates
# (Site-specific — check which templates are in use)
Write-Host "  Active templates:"
certutil -catemplates | ForEach-Object { Write-Host "    $_" }

# CAT II — Ensure AIA and CRL distribution points are configured
certutil -getreg CA\CRLPublicationURLs | Write-Host
certutil -getreg CA\CACertPublicationURLs | Write-Host

# CAT II — Enable CA auditing
certutil -setreg CA\AuditFilter 127   # Audit all events
Write-Host "  ✓ CA audit filter set to 127 (all events)" -ForegroundColor Green

# Restart ADCS to apply audit changes
Restart-Service CertSvc -Force

Write-Host "✓ ADCS hardening complete" -ForegroundColor Green
```

### Certificate Template Security

```powershell
# Audit certificate templates for dangerous configurations
# ESC1: Template allows requesters to specify a SAN (Subject Alternative Name)
# ESC2: Template has Any Purpose or no EKU
# ESC4: Template has overly permissive ACLs

Write-Host "`n  Checking for dangerous template configurations..."

$templates = Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$((Get-ADDomain).DistinguishedName)" `
    -Filter {objectClass -eq "pKICertificateTemplate"} `
    -Properties msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag, pKIExtendedKeyUsage, nTSecurityDescriptor

foreach ($t in $templates) {
    $flags = $t."msPKI-Certificate-Name-Flag"
    # ESC1: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    if ($flags -band 1) {
        Write-Warning "  ⚠ ESC1 — $($t.Name): Enrollee can supply Subject (SAN injection risk)"
    }
}
```

---

## ADFS

### Federation Services Hardening

```powershell
# Harden-ADFS.ps1
[CmdletBinding()]
param()

Write-Host "`n=== ADFS Hardening ===" -ForegroundColor Cyan

# Verify ADFS is installed
$adfsSvc = Get-Service -Name adfssrv -ErrorAction SilentlyContinue
if (-not $adfsSvc) {
    Write-Host "  ⏭ ADFS not installed — skipping" -ForegroundColor Yellow
    return
}

# CAT I — Ensure token-signing cert uses RSA 2048+ or ECDSA P-256+
$signingCert = Get-AdfsCertificate -CertificateType Token-Signing
$keySize = $signingCert.Certificate.PublicKey.Key.KeySize
if ($keySize -lt 2048) {
    Write-Warning "  ⚠ Token-signing key is $keySize bit — must be 2048+"
} else {
    Write-Host "  ✓ Token-signing key: $keySize bit" -ForegroundColor Green
}

# CAT II — Enable extranet lockout
$properties = Get-AdfsProperties
if (-not $properties.ExtranetLockoutEnabled) {
    Set-AdfsProperties -EnableExtranetLockout $true `
        -ExtranetLockoutThreshold 15 `
        -ExtranetObservationWindow (New-TimeSpan -Minutes 30)
    Write-Host "  ✓ Extranet lockout enabled (15 attempts / 30 min)" -ForegroundColor Green
}

# CAT II — Disable WS-Trust endpoints if not used
$wsTrustEndpoints = Get-AdfsEndpoint | Where-Object {
    $_.Protocol -eq "WSTrust" -and $_.Enabled
}
foreach ($ep in $wsTrustEndpoints) {
    Write-Warning "  ⚠ WS-Trust endpoint enabled: $($ep.FullUrl) — disable if not needed"
}

# CAT II — Enforce token lifetime limits
$rpTrusts = Get-AdfsRelyingPartyTrust
foreach ($rp in $rpTrusts) {
    if ($rp.TokenLifetime -gt 60 -or $rp.TokenLifetime -eq 0) {
        Set-AdfsRelyingPartyTrust -TargetName $rp.Name -TokenLifetime 60
        Write-Host "  ✓ $($rp.Name): token lifetime set to 60 min" -ForegroundColor Green
    }
}

# CAT II — Enable audit logging
Set-AdfsProperties -LogLevel @("FailureAudits","SuccessAudits","Verbose")
auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable

Write-Host "✓ ADFS hardening complete" -ForegroundColor Green
```

---

## Common Tailoring Exceptions

| Component | Finding | Default | Tailored | Reason |
|-----------|---------|---------|----------|--------|
| AD DS | Kerberos DES | Disabled | Enabled | Legacy app (document upgrade plan) |
| AD DS | Unconstrained delegation | Not allowed | Allowed on specific servers | Application requirement (use constrained instead if possible) |
| AD DS | Account lockout unlock | Admin only | 30 min auto-unlock | No 24/7 help desk coverage |
| ADCS | Manager approval | All templates | Subset only | Automated cert enrollment for web servers |
| ADFS | WS-Trust endpoints | Disabled | Enabled | Legacy SAML 1.1 client dependency |
| ADFS | Token lifetime | 60 min | 480 min | Long-running batch processes |
