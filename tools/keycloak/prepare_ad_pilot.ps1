<#
.SYNOPSIS
Plan, or explicitly create, the two task-owned AD SSO pilot accounts.
.DESCRIPTION
Default invocation is read-only. -Apply creates only the two fixed identities
below and saves DPAPI-protected PSCredentials on AD-MAIN. No existing password,
expiry, group, OU, GPO or account is modified. Run under the approved operator
identity on AD-MAIN; that same Windows identity must decrypt the credentials.
#>
[CmdletBinding()]
param([switch]$Apply)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$domainName = 'sosnadmin.local'
$domainDn = 'DC=sosnadmin,DC=local'
$server = 'AD-MAIN.sosnadmin.local'
$credentialRoot = 'C:\ProgramData\SsoSetup'
$taskMarker = 'endpoint-sso-pilot-20261027; owner=prepare_ad_pilot.ps1'
$specifications = @(
    @{ Name = 'svc-keycloak-ldap'; Container = 'CN=Users,DC=sosnadmin,DC=local';
       DisplayName = 'SSO directory bind pilot'; Days = 30; Purpose = 'readonly-ldap-bind' },
    @{ Name = 'ssopilot-20261027'; Container = 'OU=TEST,DC=sosnadmin,DC=local';
       DisplayName = 'Synthetic SSO pilot 20261027'; Days = 7; Purpose = 'synthetic-sso-acceptance' }
)

function Assert-NoReparsePoint([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Reparse-point credential path is prohibited'
        }
    }
}

function Assert-PrivateCredentialFile([string]$Path) {
    Assert-NoReparsePoint $Path
    $allowedSids = @('S-1-5-18', 'S-1-5-32-544')
    $acl = Get-Acl -LiteralPath $Path
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if ($sid -notin $allowedSids) {
                throw 'Existing credential ACL grants access beyond SYSTEM/Administrators'
            }
        }
    }
}

function Read-SavedCredential([string]$Path, [string]$Principal) {
    Assert-PrivateCredentialFile $Path
    try { $credential = Import-Clixml -LiteralPath $Path -ErrorAction Stop }
    catch { throw 'Saved credential is not decryptable by this operator; do not reset the account' }
    if ($credential -isnot [Management.Automation.PSCredential] -or
        $credential.UserName -cne $Principal -or $credential.Password.Length -lt 32) {
        throw 'Saved credential does not match the fixed pilot principal'
    }
    return $credential
}

function New-StrongSecurePassword {
    # Every sample uses rejection sampling; no modulo-biased System.Random.
    # The complete value stays local and is never emitted to any output stream.
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@-!'
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    $buffer = New-Object byte[] 1
    try {
        do {
            $value = New-Object Text.StringBuilder
            while ($value.Length -lt 40) {
                $random.GetBytes($buffer)
                $limit = 256 - (256 % $alphabet.Length)
                if ([int]$buffer[0] -lt $limit) {
                    [void]$value.Append($alphabet[[int]$buffer[0] % $alphabet.Length])
                }
            }
            $plain = $value.ToString()
        } until ($plain -cmatch '[A-Z]' -and $plain -cmatch '[a-z]' -and
                 $plain -match '[0-9]' -and $plain -match '[_@!\-]')
        $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
        $plain = $null
        [void]$value.Clear()
        return $secure
    }
    finally { [Array]::Clear($buffer, 0, $buffer.Length); $random.Dispose() }
}

Import-Module ActiveDirectory
$domain = Get-ADDomain -Server $server
if ($domain.DNSRoot -ine $domainName -or $domain.DistinguishedName -ine $domainDn) {
    throw 'Expected domain sosnadmin.local; no changes were made'
}
[void](Get-ADOrganizationalUnit -Identity 'OU=TEST,DC=sosnadmin,DC=local' -Server $server -ErrorAction Stop)
[void](Get-ADObject -Identity 'CN=Users,DC=sosnadmin,DC=local' -Server $server -ErrorAction Stop)
if (-not (Test-Path -LiteralPath $credentialRoot -PathType Container)) {
    throw 'Existing C:\ProgramData\SsoSetup directory is required; no directory is created'
}
Assert-NoReparsePoint $credentialRoot

# Validate both identities before the first write. This cannot create arbitrary
# users: the names, containers and purposes are constants, not parameters.
$prepared = @()
foreach ($specification in $specifications) {
    $name = $specification.Name
    $principal = "$name@$domainName"
    $dn = "CN=$name,$($specification.Container)"
    $description = "$taskMarker; purpose=$($specification.Purpose)"
    $credentialPath = Join-Path $credentialRoot "$name.credential.xml"
    $matches = @(Get-ADUser -Server $server -LDAPFilter "(|(sAMAccountName=$name)(userPrincipalName=$principal)(cn=$name))" -Properties Description,UserPrincipalName,Enabled,AccountExpirationDate,memberOf,adminCount)
    if ($matches.Count -gt 1) { throw 'Ambiguous existing pilot name; refusing all changes' }
    $existing = if ($matches.Count -eq 1) { $matches[0] } else { $null }
    $credential = $null
    $saved = Test-Path -LiteralPath $credentialPath -PathType Leaf
    if ($null -ne $existing) {
        if ($existing.DistinguishedName -ine $dn -or $existing.Description -cne $description -or
            $existing.UserPrincipalName -ine $principal -or -not $saved) {
            throw 'Existing account is not this task-owned identity with a saved credential; refusing all changes'
        }
        if (-not $existing.Enabled -or $null -eq $existing.AccountExpirationDate -or
            $existing.AccountExpirationDate.ToUniversalTime() -le [DateTime]::UtcNow -or
            $existing.AccountExpirationDate.ToUniversalTime() -gt [DateTime]::UtcNow.AddDays($specification.Days).AddMinutes(1) -or
            @($existing.memberOf | Where-Object { $null -ne $_ }).Count -ne 0 -or $existing.adminCount -eq 1) {
            throw 'Existing pilot account state or privilege differs from the bounded pilot; refusing all changes'
        }
        $credential = Read-SavedCredential $credentialPath $principal
    }
    elseif ($saved) {
        # A previous failed creation may have persisted its credential first.
        # Reuse it only for this same absent fixed principal, never rotate it.
        $credential = Read-SavedCredential $credentialPath $principal
    }
    $prepared += [pscustomobject]@{
        Specification = $specification; Principal = $principal; Dn = $dn;
        Description = $description; Existing = $existing;
        CredentialPath = $credentialPath; Credential = $credential
    }
}

if (-not $Apply) {
    foreach ($item in $prepared) {
        [pscustomobject]@{
            Name = $item.Specification.Name; DistinguishedName = $item.Dn;
            ObjectGuid = if ($null -ne $item.Existing) { $item.Existing.ObjectGuid.ToString() } else { $null };
            Status = if ($null -ne $item.Existing) { 'OwnedExistingUnchanged' } else { 'WouldCreate' }
        }
    }
    return
}

# DPAPI and machine targeting are meaningful only on the approved domain host.
if ($env:COMPUTERNAME -ine 'AD-MAIN') { throw 'Apply must run locally on AD-MAIN' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$operator = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $operator.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Apply requires the approved elevated operator'
}
$directoryAcl = New-Object Security.AccessControl.DirectorySecurity
$directoryAcl.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier($sid)),
        [Security.AccessControl.FileSystemRights]::FullControl,
        ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow)
    [void]$directoryAcl.AddAccessRule($rule)
}
$directoryAcl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
Set-Acl -LiteralPath $credentialRoot -AclObject $directoryAcl

foreach ($item in $prepared) {
    if ($null -ne $item.Existing) {
        [pscustomobject]@{Name=$item.Specification.Name; DistinguishedName=$item.Dn;
            ObjectGuid=$item.Existing.ObjectGuid.ToString(); Status='OwnedExistingUnchanged'}
        continue
    }
    if ($null -eq $item.Credential) {
        $item.Credential = New-Object Management.Automation.PSCredential($item.Principal, (New-StrongSecurePassword))
        # Save before AD creation so a later failure never leaves an unknown
        # newly generated password. CreateNew refuses credential replacement.
        $serialized = [Management.Automation.PSSerializer]::Serialize($item.Credential)
        $stream = [IO.File]::Open($item.CredentialPath, [IO.FileMode]::CreateNew,
                                 [IO.FileAccess]::Write, [IO.FileShare]::None)
        $bytes = $null
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($serialized)
            $stream.Write($bytes, 0, $bytes.Length)
        }
        finally { $stream.Dispose(); $serialized = $null; if ($null -ne $bytes) { [Array]::Clear($bytes,0,$bytes.Length) } }
        Assert-PrivateCredentialFile $item.CredentialPath
        # Round-trip DPAPI under the same approved operator before the AD write.
        $item.Credential = Read-SavedCredential $item.CredentialPath $item.Principal
    }
    $parameters = @{
        Server = $server; Name = $item.Specification.Name;
        SamAccountName = $item.Specification.Name; UserPrincipalName = $item.Principal;
        DisplayName = $item.Specification.DisplayName; Description = $item.Description;
        Path = $item.Specification.Container; AccountPassword = $item.Credential.Password;
        Enabled = $true; PasswordNeverExpires = $false; PasswordNotRequired = $false;
        ChangePasswordAtLogon = $false;
        AccountExpirationDate = [DateTime]::UtcNow.AddDays($item.Specification.Days);
        ErrorAction = 'Stop'; PassThru = $true
    }
    try { $created = New-ADUser @parameters }
    catch { throw 'Pilot account creation failed; saved credential retained. Inspect only directory metadata before retrying.' }
    [pscustomobject]@{Name=$item.Specification.Name; DistinguishedName=$created.DistinguishedName;
        ObjectGuid=$created.ObjectGuid.ToString(); Status='Created'}
}
