from pathlib import Path
import subprocess


SCRIPT = Path("tools/keycloak/prepare_ad_pilot.ps1").resolve()


def powershell(code):
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", code],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def test_ad_pilot_script_parses_in_windows_powershell_51():
    powershell(f"$tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}',[ref]$tokens,[ref]$errors); if($errors.Count){{throw $errors[0]}}")


def test_default_plan_has_no_ad_or_filesystem_mutations():
    output = powershell(r"""
$ErrorActionPreference='Stop'
function Import-Module { param($Name) }
function Get-ADDomain { [pscustomobject]@{DNSRoot='sosnadmin.local';DistinguishedName='DC=sosnadmin,DC=local'} }
function Get-ADOrganizationalUnit { param($Identity,$Server,$ErrorAction) [pscustomobject]@{DistinguishedName=$Identity} }
function Get-ADObject { param($Identity,$Server,$ErrorAction) [pscustomobject]@{DistinguishedName=$Identity} }
function Get-ADUser { param($LDAPFilter,$Server,$Properties,$ErrorAction) }
function Test-Path { param($LiteralPath,$PathType) $LiteralPath -eq 'C:\ProgramData\SsoSetup' }
function Get-Item { param($LiteralPath,$ErrorAction) [pscustomobject]@{FullName=$LiteralPath;Attributes=[System.IO.FileAttributes]::Directory} }
function New-ADUser { throw 'UNAUTHORIZED AD WRITE' }
function Set-Acl { throw 'UNAUTHORIZED FILE WRITE' }
function Export-Clixml { throw 'UNAUTHORIZED CREDENTIAL WRITE' }
""" + f"& '{SCRIPT}' | ConvertTo-Json -Compress")
    assert "WouldCreate" in output
    assert "svc-keycloak-ldap" in output
    assert "ssopilot-20261027" in output
    assert "Password" not in output


def test_wrong_domain_is_refused_before_any_mutation():
    powershell(r"""
$ErrorActionPreference='Stop'
function Import-Module { param($Name) }
function Get-ADDomain { [pscustomobject]@{DNSRoot='other.local';DistinguishedName='DC=other,DC=local'} }
function New-ADUser { throw 'UNAUTHORIZED AD WRITE' }
$refused=$false
""" + f"try {{ & '{SCRIPT}' -Apply }} catch {{ if($_.Exception.Message -match 'Expected domain'){{$refused=$true}} else {{throw}} }}; if(-not $refused){{throw 'Wrong domain was accepted'}}")


def test_only_new_user_command_exists_in_ad_write_surface():
    text = SCRIPT.read_text(encoding="utf-8")
    assert text.count("New-ADUser @parameters") == 1
    for prohibited in ("Set-ADUser", "Set-ADAccountPassword", "Add-ADGroupMember", "New-ADGroup", "New-ADOrganizationalUnit", "Remove-ADUser", "Set-GP"):
        assert prohibited not in text
    assert "[switch]$Apply" in text
    assert "OU=TEST,DC=sosnadmin,DC=local" in text
    assert "CN=Users,DC=sosnadmin,DC=local" in text


def test_missing_existing_ou_is_refused_before_mutations():
    powershell(r"""
$ErrorActionPreference='Stop'
function Import-Module { param($Name) }
function Get-ADDomain { [pscustomobject]@{DNSRoot='sosnadmin.local';DistinguishedName='DC=sosnadmin,DC=local'} }
function Get-ADOrganizationalUnit { throw 'MISSING_APPROVED_OU' }
function New-ADUser { throw 'UNAUTHORIZED AD WRITE' }
$refused=$false
""" + f"try {{ & '{SCRIPT}' -Apply }} catch {{ if($_.Exception.Message -match 'MISSING_APPROVED_OU'){{$refused=$true}} else {{throw}} }}; if(-not $refused){{throw 'Missing OU was accepted'}}")


def test_foreign_existing_name_or_missing_credential_is_not_adopted():
    powershell(r"""
$ErrorActionPreference='Stop'
function Import-Module { param($Name) }
function Get-ADDomain { [pscustomobject]@{DNSRoot='sosnadmin.local';DistinguishedName='DC=sosnadmin,DC=local'} }
function Get-ADOrganizationalUnit { param($Identity,$Server,$ErrorAction) [pscustomobject]@{DistinguishedName=$Identity} }
function Get-ADObject { param($Identity,$Server,$ErrorAction) [pscustomobject]@{DistinguishedName=$Identity} }
function Get-ADUser { [pscustomobject]@{DistinguishedName='CN=svc-keycloak-ldap,CN=Users,DC=sosnadmin,DC=local';Description='Unrelated existing account';UserPrincipalName='svc-keycloak-ldap@sosnadmin.local'} }
function Test-Path { param($LiteralPath,$PathType) $LiteralPath -eq 'C:\ProgramData\SsoSetup' }
function Get-Item { param($LiteralPath,$ErrorAction) [pscustomobject]@{FullName=$LiteralPath;Attributes=[System.IO.FileAttributes]::Directory} }
function New-ADUser { throw 'UNAUTHORIZED AD WRITE' }
function Set-Acl { throw 'UNAUTHORIZED FILE WRITE' }
$refused=$false
""" + f"try {{ & '{SCRIPT}' -Apply }} catch {{ if($_.Exception.Message -match 'not this task-owned identity'){{$refused=$true}} else {{throw}} }}; if(-not $refused){{throw 'Foreign account was adopted'}}")
