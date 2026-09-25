<#
.SYNOPSIS
    Read-only pre-flight: what in config/ already exists in THIS domain, and does it match?

.DESCRIPTION
    Every measurement this project has published comes from an empty lab domain. A production
    domain is not empty, and the deployment planners decide "already exists" like this:

      - groups and users: Get-AD* -Identity <samAccountName>, which searches the WHOLE domain and
        ignores the configured OU, group scope and category. A hit means NOTHING is planned - the
        object is adopted silently, wherever it sits and whatever it is.
      - OUs: by full distinguished name, so path-aware - but an existing OU keeps whatever
        accidental-deletion protection, GPO inheritance and security inheritance it already has,
        because no action is planned for it.
      - GPOs: by display name.

    The audit afterwards checks the properties the planners do not, so the failure mode in a
    populated domain is: deploy reports "already exists / Converged", audit reports drift, and
    nothing in the tool closes the gap.

    This script answers, before anything is written, which of those collisions actually exist here.

    READ-ONLY. It runs Get-* only. It writes one report file and nothing else.

.PARAMETER PreferredDc
    Domain controller to read from.

.PARAMETER RepositoryRoot
    Repository root. Defaults to the parent of this script's folder.

.PARAMETER OutputPath
    Report file. Defaults to TierModel-Collision-<yyyyMMdd-HHmmss>.json in the current directory.

.EXAMPLE
    .\Test-TierModelCollision.ps1 -PreferredDc dc01.contoso.com -RepositoryRoot C:\Lab\ActiveDirectoryTierModel
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PreferredDc,

    [string]$RepositoryRoot,

    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy    -ErrorAction SilentlyContinue

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = Split-Path -Parent $PSScriptRoot }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $stamp = [DateTime]::Now.ToString('yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
    $OutputPath = Join-Path (Get-Location) "TierModel-Collision-$stamp.json"
}

$domain   = Get-ADDomain -Server $PreferredDc
$domainDn = $domain.DistinguishedName

Write-Host "Tier Model collision pre-flight (read-only)" -ForegroundColor Cyan
Write-Host "  DC     : $PreferredDc"
Write-Host "  Domain : $domainDn"
Write-Host "  Config : $RepositoryRoot\config"
Write-Host ""

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param($Severity, $Kind, $Name, $Detail)
    $findings.Add([ordered]@{ Severity = $Severity; Kind = $Kind; Name = $Name; Detail = $Detail })
}

function Read-Config { param($File) Get-Content (Join-Path $RepositoryRoot "config\$File") -Raw | ConvertFrom-Json }
function Resolve-Path2 {
    param([string]$Path)
    # Mirrors Resolve-TierModelOuPath: the placeholder becomes the domain DN, and a purely
    # relative path is anchored at the domain root.
    if ($Path -match '\{\{DOMAIN_DN\}\}') { return $Path -replace '\{\{DOMAIN_DN\}\}', $domainDn }
    if ($Path -match 'DC=')               { return $Path }
    return "$Path,$domainDn"
}

# ---------------------------------------------------------------------------- OUs
Write-Host "1/4  Organizational units" -ForegroundColor Cyan
$ouConfig = Read-Config 'tiermodel-ous.json'
$ouExisting = 0
foreach ($ou in $ouConfig.organizationUnits) {
    $dn = "OU=$($ou.name)," + (Resolve-Path2 $ou.path)
    $found = $null
    try { $found = Get-ADOrganizationalUnit -Identity $dn -Server $PreferredDc -Properties ProtectedFromAccidentalDeletion, gPOptions -ErrorAction Stop } catch { }
    if (-not $found) { continue }
    $ouExisting++

    # An adopted OU keeps whatever it already has - the deployment plans no action for it.
    $wantProtect = [bool]$ou.protectFromAccidentalDeletion
    $wantBlock   = [bool]$ou.blockGpoInheritance
    $hasProtect  = [bool]$found.ProtectedFromAccidentalDeletion
    $hasBlock    = ($found.gPOptions -eq 1)

    $mismatch = @()
    if ($wantProtect -and -not $hasProtect) { $mismatch += 'accidental-deletion protection is OFF' }
    if ($wantBlock   -and -not $hasBlock)   { $mismatch += 'GPO inheritance is NOT blocked' }

    if ($mismatch.Count -gt 0) {
        Add-Finding 'High' 'OuExistsWithWrongProperties' $dn ($mismatch -join '; ')
    } else {
        Add-Finding 'Info' 'OuExists' $dn 'already present and matching'
    }
}
Write-Host "     $($ouConfig.organizationUnits.Count) configured, $ouExisting already present"

# ---------------------------------------------------------------------------- groups
Write-Host "2/4  Groups" -ForegroundColor Cyan
$groupConfig = Read-Config 'tiermodel-groups.json'
$grpExisting = 0
foreach ($g in $groupConfig.groups) {
    $sam = $g.samaccountname
    $found = $null
    try { $found = Get-ADGroup -Identity $sam -Server $PreferredDc -Properties GroupScope, GroupCategory -ErrorAction Stop } catch { }
    if (-not $found) { continue }
    $grpExisting++

    $wantParent = Resolve-Path2 $g.path
    $haveParent = ($found.DistinguishedName -split ',', 2)[1]

    $mismatch = @()
    if ($haveParent -ne $wantParent)                        { $mismatch += "sits in '$haveParent', config says '$wantParent'" }
    if ([string]$found.GroupScope    -ne [string]$g.groupscope)    { $mismatch += "scope $($found.GroupScope), config says $($g.groupscope)" }
    if ([string]$found.GroupCategory -ne [string]$g.groupcategory) { $mismatch += "category $($found.GroupCategory), config says $($g.groupcategory)" }

    if ($mismatch.Count -gt 0) {
        # This is the one that bites: the planner sees the name, plans nothing, and the audit
        # later calls it drift with no way to fix it from the tool.
        Add-Finding 'Critical' 'GroupAdoptedButWrong' $sam ($mismatch -join '; ')
    } else {
        Add-Finding 'Info' 'GroupExists' $sam "already present and matching ($($found.DistinguishedName))"
    }
}
Write-Host "     $($groupConfig.groups.Count) configured, $grpExisting already present"

# ---------------------------------------------------------------------------- users
Write-Host "3/4  Service accounts" -ForegroundColor Cyan
$userConfig = Read-Config 'tiermodel-users.json'
$usrExisting = 0
foreach ($u in $userConfig.users) {
    $sam = $u.samaccountname
    if (-not $sam) { $sam = $u.samAccountName }
    $found = $null
    try { $found = Get-ADUser -Identity $sam -Server $PreferredDc -ErrorAction Stop } catch { }
    if (-not $found) { continue }
    $usrExisting++
    Add-Finding 'Critical' 'UserAlreadyExists' $sam "existing account at $($found.DistinguishedName) will be adopted, not created - its password, enabled state and group memberships are whatever they already are"
}
Write-Host "     $($userConfig.users.Count) configured, $usrExisting already present"

# ---------------------------------------------------------------------------- GPOs
Write-Host "4/4  Group policy objects" -ForegroundColor Cyan
$gpoExisting = 0
$gpoTotal    = 0
if (Get-Module GroupPolicy) {
    $gpoConfig = Read-Config 'tiermodel-gpos.json'
    $names = @($gpoConfig.gpos | ForEach-Object { $_.name } | Where-Object { $_ }) | Sort-Object -Unique
    $gpoTotal = $names.Count
    foreach ($n in $names) {
        $found = $null
        try { $found = Get-GPO -Name $n -Server $PreferredDc -ErrorAction Stop } catch { }
        if (-not $found) { continue }
        $gpoExisting++
        Add-Finding 'High' 'GpoAlreadyExists' $n "existing GPO $($found.Id) will be adopted; its settings are only re-imported if its SYSVOL policy folder is provably empty"
    }
    Write-Host "     $gpoTotal configured, $gpoExisting already present"
} else {
    Write-Host "     skipped - GroupPolicy module not available"
}

# ---------------------------------------------------------------------------- verdict
$critical = @($findings | Where-Object Severity -eq 'Critical')
$high     = @($findings | Where-Object Severity -eq 'High')

[ordered]@{
    GeneratedUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    PreferredDc  = $PreferredDc
    DomainDn     = $domainDn
    Summary      = [ordered]@{
        OusConfigured = $ouConfig.organizationUnits.Count;  OusPresent = $ouExisting
        GroupsConfigured = $groupConfig.groups.Count;       GroupsPresent = $grpExisting
        UsersConfigured = $userConfig.users.Count;          UsersPresent = $usrExisting
        GposConfigured = $gpoTotal;                         GposPresent = $gpoExisting
        Critical = $critical.Count; High = $high.Count
    }
    Findings = $findings
} | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host ""
if ($critical.Count -eq 0 -and $high.Count -eq 0) {
    Write-Host "No collisions. Nothing in config/ already exists here in a conflicting form." -ForegroundColor Green
} else {
    Write-Host ("{0} critical, {1} high." -f $critical.Count, $high.Count) -ForegroundColor Red
    foreach ($f in ($critical + $high)) {
        Write-Host ("  [{0}] {1}: {2}" -f $f.Kind, $f.Name, $f.Detail) -ForegroundColor Yellow
    }
}
Write-Host ("Report: {0}" -f $OutputPath)
exit ([int]($critical.Count -gt 0))
