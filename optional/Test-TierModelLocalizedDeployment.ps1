[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PreferredDc,

    [string]$OutputPath,

    [string]$RepositoryRoot,

    [switch]$IncludeAudit,

    [switch]$IncludeWinLaps,

    [switch]$IncludeAuthSilos
)

<#
.SYNOPSIS
    Post-deployment verification for a Tier Model deployed against a localized (e.g. German)
    Active Directory. Read-only. Produces one JSON file.

.DESCRIPTION
    Audit-TierModel.ps1 already answers "does the estate match the configuration". It does not
    answer the three questions that matter specifically for a localized directory, which is what
    this script adds:

    1. WHICH DIRECTORY, IN WHICH LANGUAGE, WAS THIS RUN AGAINST?
       The audit report carries no EnvironmentSnapshot, so a report from a remote lab cannot be
       read without also knowing the domain's language. This records it: the host install
       language, the domain SID, and the actual directory names of three well-known groups.

    2. DID EVERY BUILT-IN PRINCIPAL RESOLVE, AND TO WHAT?
       The Tier Model names built-ins in English and resolves them to well-known SIDs, because
       Active Directory localizes those names at domain creation. This records, for every
       principal the configuration names: the configured name, the SID it resolved to, the
       source of that resolution, and the name the directory actually carries -- so
       "Domain Admins -> S-1-5-21-...-512 -> Domaenen-Admins" is visible rather than assumed.

    3. IS THE DENY-APPLY ACE ACTUALLY ON THE GPC?
       Nothing in the product audits this. Searching the module and Audit-TierModel.ps1 for
       denyApply, ApplyGroupPolicy and the extended-right GUID finds writes only, in
       New-TierModelGpo.ps1. That ACE is what keeps a tier-restriction GPO from ever applying to
       domain controllers, and a failure to write it used to be downgraded to a console warning,
       so its absence has never been detectable after the fact. This reads the GPC security
       descriptor and checks for it.

    It also captures the [Privilege Rights] lines from SYSVOL. Those are SIDs, so a run against a
    German domain and a run against an English one can be diffed directly: identical SID sets are
    the proof that localization changed nothing about the security configuration.

    EVERYTHING HERE IS READ-ONLY. No directory object, GPO, SYSVOL file or ACL is written. The
    only file created is the report.

.PARAMETER PreferredDc
    Domain controller to read from. Every read targets this one DC so the report describes a
    single replica rather than a mixture.

.PARAMETER OutputPath
    Report file. Defaults to TierModel-LocalizedVerification-<yyyyMMdd-HHmmss>.json in the
    current directory.

.PARAMETER RepositoryRoot
    Repository root. Defaults to the parent of this script's folder.

.PARAMETER IncludeAudit
    Additionally run Audit-TierModel.ps1 with -OutputFormat Json and reference its report. That
    script is read-only by design; this switch exists so the drift findings and the
    localization evidence can be collected in one pass.

.PARAMETER IncludeWinLaps
    Include the Windows LAPS delegation principals, and pass -IncludeWinLaps to the audit.

.PARAMETER IncludeAuthSilos
    Pass -IncludeAuthSilos to the audit.

.EXAMPLE
    .\optional\Test-TierModelLocalizedDeployment.ps1 -PreferredDc dc01.contoso.local

.EXAMPLE
    # Full evidence set, including drift findings
    .\optional\Test-TierModelLocalizedDeployment.ps1 -PreferredDc dc01.contoso.local `
        -IncludeWinLaps -IncludeAuthSilos -IncludeAudit

.NOTES
    Run it twice to prove idempotency -- once after the first deployment and once after a second
    deployment run. The second deployment must report Converged with zero actions; this report
    then shows that nothing about the resolution changed between them.

    This sample script is not supported under any Microsoft standard support program or service.
    The sample script is provided AS IS without warranty of any kind.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Problems = [System.Collections.Generic.List[object]]::new()

function Add-Problem {
    param(
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Message,
        [string]$Subject
    )
    $script:Problems.Add([ordered]@{
        Area    = $Area
        Subject = $Subject
        Message = $Message
    })
    Write-Host "  [!] $Area$(if ($Subject) { " ($Subject)" }): $Message" -ForegroundColor Yellow
}

function Get-SidString {
    # DomainSID / .SID come back as a SecurityIdentifier, as a String through the Windows
    # PowerShell Compatibility shim, or not at all. Probed rather than dereferenced because
    # Set-StrictMode turns an absent property into a terminating error.
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    $prop = $Value.PSObject.Properties['Value']
    $text = if ($Value -is [System.Security.Principal.SecurityIdentifier]) { $Value.Value }
            elseif ($Value -is [string]) { $Value }
            elseif ($prop) { [string]$prop.Value }
            else { [string]$Value }
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text.Trim()
}

# ---------------------------------------------------------------- setup

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Path $PSScriptRoot -Parent
}
if (-not (Test-Path -Path $RepositoryRoot -PathType Container)) {
    throw "Repository root '$RepositoryRoot' not found."
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
    $OutputPath = Join-Path (Get-Location) "TierModel-LocalizedVerification-$stamp.json"
}

$configRoot = Join-Path $RepositoryRoot 'config'
$modulePath = Join-Path $RepositoryRoot 'modules/TierModel/TierModel.psd1'

Write-Host "Tier Model localized-deployment verification" -ForegroundColor Cyan
Write-Host "  DC:         $PreferredDc"
Write-Host "  Repository: $RepositoryRoot"
Write-Host ""

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop
Import-Module $modulePath -Force -ErrorAction Stop

# ---------------------------------------------------------------- 1. environment

Write-Host "1/5  Environment" -ForegroundColor Cyan

$environment = [ordered]@{}
$environment.GeneratedUtc   = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
$environment.PreferredDc    = $PreferredDc
$environment.PSVersion      = $PSVersionTable.PSVersion.ToString()
$environment.HostCulture    = (Get-Culture).Name
$environment.HostUICulture  = (Get-UICulture).Name

try {
    $installLanguage = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' -Name 'InstallLanguage' -ErrorAction Stop
    $environment.HostInstallLanguage = $installLanguage
    $environment.HostInstallCulture  = ([System.Globalization.CultureInfo]::GetCultureInfo([Convert]::ToInt32([string]$installLanguage, 16))).Name
}
catch {
    $environment.HostInstallLanguage = $null
    Add-Problem -Area 'Environment' -Subject 'InstallLanguage' -Message $_.Exception.Message
}

$domainSid = $null
$domainDn  = $null
try {
    $adDomain = Get-ADDomain -Server $PreferredDc -ErrorAction Stop
    $domainSid = Get-SidString -Value $adDomain.DomainSID
    $domainDn  = [string]$adDomain.DistinguishedName

    $environment.DomainDnsRoot                 = [string]$adDomain.DNSRoot
    $environment.DomainNetBIOSName             = [string]$adDomain.NetBIOSName
    $environment.DomainDistinguishedName       = $domainDn
    $environment.DomainSid                     = $domainSid
    $environment.DomainMode                    = [string]$adDomain.DomainMode
    $environment.Forest                        = [string]$adDomain.Forest
    $environment.IsForestRoot                  = ([string]$adDomain.DNSRoot -ieq [string]$adDomain.Forest)
    # The wellKnownObject-backed container DNs. If a localized domain renames the Domain
    # Controllers OU, this is where it becomes visible.
    foreach ($containerProperty in @('DomainControllersContainer', 'UsersContainer', 'ComputersContainer')) {
        $node = $adDomain.PSObject.Properties[$containerProperty]
        $environment[$containerProperty] = if ($node) { [string]$node.Value } else { $null }
    }
}
catch {
    Add-Problem -Area 'Environment' -Subject 'Get-ADDomain' -Message $_.Exception.Message
}

try {
    $adForest = Get-ADForest -Server $PreferredDc -ErrorAction Stop
    $environment.ForestRootDomain = [string]$adForest.RootDomain
    $environment.ForestMode       = [string]$adForest.ForestMode
}
catch {
    Add-Problem -Area 'Environment' -Subject 'Get-ADForest' -Message $_.Exception.Message
}

# The three canary groups, resolved BY SID and read back for their directory name. This is what
# identifies the directory's language, and it is read from AD rather than translated client-side
# because a client-side translation describes the local machine, not the directory.
$canaries = @(
    [PSCustomObject]@{ English = 'Domain Admins';     Sid = if ($domainSid) { "$domainSid-512" } else { $null } }
    [PSCustomObject]@{ English = 'Server Operators';  Sid = 'S-1-5-32-549' }
    [PSCustomObject]@{ English = 'Account Operators'; Sid = 'S-1-5-32-548' }
)
$canaryResults = @()
foreach ($canary in $canaries) {
    if (-not $canary.Sid) { continue }
    try {
        $group = Get-ADGroup -Identity $canary.Sid -Server $PreferredDc -ErrorAction Stop
        $canaryResults += [ordered]@{
            EnglishName   = $canary.English
            Sid           = $canary.Sid
            DirectoryName = [string]$group.Name
            IsEnglish     = ([string]$group.Name -eq $canary.English)
        }
    }
    catch {
        Add-Problem -Area 'Environment' -Subject "canary $($canary.English)" -Message $_.Exception.Message
    }
}
$environment.WellKnownGroupCanaries = $canaryResults
$environment.DirectoryLanguage = if ($canaryResults.Count -eq 0) { 'unknown' }
                                 elseif (@($canaryResults | Where-Object { -not $_.IsEnglish }).Count -eq 0) { 'en' }
                                 else { 'localized' }

Write-Host "     directory language: $($environment.DirectoryLanguage)"

# ---------------------------------------------------------------- 2. principal resolution

Write-Host "2/5  Principal resolution" -ForegroundColor Cyan

function Get-ConfiguredPrincipalName {
    <#
        Collects every principal name the configuration names, from the keys that actually carry
        one. Mirrors the keys consumed by New-TierModelGptTmplContent, New-TierModelGpo and the
        Windows LAPS planners.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Node,

        # AllowEmptyCollection is required, not decorative: a Mandatory collection parameter
        # rejects an EMPTY collection as if it were missing, and the sink is empty on the first
        # call by definition.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$Sink
    )

    $principalKeys = @('resolvableGroups', 'forestRootOnly', 'denyApplyGroupPolicy', 'memberGroups',
                       'readGroup', 'resetGroup', 'decryptorGroup')

    if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
        foreach ($item in $Node) { Get-ConfiguredPrincipalName -Node $item -Sink $Sink }
        return
    }
    if ($Node -isnot [psobject]) { return }

    foreach ($property in $Node.PSObject.Properties) {
        $name  = $property.Name
        $value = $property.Value
        if ($null -eq $value) { continue }

        if ($principalKeys -contains $name) {
            foreach ($entry in @($value)) {
                if ($entry -is [string] -and -not [string]::IsNullOrWhiteSpace($entry)) { $null = $Sink.Add($entry) }
            }
        }
        elseif ($name -eq 'conditionalGroups') {
            foreach ($group in @($value)) {
                $namesNode = $group.PSObject.Properties['names']
                if ($namesNode) {
                    foreach ($entry in @($namesNode.Value)) {
                        if ($entry -is [string]) { $null = $Sink.Add($entry) }
                    }
                }
            }
        }
        elseif ($name -notin @('comment', 'gpoComment', 'description', 'notes', 'literalStrings')) {
            Get-ConfiguredPrincipalName -Node $value -Sink $Sink
        }
    }
}

function Get-ConfiguredLiteralString {
    <#
        Collects every 'literalStrings' value the configuration carries.

        These are the deliberate exception to "every principal resolves to a SID": machine-LOCAL
        accounts - NT SERVICE\*, IIS APPPOOL\*, CLIUSR - which have no domain SID at all and
        which secedit resolves on the target machine. New-TierModelGptTmplContent writes them
        through verbatim, so seeing them in [Privilege Rights] is the intended outcome, not drift.

        The walker above deliberately SKIPS this key because these are not resolvable principals;
        this one collects them for exactly the opposite reason - to tell an expected plain name in
        SYSVOL apart from one that should have been a SID.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Node,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$Sink
    )

    if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
        foreach ($item in $Node) { Get-ConfiguredLiteralString -Node $item -Sink $Sink }
        return
    }
    if ($Node -isnot [psobject]) { return }

    foreach ($property in $Node.PSObject.Properties) {
        if ($null -eq $property.Value) { continue }
        if ($property.Name -eq 'literalStrings') {
            foreach ($entry in @($property.Value)) {
                if ($entry -is [string] -and -not [string]::IsNullOrWhiteSpace($entry)) { $null = $Sink.Add($entry.Trim()) }
            }
        }
        else {
            Get-ConfiguredLiteralString -Node $property.Value -Sink $Sink
        }
    }
}

$principalNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$literalStrings = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$configFiles = @('tiermodel-gpos.json', 'tiermodel-authsilos.json')
if ($IncludeWinLaps) { $configFiles += 'tiermodel-winlaps.json' }

foreach ($configFile in $configFiles) {
    $path = Join-Path $configRoot $configFile
    if (-not (Test-Path $path)) {
        Add-Problem -Area 'Config' -Subject $configFile -Message 'file not found'
        continue
    }
    try {
        $configNode = Get-Content $path -Raw | ConvertFrom-Json
        Get-ConfiguredPrincipalName  -Node $configNode -Sink $principalNames
        Get-ConfiguredLiteralString  -Node $configNode -Sink $literalStrings
    }
    catch {
        Add-Problem -Area 'Config' -Subject $configFile -Message $_.Exception.Message
    }
}

$resolutions = @()
foreach ($name in ($principalNames | Sort-Object)) {
    $entry = [ordered]@{
        ConfiguredName = $name
        Sid            = $null
        Source         = $null
        DirectoryName  = $null
        ObjectClass    = $null
        Resolved       = $false
        Error          = $null
    }
    try {
        $result = Resolve-TierModelPrincipalSid -Principal $name -DomainController $PreferredDc -WarningAction SilentlyContinue
        if ($result -and $result.Success -and -not [string]::IsNullOrWhiteSpace($result.Sid)) {
            $entry.Sid      = [string]$result.Sid
            $entry.Source   = [string]$result.Source
            $entry.Resolved = $true
            # Read the object back for the name the directory actually carries. An alias-only
            # well-known SID (BUILTIN\Administrators and similar) has no directory object; that
            # is expected and is not recorded as a problem.
            try {
                # By LDAP filter, not -Identity: Get-ADObject's -Identity accepts a
                # distinguishedName or an objectGUID, NOT a SID (unlike Get-ADGroup/Get-ADUser).
                $adObject = @(Get-ADObject -LDAPFilter "(objectSid=$($entry.Sid))" -Server $PreferredDc -Properties name, objectClass -ErrorAction Stop)
                if ($adObject.Count -gt 0) {
                    $entry.DirectoryName = [string]$adObject[0].name
                    $entry.ObjectClass   = [string]$adObject[0].objectClass
                }
                else {
                    $entry.DirectoryName = '(no directory object for this SID)'
                }
            }
            catch {
                $entry.DirectoryName = '(no directory object for this SID)'
            }
        }
        else {
            $entry.Error = if ($result) { [string]$result.Error } else { 'no result' }
        }
    }
    catch {
        $entry.Error = $_.Exception.Message
    }
    $resolutions += $entry
}

$unresolved = @($resolutions | Where-Object { -not $_.Resolved })
$localized  = @($resolutions | Where-Object { $_.Resolved -and $_.DirectoryName -and $_.DirectoryName -ne $_.ConfiguredName -and $_.DirectoryName -notlike '(*' })
Write-Host "     $($resolutions.Count) principals, $($unresolved.Count) unresolved, $($localized.Count) carrying a different directory name"
foreach ($item in $unresolved) {
    Add-Problem -Area 'PrincipalResolution' -Subject $item.ConfiguredName -Message ($item.Error)
}

# ---------------------------------------------------------------- 3. Deny-Apply ACE on the GPC

Write-Host "3/5  Deny-Apply ACE on the GPC" -ForegroundColor Cyan

# Documented extended right "Apply Group Policy".
$applyGpoGuid = [Guid]'edacfd8f-ffb3-11d1-b41d-00a0c968f939'
$denyApplyChecks = @()

try {
    $gposConfig = Get-Content (Join-Path $configRoot 'tiermodel-gpos.json') -Raw | ConvertFrom-Json
    $allGpos = Get-GPO -All -Server $PreferredDc -ErrorAction Stop

    foreach ($ouKey in $gposConfig.gpos.PSObject.Properties.Name) {
        foreach ($listName in @('ImportOnlyGpo', 'PostConfigureGpo')) {
            $listNode = $gposConfig.gpos.$ouKey.PSObject.Properties[$listName]
            if (-not $listNode -or -not $listNode.Value) { continue }

            foreach ($gpoEntry in @($listNode.Value)) {
                $denyNode = $gpoEntry.PSObject.Properties['denyApplyGroupPolicy']
                if (-not $denyNode -or -not $denyNode.Value) { continue }

                $configuredName = [string]$gpoEntry.name
                # Matched with -like: the configured name carries a leading '*', and
                # Test-TierModelWinLapsDecryptor treats such names as patterns. -like is correct
                # whether the deployed GPO uses the literal name or a prefixed one.
                $matched = @($allGpos | Where-Object { $_.DisplayName -like $configuredName -or $_.DisplayName -eq $configuredName })

                if ($matched.Count -eq 0) {
                    Add-Problem -Area 'DenyApplyAcl' -Subject $configuredName -Message 'no GPO matches this configured name'
                    continue
                }

                foreach ($gpo in $matched) {
                    $gpcDn = "CN={$($gpo.Id)},CN=Policies,CN=System,$domainDn"
                    $aces = @()
                    try {
                        $gpcAcl = Get-Acl -Path "AD:$gpcDn" -ErrorAction Stop
                        $aces = @($gpcAcl.Access)
                    }
                    catch {
                        Add-Problem -Area 'DenyApplyAcl' -Subject $gpo.DisplayName -Message "cannot read the GPC security descriptor: $($_.Exception.Message)"
                        continue
                    }

                    foreach ($denyGroup in @($denyNode.Value)) {
                        $check = [ordered]@{
                            GpoDisplayName = [string]$gpo.DisplayName
                            GpcDn          = $gpcDn
                            ConfiguredName = [string]$denyGroup
                            Sid            = $null
                            AcePresent     = $false
                            Error          = $null
                        }
                        try {
                            $sidResult = Resolve-TierModelPrincipalSid -Principal $denyGroup -DomainController $PreferredDc -WarningAction SilentlyContinue
                            if (-not $sidResult -or -not $sidResult.Success) {
                                throw "principal did not resolve: $(if ($sidResult) { $sidResult.Error } else { 'no result' })"
                            }
                            $check.Sid = [string]$sidResult.Sid

                            foreach ($ace in $aces) {
                                $aceSid = $null
                                try {
                                    $aceSid = if ($ace.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                                        $ace.IdentityReference.Value
                                    } else {
                                        $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                                    }
                                }
                                catch { continue }

                                if ($aceSid -ne $check.Sid) { continue }
                                if ("$($ace.AccessControlType)" -ne 'Deny') { continue }
                                if ("$($ace.ActiveDirectoryRights)" -notmatch 'ExtendedRight') { continue }
                                if ([Guid]$ace.ObjectType -ne $applyGpoGuid) { continue }
                                $check.AcePresent = $true
                                break
                            }

                            if (-not $check.AcePresent) {
                                Add-Problem -Area 'DenyApplyAcl' -Subject "$($gpo.DisplayName) / $denyGroup" `
                                    -Message "no Deny ACE for Apply Group Policy ($($check.Sid)) on the GPC - this GPO can apply to that principal"
                            }
                        }
                        catch {
                            $check.Error = $_.Exception.Message
                            Add-Problem -Area 'DenyApplyAcl' -Subject "$($gpo.DisplayName) / $denyGroup" -Message $_.Exception.Message
                        }
                        $denyApplyChecks += $check
                    }
                }
            }
        }
    }
}
catch {
    Add-Problem -Area 'DenyApplyAcl' -Message $_.Exception.Message
}

Write-Host "     $($denyApplyChecks.Count) ACE check(s), $(@($denyApplyChecks | Where-Object { -not $_.AcePresent }).Count) missing"

# ---------------------------------------------------------------- 4. [Privilege Rights] from SYSVOL

Write-Host "4/5  [Privilege Rights] in SYSVOL" -ForegroundColor Cyan

$privilegeRights = @()
try {
    $sysvolDomain = $environment.DomainDnsRoot
    foreach ($gpo in (Get-GPO -All -Server $PreferredDc -ErrorAction Stop)) {
        $gptTmpl = "\\$sysvolDomain\SYSVOL\$sysvolDomain\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        if (-not (Test-Path -LiteralPath $gptTmpl)) { continue }

        $rights = [ordered]@{}
        try {
            # GptTmpl.inf is UTF-16LE; secedit writes it that way and so does this project.
            $inPrivilegeSection = $false
            foreach ($line in (Get-Content -LiteralPath $gptTmpl -Encoding Unicode -ErrorAction Stop)) {
                $trimmed = $line.Trim()
                if ($trimmed -match '^\[(.+)\]$') {
                    $inPrivilegeSection = ($matches[1] -eq 'Privilege Rights')
                    continue
                }
                if (-not $inPrivilegeSection -or $trimmed -notmatch '^([A-Za-z]+)\s*=\s*(.*)$') { continue }
                $values = @($matches[2] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                $rights[$matches[1]] = @($values | Sort-Object)
            }
        }
        catch {
            Add-Problem -Area 'PrivilegeRights' -Subject $gpo.DisplayName -Message $_.Exception.Message
            continue
        }

        if ($rights.Count -gt 0) {
            # A name rather than a SID here would mean the deployment wrote a LOCALIZABLE value
            # into security policy - the whole failure mode this branch exists to prevent.
            #
            # With one designed exception: the machine-local accounts the configuration lists as
            # literalStrings (NT SERVICE\*, IIS APPPOOL\*, CLIUSR) have no domain SID and are
            # resolved by secedit on the target. Reporting those as problems buries the one
            # finding that would matter - a plain name that nobody configured - under 140 entries
            # of noise, which is exactly what the 2026-09-16 lab report did.
            $nonSid = @()
            foreach ($key in $rights.Keys) {
                $nonSid += @($rights[$key] | Where-Object { $_ -notmatch '^\*S-1-' })
            }
            $unexpectedNonSid = @($nonSid | Where-Object { -not $literalStrings.Contains($_.TrimStart('*')) })
            if ($unexpectedNonSid.Count -gt 0) {
                Add-Problem -Area 'PrivilegeRights' -Subject $gpo.DisplayName `
                    -Message "non-SID principal(s) in [Privilege Rights] that are not configured as literalStrings: $(($unexpectedNonSid | Sort-Object -Unique) -join ', ')"
            }
            $privilegeRights += [ordered]@{
                GpoDisplayName          = [string]$gpo.DisplayName
                GpoId                   = [string]$gpo.Id
                Rights                  = $rights
                NonSidEntries           = $nonSid
                UnexpectedNonSidEntries = $unexpectedNonSid
            }
        }
    }
}
catch {
    Add-Problem -Area 'PrivilegeRights' -Message $_.Exception.Message
}

Write-Host "     $($privilegeRights.Count) GPO(s) with a [Privilege Rights] section"

# ---------------------------------------------------------------- 5. optional drift audit

Write-Host "5/5  Drift audit" -ForegroundColor Cyan

$auditReference = $null
if ($IncludeAudit) {
    try {
        $auditScript = Join-Path $RepositoryRoot 'Audit-TierModel.ps1'
        $auditBase   = [System.IO.Path]::ChangeExtension($OutputPath, $null).TrimEnd('.') + '-audit'
        $auditArgs   = @{
            PreferredDc    = $PreferredDc
            OutputFormat   = 'Json'
            OutputFileBase = $auditBase
        }
        if ($IncludeWinLaps)   { $auditArgs['IncludeWinLaps']   = $true }
        if ($IncludeAuthSilos) { $auditArgs['IncludeAuthSilos'] = $true }

        & $auditScript @auditArgs
        $auditReference = [ordered]@{ Invoked = $true; OutputFileBase = $auditBase }
    }
    catch {
        $auditReference = [ordered]@{ Invoked = $true; Error = $_.Exception.Message }
        Add-Problem -Area 'Audit' -Message $_.Exception.Message
    }
}
else {
    $auditReference = [ordered]@{ Invoked = $false; Hint = 'Re-run with -IncludeAudit to collect drift findings in the same pass.' }
    Write-Host "     skipped (-IncludeAudit not specified)"
}

# ---------------------------------------------------------------- report

$report = [ordered]@{
    SchemaVersion     = '1.0.0'
    Environment       = $environment
    PrincipalResolution = [ordered]@{
        Total               = $resolutions.Count
        Unresolved          = $unresolved.Count
        LocalizedNameCount  = $localized.Count
        Entries             = $resolutions
    }
    DenyApplyAcl      = [ordered]@{
        Checked = $denyApplyChecks.Count
        Missing = @($denyApplyChecks | Where-Object { -not $_.AcePresent }).Count
        Entries = $denyApplyChecks
    }
    PrivilegeRights   = $privilegeRights
    Audit             = $auditReference
    Problems          = $script:Problems
}

$report | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host ""
if ($script:Problems.Count -eq 0) {
    Write-Host "No problems found." -ForegroundColor Green
}
else {
    Write-Host "$($script:Problems.Count) problem(s) recorded - see the Problems section." -ForegroundColor Yellow
}
Write-Host "Report: $OutputPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "To prove the localization claim, run this on an ENGLISH domain too and diff the" -ForegroundColor DarkGray
Write-Host "PrivilegeRights sections: the SID sets must be identical." -ForegroundColor DarkGray
