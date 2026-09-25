[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ReferencePath,

    [Parameter(Mandatory)]
    [string]$DifferencePath,

    [string]$OutputPath
)

<#
.SYNOPSIS
    Compares two Test-TierModelLocalizedDeployment reports and proves that localization changed
    nothing about the security configuration. Read-only.

.DESCRIPTION
    The claim the localized-directory work rests on is that the SAME configuration, deployed to
    an English domain and to a localized one, produces the SAME security configuration. No unit
    test can establish that: it needs two live domains.

    WHY A PLAIN DIFF DOES NOT WORK, AND WHY THIS SCRIPT EXISTS.
    Every domain-scoped principal in [Privilege Rights] is written as a SID that carries its own
    domain's SID as a prefix:

        *S-1-5-21-2230522700-2543936044-3532250090-512      one domain
        *S-1-5-21-1004336348-1177238915-682003330-512       the other

    Those are the same principal -- Domain Admins, RID 512 -- and any textual comparison calls
    them different. In the measured lab data that is 1651 SID entries across 29 GPOs, so a naive
    diff yields a wall of false differences and the only conclusion available from it is wrong.
    Earlier guidance in this repository said to diff the sections directly; it was mistaken and
    is corrected alongside this script.

    So each report's OWN domain SID is replaced by the placeholder <DOMAIN> before anything is
    compared, and what remains is compared.

    NORMALISING THE DOMAIN SID ALONE IS NOT ENOUGH, AND THAT IS NOT OBVIOUS.
    Below the domain SID sits a second, independent source of the same kind of false difference:
    the RID. Active Directory allocates a RID when an object is created, from a pool that starts
    at 1000, so a Tier Model group's RID records how many objects its domain had created before it
    -- not anything the configuration says. The parity run of 2026-09-24 made that concrete: the
    two lab domains differed by exactly one object, every locally created RID was off by one, and
    this script reported 84 differences (31 principals, 53 rights) against two deployments that
    were in fact identical. 31 of the 56 configured principals and 894 of the 1791 [Privilege
    Rights] entries carry such a RID.

    A SID at or above the RID pool is therefore mapped back to the name the configuration gave it,
    through the report's OWN PrincipalResolution table, and compared by that name. A RID below the
    pool keeps its number: those are fixed by the protocol (500, 512, 516, 571, ...) and a
    difference there is a real resolution defect. So does a locally allocated SID the report does
    not name -- it cannot be compared by identity, so it stays comparable by RID and is still
    reported.

    Three classes deliberately survive untouched:

      - a SID belonging to NEITHER domain, because a foreign SID reaching the settings is a
        finding, not noise -- it is what the open question about Import-GPO's <SecurityGroups>
        is looking for;
      - non-domain well-known SIDs (S-1-5-32-*, S-1-1-0, S-1-5-10), which are invariant already;
      - the machine-local principals the configuration declares as literalStrings
        (NT SERVICE\*, IIS APPPOOL\*, CLIUSR), which have no domain SID by construction and are
        resolved by the Security Configuration Engine on the target machine.

    WHAT IS COMPARED, AND WHAT IS DELIBERATELY NOT.
    Principal resolution is compared by SID and by SOURCE, never by the rendered directory name.
    The same principal carrying a different name on the two domains -- Domain Admins reading
    Domaenen-Admins -- is the intended outcome of the change; flagging it would fail the proof on
    precisely the thing it exists to demonstrate. The source is compared because the same SID
    reached by a different route means one domain fell back to a name lookup, which is a real
    finding even when the SID matches.

    GPOs are joined by DISPLAY NAME, not by GUID: a GPO is created per domain and its GUID
    differs by construction.

    READ-ONLY. Two report files are read; nothing else is touched.

.PARAMETER ReferencePath
    The first report, conventionally the English domain's.

.PARAMETER DifferencePath
    The second report, conventionally the localized domain's.

.PARAMETER OutputPath
    Result file. Defaults to TierModel-Parity-<yyyyMMdd-HHmmss>.json in the current directory.

.EXAMPLE
    .\Compare-TierModelDeploymentReport.ps1 -ReferencePath .\en.json -DifferencePath .\de.json

.NOTES
    Exit code 0 when the two reports agree, 1 when they do not, so the comparison can gate a
    pipeline. Timestamps use InvariantCulture so the filename does not vary with host locale.
#>

function ConvertTo-DomainRelativeSid {
    <#
    .SYNOPSIS
        Replaces a report's own domain SID with <DOMAIN>, leaving everything else verbatim.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$DomainSid
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    if ([string]::IsNullOrWhiteSpace($DomainSid)) { return $Value }

    # secedit writes [Privilege Rights] principals with a leading asterisk. Keep it: a value that
    # lost its prefix on one side only would be a difference worth seeing.
    $prefix = ''
    $body   = $Value
    if ($body.StartsWith('*')) {
        $prefix = '*'
        $body   = $body.Substring(1)
    }

    # Anchored on both ends: the domain SID must be followed by exactly one RID and nothing else.
    # Without the anchor, one domain's SID would also match a longer, different SID that happens
    # to start with the same digits.
    $pattern = '^{0}-(\d+)$' -f [regex]::Escape($DomainSid)
    if ($body -match $pattern) {
        return '{0}<DOMAIN>-{1}' -f $prefix, $matches[1]
    }

    return $Value
}

function Get-FirstAllocatedRid {
    <#
    .SYNOPSIS
        The first RID Active Directory hands out from a domain's RID pool.

    .DESCRIPTION
        Everything below it is a well-known domain RID fixed by the protocol (500 Administrator,
        512 Domain Admins, 516 Domain Controllers, 571 Allowed RODC Password Replication Group,
        ...) and therefore comparable across domains. Everything at or above it was allocated when
        the object was created, so it records how many objects the domain had created before - it
        is NOT a property of the configuration.

        This is a function and not a script-scope variable on purpose.
        tests/Unit.ParityComparison.Tests.ps1 lifts FUNCTIONS out of this file's AST and
        dot-sources them individually; a top-level assignment is never lifted, so the variable
        would be $null under test. PowerShell coerces $null to 0 in a numeric comparison, so
        "$rid -ge $null" is true for every RID - the built-in check would have failed open, in the
        tests only, without a single error. Keep it callable.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param()

    return 1000
}

function Get-DomainRelativeRid {
    <#
    .SYNOPSIS
        Returns the RID when $Value is exactly "<DomainSid>-<rid>", otherwise $null.

    .DESCRIPTION
        The anchoring is the same as ConvertTo-DomainRelativeSid's and for the same reason: without
        it, one domain's SID also matches a longer, different SID that happens to start with the
        same digits. $null means "not a SID of this domain" - which covers well-known SIDs, foreign
        domain SIDs and the machine-local literalStrings alike.
    #>
    [CmdletBinding()]
    [OutputType([System.Nullable[int]])]
    param(
        [AllowNull()][AllowEmptyString()][string]$Value,
        [AllowNull()][AllowEmptyString()][string]$DomainSid
    )

    if ([string]::IsNullOrWhiteSpace($Value))     { return $null }
    if ([string]::IsNullOrWhiteSpace($DomainSid)) { return $null }

    $body = if ($Value.StartsWith('*')) { $Value.Substring(1) } else { $Value }

    $pattern = '^{0}-(\d+)$' -f [regex]::Escape($DomainSid)
    if ($body -match $pattern) { return [int]$matches[1] }
    return $null
}

function Get-ReportPrincipalMap {
    <#
    .SYNOPSIS
        Builds SID -> configured name from a report's own PrincipalResolution section.

    .DESCRIPTION
        This is what lets a locally allocated RID be compared by identity instead of by number.
        Each report carries the table for its own domain, so the mapping is never shared between
        the two sides. Absence of the section is tolerated exactly as Get-ReportDomainSid tolerates
        a missing Environment: the caller then falls back to comparing the RID, which is the old
        behaviour and still reports rather than hides.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)]$Report)

    $map = @{}

    $section = $Report.PSObject.Properties['PrincipalResolution']
    if (-not $section) { return $map }
    $entries = $section.Value.PSObject.Properties['Entries']
    if (-not $entries) { return $map }

    foreach ($entry in @($entries.Value)) {
        if (-not $entry) { continue }
        $sid = [string]$entry.Sid
        if ([string]::IsNullOrWhiteSpace($sid)) { continue }
        # First writer wins. Two configured names resolving to the same SID is legitimate (an alias
        # and its canonical form), and either name identifies the same principal for comparison.
        if (-not $map.ContainsKey($sid)) { $map[$sid] = [string]$entry.ConfiguredName }
    }

    return $map
}

function ConvertTo-ComparablePrincipal {
    <#
    .SYNOPSIS
        Reduces a principal to the form in which the two domains can actually be compared.

    .DESCRIPTION
        Normalising the domain SID alone is not enough, and the parity run of 2026-09-24 is what
        showed it: 31 of 56 configured principals and 894 of 1791 [Privilege Rights] entries carry
        a RID the directory allocated at creation time. The two lab domains differed by exactly one
        object before the first Tier Model container was created, so every one of those RIDs was
        off by one and the comparison reported 84 differences where there were none.

        A locally allocated RID is therefore mapped back to the name the configuration gave it -
        which is the thing the configuration actually asserts. Three classes deliberately keep
        their number:

          - a RID below the RID pool (see Get-FirstAllocatedRid), because those are fixed by
            the protocol and a difference there is a real resolution defect;
          - a locally allocated SID the report's own PrincipalResolution does not know, because a
            SID in the settings that the configuration never named cannot be compared by identity -
            it stays comparable by RID and will still be reported. Measured on both lab domains:
            zero such SIDs. This is a guard, not a routine path;
          - everything that is not this domain's SID at all - well-known SIDs, the machine-local
            literalStrings, and above all a FOREIGN domain SID, which is the finding the whole
            comparison exists to surface.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][AllowEmptyString()][string]$Value,
        [AllowNull()][AllowEmptyString()][string]$DomainSid,
        [AllowNull()][hashtable]$PrincipalMap
    )

    $rid = Get-DomainRelativeRid -Value $Value -DomainSid $DomainSid
    if ($null -eq $rid -or $rid -lt (Get-FirstAllocatedRid)) {
        return (ConvertTo-DomainRelativeSid -Value $Value -DomainSid $DomainSid)
    }

    $prefix = ''
    $body   = $Value
    if ($body.StartsWith('*')) {
        $prefix = '*'
        $body   = $body.Substring(1)
    }

    if ($null -ne $PrincipalMap -and $PrincipalMap.ContainsKey($body)) {
        return '{0}<PRINCIPAL:{1}>' -f $prefix, $PrincipalMap[$body]
    }

    return (ConvertTo-DomainRelativeSid -Value $Value -DomainSid $DomainSid)
}

function Get-ReportDomainSid {
    <#
    .SYNOPSIS
        Reads Environment.DomainSid out of a report, tolerating its absence.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)]$Report)

    $environment = $Report.PSObject.Properties['Environment']
    if (-not $environment) { return '' }
    $sid = $environment.Value.PSObject.Properties['DomainSid']
    if (-not $sid) { return '' }
    return [string]$sid.Value
}

function Compare-PrivilegeRightsSection {
    <#
    .SYNOPSIS
        Compares the [Privilege Rights] sets of two reports after normalising each report's own
        domain SID. Emits one object per difference; emits nothing when they agree.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Reference,
        [Parameter(Mandatory)]$Difference
    )

    $referenceDomain  = Get-ReportDomainSid -Report $Reference
    $differenceDomain = Get-ReportDomainSid -Report $Difference

    $index = {
        param($Report)
        $map = @{}
        $section = $Report.PSObject.Properties['PrivilegeRights']
        if ($section) {
            foreach ($gpo in @($section.Value)) {
                if (-not $gpo) { continue }
                $map[[string]$gpo.GpoDisplayName] = $gpo
            }
        }
        return $map
    }

    $referenceGpos  = & $index $Reference
    $differenceGpos = & $index $Difference

    # Each report's own table, never shared: a SID is mapped to a name only by the domain it
    # belongs to.
    $referencePrincipals  = Get-ReportPrincipalMap -Report $Reference
    $differencePrincipals = Get-ReportPrincipalMap -Report $Difference

    $normaliseSet = {
        param($Values, $DomainSid, $PrincipalMap)
        $normalised = foreach ($value in @($Values)) {
            ConvertTo-ComparablePrincipal -Value ([string]$value) -DomainSid $DomainSid -PrincipalMap $PrincipalMap
        }
        # Sorted and joined so the comparison is order-independent: secedit's ordering is not a
        # property of the configuration. Case-insensitive because SIDs and the machine-local
        # names are written with varying case by different tools.
        return (@($normalised) | Sort-Object -Unique) -join '; '
    }

    foreach ($name in ($referenceGpos.Keys + $differenceGpos.Keys | Sort-Object -Unique)) {

        if (-not $differenceGpos.ContainsKey($name)) {
            [PSCustomObject]@{
                Section = 'PrivilegeRights'; Kind = 'GpoMissingInDifference'
                Gpo = $name; Right = $null; ReferenceValue = '(present)'; DifferenceValue = '(absent)'
            }
            continue
        }
        if (-not $referenceGpos.ContainsKey($name)) {
            [PSCustomObject]@{
                Section = 'PrivilegeRights'; Kind = 'GpoMissingInReference'
                Gpo = $name; Right = $null; ReferenceValue = '(absent)'; DifferenceValue = '(present)'
            }
            continue
        }

        $referenceRights  = @{}
        $differenceRights = @{}
        foreach ($property in $referenceGpos[$name].Rights.PSObject.Properties)  { $referenceRights[$property.Name]  = $property.Value }
        foreach ($property in $differenceGpos[$name].Rights.PSObject.Properties) { $differenceRights[$property.Name] = $property.Value }

        foreach ($right in ($referenceRights.Keys + $differenceRights.Keys | Sort-Object -Unique)) {

            $referenceSet  = if ($referenceRights.ContainsKey($right))  { & $normaliseSet $referenceRights[$right]  $referenceDomain  $referencePrincipals }  else { $null }
            $differenceSet = if ($differenceRights.ContainsKey($right)) { & $normaliseSet $differenceRights[$right] $differenceDomain $differencePrincipals } else { $null }

            if ($referenceSet -ceq $differenceSet) { continue }
            if ($null -ne $referenceSet -and $null -ne $differenceSet -and
                [string]::Equals($referenceSet, $differenceSet, [StringComparison]::OrdinalIgnoreCase)) { continue }

            [PSCustomObject]@{
                Section         = 'PrivilegeRights'
                Kind            = if ($null -eq $referenceSet) { 'RightMissingInReference' }
                                  elseif ($null -eq $differenceSet) { 'RightMissingInDifference' }
                                  else { 'ValuesDiffer' }
                Gpo             = $name
                Right           = $right
                ReferenceValue  = if ($null -eq $referenceSet)  { '(absent)' } else { $referenceSet }
                DifferenceValue = if ($null -eq $differenceSet) { '(absent)' } else { $differenceSet }
            }
        }
    }
}

function Compare-PrincipalResolutionSection {
    <#
    .SYNOPSIS
        Compares how each configured principal resolved on the two domains, by SID and by source.
        The rendered directory name is deliberately not compared.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Reference,
        [Parameter(Mandatory)]$Difference
    )

    $referenceDomain  = Get-ReportDomainSid -Report $Reference
    $differenceDomain = Get-ReportDomainSid -Report $Difference

    $index = {
        param($Report)
        $map = @{}
        $section = $Report.PSObject.Properties['PrincipalResolution']
        if ($section) {
            $entries = $section.Value.PSObject.Properties['Entries']
            if ($entries) {
                foreach ($entry in @($entries.Value)) {
                    if (-not $entry) { continue }
                    $map[[string]$entry.ConfiguredName] = $entry
                }
            }
        }
        return $map
    }

    $referenceEntries  = & $index $Reference
    $differenceEntries = & $index $Difference

    foreach ($name in ($referenceEntries.Keys + $differenceEntries.Keys | Sort-Object -Unique)) {

        $inReference  = $referenceEntries.ContainsKey($name)
        $inDifference = $differenceEntries.ContainsKey($name)

        if (-not $inReference -or -not $inDifference) {
            [PSCustomObject]@{
                Section = 'PrincipalResolution'
                Kind    = if ($inReference) { 'PrincipalMissingInDifference' } else { 'PrincipalMissingInReference' }
                ConfiguredName   = $name
                ReferenceSid     = if ($inReference)  { [string]$referenceEntries[$name].Sid }  else { '(absent)' }
                DifferenceSid    = if ($inDifference) { [string]$differenceEntries[$name].Sid } else { '(absent)' }
                ReferenceSource  = if ($inReference)  { [string]$referenceEntries[$name].Source }  else { '(absent)' }
                DifferenceSource = if ($inDifference) { [string]$differenceEntries[$name].Source } else { '(absent)' }
            }
            continue
        }

        $referenceEntry  = $referenceEntries[$name]
        $differenceEntry = $differenceEntries[$name]

        $referenceSid  = ConvertTo-DomainRelativeSid -Value ([string]$referenceEntry.Sid)  -DomainSid $referenceDomain
        $differenceSid = ConvertTo-DomainRelativeSid -Value ([string]$differenceEntry.Sid) -DomainSid $differenceDomain

        $referenceRid  = Get-DomainRelativeRid -Value ([string]$referenceEntry.Sid)  -DomainSid $referenceDomain
        $differenceRid = Get-DomainRelativeRid -Value ([string]$differenceEntry.Sid) -DomainSid $differenceDomain

        # Both sides resolved to a principal their own domain allocated. The entries are already
        # joined on the configured name, so the RID carries no information the comparison could
        # use: it says how many objects the domain had created before, not what the configuration
        # asserts. Compared by number it is guaranteed noise the moment the two domains were not
        # built in lockstep - on the 2026-09-24 lab pair every one of these was off by exactly one.
        # The Source comparison below still runs, and it is the one that catches a domain falling
        # back to a name lookup.
        $firstAllocatedRid = Get-FirstAllocatedRid
        $bothLocallyAllocated =
            $null -ne $referenceRid  -and $referenceRid  -ge $firstAllocatedRid -and
            $null -ne $differenceRid -and $differenceRid -ge $firstAllocatedRid

        $sidDiffers = (-not $bothLocallyAllocated) -and
            -not [string]::Equals($referenceSid, $differenceSid, [StringComparison]::OrdinalIgnoreCase)

        $sourceDiffers = -not [string]::Equals([string]$referenceEntry.Source, [string]$differenceEntry.Source, [StringComparison]::OrdinalIgnoreCase)

        # A principal that resolved on one domain and not on the other was invisible before: the
        # SIDs could still match while one side carried Resolved = false with an error. Compared
        # only when BOTH entries carry the field - a report written by an older version of
        # Test-TierModelLocalizedDeployment would otherwise differ from a current one on schema
        # rather than on substance.
        $resolvedDiffers =
            $null -ne $referenceEntry.PSObject.Properties['Resolved'] -and
            $null -ne $differenceEntry.PSObject.Properties['Resolved'] -and
            ([bool]$referenceEntry.Resolved) -ne ([bool]$differenceEntry.Resolved)

        if ($bothLocallyAllocated -and -not $sourceDiffers -and -not $resolvedDiffers) {
            # Reclassified in the open, never swallowed: this is reported alongside the result and
            # counted, but it does not make the two deployments differ.
            [PSCustomObject]@{
                Section          = 'PrincipalResolution'
                Kind             = 'LocalRidNotCompared'
                ConfiguredName   = $name
                ReferenceSid     = $referenceSid
                DifferenceSid    = $differenceSid
                ReferenceSource  = [string]$referenceEntry.Source
                DifferenceSource = [string]$differenceEntry.Source
            }
            continue
        }

        if (-not $sidDiffers -and -not $sourceDiffers -and -not $resolvedDiffers) { continue }

        [PSCustomObject]@{
            Section          = 'PrincipalResolution'
            Kind             = if ($sidDiffers) { 'SidDiffers' }
                               elseif ($sourceDiffers) { 'SourceDiffers' }
                               else { 'ResolutionDiffers' }
            ConfiguredName   = $name
            ReferenceSid     = $referenceSid
            DifferenceSid    = $differenceSid
            ReferenceSource  = [string]$referenceEntry.Source
            DifferenceSource = [string]$differenceEntry.Source
        }
    }
}

# ------------------------------------------------------------------------------------ main

$ErrorActionPreference = 'Stop'

foreach ($path in @($ReferencePath, $DifferencePath)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Report not found: $path"
    }
}

$referenceReport  = Get-Content -LiteralPath $ReferencePath  -Raw | ConvertFrom-Json
$differenceReport = Get-Content -LiteralPath $DifferencePath -Raw | ConvertFrom-Json

$referenceLanguage  = $referenceReport.Environment.DirectoryLanguage
$differenceLanguage = $differenceReport.Environment.DirectoryLanguage

Write-Host "Tier Model parity comparison" -ForegroundColor Cyan
Write-Host ("  reference : {0}  (directory language: {1}, domain SID: {2})" -f `
    $ReferencePath, $referenceLanguage, (Get-ReportDomainSid -Report $referenceReport))
Write-Host ("  difference: {0}  (directory language: {1}, domain SID: {2})" -f `
    $DifferencePath, $differenceLanguage, (Get-ReportDomainSid -Report $differenceReport))

if ($referenceLanguage -eq $differenceLanguage) {
    # Not fatal: comparing two domains of the same language is a legitimate regression check.
    # But the parity PROOF needs one of each, so say so rather than let it pass unnoticed.
    Write-Warning ("Both reports report directory language '{0}'. This is not the English/localized parity proof." -f $referenceLanguage)
}

$records = @()
$records += @(Compare-PrincipalResolutionSection -Reference $referenceReport -Difference $differenceReport)
$records += @(Compare-PrivilegeRightsSection    -Reference $referenceReport -Difference $differenceReport)

# LocalRidNotCompared is an observation, not a difference: the two domains allocated their own RIDs,
# which they always do. It is kept in the result file and printed, so the narrowing of the
# comparison is visible rather than silent - but it must not reach the count or the exit code, or
# the exit code would stop meaning "these two deployments differ".
$notCompared = @($records | Where-Object { $_.Kind -eq 'LocalRidNotCompared' })
$differences = @($records | Where-Object { $_.Kind -ne 'LocalRidNotCompared' })

$principalCount = @($differences | Where-Object { $_.Section -eq 'PrincipalResolution' }).Count
$rightsCount    = @($differences | Where-Object { $_.Section -eq 'PrivilegeRights' }).Count

Write-Host ""
Write-Host ("  PrincipalResolution differences: {0}" -f $principalCount)
Write-Host ("  PrivilegeRights differences    : {0}" -f $rightsCount)
if ($notCompared.Count -gt 0) {
    Write-Host ("  compared by identity, not by RID: {0} principal(s) - their RIDs are domain-allocated" -f $notCompared.Count)
}

foreach ($difference in $differences) {
    Write-Host ("    [{0}] {1}" -f $difference.Kind, ($difference | ConvertTo-Json -Compress)) -ForegroundColor Yellow
}

if (-not $OutputPath) {
    $stamp = [DateTime]::Now.ToString('yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
    $OutputPath = "TierModel-Parity-$stamp.json"
}

[ordered]@{
    SchemaVersion = '1.1.0'
    GeneratedUtc  = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    Reference     = [ordered]@{ Path = $ReferencePath;  DirectoryLanguage = $referenceLanguage;  DomainSid = (Get-ReportDomainSid -Report $referenceReport) }
    Difference    = [ordered]@{ Path = $DifferencePath; DirectoryLanguage = $differenceLanguage; DomainSid = (Get-ReportDomainSid -Report $differenceReport) }
    DifferenceCount     = $differences.Count
    Differences         = $differences
    LocalRidNotCompared = $notCompared
} | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host ""
if ($differences.Count -eq 0) {
    Write-Host "No differences. The two deployments carry the same security configuration." -ForegroundColor Green
}
else {
    Write-Host ("{0} difference(s). See {1}." -f $differences.Count, $OutputPath) -ForegroundColor Red
}
Write-Host ("Report: {0}" -f $OutputPath)

exit ([int]($differences.Count -gt 0))
