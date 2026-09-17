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
    compared, and what remains is compared. Three classes deliberately survive untouched:

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

    $normaliseSet = {
        param($Values, $DomainSid)
        $normalised = foreach ($value in @($Values)) {
            ConvertTo-DomainRelativeSid -Value ([string]$value) -DomainSid $DomainSid
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

            $referenceSet  = if ($referenceRights.ContainsKey($right))  { & $normaliseSet $referenceRights[$right]  $referenceDomain }  else { $null }
            $differenceSet = if ($differenceRights.ContainsKey($right)) { & $normaliseSet $differenceRights[$right] $differenceDomain } else { $null }

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

        $sidDiffers    = -not [string]::Equals($referenceSid, $differenceSid, [StringComparison]::OrdinalIgnoreCase)
        $sourceDiffers = -not [string]::Equals([string]$referenceEntry.Source, [string]$differenceEntry.Source, [StringComparison]::OrdinalIgnoreCase)

        if (-not $sidDiffers -and -not $sourceDiffers) { continue }

        [PSCustomObject]@{
            Section          = 'PrincipalResolution'
            Kind             = if ($sidDiffers) { 'SidDiffers' } else { 'SourceDiffers' }
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

$differences = @()
$differences += @(Compare-PrincipalResolutionSection -Reference $referenceReport -Difference $differenceReport)
$differences += @(Compare-PrivilegeRightsSection    -Reference $referenceReport -Difference $differenceReport)

$principalCount = @($differences | Where-Object { $_.Section -eq 'PrincipalResolution' }).Count
$rightsCount    = @($differences | Where-Object { $_.Section -eq 'PrivilegeRights' }).Count

Write-Host ""
Write-Host ("  PrincipalResolution differences: {0}" -f $principalCount)
Write-Host ("  PrivilegeRights differences    : {0}" -f $rightsCount)

foreach ($difference in $differences) {
    Write-Host ("    [{0}] {1}" -f $difference.Kind, ($difference | ConvertTo-Json -Compress)) -ForegroundColor Yellow
}

if (-not $OutputPath) {
    $stamp = [DateTime]::Now.ToString('yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
    $OutputPath = "TierModel-Parity-$stamp.json"
}

[ordered]@{
    SchemaVersion = '1.0.0'
    GeneratedUtc  = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    Reference     = [ordered]@{ Path = $ReferencePath;  DirectoryLanguage = $referenceLanguage;  DomainSid = (Get-ReportDomainSid -Report $referenceReport) }
    Difference    = [ordered]@{ Path = $DifferencePath; DirectoryLanguage = $differenceLanguage; DomainSid = (Get-ReportDomainSid -Report $differenceReport) }
    DifferenceCount = $differences.Count
    Differences     = $differences
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
