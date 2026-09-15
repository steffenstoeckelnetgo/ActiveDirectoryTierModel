[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)]
    [string]$Language,

    [Parameter(Mandatory)]
    [string]$SourcePath,

    [string]$ConfigPath,

    [string]$ReferenceManifest,

    [switch]$Force
)

<#
.SYNOPSIS
    Generates config/tiermodel-adml-<Language>.json from a folder of ADML files.

.DESCRIPTION
    Deploy-TierModel.ps1 and Audit-TierModel.ps1 already accept -AdmlLanguage and load
    config\tiermodel-adml-<language>.json, but only the en-US manifest and its ADML files ship
    with the repository. A German (or any other) central store needs
    SYSVOL\...\PolicyDefinitions\<language> populated, or the Group Policy editor reports
    "resource not found" for every ADMX-backed setting on a host of that language.

    The ADML files themselves are Microsoft redistributables and are not in this repository.
    This script turns a folder of them into the manifest the Tier Model expects, with the MD5
    hashes it verifies against, so the content drop is a copy plus one command rather than hand
    written JSON for several dozen files.

    Each entry inherits its comment and downloadLink from the matching entry in the en-US
    manifest (or -ReferenceManifest), so provenance is preserved: the German LAPS.adml is
    documented as coming from the same Microsoft download as the English one. Files with no
    counterpart in the reference are still emitted, with a placeholder comment to fill in.

    HOW TO GET THE ADML FILES
      1. Open config\tiermodel-adml-en-US.json and note the downloadLink of each entry. There
         are three sources: the Windows 11 Administrative Templates, the Microsoft 365 Apps
         Administrative Templates, and the Microsoft Edge policy templates.
      2. Download each one in the target language and install or extract it.
      3. Copy the .adml files from its <language> folder into a single folder, keeping the same
         file names as config\admx\en-US.
      4. Run this script against that folder.
      5. Copy the folder to config\admx\<language>\ and deploy with -AdmlLanguage <language>.

.PARAMETER Language
    Language tag, e.g. 'de-DE'. Used for the file name, destinationPath and sourcePath.

.PARAMETER SourcePath
    Folder holding the .adml files for that language.

.PARAMETER ConfigPath
    Folder to write the manifest into. Defaults to the repository's config folder.

.PARAMETER ReferenceManifest
    Manifest to inherit comment and downloadLink from. Defaults to tiermodel-adml-en-US.json.

.PARAMETER Force
    Overwrite an existing manifest for this language.

.EXAMPLE
    .\optional\New-TierModelAdmlManifest.ps1 -Language de-DE -SourcePath 'C:\ADMX\de-DE'

.EXAMPLE
    # Regenerate after refreshing the files in place
    .\optional\New-TierModelAdmlManifest.ps1 -Language de-DE -SourcePath .\config\admx\de-DE -Force

.NOTES
    This sample script is not supported under any Microsoft standard support program or service.
    The sample script is provided AS IS without warranty of any kind.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Language -notmatch '^[a-z]{2}(-[A-Za-z]{2,8})?$') {
    throw "Language '$Language' is not a language tag such as 'de-DE'."
}

if (-not (Test-Path -Path $SourcePath -PathType Container)) {
    throw "Source path '$SourcePath' does not exist or is not a folder."
}

$repositoryRoot = Split-Path -Path $PSScriptRoot -Parent
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $repositoryRoot 'config'
}
if (-not (Test-Path -Path $ConfigPath -PathType Container)) {
    throw "Config path '$ConfigPath' does not exist or is not a folder."
}

if ([string]::IsNullOrWhiteSpace($ReferenceManifest)) {
    $ReferenceManifest = Join-Path $ConfigPath 'tiermodel-adml-en-US.json'
}
if (-not (Test-Path -Path $ReferenceManifest -PathType Leaf)) {
    throw "Reference manifest '$ReferenceManifest' not found."
}

$outputPath = Join-Path $ConfigPath "tiermodel-adml-$Language.json"
if ((Test-Path -Path $outputPath) -and -not $Force) {
    throw "Manifest '$outputPath' already exists. Re-run with -Force to overwrite it."
}

$reference = Get-Content -Path $ReferenceManifest -Raw | ConvertFrom-Json
$referenceFiles = $reference.adml.files

$admlFiles = @(Get-ChildItem -Path $SourcePath -Filter '*.adml' -File | Sort-Object Name)
if ($admlFiles.Count -eq 0) {
    throw "No .adml files found in '$SourcePath'."
}

# Report against the reference set so a partial drop is visible before it reaches SYSVOL,
# rather than surfacing as a missing-resource error in the Group Policy editor later.
$referenceNames = @($referenceFiles.PSObject.Properties.Name)
$presentNames = @($admlFiles.Name)

$missing = @($referenceNames | Where-Object { $presentNames -notcontains $_ })
if ($missing.Count -gt 0) {
    Write-Warning "$($missing.Count) file(s) present in the reference manifest have no $Language counterpart: $($missing -join ', ')"
}

$extra = @($presentNames | Where-Object { $referenceNames -notcontains $_ })
if ($extra.Count -gt 0) {
    Write-Warning "$($extra.Count) file(s) have no reference entry and will get a placeholder comment: $($extra -join ', ')"
}

$files = [ordered]@{}
$today = (Get-Date).ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)

foreach ($admlFile in $admlFiles) {
    # MD5 matches what the shipped manifests record and what Get-TierModelAdmx verifies. It is a
    # change-detection checksum for files the operator already trusts, not a security control.
    $hash = (Get-FileHash -Path $admlFile.FullName -Algorithm MD5).Hash.ToUpperInvariant()

    $referenceEntry = $referenceFiles.PSObject.Properties[$admlFile.Name]
    $comment = if ($referenceEntry) { $referenceEntry.Value.comment } else { "TODO: describe the source of $($admlFile.Name)" }
    $downloadLink = if ($referenceEntry) { $referenceEntry.Value.downloadLink } else { '' }

    $files[$admlFile.Name] = [ordered]@{
        comment      = $comment
        hashDate     = $today
        downloadLink = $downloadLink
        hash         = $hash
    }
}

$manifest = [ordered]@{
    version     = $reference.version
    lastUpdated = $today
    comment     = "ADML $Language language files with MD5 hash verification"
    adml        = [ordered]@{
        destinationPath = "\\{{DOMAIN_FQDN}}\SYSVOL\{{DOMAIN_FQDN}}\Policies\PolicyDefinitions\$Language"
        sourcePath      = "config\admx\$Language"
        files           = $files
    }
}

if ($PSCmdlet.ShouldProcess($outputPath, "Write ADML manifest for $Language ($($files.Count) files)")) {
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -Path $outputPath -Encoding UTF8
    Write-Host "Wrote $outputPath ($($files.Count) files)." -ForegroundColor Green
    Write-Host "Next: copy the .adml files to config\admx\$Language\ and deploy with -AdmlLanguage $Language." -ForegroundColor Cyan
}
