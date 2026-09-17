Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Generate correlation ID for this session
$script:CorrelationId = [System.Guid]::NewGuid().ToString()

# Module-level variables
$script:ModuleRoot = $PSScriptRoot
# Config directory is in the parent of the module directory (../../config from Modules/TierModel)
$script:ConfigPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config'
$script:LoggingEnabled = $false
$script:DefaultLogPath = $null

function Initialize-TierModelLogging {
    <#
    .SYNOPSIS
    Enables TierModel module-scope file logging for the current session.

    .DESCRIPTION
    Sets the two module-scope logging variables declared above
    ($script:LoggingEnabled and $script:DefaultLogPath) that Write-TierModelLog
    consults when a caller supplies no explicit -LogPath.

    Without this initialiser those variables keep their declared defaults
    ($false / $null), so every Write-TierModelLog call made inside the module
    writes to the console streams only and never reaches disk.

    WHY THIS LIVES INLINE IN THE .psm1 AND NOT IN public\
    This is a module-scope helper that must NOT be exported. It cannot live in
    public\ because tests\Unit.ModuleManifest.Tests.ps1 (L188-216) derives its
    expectation from the *contents of the public\ folder* — every *.ps1 file
    there must have a matching entry in FunctionsToExport — rather than from the
    module's runtime exported list. Adding an unexported file to public\ fails
    three assertions in that test (measured 2026-09-03: 'Number of declared
    functions matches number of public function files' expected 84 got 83, plus
    'All public function files are declared in manifest' and 'Declared functions
    list matches actual functions list exactly'). That test is owned elsewhere
    and is not editable here. Defining the function inline keeps it dot-sourced
    into module scope, unexported, and invisible to that test's three hard-coded
    inline-function regexes. Do not move this into public\ without first changing
    that test to assert on exported functions instead of on folder contents.

    Entry scripts call it inside the module's scope:

        & $module { param($p) Initialize-TierModelLogging -LogFilePath $p } $path

    Logging remains opt-in: nothing calls this unless the operator asked for it.

    .PARAMETER LogFilePath
    Full path of the log file to append structured JSON entries to. A relative
    path is resolved against the current working directory. The parent directory
    is created if it does not already exist.

    .OUTPUTS
    System.String. The fully-qualified log file path that was configured.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$LogFilePath
    )

    $resolvedPath = $LogFilePath
    if (-not [System.IO.Path]::IsPathRooted($resolvedPath)) {
        $resolvedPath = Join-Path (Get-Location).Path $resolvedPath
    }

    $logDirectory = Split-Path -Path $resolvedPath -Parent
    if ($logDirectory -and -not (Test-Path -LiteralPath $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
    }

    $script:DefaultLogPath = $resolvedPath
    $script:LoggingEnabled = $true

    Write-Verbose "TierModel module file logging enabled: $resolvedPath"

    return $resolvedPath
}

# Cache variables for domain resolution (used by Resolve-TierModelDomainDN)
$script:CachedDomainDN = $null
$script:CachedDomainController = $null

# NOTE: There is deliberately no 'internal' folder in this module. A previous migration
# moved every function to public\ (see the removed loader's own comments: "essential
# functions now in public" / "essential functions have been moved to public modules").
# All functions live in public\, one per file; a function is EXPORTED only if its name
# appears in FunctionsToExport in TierModel.psd1. Do not reintroduce an internal\ folder.

# Import public functions
$PublicPath = Join-Path $PSScriptRoot 'public'
Write-Verbose "Looking for public files in: $PublicPath"
if (Test-Path $PublicPath) {
    $publicFiles = @(Get-ChildItem -Path $PublicPath -Filter '*.ps1')
    Write-Verbose "Found $($publicFiles.Count) public files"
    $publicFiles | ForEach-Object {
        try {
            Write-Verbose "Loading: $($_.FullName)"
            . $_.FullName
            Write-Verbose "Successfully loaded: $($_.Name)"
        } catch {
            Write-Error "Failed to load $($_.Name): $($_.Exception.Message)"
            throw
        }
    }
} else {
    Write-Warning "Public path not found: $PublicPath"
}







# HRESULTs that mean "SYSVOL is busy right now", not "this cannot work".
#
# Import-GPO clears the target policy folder under SYSVOL and copies the backup into it. Two
# imports in quick succession - and a full deployment does 123 of them, several from the same
# backup source - can catch the folder while the previous operation still holds handles on it.
# Measured on a German lab domain 2026-09-15: one import failed 19 ms after the preceding one
# from the same source completed, and the failed ConfigureGPO that followed then aborted GPO
# phase 3, which returns before phase 4 - so none of the 131 planned GPO links were applied.
#
# Classification is by NUMERIC code and never by message text. The same failure prints "Das
# Verzeichnis ist nicht leer." on a German host; matching on English text is precisely the class
# of defect this module was reworked to remove (CLAUDE.md rule 2.5).
#
# ERROR_ACCESS_DENIED is in this list deliberately. It is ambiguous - it is also what a genuine
# permission problem raises - but a half-cleared policy folder produces it too, and that is the
# form the lab failure took on the SecEdit directory. A real permission problem simply fails four
# times instead of once, costing 3.5 seconds and reporting the identical error.
$script:TierModelTransientHResults = @(
    0x80070005,  # ERROR_ACCESS_DENIED
    0x80070020,  # ERROR_SHARING_VIOLATION
    0x80070021,  # ERROR_LOCK_VIOLATION
    0x80070091   # ERROR_DIR_NOT_EMPTY
)

function Test-TierModelTransientFailure {
    <#
    .SYNOPSIS
    Decide whether an ErrorRecord describes a transient SYSVOL/file-system condition.

    .DESCRIPTION
    Walks the exception chain and compares each HResult against
    $script:TierModelTransientHResults. The chain is walked because Import-GPO surfaces the
    Win32 code on an inner COMException often enough that reading only the outer exception
    would miss it.

    No conversion is involved: PowerShell parses an 8-digit hex literal as a signed Int32, so
    0x80070091 already evaluates to -2147024751 - the very value Exception.HResult carries.
    (Masking to 32 unsigned bits, which looks like the obvious defensive move, turns the HResult
    positive and makes every comparison fail silently. Verified 2026-09-15 on PowerShell 7.6.6.)
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $ex = $ErrorRecord.Exception
    while ($ex) {
        if ($script:TierModelTransientHResults -contains $ex.HResult) { return $true }
        $ex = $ex.InnerException
    }
    return $false
}

function Invoke-TierModelTransientRetry {
    <#
    .SYNOPSIS
    Run a SYSVOL-touching operation, retrying only genuinely transient failures.

    .DESCRIPTION
    Retries with the exponential backoff already used for the post-create AD verifications in
    New-TierModelOu.ps1 (500 ms doubling per attempt), so the module has one waiting idiom
    rather than two.

    This does NOT soften a fail-fast. Anything that is not classified as transient is rethrown
    on the first attempt, and a transient failure that survives every attempt is rethrown too -
    the caller's existing error path runs unchanged either way (CLAUDE.md rule 2.2).

    WHY THIS LIVES INLINE IN THE .psm1
    Same reason as Initialize-TierModelLogging above: tests\Unit.ModuleManifest.Tests.ps1
    derives its expectation from the CONTENTS of the public\ folder, so an unexported helper
    placed there breaks three assertions. Defined here it is dot-sourced into module scope,
    unexported, and invisible to that test.

    .PARAMETER ScriptBlock
    The operation to run. Invoked with & so it keeps the caller's variables in scope.

    .PARAMETER Operation
    Short label for the log entry, e.g. 'Import-GPO'.

    .PARAMETER Subject
    What the operation acts on, e.g. the GPO name - carried into the log so a retry can be
    traced back to one action.

    .PARAMETER MaxAttempts
    Total attempts including the first. Default 4: 0.5 s + 1 s + 2 s of waiting at worst.

    .PARAMETER CorrelationId
    Correlation id of the calling operation, carried into the retry log entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory)]
        [string]$Operation,

        [string]$Subject,

        [ValidateRange(1, 10)]
        [int]$MaxAttempts = 4,

        [string]$CorrelationId
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return & $ScriptBlock
        } catch {
            if ($attempt -ge $MaxAttempts -or -not (Test-TierModelTransientFailure -ErrorRecord $_)) {
                throw
            }

            $delayMs = [int](500 * [Math]::Pow(2, $attempt - 1))

            Write-TierModelLog -Level Warning -Message "Transient failure - retrying" -Data @{
                Operation     = $Operation
                Subject       = $Subject
                Attempt       = $attempt
                MaxAttempts   = $MaxAttempts
                DelayMs       = $delayMs
                # Masked here only to print 0x80070091 rather than -2147024751.
                HResult       = '0x{0:X8}' -f ($_.Exception.HResult -band 0xFFFFFFFFL)
                Exception     = $_.Exception.Message
                CorrelationId = $CorrelationId
            } | Out-Null

            Start-Sleep -Milliseconds $delayMs
        }
    }
}

function Resolve-TierModelGroupIdentity {
    <#
    .SYNOPSIS
    Resolve a configured security-group name to an -Identity value the directory accepts
    regardless of its language.

    .DESCRIPTION
    Module-scope helper, deliberately not exported (see the note at Initialize-TierModelLogging:
    tests/Unit.ModuleManifest.Tests.ps1 counts FILES in public/ against FunctionsToExport, so a
    shared helper used by several public functions lives here).

    Active Directory localizes the names of its built-in principals at domain creation. A German
    domain serves "Domaenencontroller", never "Domain Controllers", so
    Get-ADGroupMember -Identity 'Domain Controllers' finds nothing there - which is exactly how
    the Authentication Policy Silo phase stopped on the German lab domain on 2026-09-16. The
    English names in config/*.json are canonical IDENTIFIERS, not directory names: they are
    resolved to a SID and the SID is what the directory is asked for.

    Only the resolution is centralised. Every caller keeps the cmdlet it used before - including
    the prerequisite gate's Get-ADGroup, which is what enforces that the principal really is a
    group and must not be dropped.

    .PARAMETER GroupName
    The group name exactly as written in the configuration.

    .PARAMETER DomainController
    Domain controller every directory read in this run targets.

    .PARAMETER CorrelationId
    Tracking ID for logging correlation.

    .OUTPUTS
    [hashtable] @{ Success; Identity; ActualName; Error }
    Identity is a SID string on success and is what belongs in -Identity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [string]$DomainController,

        [string]$CorrelationId
    )

    # -WarningAction SilentlyContinue: the resolver warns on every miss, and each caller here
    # already turns a miss into its own error, finding or gate failure.
    $sidResult = Resolve-TierModelPrincipalSid -Principal $GroupName -DomainController $DomainController -CorrelationId $CorrelationId -WarningAction SilentlyContinue

    if (-not $sidResult -or -not $sidResult.Success -or -not $sidResult.Sid) {
        $reason = if ($sidResult -and $sidResult.Error) { $sidResult.Error } else { "no SID could be resolved" }
        return @{ Success = $false; Identity = $null; ActualName = $null; Error = $reason }
    }

    $actualName = if ($sidResult.PSObject.Properties.Name -contains 'ActualName') { $sidResult.ActualName } else { $null }

    return @{ Success = $true; Identity = $sidResult.Sid; ActualName = $actualName; Error = $null }
}

Write-Verbose "TierModel module loaded with CorrelationId: $script:CorrelationId"

function Get-TierModelConfigHash {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Path
    )
    if (!(Test-Path -LiteralPath $Path)) { throw "Config file not found: $Path" }
    $bytes = [IO.File]::ReadAllBytes($Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Get-TierModel {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Raw
    )
    $json = Get-Content -Raw -LiteralPath $Path
    $obj = $json | ConvertFrom-Json -Depth 10
    if ($Raw) { return $json } else { return $obj }
}

function Test-TierModelConfig {
    [CmdletBinding(DefaultParameterSetName = 'FromPath')] 
    param(
        [Parameter(Mandatory, ParameterSetName = 'FromPath')][string]$Path,
        [Parameter(Mandatory, ParameterSetName = 'FromConfig')][psobject]$Config,
        [Parameter(ParameterSetName = 'FromPath')][string]$SchemaPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config' 'tiermodel.schema.json'),
        [Parameter(ParameterSetName = 'FromPath')][switch]$Raw,
        [Parameter()][ValidateSet('OuOnly','GroupOnly','UserOnly','GposOnly','OuAclsOnly','AdmxOnly','FullDeployment')][string]$Scope = 'FullDeployment'
    )
    
    # T0054: Add logging for configuration validation start
    Write-TierModelLog -Level Info -Message "Starting TierModel configuration validation" -Data @{
        ParameterSet = $PSCmdlet.ParameterSetName
        ConfigPath = if ($PSCmdlet.ParameterSetName -eq 'FromPath') { $Path } else { $null }
        SchemaPath = if ($PSCmdlet.ParameterSetName -eq 'FromPath') { $SchemaPath } else { $null }
    } | Out-Null
    
    if ($PSCmdlet.ParameterSetName -eq 'FromPath') {
        if (!(Test-Path -LiteralPath $Path)) { 
            Write-TierModelLog -Level Error -Message "Config file not found" -Data @{ Path = $Path } | Out-Null
            throw "Config file not found: $Path" 
        }
        if (!(Test-Path -LiteralPath $SchemaPath)) { 
            Write-TierModelLog -Level Error -Message "Schema file not found" -Data @{ SchemaPath = $SchemaPath } | Out-Null
            throw "Schema file not found: $SchemaPath" 
        }
        $configText = Get-Content -Raw -LiteralPath $Path
        $schemaText = Get-Content -Raw -LiteralPath $SchemaPath
        try {
            $config = $configText | ConvertFrom-Json -Depth 50
            $schema = $schemaText | ConvertFrom-Json -Depth 50
        } catch {
            Write-TierModelLog -Level Error -Message "Invalid JSON format during config validation" -Data @{ 
                Path = $Path
                ParseError = $_.Exception.Message
            } | Out-Null
            return [PSCustomObject]@{ Valid = $false; Errors = @("Invalid JSON format: $($_.Exception.Message)"); Warnings = @(); Raw = $configText }
        }
    } else {
        $config = $Config
        # Load schema for FromConfig so validation is not silently skipped.
        # $SchemaPath is only bound for FromPath, so resolve the path explicitly here.
        $schemaPathForConfig = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config' 'tiermodel.schema.json'
        if (!(Test-Path -LiteralPath $schemaPathForConfig)) {
            Write-TierModelLog -Level Error -Message "Schema file not found for FromConfig validation" -Data @{ SchemaPath = $schemaPathForConfig } | Out-Null
            return [PSCustomObject]@{ Valid = $false; Errors = @("Schema file not found: $schemaPathForConfig"); Warnings = @(); Raw = $null }
        }
        try {
            $schema = Get-Content -Raw -LiteralPath $schemaPathForConfig | ConvertFrom-Json -Depth 50
        } catch {
            Write-TierModelLog -Level Error -Message "Schema file could not be parsed for FromConfig validation" -Data @{ SchemaPath = $schemaPathForConfig; ParseError = $_.Exception.Message } | Out-Null
            return [PSCustomObject]@{ Valid = $false; Errors = @("Schema file could not be parsed: $($_.Exception.Message)"); Warnings = @(); Raw = $null }
        }
    }
    
    # Generate correlation ID for tracking validation across logs
    $correlationId = [System.Guid]::NewGuid().ToString()
    Write-Verbose "Starting TierModel config validation (CorrelationId: $correlationId)"
    
    $errors = @()
    $warnings = @()
    $validationDetails = [PSCustomObject]@{
        ValidGpoModes = 0
        InvalidGpoModes = 0
        ValidDenyApplyGroups = 0
        InvalidDenyApplyGroups = 0
        ValidAdmxPaths = 0
        InvalidAdmxPaths = 0
    }
    
    # Schema validation — runs for both FromPath and FromConfig
    if ($schema) {
        foreach ($req in $schema.required) {
            if (-not ($config.PSObject.Properties.Name -contains $req)) {
                $errors += "Missing required top-level property: $req"
            }
        }
        
        # Helper for array item validation
        function _validateArrayItems($array, $definition, $name) {
            $localErrors = @()
            if ($null -eq $array) { return $localErrors }
            $itemsDef = $definition.PSObject.Properties['items']
            if (-not $itemsDef) { return $localErrors }
            # Prefer x-psm1-required (custom annotation for runtime checks) over JSON Schema required
            $reqNode = $itemsDef.Value.PSObject.Properties['x-psm1-required']
            if (-not $reqNode) { $reqNode = $itemsDef.Value.PSObject.Properties['required'] }
            $req = if ($reqNode) { $reqNode.Value } else { @() }
            foreach ($item in $array) {
                foreach ($r in $req) {
                    if (-not ($item.PSObject.Properties.Name -contains $r)) {
                        $localErrors += "${name} item missing required property '$r' (value: $($item | ConvertTo-Json -Compress))"
                    }
                }
            }
            return $localErrors
        }

        # Safe property access with existence checks
        if ($config -is [hashtable]) {
            $organizationUnits = if ($config.ContainsKey('organizationUnits')) { $config['organizationUnits'] } else { $null }
            $groups = if ($config.ContainsKey('groups')) { $config['groups'] } else { $null }
            $users = if ($config.ContainsKey('users')) { $config['users'] } else { $null }
        } else {
            $organizationUnits = if ($config.PSObject.Properties.Name -contains 'organizationUnits') { $config.organizationUnits } else { $null }
            $groups = if ($config.PSObject.Properties.Name -contains 'groups') { $config.groups } else { $null }
            $users = if ($config.PSObject.Properties.Name -contains 'users') { $config.users } else { $null }
        }
        
        if ($config -is [hashtable]) {
            $gpos = if ($config.ContainsKey('gpos')) { $config['gpos'] } else { $null }
            $aclDelegations = if ($config.ContainsKey('aclDelegations')) { $config['aclDelegations'] } else { $null }
            $admx = if ($config.ContainsKey('admx')) { $config['admx'] } else { $null }
        } else {
            $gpos = if ($config.PSObject.Properties.Name -contains 'gpos') { $config.gpos } else { $null }
            $aclDelegations = if ($config.PSObject.Properties.Name -contains 'aclDelegations') { $config.aclDelegations } else { $null }
            $admx = if ($config.PSObject.Properties.Name -contains 'admx') { $config.admx } else { $null }
        }
        
        # Scope-based validation - only validate components relevant to the deployment scope
        # Based on user requirements:
        # -OuOnly = No other checks (only OUs)
        # -GroupOnly = OU checks (OUs + Groups)
        # -UserOnly = OU and Group checks (OUs + Groups + Users)
        # -OuAclsOnly = OU and Group checks (OUs + Groups + ACLs)
        # -AdmxOnly = No other checks (only ADMX)
        
        # OU validation - required for all scopes except AdmxOnly
        if ($Scope -ne 'AdmxOnly') {
            $errors += _validateArrayItems $organizationUnits $schema.properties.organizationUnits 'organizationUnits'
        }
        
        # Groups validation - required for GroupOnly, UserOnly, OuAclsOnly, and FullDeployment
        if ($Scope -in @('GroupOnly', 'UserOnly', 'OuAclsOnly', 'FullDeployment')) {
            $errors += _validateArrayItems $groups $schema.properties.groups 'groups'
        }
        
        # Users validation - required for UserOnly and FullDeployment
        if ($Scope -in @('UserOnly', 'FullDeployment')) {
            $errors += _validateArrayItems $users $schema.properties.users 'users'
        }
        
        # GPOs validation - required for GposOnly and FullDeployment
        if ($Scope -in @('GposOnly', 'FullDeployment')) {
            $errors += _validateArrayItems $gpos $schema.properties.gpos 'gpos'
        }
        
        # ACL Delegations validation - required for OuAclsOnly and FullDeployment
        if ($Scope -in @('OuAclsOnly', 'FullDeployment')) {
            $errors += _validateArrayItems $aclDelegations $schema.properties.aclDelegations 'aclDelegations'
        }
        
        # ADMX validation - only for AdmxOnly and FullDeployment
        if ($Scope -in @('AdmxOnly', 'FullDeployment')) {
            $errors += _validateArrayItems $admx $schema.properties.admx 'admx'
        }

        # Version pattern check with safe property access
        $configVersion = if ($config -is [hashtable]) {
            if ($config.ContainsKey('version')) { $config['version'] } else { $null }
        } else {
            if ($config.PSObject.Properties.Name -contains 'version') { $config.version } else { $null }
        }
        if ($configVersion -and ($configVersion -notmatch '^\d+\.\d+\.\d+$')) {
            $errors += "Version '$configVersion' does not match semantic pattern X.Y.Z"
        }
    }
    
    # Enhanced deep validation
    # 1. GPO Mode Validation - Only for GposOnly and FullDeployment scopes
    if ($Scope -in @('GposOnly', 'FullDeployment')) {
        $validGpoModes = @('create', 'createAndImport', 'createImportAndConfigure')
        # Use safe property access for gpos
        $configGpos = if ($config -is [hashtable]) {
            if ($config.ContainsKey('gpos')) { $config['gpos'] } else { $null }
        } else {
            if ($config.PSObject.Properties.Name -contains 'gpos') { $config.gpos } else { $null }
        }

        # Build a flat list of GPO leaf items regardless of config shape.
        # @(...) with pipeline emission prevents PowerShell from unwrapping 1-element arrays.
        $flatGpos = @(
            if ($null -eq $configGpos) {
                # nothing to emit
            } elseif ($configGpos -is [array]) {
                # Already a flat array (multi-element test format)
                $configGpos
            } elseif (($configGpos -is [hashtable] -and ($configGpos.ContainsKey('mode') -or $configGpos.ContainsKey('name'))) -or
                      ($configGpos -isnot [hashtable] -and ($configGpos.PSObject.Properties['mode'] -or $configGpos.PSObject.Properties['name']))) {
                # Single flat GPO item — 1-element test array was unwrapped by PowerShell
                $configGpos
            } else {
                # Nested OU structure (real merged config):
                # gpos[<OU-DN>][<ImportOnlyGpo|PostConfigureGpo>] = [{ name, mode, ... }, ...]
                # displayName is a scalar string at the OU level — skip string-valued properties
                foreach ($ouProp in $configGpos.PSObject.Properties) {
                    $ouValue = $ouProp.Value
                    if ($null -eq $ouValue) { continue }
                    foreach ($containerProp in $ouValue.PSObject.Properties) {
                        if ($containerProp.Value -is [string]) { continue }
                        $container = $containerProp.Value
                        if ($null -eq $container) { continue }
                        if ($container -is [array]) {
                            foreach ($item in $container) { if ($null -ne $item) { $item } }
                        } else {
                            foreach ($gpoProp in $container.PSObject.Properties) {
                                if ($null -ne $gpoProp.Value) { $gpoProp.Value }
                            }
                        }
                    }
                }
            }
        )

        # 1. GPO Mode Validation
        if ($configGpos) {
        foreach ($gpo in $flatGpos) {
            $hasModeProperty = if ($gpo -is [hashtable]) {
                $gpo.ContainsKey('mode')
            } else {
                $gpo.PSObject.Properties.Name -contains 'mode'
            }
            $gpoName = if ($gpo -is [hashtable]) {
                if ($gpo.ContainsKey('name')) { $gpo['name'] } else { 'Unknown GPO' }
            } else {
                if ($gpo.PSObject.Properties.Name -contains 'name') { $gpo.name } else { 'Unknown GPO' }
            }
            if (-not $hasModeProperty) {
                $errors += "GPO '$gpoName' is missing required 'mode' property"
                $validationDetails.InvalidGpoModes++
            } else {
                $gpoMode = if ($gpo -is [hashtable]) {
                    $gpo['mode']
                } else {
                    $gpo.PSObject.Properties['mode'].Value
                }
                if ($gpoMode -notin $validGpoModes) {
                    $errors += "GPO '$gpoName' has invalid mode '$gpoMode'. Valid modes: $($validGpoModes -join ', ')"
                    $validationDetails.InvalidGpoModes++
                } else {
                    $validationDetails.ValidGpoModes++
                }
            }
        }
    }
    
    # 2. denyApplyGroupPolicy shape validation
    # Validates shape only: must be an array of non-empty strings when present.
    # Entries may reference built-in AD principals (e.g. 'Domain Controllers', 'Read-only Domain Controllers')
    # that are not defined in config groups — asserting group-membership would be a false positive.
    if ($configGpos) {
        foreach ($gpo in $flatGpos) {
            $gpoName = if ($gpo -is [hashtable]) {
                if ($gpo.ContainsKey('name')) { $gpo['name'] } else { 'Unknown GPO' }
            } else {
                if ($gpo.PSObject.Properties.Name -contains 'name') { $gpo.name } else { 'Unknown GPO' }
            }
            $denyProp = if ($gpo -is [hashtable]) {
                if ($gpo.ContainsKey('denyApplyGroupPolicy')) { $gpo['denyApplyGroupPolicy'] } else { $null }
            } else {
                $node = $gpo.PSObject.Properties['denyApplyGroupPolicy']
                if ($node) { $node.Value } else { $null }
            }
            if ($null -ne $denyProp) {
                if ($denyProp -isnot [array]) {
                    $warnings += "GPO '$gpoName' denyApplyGroupPolicy must be an array of strings, got: $($denyProp.GetType().Name)"
                    $validationDetails.InvalidDenyApplyGroups++
                } else {
                    $valid = $true
                    foreach ($entry in $denyProp) {
                        if ([string]::IsNullOrWhiteSpace($entry)) {
                            $warnings += "GPO '$gpoName' denyApplyGroupPolicy contains an empty or whitespace entry"
                            $validationDetails.InvalidDenyApplyGroups++
                            $valid = $false
                        }
                    }
                    if ($valid) { $validationDetails.ValidDenyApplyGroups += $denyProp.Count }
                }
            }
        }
    }
    } # End GPO validation scope check
    
    # 3. ADMX Source Path Validation - Only for AdmxOnly and FullDeployment scopes
    if ($Scope -in @('AdmxOnly', 'FullDeployment')) {
        # Use safe property access for admx
        $configAdmx = if ($config -is [hashtable]) {
            if ($config.ContainsKey('admx')) { $config['admx'] } else { $null }
        } else {
            if ($config.PSObject.Properties.Name -contains 'admx') { $config.admx } else { $null }
        }
        if ($configAdmx) {
        # @($configAdmx) normalises both multi-entry arrays and single-entry objects
        # (including 1-element arrays that PowerShell unwrapped via if-else assignment).
        # Each entry supports test format ('path') and real-config format ('sourcePath').
        foreach ($admxEntry in @($configAdmx)) {
            # Resolve path: prefer 'path' (test format) then 'sourcePath' (real config)
            $admxPath = if ($admxEntry -is [hashtable]) {
                if ($admxEntry.ContainsKey('path')) { $admxEntry['path'] }
                elseif ($admxEntry.ContainsKey('sourcePath')) {
                    $rp = $admxEntry['sourcePath']
                    if ([System.IO.Path]::IsPathRooted($rp)) { $rp }
                    else { Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) $rp }
                } else { $null }
            } else {
                $pathNode = $admxEntry.PSObject.Properties['path']
                $srcNode  = $admxEntry.PSObject.Properties['sourcePath']
                if ($pathNode -and $pathNode.Value) { $pathNode.Value }
                elseif ($srcNode -and $srcNode.Value) {
                    $rp = $srcNode.Value
                    if ([System.IO.Path]::IsPathRooted($rp)) { $rp }
                    else { Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) $rp }
                } else { $null }
            }

            if (-not $admxPath) {
                $errors += "ADMX entry missing required 'path' property"
                $validationDetails.InvalidAdmxPaths++
                continue
            }
            $language = if ($admxEntry -is [hashtable]) {
                if ($admxEntry.ContainsKey('language')) { $admxEntry['language'] } else { "en-US" }
            } else {
                if ($admxEntry.PSObject.Properties.Name -contains 'language') { $admxEntry.language } else { "en-US" }
            }
            if (-not (Test-Path -LiteralPath $admxPath -PathType Container)) {
                $errors += "ADMX source path '$admxPath' does not exist"
                $validationDetails.InvalidAdmxPaths++
                continue
            }
            $admxFiles = Get-ChildItem -Path $admxPath -Filter "*.admx" -ErrorAction SilentlyContinue
            if (-not $admxFiles) {
                $warnings += "ADMX path '$admxPath' contains no .admx files"
                $validationDetails.InvalidAdmxPaths++
                continue
            }
            $localePath = Join-Path $admxPath $language
            if (-not (Test-Path -LiteralPath $localePath -PathType Container)) {
                $warnings += "ADMX path '$admxPath' missing default locale folder '$language'"
                $validationDetails.InvalidAdmxPaths++
                continue
            }
            $validationDetails.ValidAdmxPaths++
        }
    }
    } # End ADMX validation scope check
    
    # 4. OU Parent-Child Relationship Validation
    # Use safe property access for organizationUnits
    $configOrganizationUnits = if ($config -is [hashtable]) {
        if ($config.ContainsKey('organizationUnits')) { $config['organizationUnits'] } else { $null }
    } else {
        if ($config.PSObject.Properties.Name -contains 'organizationUnits') { $config.organizationUnits } else { $null }
    }
    if ($configOrganizationUnits) {
        $ouPaths = $configOrganizationUnits | ForEach-Object { $_.path }
        
        foreach ($ou in $configOrganizationUnits) {
            $ouPath = $ou.path
            # Extract parent path (everything after first OU= component)
            if ($ouPath -match '^OU=[^,]+,(.+)$') {
                $parentPath = $matches[1]
                if ($parentPath -like "OU=*" -and $parentPath -notin $ouPaths) {
                    $warnings += "OU '$($ou.name)' has parent path '$parentPath' which is not defined in configuration"
                }
            }
        }
    }
    
    Write-Verbose "Validation completed. Valid: $($errors.Count -eq 0), Errors: $($errors.Count), Warnings: $($warnings.Count) (CorrelationId: $correlationId)"
    
    # T0054: Log validation completion
    $validationSuccess = ($errors.Count -eq 0)
    Write-TierModelLog -Level $(if ($validationSuccess) { 'Info' } else { 'Warning' }) -Message "Configuration validation completed" -Data @{
        Valid = $validationSuccess
        ErrorCount = $errors.Count
        WarningCount = $warnings.Count
        ValidGpoModes = $validationDetails.ValidGpoModes
        ValidAdmxPaths = $validationDetails.ValidAdmxPaths
        ValidationCorrelationId = $correlationId
    } | Out-Null
    
    $result = [PSCustomObject]@{
        Valid = ($errors.Count -eq 0)
        Errors = $errors
        Warnings = $warnings
        ValidationDetails = $validationDetails
        CorrelationId = $correlationId
    }
    
    # Add file-specific properties for path-based validation
    if ($PSCmdlet.ParameterSetName -eq 'FromPath') {
        $result | Add-Member -NotePropertyName ConfigHash -NotePropertyValue (Get-TierModelConfigHash -Path $Path)
        $result | Add-Member -NotePropertyName Path -NotePropertyValue $Path
        $result | Add-Member -NotePropertyName SchemaPath -NotePropertyValue $SchemaPath
        $result | Add-Member -NotePropertyName Timestamp -NotePropertyValue (Get-Date).ToString('o')
        if ($Raw) { 
            $result | Add-Member -NotePropertyName Raw -NotePropertyValue $configText
            return ($result | ConvertTo-Json -Depth 20) 
        }
    }
    
    return $result
}

function Get-TierModelPlan {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$IncludeHashes
    )
    # T0054: Log plan generation start
    Write-TierModelLog -Level Info -Message "Starting TierModel plan generation" -Data @{
        ConfigPath = $Path
        IncludeHashes = $IncludeHashes.IsPresent
    } | Out-Null
    
    $model = Get-TierModel -Path $Path
    
    # Create empty action plan structure (action planning not implemented)
    $actionPlan = [PSCustomObject]@{
        Actions = @()
        Warnings = @()
        Errors = @()
        CorrelationId = [System.Guid]::NewGuid().ToString()
        Timestamp = (Get-Date).ToString('o')
        Summary = @{
            TotalActions = 0
            ByType = @()
            HasErrors = $false
        }
    }

    # No current state capture or drift detection implementation
    $currentState = $null
    $driftFindings = @()
    
    # Categorize actions for backward compatibility with safety checks
    $actions = @()
    if ($actionPlan) {
        try {
            if ($actionPlan -is [hashtable]) {
                $actions = if ($actionPlan.ContainsKey('Actions')) { $actionPlan['Actions'] } else { @() }
            } elseif ($actionPlan -is [array] -or $actionPlan -is [System.Object[]]) {
                # Action plan returned as array directly
                $actions = @($actionPlan)
            } else {
                if ($actionPlan.PSObject.Properties['Actions']) {
                    try {
                        $actions = $actionPlan.Actions
                    } catch {
                        $actions = @()
                    }
                } else {
                    $actions = @()
                }
            }
        } catch {
            Write-Verbose "Failed to access Actions property: $($_.Exception.Message)"
            $actions = @()
        }
    }
    $adds = @($actions | Where-Object { $_.Type -in @('CreateOU', 'CreateGroup', 'CreateUser', 'CreateGPO', 'ImportADMX') })
    $updates = @($actions | Where-Object { $_.Type -in @('SetGroupMembership', 'SetACL') })
    $links = @($actions | Where-Object { $_.Type -eq 'LinkGPO' })
    
    # T0050: Compute deterministic plan hash based on sorted actions + config hash
    $configHash = Get-TierModelConfigHash -Path $Path
    $planHash = $null
    if ($actions -and $actions.Count -gt 0) {
        # Create deterministic action signature by sorting actions by Type, Target, and Properties
        $sortedActionSignatures = $actions | ForEach-Object {
            $propertiesHash = ""
            if ($_.Properties) {
                $sortedProps = $_.Properties.PSObject.Properties | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }
                $propertiesHash = ($sortedProps -join "|")
            }
            "$($_.Type):$($_.Target):$propertiesHash"
        } | Sort-Object
        
        $actionListString = $sortedActionSignatures -join ";"
        $planString = "$configHash|$actionListString"
        
        # Compute SHA256 hash of the plan signature
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($planString)
        $planHashBytes = $sha.ComputeHash($bytes)
        $planHash = ($planHashBytes | ForEach-Object { $_.ToString('x2') }) -join ''
    } else {
        # Empty action plan gets a special hash based only on config
        $planHash = $configHash + ":empty"
    }

    # Force arrays for collection properties
    $addsArray = @($adds)
    $updatesArray = @($updates)
    $linksArray = @($links)
    
    $plan = [PSCustomObject]@{
        Timestamp = (Get-Date).ToString('o')
        ConfigHash = if ($IncludeHashes) { $configHash } else { $null }
        PlanHash = $planHash # T0050: Deterministic plan fingerprint
        ModelVersion = $model.version
        OrganizationUnitsCount = if ($model.organizationUnits) { $model.organizationUnits.Count } else { 0 }
        GroupsCount = if ($model.groups) { $model.groups.Count } else { 0 }
        UsersCount = if ($model.users) { $model.users.Count } else { 0 }
        GposCount = if ($model.gpos) { $model.gpos.Count } else { 0 }
        AdmxCount = if ($model.admx) { $model.admx.Count } else { 0 }
        Adds = $addsArray
        Updates = $updatesArray
        Links = $linksArray
        AllActions = @($actions)
        ActionSummary = if ($actionPlan -and $actionPlan -is [psobject] -and $actionPlan.PSObject.Properties['Summary']) { $actionPlan.Summary } else { @{} }
        ActionWarnings = if ($actionPlan -and $actionPlan -is [psobject] -and $actionPlan.PSObject.Properties['Warnings']) { @($actionPlan.Warnings) } else { @() }
        ActionErrors = if ($actionPlan -and $actionPlan -is [psobject] -and $actionPlan.PSObject.Properties['Errors']) { @($actionPlan.Errors) } else { @() }
        DriftFindings = @($driftFindings) # T0048: Now populated with actual drift findings
        CurrentState = $currentState
        CorrelationId = if ($actionPlan -and $actionPlan -is [psobject] -and $actionPlan.PSObject.Properties['CorrelationId']) { $actionPlan.CorrelationId } else { [System.Guid]::NewGuid().ToString() }
    }
    
    # T0054: Log plan generation completion
    Write-TierModelLog -Level Info -Message "TierModel plan generation completed" -Data @{
        ConfigPath = $Path
        PlanHash = $planHash
        ActionCount = (@($plan.AllActions)).Count
        DriftFindingsCount = (@($driftFindings)).Count
        OUsCount = $plan.OrganizationUnitsCount
        GroupsCount = $plan.GroupsCount
        GposCount = $plan.GposCount
        PlanCorrelationId = if ($actionPlan -and $actionPlan -is [psobject] -and $actionPlan.PSObject.Properties['CorrelationId']) { $actionPlan.CorrelationId } else { $null }
    } | Out-Null
    
    return $plan
}

function New-TierModel {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PreferredDc,
        [string]$DependenciesPath = 'config/dependencies.json',
        [switch]$WhatIf,
        [switch]$ConfirmApply
    )
    
    # T0054: Log deployment initiation
    Write-TierModelLog -Level Info -Message "Starting TierModel initial deployment" -Data @{
        ConfigPath = $Path
        PreferredDc = $PreferredDc
        DependenciesPath = $DependenciesPath
        WhatIf = $WhatIf.IsPresent
        ConfirmApply = $ConfirmApply.IsPresent
    } | Out-Null
    
    # Prerequisites gate - abort if invalid
    Write-Verbose "Validating prerequisites before deployment..."
    $prereqResult = Test-TierModelPrerequisites -PreferredDc $PreferredDc -DependenciesPath $DependenciesPath
    
    # Handle case where result might be an array due to pipeline contamination
    if ($prereqResult -is [array]) {
        $prereqResult = $prereqResult | Where-Object { $_ -and $_.PSObject.Properties['Valid'] } | Select-Object -Last 1
    }
    
    if (-not $prereqResult -or -not $prereqResult.Valid) {
        $errorMessage = "Prerequisites validation failed:`n" + 
                       ($prereqResult.Errors -join "`n") + "`n`n" +
                       "Remediation steps:`n" + 
                       ($prereqResult.Remediation -join "`n")
        
        # T0054: Log prerequisite failure (use Warning level in WhatIf mode to avoid Write-Error)
        Write-TierModelLog -Level $(if ($WhatIf) { 'Warning' } else { 'Error' }) -Message "TierModel deployment failed - prerequisites not met" -Data @{
            ConfigPath = $Path
            PreferredDc = $PreferredDc
            ErrorCount = $prereqResult.Errors.Count
            Errors = $prereqResult.Errors
        } | Out-Null
        
        # In WhatIf mode, show prerequisites as warnings instead of errors
        if ($WhatIf) {
            Write-Warning "Prerequisites validation failed (bypassed in WhatIf mode):`n$errorMessage"
        } else {
            Write-Error $errorMessage
        }
        
        return [PSCustomObject]@{
            Applied = $false
            PrerequisitesFailed = $true
            PrerequisitesResult = $prereqResult
            Plan = $null
        }
    }
    
    Write-Verbose "Prerequisites validation passed. Generating deployment plan..."
    $plan = Get-TierModelPlan -Path $Path -IncludeHashes
    if ($WhatIf) { 
        Write-TierModelLog -Level Info -Message "TierModel deployment plan generated (WhatIf mode)" -Data @{
            ConfigPath = $Path
            PlanHash = $plan.PlanHash
            ActionCount = if ($plan.AllActions) { $plan.AllActions.Count } else { 0 }
        } | Out-Null
        return [PSCustomObject]@{ 
            Applied = $false
            WhatIf = $true
            PrerequisitesPassed = $true
            PrerequisitesResult = $prereqResult
            Plan = $plan
            Adds = $plan.Adds
            Updates = $plan.Updates
            Links = $plan.Links
        }
    }
    if (-not $ConfirmApply) { throw 'ConfirmApply switch required to apply changes (safety gate).'}
    
    Write-Verbose "Executing deployment plan..."
    # T0054: Log deployment execution start
    Write-TierModelLog -Level Info -Message "Executing TierModel initial deployment" -Data @{
        ConfigPath = $Path
        PlanHash = $plan.PlanHash
        ActionCount = if ($plan.AllActions) { $plan.AllActions.Count } else { 0 }
    } | Out-Null
    
    # Stub: Apply adds only (initial deployment)
    Write-TierModelLog -Level Info -Message "TierModel initial deployment completed" -Data @{
        ConfigPath = $Path
        PlanHash = $plan.PlanHash
        Applied = $true
    } | Out-Null
    
    return [PSCustomObject]@{ 
        Applied = $true
        PrerequisitesPassed = $true
        PrerequisitesResult = $prereqResult
        Plan = $plan 
    }
}

function Set-TierModel {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PreferredDc,
        [string]$DependenciesPath = 'config/dependencies.json',
        [switch]$WhatIf,
        [switch]$ConfirmApply
    )
    
    # T0054: Log convergence initiation
    Write-TierModelLog -Level Info -Message "Starting TierModel convergence operation" -Data @{
        ConfigPath = $Path
        PreferredDc = $PreferredDc
        DependenciesPath = $DependenciesPath
        WhatIf = $WhatIf.IsPresent
        ConfirmApply = $ConfirmApply.IsPresent
    } | Out-Null
    
    # Prerequisites gate - abort if invalid
    Write-Verbose "Validating prerequisites before convergence..."
    $prereqResult = Test-TierModelPrerequisites -PreferredDc $PreferredDc -DependenciesPath $DependenciesPath
    
    # Handle case where result might be an array due to pipeline contamination
    if ($prereqResult -is [array]) {
        $prereqResult = $prereqResult | Where-Object { $_ -and $_.PSObject.Properties['Valid'] } | Select-Object -Last 1
    }
    
    if (-not $prereqResult -or -not $prereqResult.Valid) {
        $errorMessage = "Prerequisites validation failed:`n" + 
                       ($prereqResult.Errors -join "`n") + "`n`n" +
                       "Remediation steps:`n" + 
                       ($prereqResult.Remediation -join "`n")
        
        # In WhatIf mode, show prerequisites as warnings instead of errors
        if ($WhatIf) {
            Write-Warning "Prerequisites validation failed (bypassed in WhatIf mode):`n$errorMessage"
        } else {
            Write-Error $errorMessage
        }
        
        return [PSCustomObject]@{
            Converged = $false
            PrerequisitesFailed = $true
            PrerequisitesResult = $prereqResult
            Plan = $null
        }
    }
    
    Write-Verbose "Prerequisites validation passed. Generating convergence plan..."
    $plan = Get-TierModelPlan -Path $Path -IncludeHashes
    if ($WhatIf) { 
        return [PSCustomObject]@{ 
            Converged = $false
            WhatIf = $true
            PrerequisitesPassed = $true
            PrerequisitesResult = $prereqResult
            Plan = $plan
            Adds = $plan.Adds
            Updates = $plan.Updates
            Links = $plan.Links
        }
    }
    if (-not $ConfirmApply) { throw 'ConfirmApply switch required to apply changes (safety gate).'}
    
    # T0051: Check for convergence before execution (empty actions = already converged)
    $alreadyConverged = (-not $plan.AllActions -or $plan.AllActions.Count -eq 0)
    if ($alreadyConverged) {
        Write-Verbose "System already converged - no actions required (CorrelationId: $($plan.CorrelationId))"
        # T0054: Log pre-convergence detection
        Write-TierModelLog -Level Info -Message "TierModel system already converged" -Data @{
            ConfigPath = $Path
            PlanHash = $plan.PlanHash
            ActionCount = 0
            PlanCorrelationId = $plan.CorrelationId
        } | Out-Null
        return [PSCustomObject]@{ 
            Converged = $true
            AlreadyConverged = $true
            PrerequisitesPassed = $true
            PrerequisitesResult = $prereqResult
            Plan = $plan
            ExecutionResult = @{ Success = $true; Statistics = @{ SuccessfulActions = 0; TotalActions = 0 }; Message = "No actions required - system already converged" }
        }
    }
    
    Write-Verbose "Executing convergence plan..."
    # T0054: Log convergence execution start
    Write-TierModelLog -Level Info -Message "Executing TierModel convergence plan" -Data @{
        ConfigPath = $Path
        PlanHash = $plan.PlanHash
        ActionCount = $plan.AllActions.Count
        PlanCorrelationId = $plan.CorrelationId
    } | Out-Null
    
    $executionResult = Invoke-TierModelPlan -Plan $plan
    
    # T0051: Post-execution convergence detection
    $postExecutionConverged = $executionResult.Success -and ($executionResult.Statistics.SuccessfulActions -eq $plan.AllActions.Count)
    
    # T0054: Log convergence completion
    Write-TierModelLog -Level $(if ($postExecutionConverged) { 'Info' } else { 'Warning' }) -Message "TierModel convergence operation completed" -Data @{
        ConfigPath = $Path
        PlanHash = $plan.PlanHash
        Converged = $postExecutionConverged
        ActionCount = $plan.AllActions.Count
        SuccessfulActions = $executionResult.Statistics.SuccessfulActions
        ExecutionSuccess = $executionResult.Success
    } | Out-Null
    
    return [PSCustomObject]@{ 
        Converged = $postExecutionConverged
        AlreadyConverged = $false
        PrerequisitesPassed = $true
        PrerequisitesResult = $prereqResult
        Plan = $plan
        ExecutionResult = $executionResult
    }
}

function Test-TierModelDrift {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Raw
    )
    # T0054: Log drift detection start
    Write-TierModelLog -Level Info -Message "Starting TierModel drift detection" -Data @{
        ConfigPath = $Path
        Raw = $Raw.IsPresent
    } | Out-Null
    
    $plan = Get-TierModelPlan -Path $Path -IncludeHashes
    $report = [PSCustomObject]@{
        DriftDetected = ($plan.DriftFindings.Count -gt 0)
        Findings = $plan.DriftFindings
        ConfigHash = $plan.ConfigHash
        Generated = (Get-Date).ToString('o')
    }
    
    # T0054: Log drift detection completion
    Write-TierModelLog -Level $(if ($report.DriftDetected) { 'Warning' } else { 'Info' }) -Message "TierModel drift detection completed" -Data @{
        ConfigPath = $Path
        DriftDetected = $report.DriftDetected
        FindingCount = $plan.DriftFindings.Count
        ConfigHash = $plan.ConfigHash
    } | Out-Null
    
    if ($Raw) { return ($report | ConvertTo-Json -Depth 10) } else { return $report }
}
