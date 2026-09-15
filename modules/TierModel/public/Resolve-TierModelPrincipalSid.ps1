# TierModel SID Resolution Module
# Handles resolution of security principals to SIDs for GPO editing

function Resolve-TierModelPrincipalSid {
    <#
    .SYNOPSIS
    Resolves security principal names to SIDs with caching
    
    .DESCRIPTION
    Converts security principal names (users, groups, well-known principals) to SIDs.
    Supports caching for performance and handles well-known SIDs directly.

    Built-in principals are resolved BY SID, never by directory name. Active Directory localizes
    the names of its built-in principals at domain creation and an administrator can rename them,
    so 'Domain Admins' is 'Domaenen-Admins' on a German domain and a name lookup finds nothing.
    The English names in config/*.json are therefore canonical identifiers: they map to a
    well-known RID, the SID is composed against the domain being deployed to, and the object is
    read back by that SID to confirm it exists. See specs/008-german-language-support/spec.md.

    Resolution order:
      1. Direct SID passthrough
      2. Administrator (RID 500) - cache-bypassing, handles the renamed built-in account
      3. Session cache
      4. Get-WellKnownSid          - absolute SIDs (BUILTIN\*, NT AUTHORITY\*), no directory read
      5. Canonical RID composition - domain- and forest-root-relative built-ins
      6. Name lookup               - Tier Model-owned groups, DnsAdmins, everything else
    
    Special handling for "Administrator" account:
    - When resolving "Administrator", first attempts to find the built-in Administrator account (RID 500)
    - This handles scenarios where the Administrator account has been renamed (e.g., to "Root")
    - Returns the actual SID even if the account name has changed
    - Protects against honeypot accounts that may have taken the "Administrator" name
    
    .PARAMETER Principal
    The security principal name to resolve (e.g., "Domain Admins", "BUILTIN\Users", "Administrator", "S-1-5-32-544")
    
    .PARAMETER DomainController
    The domain controller to use for Active Directory operations
    
    .PARAMETER UseCache
    Whether to use the SID cache for resolved principals (default: $true)
    
    .PARAMETER CorrelationId
    Tracking ID for logging correlation
    
    .EXAMPLE
    $sid = Resolve-TierModelPrincipalSid -Principal "Domain Admins"
    
    .EXAMPLE
    $sid = Resolve-TierModelPrincipalSid -Principal "BUILTIN\Administrators" -UseCache $false
    
    .EXAMPLE
    $sid = Resolve-TierModelPrincipalSid -Principal "Administrator"
    # Returns the SID for the built-in Administrator account (RID 500) even if renamed
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Principal,
        
        [Parameter(Mandatory)]
        [string]$DomainController,
        
        [bool]$UseCache = $true,
        
        [string]$CorrelationId = [System.Guid]::NewGuid().ToString()
    )
    
    begin {
        Write-Verbose "Starting SID resolution for principals (CorrelationId: $CorrelationId)"
        
        # Initialize cache if not exists
        if (-not $script:SidCache) {
            $script:SidCache = @{}
        }
    }
    
    process {
        Write-Verbose "Resolving SID for principal: '$Principal' (CorrelationId: $CorrelationId)"
        
        # Check if already a SID
        if ($Principal -match '^S-\d+-\d+') {
            Write-Verbose "Principal is already a SID: $Principal (CorrelationId: $CorrelationId)"
            return [PSCustomObject]@{
                Principal = $Principal
                Sid = $Principal
                Source = "DirectSID"
                Cached = $false
                Success = $true
                Error = $null
            }
        }
        
        # Special handling for "Administrator" account - bypass cache since it's domain-specific
        if ($Principal -ieq "Administrator") {
            try {
                # Get the domain SID from specified domain controller
                $domainSid = ConvertTo-TierModelSidString -InputSid (Get-ADDomain -Server $DomainController -ErrorAction Stop).DomainSID -Context "the domain SID of '$DomainController'"
                
                # Build the Administrator SID (RID 500)
                $adminSid = "$domainSid-500"
                
                # Look up the renamed built-in Administrator account by SID
                $adminUser = Get-ADUser -Identity $adminSid -Server $DomainController -ErrorAction Stop
                
                Write-Verbose "Found built-in Administrator account (RID 500) with current name: '$($adminUser.SamAccountName)' (CorrelationId: $CorrelationId)"
                
                return @{
                    Principal = $Principal
                    Sid = ConvertTo-TierModelSidString -InputSid $adminUser.SID -Context "built-in Administrator account (RID 500)"
                    Source = "ADUser-RID500"
                    Success = $true
                    Error = $null
                    ActualName = $adminUser.SamAccountName
                    Cached = $false
                }
            } catch {
                Write-Verbose "Failed to resolve Administrator account via RID 500: $($_.Exception.Message) (CorrelationId: $CorrelationId)"
                # Continue to normal resolution if RID 500 lookup fails
            }
        }
        
        # Check cache first (except for Administrator which is handled above)
        if ($UseCache -and $script:SidCache.ContainsKey($Principal)) {
            Write-Verbose "Found cached SID for '$Principal' (CorrelationId: $CorrelationId)"
            $cachedResult = $script:SidCache[$Principal]
            return [PSCustomObject]@{
                Principal = $Principal
                Sid = $cachedResult.Sid
                Source = $cachedResult.Source
                Cached = $true
                Success = $cachedResult.Success
                Error = $cachedResult.Error
            }
        }
        
        # Try well-known SIDs first
        $wellKnownSid = Get-WellKnownSid -Principal $Principal
        if ($wellKnownSid) {
            Write-Verbose "Resolved well-known SID for '$Principal': $wellKnownSid (CorrelationId: $CorrelationId)"
            $result = @{
                Sid = $wellKnownSid
                Source = "WellKnown" 
                Success = $true
                Error = $null
            }
            
            if ($UseCache) {
                $script:SidCache[$Principal] = $result
            }
            
            return [PSCustomObject]@{
                Principal = $Principal
                Sid = $wellKnownSid
                Source = "WellKnown"
                Cached = $false
                Success = $true
                Error = $null
            }
        }
        
        # --- Canonical well-known principal resolution (language- and rename-independent) ---
        # Built-in Active Directory principals are LOCALISED once, at domain creation, from the
        # install language of the first domain controller, and then replicated. A German domain
        # serves "Domaenen-Admins", never "Domain Admins", so Get-ADGroup -Identity 'Domain Admins'
        # returns nothing there. The same lookup also fails wherever an administrator has renamed
        # a built-in group. Their SIDs, however, are fixed: a well-known RID under the domain (or
        # forest-root) SID.
        #
        # So the English names in config/*.json are treated as CANONICAL IDENTIFIERS, not as
        # directory names: map the name to its RID, compose the SID from the domain this run
        # targets, and confirm THAT object exists. This is the same reasoning the Administrator
        # (RID 500) path above already applies, generalised to every built-in principal the Tier
        # Model references. See specs/008-german-language-support/spec.md.
        $canonical = Get-TierModelCanonicalPrincipal -Principal $Principal
        if ($canonical) {
            $canonicalResult = Resolve-TierModelCanonicalSid -Canonical $canonical -Principal $Principal -DomainController $DomainController -CorrelationId $CorrelationId

            if ($canonicalResult.Success) {
                Write-Verbose "Resolved canonical SID for '$Principal': $($canonicalResult.Sid) (directory name: '$($canonicalResult.ActualName)') (CorrelationId: $CorrelationId)"

                if ($UseCache) {
                    $script:SidCache[$Principal] = @{
                        Sid = $canonicalResult.Sid
                        Source = $canonicalResult.Source
                        Success = $true
                        Error = $null
                    }
                }

                $canonicalObj = [PSCustomObject]@{
                    Principal = $Principal
                    Sid = $canonicalResult.Sid
                    Source = $canonicalResult.Source
                    Cached = $false
                    Success = $true
                    Error = $null
                }
                if ($canonicalResult.ActualName) {
                    $canonicalObj | Add-Member -NotePropertyName 'ActualName' -NotePropertyValue $canonicalResult.ActualName -Force
                }
                return $canonicalObj
            }

            # The principal is a known built-in, but this domain does not have it: a
            # forestRootOnly group seen from a child domain, or an optional group that was never
            # created (e.g. Allowed RODC Password Replication Group). Fall through to the existing
            # paths so the caller gets exactly the "not found" outcome it got before this change -
            # callers such as New-TierModelGptTmplContent rely on that to SKIP the principal
            # rather than write an unresolvable SID into [Privilege Rights].
            Write-Verbose "Canonical principal '$Principal' is not present in this domain: $($canonicalResult.Error) (CorrelationId: $CorrelationId)"
        }

        # Try AD resolution
        try {
            $adResult = Resolve-ADPrincipalSid -Principal $Principal -DomainController $DomainController -CorrelationId $CorrelationId
            
            if ($adResult.Success) {
                Write-Verbose "Resolved AD SID for '$Principal': $($adResult.Sid) (CorrelationId: $CorrelationId)"
                
                # Special logging for Administrator account resolution
                if ($Principal -ieq "Administrator" -and $adResult.PSObject.Properties.Name -contains 'ActualName') {
                    Write-Verbose "Administrator account resolved to actual account name: '$($adResult.ActualName)' (CorrelationId: $CorrelationId)"
                }
                
                if ($UseCache) {
                    $script:SidCache[$Principal] = @{
                        Sid = $adResult.Sid
                        Source = $adResult.Source
                        Success = $true
                        Error = $null
                    }
                }
                
                # Build result object with optional ActualName property
                $resultObj = [PSCustomObject]@{
                    Principal = $Principal
                    Sid = $adResult.Sid
                    Source = $adResult.Source
                    Cached = $false
                    Success = $true
                    Error = $null
                }
                
                # Add ActualName if it exists (for renamed Administrator account)
                if ($adResult.PSObject.Properties.Name -contains 'ActualName') {
                    $resultObj | Add-Member -NotePropertyName 'ActualName' -NotePropertyValue $adResult.ActualName -Force
                }
                
                return $resultObj
            }
            else {
                Write-Warning "Failed to resolve SID for '$Principal': $($adResult.Error) (CorrelationId: $CorrelationId)"
                
                $result = @{
                    Sid = $null
                    Source = "Failed"
                    Success = $false
                    Error = $adResult.Error
                }
                
                if ($UseCache) {
                    $script:SidCache[$Principal] = $result
                }
                
                return [PSCustomObject]@{
                    Principal = $Principal
                    Sid = $null
                    Source = "Failed"
                    Cached = $false
                    Success = $false
                    Error = $adResult.Error
                }
            }
        }
        catch {
            $errorMsg = "Exception resolving SID for '$Principal': $($_.Exception.Message)"
            Write-Warning "$errorMsg (CorrelationId: $CorrelationId)"
            
            $result = @{
                Sid = $null
                Source = "Exception"
                Success = $false
                Error = $errorMsg
            }
            
            if ($UseCache) {
                $script:SidCache[$Principal] = $result
            }
            
            return [PSCustomObject]@{
                Principal = $Principal
                Sid = $null
                Source = "Exception" 
                Cached = $false
                Success = $false
                Error = $errorMsg
            }
        }
    }
}

function ConvertTo-TierModelSidString {
    <#
    .SYNOPSIS
    Normalises a "SID-ish" value returned by an AD cmdlet into a validated SID string.

    .DESCRIPTION
    Private helper (not exported). AD cmdlets normally return a live
    [System.Security.Principal.SecurityIdentifier] for .SID / .objectSid. On platforms where
    the ActiveDirectory module loads through the Windows PowerShell Compatibility shim
    (WinPSCompatSession — platform-dependent; not reproduced on Windows Server 2025 /
    PowerShell 7.5.1), the objects are DESERIALIZED and those properties come back as plain
    [String]. Reading .Value off a String yields $null, which previously produced BLANK
    principals in GPO GptTmpl.inf (User Rights Assignment and Restricted Groups) - a silent
    security-configuration failure. The helper also defends against any other code path that
    returns a SID as a string rather than as a SecurityIdentifier.

    This helper accepts every shape safely (SecurityIdentifier, String, byte[],
    deserialized PSObject exposing .Value) and THROWS when the result cannot be
    validated as a real SID, so callers fail loudly instead of writing empty values.

    .PARAMETER InputSid
    The raw value read from .SID / .objectSid / .DomainSID.

    .PARAMETER Context
    Human-readable description of what was being resolved, used in the error message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        $InputSid,

        [Parameter(Mandatory)]
        [string]$Context
    )

    $candidate = $null

    if ($null -eq $InputSid) {
        $candidate = $null
    }
    elseif ($InputSid -is [System.Security.Principal.SecurityIdentifier]) {
        $candidate = $InputSid.Value
    }
    elseif ($InputSid -is [string]) {
        # String shape (deserialized on some platforms, or returned directly by certain cmdlets):
        $candidate = $InputSid
    }
    elseif ($InputSid -is [byte[]]) {
        try { $candidate = ([System.Security.Principal.SecurityIdentifier]::new($InputSid, 0)).Value } catch { $candidate = $null }
    }
    else {
        # PSObject / deserialized wrapper: prefer an explicit .Value property, else ToString().
        $valueProperty = $InputSid.PSObject.Properties['Value']
        if ($valueProperty -and -not [string]::IsNullOrWhiteSpace([string]$valueProperty.Value)) {
            $candidate = [string]$valueProperty.Value
        }
        else {
            $candidate = [string]$InputSid
        }
    }

    if ([string]::IsNullOrWhiteSpace($candidate)) {
        throw "SID resolution returned an empty value for $Context (a deserialized [String] was received where a live [System.Security.Principal.SecurityIdentifier] was expected; cause undetermined). Refusing to emit a blank SID into security policy."
    }

    $candidate = $candidate.Trim()

    if ($candidate -notmatch '^S-1-\d+(-\d+)+$') {
        throw "SID resolution returned a malformed value ('$candidate') for $Context. Refusing to emit an invalid SID into security policy."
    }

    try {
        $null = [System.Security.Principal.SecurityIdentifier]::new($candidate)
    }
    catch {
        throw "SID resolution returned a value ('$candidate') for $Context that is not a valid security identifier: $($_.Exception.Message)"
    }

    return $candidate
}

function Get-TierModelDomainSidValue {
    <#
    .SYNOPSIS
    Reads the domain SID out of a Get-ADDomain result in whatever shape it arrives.

    .DESCRIPTION
    Private helper (not exported). DomainSID is normally a SecurityIdentifier, but comes back as a
    plain String through the Windows PowerShell Compatibility shim, and is absent altogether from
    some partial objects. Set-StrictMode -Version Latest turns that absence into a terminating
    error on plain property access, so the property is probed rather than dereferenced.

    Returns $null when no usable SID is present; callers must treat that as "unknown".

    .PARAMETER Domain
    The object returned by Get-ADDomain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Domain
    )

    if ($null -eq $Domain) { return $null }

    $sidProperty = $Domain.PSObject.Properties['DomainSID']
    if (-not $sidProperty) { return $null }

    $sidValue = $sidProperty.Value
    if ($null -eq $sidValue) { return $null }

    $text = if ($sidValue -is [System.Security.Principal.SecurityIdentifier]) {
        $sidValue.Value
    }
    elseif ($sidValue -is [string]) {
        $sidValue
    }
    else {
        $nestedValue = $sidValue.PSObject.Properties['Value']
        if ($nestedValue) { [string]$nestedValue.Value } else { [string]$sidValue }
    }

    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text.Trim()
}

function ConvertTo-TierModelIdentitySid {
    <#
    .SYNOPSIS
    Normalises any identity shape (IdentityReference, NTAccount, SID string, "DOMAIN\Name") to a
    SID string.

    .DESCRIPTION
    Private helper (not exported). Security descriptors and the LAPS cmdlets hand identities back
    as display names that the LOCAL machine translated: on German Windows the same ACE reads
    "NT-AUTORITAET\SELBST", "VORDEFINIERT\Administratoren" or "<DOM>\Domaenen-Admins" instead of
    "NT AUTHORITY\SELF", "BUILTIN\Administrators" or "<DOM>\Domain Admins". Comparing those
    strings to English literals silently fails on every non-English host - the Tier Model then
    misses its own SELF ACE (re-applying the delegation on every run) and reports every legitimate
    administrative holder as drift.

    Translating back to a SID removes the language from the comparison entirely.

    Returns $null when the identity cannot be translated (an orphaned SID from a deleted trust, a
    principal from an unreachable domain). Callers must treat $null as "unknown", never as a match.

    .PARAMETER Identity
    The identity to normalise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        $Identity
    )

    if ($null -eq $Identity) { return $null }

    if ($Identity -is [System.Security.Principal.SecurityIdentifier]) {
        return $Identity.Value
    }

    $text = if ($Identity -is [System.Security.Principal.NTAccount]) {
        $Identity.Value
    }
    elseif ($Identity -is [string]) {
        $Identity
    }
    else {
        # IdentityReference and deserialized wrappers expose .Value; fall back to ToString().
        $valueProperty = $Identity.PSObject.Properties['Value']
        if ($valueProperty) { [string]$valueProperty.Value } else { [string]$Identity }
    }

    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $text = $text.Trim()

    # Already a SID.
    if ($text -match '^S-1-\d+(-\d+)+$') { return $text }

    try {
        return ([System.Security.Principal.NTAccount]::new($text)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        return $null
    }
}

function Test-TierModelIdentityMatch {
    <#
    .SYNOPSIS
    Compares two identities by SID, falling back to a name comparison only when a SID cannot be
    obtained for both.

    .DESCRIPTION
    Private helper (not exported). Either side may be an IdentityReference, an NTAccount, a SID
    string or "DOMAIN\Name". When both translate to a SID the comparison is by SID and is
    language- and rename-independent.

    The name fallback matters for principals that no longer exist (an ACE left behind by a deleted
    group translates to nothing), where a string comparison is all that is available. It compares
    the full value and the sAMAccountName portion, which is what the previous code did.

    .PARAMETER Left
    First identity.

    .PARAMETER Right
    Second identity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        $Left,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        $Right
    )

    $leftSid  = ConvertTo-TierModelIdentitySid -Identity $Left
    $rightSid = ConvertTo-TierModelIdentitySid -Identity $Right

    if ($leftSid -and $rightSid) {
        return ($leftSid -eq $rightSid)
    }

    $leftText  = [string]$(if ($Left  -and $Left.PSObject.Properties['Value'])  { $Left.Value }  else { $Left })
    $rightText = [string]$(if ($Right -and $Right.PSObject.Properties['Value']) { $Right.Value } else { $Right })

    if ([string]::IsNullOrWhiteSpace($leftText) -or [string]::IsNullOrWhiteSpace($rightText)) { return $false }

    if ($leftText -ieq $rightText) { return $true }

    return ((($leftText -split '\\')[-1]) -ieq (($rightText -split '\\')[-1]))
}

function Resolve-TierModelLapsPrincipal {
    <#
    .SYNOPSIS
    Resolves configured Windows LAPS delegation group names to SID + sAMAccountName.

    .DESCRIPTION
    Private helper (not exported). Shared by the LAPS planner (Get-TierModelWinLapsAcl) and the
    LAPS audit (Test-TierModelWinLapsAcl) so both agree on what a configured group resolves to.

    Both used to resolve with Get-ADGroup -Filter "Name -eq '<config name>'". That breaks on a
    localised directory in a particularly quiet way: config/tiermodel-winlaps.json names
    'Domain Admins' for the domain controller delegation, a German domain calls that group
    'Domaenen-Admins', and a -Filter that matches nothing returns an EMPTY RESULT rather than
    throwing. The planner then recorded RequiredGroupNotFound and blocked the whole LAPS
    deployment, while the audit silently checked an empty principal list and called the delegation
    compliant.

    Resolving through Resolve-TierModelPrincipalSid puts built-ins on the canonical SID path, then
    reads the object back BY SID for the sAMAccountName the directory actually uses. Groups the
    Tier Model owns (Tier 0 Server Operators, ...) are unaffected - they keep taking the name path.

    .PARAMETER GroupNames
    Group names as written in the configuration.

    .PARAMETER DomainController
    Domain controller every directory read in this run targets.

    .PARAMETER NetBiosDomain
    NetBIOS domain name used to build the "NETBIOS\sAMAccountName" form. Looked up when omitted.

    .OUTPUTS
    [PSCustomObject] per group: Config, Sid, Sam, Qualified, Found.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$GroupNames,

        [Parameter(Mandatory)]
        [string]$DomainController,

        [string]$NetBiosDomain
    )

    if (-not $PSBoundParameters.ContainsKey('NetBiosDomain') -or [string]::IsNullOrWhiteSpace($NetBiosDomain)) {
        try {
            $NetBiosDomain = (Get-ADDomain -Server $DomainController -ErrorAction Stop).NetBIOSName
        }
        catch {
            $NetBiosDomain = $null
        }
    }

    foreach ($groupName in $GroupNames) {
        if ([string]::IsNullOrWhiteSpace($groupName)) { continue }

        $resolvedSid = $null
        $resolvedSam = $null

        $sidResult = Resolve-TierModelPrincipalSid -Principal $groupName -DomainController $DomainController -WarningAction SilentlyContinue
        if ($sidResult -and $sidResult.Success -and -not [string]::IsNullOrWhiteSpace($sidResult.Sid)) {
            $resolvedSid = $sidResult.Sid
            try {
                $adGroup = Get-ADGroup -Identity $resolvedSid -Server $DomainController -Properties sAMAccountName -ErrorAction Stop
                if ($adGroup) { $resolvedSam = $adGroup.sAMAccountName }
            }
            catch {
                # SID is valid but the object is not readable as a group (an alias-only well-known
                # SID such as BUILTIN\Administrators has no directory object). The SID still
                # identifies it; fall back to the configured name for display.
                $resolvedSam = $null
            }
        }

        if (-not $resolvedSam) {
            # No SID, or no readable group object: keep the previous name-based lookup so nothing
            # that worked before stops working.
            $adGroupByName = $null
            try {
                $escapedName = $groupName -replace "'", "''"
                # -Filter does not throw when nothing matches, it returns empty. This catch is
                # therefore for a genuine read failure, not for "group not found".
                $adGroupByName = Get-ADGroup -Filter "Name -eq '$escapedName'" -Server $DomainController -Properties sAMAccountName -ErrorAction Stop
            }
            catch {
                $adGroupByName = $null
            }

            if ($adGroupByName) {
                $resolvedSam = $adGroupByName.sAMAccountName

                if (-not $resolvedSid) {
                    # Normalising the SID gets its OWN try on purpose. It used to share the
                    # lookup's catch, so a SID that failed to normalise also discarded the
                    # sAMAccountName that had just been read successfully. That name is not a
                    # nice-to-have: it is what the LAPS cmdlets and the audit match on when no
                    # SID is available, so losing it turned a degraded result into no result -
                    # the planner then reported RequiredGroupNotFound and blocked the whole
                    # Windows LAPS deployment.
                    try {
                        $resolvedSid = ConvertTo-TierModelSidString -InputSid $adGroupByName.SID -Context "group '$groupName'"
                    }
                    catch {
                        $resolvedSid = $null
                    }
                }
            }
        }

        $found = [bool]($resolvedSid -or $resolvedSam)
        $samForDisplay = if ($resolvedSam) { $resolvedSam } else { $groupName }

        [PSCustomObject]@{
            Config    = $groupName
            Sid       = $resolvedSid
            Sam       = $samForDisplay
            Qualified = if ($NetBiosDomain -and $resolvedSam) { "$NetBiosDomain\$resolvedSam" } else { $null }
            Found     = $found
        }
    }
}

function Get-TierModelCanonicalPrincipal {
    <#
    .SYNOPSIS
    Maps a canonical (English) built-in principal name to its well-known RID.

    .DESCRIPTION
    Private helper (not exported). The configuration set names built-in Active Directory
    principals in English. Those NAMES are localised per domain and can be renamed; their RIDs
    are not. This table is the mapping from the canonical name the configuration uses to the
    RID that identifies the principal in any domain, in any language.

    Only principals whose SID must be COMPOSED from a domain SID belong here. Built-ins with an
    absolute, domain-independent SID (BUILTIN\Administrators = S-1-5-32-544, NT AUTHORITY\SELF =
    S-1-5-10, ...) are served by Get-WellKnownSid, which needs no directory round trip at all.

    Scope values (both compose against the SID of the domain being deployed to - see
    Resolve-TierModelCanonicalSid for why that is correct for ForestRoot too):
      Domain     - RID is allocated in every domain.
      ForestRoot - RID is allocated ONLY in the forest root domain, so these principals
                   legitimately do not resolve when deploying into a child domain.

    Administrator (RID 500) is deliberately absent: Resolve-TierModelPrincipalSid handles it
    earlier with its own cache-bypassing path, which must keep running first.

    .PARAMETER Principal
    The principal name as written in the configuration.

    .OUTPUTS
    [hashtable] @{ Scope; Rid; ObjectClass; CanonicalName } or $null when not a known built-in.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Principal
    )

    # Canonical name -> @{ Scope; Rid; ObjectClass }
    $canonicalPrincipals = @{
        # --- Domain-relative groups (RID under <domainSID>) ---
        'Domain Admins'                            = @{ Scope = 'Domain';     Rid = 512; ObjectClass = 'group' }
        'Domain Users'                             = @{ Scope = 'Domain';     Rid = 513; ObjectClass = 'group' }
        'Domain Guests'                            = @{ Scope = 'Domain';     Rid = 514; ObjectClass = 'group' }
        'Domain Computers'                         = @{ Scope = 'Domain';     Rid = 515; ObjectClass = 'group' }
        'Domain Controllers'                       = @{ Scope = 'Domain';     Rid = 516; ObjectClass = 'group' }
        'Cert Publishers'                          = @{ Scope = 'Domain';     Rid = 517; ObjectClass = 'group' }
        'Group Policy Creator Owners'              = @{ Scope = 'Domain';     Rid = 520; ObjectClass = 'group' }
        'Read-only Domain Controllers'             = @{ Scope = 'Domain';     Rid = 521; ObjectClass = 'group' }
        'Cloneable Domain Controllers'             = @{ Scope = 'Domain';     Rid = 522; ObjectClass = 'group' }
        'Protected Users'                          = @{ Scope = 'Domain';     Rid = 525; ObjectClass = 'group' }
        'Key Admins'                               = @{ Scope = 'Domain';     Rid = 526; ObjectClass = 'group' }
        'Allowed RODC Password Replication Group'  = @{ Scope = 'Domain';     Rid = 571; ObjectClass = 'group' }
        'Denied RODC Password Replication Group'   = @{ Scope = 'Domain';     Rid = 572; ObjectClass = 'group' }

        # --- Domain-relative users ---
        'Guest'                                    = @{ Scope = 'Domain';     Rid = 501; ObjectClass = 'user'  }

        # --- Forest-root-relative groups (RID under <forestRootDomainSID>) ---
        'Enterprise Admins'                        = @{ Scope = 'ForestRoot'; Rid = 519; ObjectClass = 'group' }
        'Schema Admins'                            = @{ Scope = 'ForestRoot'; Rid = 518; ObjectClass = 'group' }
        'Enterprise Key Admins'                    = @{ Scope = 'ForestRoot'; Rid = 527; ObjectClass = 'group' }
        'Enterprise Read-only Domain Controllers'  = @{ Scope = 'ForestRoot'; Rid = 498; ObjectClass = 'group' }
    }

    # Exact match first, then case-insensitive - mirrors Get-WellKnownSid's contract.
    if ($canonicalPrincipals.ContainsKey($Principal)) {
        $entry = $canonicalPrincipals[$Principal]
        return @{ Scope = $entry.Scope; Rid = $entry.Rid; ObjectClass = $entry.ObjectClass; CanonicalName = $Principal }
    }

    $matchingKey = $canonicalPrincipals.Keys | Where-Object { $_ -ieq $Principal } | Select-Object -First 1
    if ($matchingKey) {
        $entry = $canonicalPrincipals[$matchingKey]
        return @{ Scope = $entry.Scope; Rid = $entry.Rid; ObjectClass = $entry.ObjectClass; CanonicalName = $matchingKey }
    }

    return $null
}

function Resolve-TierModelCanonicalSid {
    <#
    .SYNOPSIS
    Composes and VERIFIES the SID of a canonical built-in principal in the target domain.

    .DESCRIPTION
    Private helper (not exported). Takes the Get-TierModelCanonicalPrincipal entry, composes
    <domainSID>-<RID> against the domain this run targets, and then reads the object back BY SID.

    The read-back is not a sanity check, it is load-bearing. Two cases must keep resolving to
    "not found", exactly as the previous name-based lookup did:

      - forestRootOnly groups (Enterprise/Schema Admins) when deploying into a CHILD domain;
      - optional groups that a given domain never created (Allowed RODC Password Replication
        Group, Protected Users on an old DFL).

    Composing a SID without verifying it would silently write an unresolvable SID into GPO
    [Privilege Rights], which is a security-configuration failure rather than a missing entry.

    The verified object's directory Name is returned as ActualName, so a run against a German
    domain logs "Domain Admins -> S-1-5-21-...-512 (Domaenen-Admins)".

    .PARAMETER Canonical
    Entry returned by Get-TierModelCanonicalPrincipal.

    .PARAMETER Principal
    The original principal string, for messages.

    .PARAMETER DomainController
    Domain controller every directory read in this run targets.

    .PARAMETER CorrelationId
    Tracking ID for logging correlation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Canonical,

        [Parameter(Mandatory)]
        [string]$Principal,

        [Parameter(Mandatory)]
        [string]$DomainController,

        [string]$CorrelationId = [System.Guid]::NewGuid().ToString()
    )

    # Defensive init: the module-scope cache is created when this file is dot-sourced, but
    # Set-StrictMode -Version Latest makes reading an undefined $script: variable throw, and test
    # harnesses can reset module state between contexts.
    if (-not $script:CanonicalDomainSidCache) { $script:CanonicalDomainSidCache = @{} }

    # Every canonical RID is composed against the SID of the domain this run targets - including
    # the ForestRoot-scope ones. That is not an approximation, it is what makes child domains
    # behave as before:
    #
    #   - In the FOREST ROOT domain, RID 519 under the domain SID IS Enterprise Admins.
    #   - In a CHILD domain, RID 519 is simply not allocated, so the read-back below finds
    #     nothing and the principal is reported as not found - exactly what
    #     Get-ADGroup -Identity 'Enterprise Admins' -Server <childDC> did before this change.
    #
    # Preserving that parity is deliberate. Resolving forest-root groups cross-domain would ADD
    # principals to GPO user-rights lists in child domains; that is a security-policy change and
    # belongs in its own reviewed decision, not in a localisation fix.
    #
    # Memoised per domain controller: a deployment resolves hundreds of principals and must not
    # issue hundreds of Get-ADDomain round trips.
    try {
        if (-not $script:CanonicalDomainSidCache.ContainsKey($DomainController)) {
            $adDomain = Get-ADDomain -Server $DomainController -ErrorAction Stop
            $script:CanonicalDomainSidCache[$DomainController] = ConvertTo-TierModelSidString -InputSid $adDomain.DomainSID -Context "the domain SID of '$DomainController'"
        }
        $baseSid = $script:CanonicalDomainSidCache[$DomainController]
    }
    catch {
        return @{ Sid = $null; Source = 'CanonicalError'; Success = $false; Error = "Could not resolve the domain SID for '$Principal' from '$DomainController': $($_.Exception.Message)"; ActualName = $null }
    }

    $composedSid = "$baseSid-$($Canonical.Rid)"

    # Read the object back BY SID. A failure here means the principal does not exist in this
    # domain, which is a legitimate outcome - see the .DESCRIPTION.
    try {
        $adObject = if ($Canonical.ObjectClass -eq 'user') {
            Get-ADUser -Identity $composedSid -Server $DomainController -ErrorAction Stop
        } else {
            Get-ADGroup -Identity $composedSid -Server $DomainController -ErrorAction Stop
        }
    }
    catch {
        return @{ Sid = $null; Source = 'CanonicalNotFound'; Success = $false; Error = "Canonical principal '$Principal' (RID $($Canonical.Rid), scope $($Canonical.Scope)) does not exist in the domain served by '$DomainController': $($_.Exception.Message)"; ActualName = $null }
    }

    if (-not $adObject) {
        return @{ Sid = $null; Source = 'CanonicalNotFound'; Success = $false; Error = "Canonical principal '$Principal' (RID $($Canonical.Rid), scope $($Canonical.Scope)) was not found in the domain served by '$DomainController'"; ActualName = $null }
    }

    # Normalise from the returned object rather than trusting the composed string, so the SID
    # written into security policy is always one the directory itself handed back.
    $verifiedSid = ConvertTo-TierModelSidString -InputSid $adObject.SID -Context "canonical principal '$Principal' (RID $($Canonical.Rid))"

    return @{
        Sid = $verifiedSid
        Source = "Canonical$($Canonical.Scope)Rid"
        Success = $true
        Error = $null
        ActualName = $adObject.Name
    }
}

function Get-WellKnownSid {
    <#
    .SYNOPSIS
    Returns SID for well-known security principals
    
    .DESCRIPTION
    Maps common security principal names to their well-known SIDs without AD queries
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Principal
    )
    
    # Well-known SID mappings
    $wellKnownSids = @{
        # Built-in groups
        "BUILTIN\Administrators" = "S-1-5-32-544"
        "BUILTIN\Users" = "S-1-5-32-545"
        "BUILTIN\Guests" = "S-1-5-32-546"
        "BUILTIN\Power Users" = "S-1-5-32-547"
        "BUILTIN\Account Operators" = "S-1-5-32-548"
        "BUILTIN\Server Operators" = "S-1-5-32-549"
        "BUILTIN\Print Operators" = "S-1-5-32-550"
        "BUILTIN\Backup Operators" = "S-1-5-32-551"
        "BUILTIN\Replicator" = "S-1-5-32-552"
        "BUILTIN\Network Configuration Operators" = "S-1-5-32-556"
        "BUILTIN\Performance Monitor Users" = "S-1-5-32-558"
        "BUILTIN\Performance Log Users" = "S-1-5-32-559"
        "BUILTIN\Distributed COM Users" = "S-1-5-32-562"
        "BUILTIN\IIS_IUSRS" = "S-1-5-32-568"
        "BUILTIN\Event Log Readers" = "S-1-5-32-573"
        "BUILTIN\Cryptographic Operators" = "S-1-5-32-569"
        "BUILTIN\Remote Desktop Users" = "S-1-5-32-555"
        "BUILTIN\Certificate Service DCOM Access" = "S-1-5-32-574"
        "BUILTIN\Remote Management Users" = "S-1-5-32-580"
        
        # NT Authority
        "NT AUTHORITY\SYSTEM" = "S-1-5-18"
        "NT AUTHORITY\LOCAL SERVICE" = "S-1-5-19"
        "NT AUTHORITY\NETWORK SERVICE" = "S-1-5-20"
        "NT AUTHORITY\Authenticated Users" = "S-1-5-11"
        "NT AUTHORITY\ANONYMOUS LOGON" = "S-1-5-7"
        "NT AUTHORITY\BATCH" = "S-1-5-3"
        "NT AUTHORITY\INTERACTIVE" = "S-1-5-4"
        "NT AUTHORITY\SERVICE" = "S-1-5-6"
        "NT AUTHORITY\DIALUP" = "S-1-5-1"
        "NT AUTHORITY\NETWORK" = "S-1-5-2"
        "NT AUTHORITY\TERMINAL SERVER USER" = "S-1-5-13"
        "NT AUTHORITY\REMOTE INTERACTIVE LOGON" = "S-1-5-14"
        "NT AUTHORITY\Local account" = "S-1-5-113"
        "NT AUTHORITY\Local account and member of Administrators group" = "S-1-5-114"
        
        # Everyone and other common principals
        "Everyone" = "S-1-1-0"
        "CREATOR OWNER" = "S-1-3-0"
        "CREATOR GROUP" = "S-1-3-1"
        
        # Short names (case-insensitive lookups).
        # These are the BUILTIN aliases as they appear WITHOUT the "BUILTIN\" prefix in
        # config/tiermodel-gpos.json. Their SIDs are fixed in every Windows language, so
        # resolving them here keeps a localised (e.g. German) domain off the name-lookup
        # path entirely - see specs/008-german-language-support/spec.md.
        #
        # DELIBERATELY LIMITED to the bare names the configuration actually uses. A bare name
        # here SHADOWS a customer's own domain group of the same name, which would previously
        # have resolved by name: 'Remote Desktop Users' or 'Event Log Readers' are perfectly
        # legal names for a custom domain group. Entries carrying the "BUILTIN\" prefix cannot
        # collide that way and are safe to list exhaustively. Do not add a bare alias here
        # without a configuration entry that needs it.
        "Administrators" = "S-1-5-32-544"
        "Users" = "S-1-5-32-545"
        "Guests" = "S-1-5-32-546"
        "Backup Operators" = "S-1-5-32-551"
        "IIS_IUSRS" = "S-1-5-32-568"
        "Cryptographic Operators" = "S-1-5-32-569"
        "SYSTEM" = "S-1-5-18"
        "Authenticated Users" = "S-1-5-11"
        "ANONYMOUS LOGON" = "S-1-5-7"
        "Local account" = "S-1-5-113"
        "IUSR" = "S-1-5-17"
        "NT AUTHORITY\SELF" = "S-1-5-10"
        "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS" = "S-1-5-9"
    }
    
    # Try exact match first
    if ($wellKnownSids.ContainsKey($Principal)) {
        return $wellKnownSids[$Principal]
    }
    
    # Try case-insensitive match
    $matchingKey = $wellKnownSids.Keys | Where-Object { $_ -ieq $Principal } | Select-Object -First 1
    if ($matchingKey) {
        return $wellKnownSids[$matchingKey]
    }
    
    return $null
}

function Resolve-ADPrincipalSid {
    <#
    .SYNOPSIS
    Resolves security principal using Active Directory
    
    .DESCRIPTION
    Attempts to resolve security principal to SID using AD cmdlets
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Principal,

        # Declared explicitly. The body has always used -Server $DomainController; until now
        # that value only reached here through PowerShell's dynamic scoping from the caller
        # Resolve-TierModelPrincipalSid, which binds to $null for any other caller.
        [Parameter(Mandatory)]
        [string]$DomainController,

        [string]$CorrelationId
    )
    
    try {
        # Load ActiveDirectory module if available
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            throw "ActiveDirectory module is not available"
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        # Try to resolve as user first.
        # The lookup itself is allowed to fail (fall through to group), but SID
        # NORMALISATION is done outside the swallowing catch so a blank/deserialized SID
        # surfaces as a loud ADError instead of being mistaken for "not a user".
        $adUser = $null
        try {
            $adUser = Get-ADUser -Identity $Principal -Server $DomainController -ErrorAction Stop
        }
        catch {
            # Not a user, try as group
            $adUser = $null
        }

        if ($adUser) {
            return @{
                Sid = ConvertTo-TierModelSidString -InputSid $adUser.SID -Context "user '$Principal'"
                Source = "ADUser"
                Success = $true
                Error = $null
            }
        }
        
        # Try to resolve as group
        $adGroup = $null
        try {
            $adGroup = Get-ADGroup -Identity $Principal -Server $DomainController -ErrorAction Stop
        }
        catch {
            # Not a group either
            $adGroup = $null
        }

        if ($adGroup) {
            return @{
                Sid = ConvertTo-TierModelSidString -InputSid $adGroup.SID -Context "group '$Principal'"
                Source = "ADGroup" 
                Success = $true
                Error = $null
            }
        }
        
        # Try generic AD object search
        $adObject = $null
        try {
            $adObject = Get-ADObject -Filter "Name -eq '$Principal' -or SamAccountName -eq '$Principal'" -Properties objectSid -Server $DomainController -ErrorAction Stop | Select-Object -First 1
        }
        catch {
            # Do NOT add a not-found heuristic here. Get-ADObject -Filter has no not-found
            # case - a filter that matches nothing returns an EMPTY RESULT SET, never an
            # exception - so every exception reaching this catch is a genuine read failure.
            # Re-throw to the outer handler, which returns Source='ADError'. The real
            # not-found path still falls through to Source='NotFound'.
            throw
        }

        if ($adObject -and $adObject.objectSid) {
            return @{
                Sid = ConvertTo-TierModelSidString -InputSid $adObject.objectSid -Context "directory object '$Principal'"
                Source = "ADObject"
                Success = $true
                Error = $null
            }
        }
        
        # Principal not found in AD
        return @{
            Sid = $null
            Source = "NotFound"
            Success = $false
            Error = "Principal '$Principal' not found in Active Directory"
        }
    }
    catch {
        return @{
            Sid = $null
            Source = "ADError"
            Success = $false
            Error = "AD query failed: $($_.Exception.Message)"
        }
    }
}

function Get-TierModelConditionalGroupNames {
    <#
    .SYNOPSIS
    Evaluates conditional group conditions and returns only the group names that should be included.

    .DESCRIPTION
    For each name in a conditionalGroup entry, evaluates all conditions before including the name.
    Currently supports:
      - type: "groupExists", operator: "exists" — includes the name only if the AD group is found.
    Names that fail any condition are silently skipped.
    If no conditions are defined, all names are returned unconditionally (backwards compatible).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$ConditionalGroup,

        [Parameter(Mandatory)]
        [string]$DomainController,

        [string]$CorrelationId = [System.Guid]::NewGuid().ToString()
    )

    $resolvedNames = @()

    # No conditions defined — include all names unconditionally (backwards compatible)
    if (-not $ConditionalGroup.PSObject.Properties['conditions'] -or
        -not $ConditionalGroup.conditions -or
        @($ConditionalGroup.conditions).Count -eq 0) {
        foreach ($name in $ConditionalGroup.names) { $resolvedNames += $name }
        return $resolvedNames
    }

    foreach ($name in $ConditionalGroup.names) {
        $include = $true

        foreach ($condition in $ConditionalGroup.conditions) {
            if ($condition.type -eq 'groupExists' -and $condition.operator -eq 'exists') {
                try {
                    $adGroup = Get-ADGroup -Identity $name -Server $DomainController -ErrorAction Stop
                } catch {
                    $adGroup = $null
                }
                if (-not $adGroup) {
                    Write-Verbose "Conditional group '$name' not found in AD - skipping (CorrelationId: $CorrelationId)"
                    $include = $false
                    break
                }
            }
            # Future condition types can be added here
        }

        if ($include) {
            $resolvedNames += $name
        }
    }

    return $resolvedNames
}

# Initialize module-level SID cache
$script:SidCache = @{}

# Memoised domain SID for canonical (RID-relative) principal resolution, keyed by domain
# controller. A deployment resolves hundreds of principals; without this each one would cost a
# Get-ADDomain round trip.
$script:CanonicalDomainSidCache = @{}
