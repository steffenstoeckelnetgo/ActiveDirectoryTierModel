function Resolve-TierModelDomainDN {
    <#
    .SYNOPSIS
    Resolve and cache domain distinguished name for TierModel operations.
    
    .DESCRIPTION
    Centralized domain DN resolution with caching to minimize AD queries
    across all TierModel cmdlets (OU, Groups, Users, GPOs, etc.).
    
    .PARAMETER DomainController
    Preferred domain controller for AD operations.
    
    .EXAMPLE
    $domainDN = Resolve-TierModelDomainDN -DomainController "dc01.contoso.com"
    # Returns: "DC=contoso,DC=com"
    
    .OUTPUTS
    String containing the domain distinguished name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainController
    )
    
    # Check cache first
    if (-not $script:CachedDomainDN -or $script:CachedDomainController -ne $DomainController) {
        try {
            $domain = Get-ADDomain -Server $DomainController -ErrorAction Stop
            $script:CachedDomainDN = $domain.DistinguishedName
            $script:CachedDomainController = $DomainController
            Write-TierModelLog -Level Debug -Message "Domain DN resolved and cached" -Data @{
                DomainController = $DomainController
                DomainDN = $script:CachedDomainDN
            } | Out-Null
        } catch {
            Write-TierModelLog -Level Error -Message "Failed to resolve domain DN" -Data @{
                DomainController = $DomainController
                Error = $_.Exception.Message
            }
            throw "Failed to resolve domain DN: $($_.Exception.Message)"
        }
    }
    
    return $script:CachedDomainDN
}

function Test-TierModelWellKnownContainer {
    <#
    .SYNOPSIS
    Is this DN one of the domain's well-known containers that always exist?

    .DESCRIPTION
    Private helper (not exported). The GPO planners classify a target DN as "a container that
    always exists" (domain root, Domain Controllers OU, Builtin, Users) so they can validate it
    instead of assuming a later phase will create it.

    That used to be three hardcoded regex literals. This version keeps them - they are correct
    wherever the containers carry their English RDN - and ADDITIONALLY compares against the DNs
    the directory itself reports (DomainControllersContainer / UsersContainer / ComputersContainer
    from Get-ADDomain). Asking the directory removes the assumption that the RDN is English, which
    is the assumption the rest of this change set is removing everywhere else.

    Falls back to the literal comparison alone when the domain cannot be read, so a directory
    hiccup degrades to today's behaviour rather than to "not a well-known container".

    .PARAMETER DistinguishedName
    The DN to classify.

    .PARAMETER DomainController
    Domain controller every directory read in this run targets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$DistinguishedName,

        [Parameter(Mandatory)]
        [string]$DomainController
    )

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return $false }

    if ($DistinguishedName -match '^OU=Domain Controllers,DC=' -or
        $DistinguishedName -match '^CN=Builtin,DC=' -or
        $DistinguishedName -match '^CN=Users,DC=' -or
        $DistinguishedName -match '^CN=Computers,DC=') {
        return $true
    }

    if (-not $script:WellKnownContainerCache) { $script:WellKnownContainerCache = @{} }

    try {
        if (-not $script:WellKnownContainerCache.ContainsKey($DomainController)) {
            $wkDomain = Get-ADDomain -Server $DomainController -ErrorAction Stop
            $containerDns = @()
            foreach ($propertyName in @('DomainControllersContainer', 'UsersContainer', 'ComputersContainer')) {
                $property = $wkDomain.PSObject.Properties[$propertyName]
                if ($property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                    $containerDns += [string]$property.Value
                }
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$wkDomain.DistinguishedName)) {
                $containerDns += "CN=Builtin,$($wkDomain.DistinguishedName)"
            }
            $script:WellKnownContainerCache[$DomainController] = $containerDns
        }

        foreach ($containerDn in $script:WellKnownContainerCache[$DomainController]) {
            if ($DistinguishedName -ieq $containerDn) { return $true }
        }
    }
    catch {
        # Domain not readable: keep the literal verdict above rather than inventing one.
    }

    return $false
}

# Cache of well-known container DNs per domain controller (see Test-TierModelWellKnownContainer).
$script:WellKnownContainerCache = @{}

function Resolve-TierModelDelegationOuDn {
    <#
    .SYNOPSIS
    Resolves a configured delegation OU DN, correcting the Domain Controllers OU from the
    directory when the configured literal does not exist.

    .DESCRIPTION
    Private helper (not exported). config/tiermodel-winlaps.json addresses the domain controller
    delegation as the literal "OU=Domain Controllers,{{DOMAIN_DN}}".

    Whether that OU carries an English RDN on a localized domain is not something this project
    can assert from here, and guessing either way would be wrong: assume it is localized and the
    change is pointless noise; assume it is not and the Windows LAPS delegation for domain
    controllers silently targets a non-existent OU.

    So neither is assumed. The configured DN is used when it resolves, and only when it does not
    is the wellKnownObject-backed DomainControllersContainer from Get-ADDomain used instead. That
    is correct in both worlds and needs no knowledge of how any given language names the OU.

    Applies only to entries flagged isDomainControllerOu; every other delegation OU is created by
    the Tier Model itself and carries the name the Tier Model gave it.

    .PARAMETER ConfiguredDn
    The DN after placeholder substitution.

    .PARAMETER IsDomainControllerOu
    Whether the configuration flagged this entry as the domain controller OU.

    .PARAMETER DomainController
    Domain controller every directory read in this run targets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfiguredDn,

        [Parameter(Mandatory)]
        [bool]$IsDomainControllerOu,

        [Parameter(Mandatory)]
        [string]$DomainController
    )

    if (-not $IsDomainControllerOu) { return $ConfiguredDn }

    try {
        $null = Get-ADObject -Identity $ConfiguredDn -Server $DomainController -ErrorAction Stop
        return $ConfiguredDn
    }
    catch {
        # Configured DN not present - fall back to what the directory itself reports.
    }

    try {
        $wkDomain = Get-ADDomain -Server $DomainController -ErrorAction Stop
        $property = $wkDomain.PSObject.Properties['DomainControllersContainer']
        if ($property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            Write-Verbose "Domain Controllers OU '$ConfiguredDn' not found; using the directory-reported container '$($property.Value)'."
            return [string]$property.Value
        }
    }
    catch {
        # Domain not readable: return the configured DN so the caller reports the OU as missing,
        # exactly as it did before, rather than silently targeting something else.
    }

    return $ConfiguredDn
}
