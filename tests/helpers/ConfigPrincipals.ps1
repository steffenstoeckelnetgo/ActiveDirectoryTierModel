# tests/helpers/ConfigPrincipals.ps1
#
# Reads the REAL config/ and reports every principal it names.
#
# Why this exists as its own enumeration rather than reusing the one inside
# optional/Test-TierModelLocalizedDeployment.ps1: that walker knows seven keys and the
# configuration uses eleven. It never sees 'memberComputerGroups' or
# 'allowedToAuthenticateFromDeviceGroups', so the report's "every principal the configuration
# names" is six principals short - and the missing keys are the Authentication Policy Silos,
# which is precisely where the localization defect of CLAUDE.md section 5 lived. A completeness
# test that inherited that blind spot would certify the gap instead of closing it.
#
# Everything here is string and JSON work only. No Active Directory, no [SecurityIdentifier],
# so it runs on Linux and in CI as well as on a lab host - which matters, because this is the
# half of the completeness proof that CAN run everywhere.

Set-StrictMode -Version Latest

function Get-TierModelPrincipalKeyName {
    <#
    .SYNOPSIS
        The configuration keys whose values are principal NAMES that the product resolves.

    .DESCRIPTION
        Derived from the product's own call sites, not from reading the configuration and
        guessing:

          resolvableGroups, forestRootOnly, alwaysInclude,
          conditionalGroups.names                       -> New-TierModelGptTmplContent
          memberGroups                                  -> New-TierModelGptTmplContent, restricted groups
          denyApplyGroupPolicy                          -> New-TierModelGpo (the Deny-Apply ACE)
          memberComputerGroups                          -> Test-TierModelAuthSiloPrerequisite,
                                                           Get-TierModelAuthSiloMembershipFd,
                                                           Set-TierModelAuthSiloMembership,
                                                           Test-TierModelAuthSilo
          allowedToAuthenticateFromDeviceGroups         -> New-TierModelAuthPolicy, Test-TierModelAuthPolicy
          readGroup, resetGroup, decryptorGroup         -> Resolve-TierModelLapsPrincipal

        'conditionalGroups' is handled separately by the walker because the names sit one level
        down, under a 'names' array.

        Adding a key here without a product call site that consumes it makes the inventory claim
        something the product does not do. Adding one at a call site without listing it here is
        what the "no undeclared key names a built-in" test catches.
    #>
    [CmdletBinding()]
    param()

    return @(
        'resolvableGroups'
        'forestRootOnly'
        'alwaysInclude'
        'memberGroups'
        'denyApplyGroupPolicy'
        'memberComputerGroups'
        'allowedToAuthenticateFromDeviceGroups'
        'readGroup'
        'resetGroup'
        'decryptorGroup'
    )
}

function Get-TierModelConfigPrincipalInventory {
    <#
    .SYNOPSIS
        Walks config/*.json and returns what it names: referenced principals, the groups the
        configuration creates, literalStrings, identityreference values, and a full index of
        every key to the string values it carries.

    .PARAMETER ConfigRoot
        The config directory. Defaults to the repository's own config/.

    .OUTPUTS
        A hashtable. 'Referenced' maps a principal name to the "file:key" sites that name it;
        name comparison is ordinal-case-insensitive throughout, because the configuration is
        inconsistent about case (PAWDomainJoin / PawDomainJoin) and Active Directory does not
        care either.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigRoot
    )

    $cmp = [StringComparer]::OrdinalIgnoreCase

    $inventory = @{
        Files              = [System.Collections.Generic.List[string]]::new()
        Referenced         = [System.Collections.Generic.Dictionary[string, [System.Collections.Generic.HashSet[string]]]]::new($cmp)
        CreatedGroups      = [System.Collections.Generic.HashSet[string]]::new($cmp)
        LiteralStrings     = [System.Collections.Generic.HashSet[string]]::new($cmp)
        IdentityReferences = [System.Collections.Generic.HashSet[string]]::new($cmp)
        KeyValues          = [System.Collections.Generic.Dictionary[string, [System.Collections.Generic.HashSet[string]]]]::new($cmp)
    }

    $principalKeys = Get-TierModelPrincipalKeyName

    # The schema describes the configuration rather than being one, and the unit-test fixture is
    # deliberately not the real thing. Neither is evidence about what gets deployed.
    $configFiles = Get-ChildItem -LiteralPath $ConfigRoot -Filter '*.json' -File |
                   Where-Object { $_.Name -notin @('tiermodel.schema.json', 'tiermodel.unittest.json') } |
                   Sort-Object Name

    foreach ($file in $configFiles) {
        $json = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
        $inventory.Files.Add($file.Name)
        Read-TierModelConfigNode -Node $json -FileName $file.Name -PrincipalKeys $principalKeys -Inventory $inventory
    }

    return $inventory
}

function Read-TierModelConfigNode {
    # Recursive worker for Get-TierModelConfigPrincipalInventory. Unexported by convention: the
    # test dot-sources this file, so everything in it is reachable, but only the two functions
    # above are meant to be called.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$Node,
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string[]]$PrincipalKeys,
        [Parameter(Mandatory)][hashtable]$Inventory
    )

    if ($null -eq $Node) { return }

    if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
        foreach ($item in $Node) {
            Read-TierModelConfigNode -Node $item -FileName $FileName -PrincipalKeys $PrincipalKeys -Inventory $Inventory
        }
        return
    }

    if ($Node -isnot [psobject]) { return }

    foreach ($property in $Node.PSObject.Properties) {
        $key   = $property.Name
        $value = $property.Value
        if ($null -eq $value) { continue }

        # Index every key against the plain strings it carries. The "no undeclared key names a
        # built-in" test reads this, and it is the only part of the walker that has to be
        # exhaustive rather than selective.
        foreach ($entry in @($value)) {
            if ($entry -is [string] -and -not [string]::IsNullOrWhiteSpace($entry)) {
                if (-not $Inventory.KeyValues.ContainsKey($key)) {
                    $Inventory.KeyValues[$key] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                }
                $null = $Inventory.KeyValues[$key].Add($entry.Trim())
            }
        }

        if ($PrincipalKeys -contains $key) {
            foreach ($entry in @($value)) {
                if ($entry -is [string] -and -not [string]::IsNullOrWhiteSpace($entry)) {
                    $name = $entry.Trim()
                    if (-not $Inventory.Referenced.ContainsKey($name)) {
                        $Inventory.Referenced[$name] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    }
                    $null = $Inventory.Referenced[$name].Add("$FileName`:$key")
                }
            }
            continue
        }

        switch ($key) {
            'conditionalGroups' {
                foreach ($group in @($value)) {
                    if ($group -isnot [psobject]) { continue }
                    $namesNode = $group.PSObject.Properties['names']
                    if (-not $namesNode) { continue }
                    foreach ($entry in @($namesNode.Value)) {
                        if ($entry -is [string] -and -not [string]::IsNullOrWhiteSpace($entry)) {
                            $name = $entry.Trim()
                            if (-not $Inventory.Referenced.ContainsKey($name)) {
                                $Inventory.Referenced[$name] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                            }
                            $null = $Inventory.Referenced[$name].Add("$FileName`:conditionalGroups.names")
                        }
                    }
                }
            }
            'literalStrings' {
                # Machine-local principals - NT SERVICE\*, IIS APPPOOL\*, CLIUSR. No domain SID
                # by construction, resolved by the Security Configuration Engine on the target
                # machine, so they are the deliberate exception to "everything resolves to a
                # SID" (rule 2.4). Collected, never treated as referenced principals.
                foreach ($entry in @($value)) {
                    if ($entry -is [string] -and -not [string]::IsNullOrWhiteSpace($entry)) {
                        $null = $Inventory.LiteralStrings.Add($entry.Trim())
                    }
                }
            }
            'identityreference' {
                # OU/MSA/gMSA/dMSA ACL delegations. These do NOT go through
                # Resolve-TierModelPrincipalSid: New-TierModelOuAcl.ps1:82-83 builds an
                # NTAccount from the value and calls .Translate(). That is language-dependent,
                # and it is only safe because every value here is a Tier Model group whose name
                # the configuration itself sets. A test pins exactly that.
                foreach ($entry in @($value)) {
                    if ($entry -is [string] -and -not [string]::IsNullOrWhiteSpace($entry)) {
                        $null = $Inventory.IdentityReferences.Add($entry.Trim())
                    }
                }
            }
        }

        # 'comment' and its siblings are prose. Descending into them costs nothing but noise in
        # the key index, and a sentence that happens to contain a group name is not a reference.
        if ($key -in @('comment', 'gpoComment', 'description', 'notes')) { continue }

        Read-TierModelConfigNode -Node $value -FileName $FileName -PrincipalKeys $PrincipalKeys -Inventory $Inventory
    }
}

function Add-TierModelCreatedGroup {
    <#
    .SYNOPSIS
        Fills the inventory's CreatedGroups set from config/tiermodel-groups.json - both
        spellings of every group the configuration creates.

    .DESCRIPTION
        A group is created once and referenced two ways: tiermodel-groups.json gives it a
        'name' ("Tier 0 Admins") and a 'samaccountname' ("Tier0Admins"), and
        tiermodel-gpos.json names it either way depending on the entry. Both are the same
        directory object, so both count as created.

        Read from that one file rather than from every 'samaccountname' in config/, and that
        narrowness is the point. A sweep of all files also picks up the three svc-* service
        accounts and the TestGroup / testuser placeholders in config/tiermodel.json, and every
        name wrongly counted as "created" is a name this test would stop asking questions
        about. A set that is too generous fails open.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Inventory,
        [Parameter(Mandatory)][string]$ConfigRoot
    )

    $path = Join-Path $ConfigRoot 'tiermodel-groups.json'
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Add-TierModelCreatedGroup: '$path' not found. Without it every Tier Model group reads as an undeclared reference, so the test would fail for the wrong reason."
    }

    $groups = (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
    foreach ($entry in @($groups.groups)) {
        if ($entry -isnot [psobject]) { continue }
        foreach ($key in @('name', 'samaccountname')) {
            $node = $entry.PSObject.Properties[$key]
            if ($node -and $node.Value -is [string] -and -not [string]::IsNullOrWhiteSpace($node.Value)) {
                $null = $Inventory.CreatedGroups.Add($node.Value.Trim())
            }
        }
    }
}
