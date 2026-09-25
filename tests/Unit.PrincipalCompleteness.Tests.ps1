<#
.SYNOPSIS
Completeness tests for principal resolution — CLAUDE.md section 6 Start here, item 2.

.DESCRIPTION
The lab report says "Total: 56, Unresolved: 0". That is one measurement, against one directory,
on one day. This file turns it into a standing guarantee, and it asserts the two things item 2
names:

  1. Every principal the REAL config/ names resolves through a DEFINED path — the canonical RID
     table, the well-known SID table, or the RID 500 path — and never falls to a name lookup it
     was not meant to take.
  2. An English and a localized directory produce IDENTICAL SID sets, both at the resolver and
     in the generated [Privilege Rights].

WHAT THE TWO HALVES OF THIS FILE COST TO RUN

The first two Describes are JSON and table lookups only. They run on any platform, including
Linux and the CI runner, which is new for this kind of evidence: until now every localization
assertion needed a Windows host.

The last two construct [SecurityIdentifier] from a string, which is not supported off Windows,
so they can only pass on a Windows host. That is the same limit the ACL files carry and it is
not worked around here: no platform skip exists anywhere in this suite, and adding one would
turn a test that cannot run into a test that reports success.

WHY THE TWO DIRECTORY FIXTURES SHARE A DOMAIN SID

The localized and the English fixture below describe the SAME domain answering in two
languages: same domain SID, same allocated RIDs, only the rendered names differ. That is
deliberate, and it is not what the parity lab run measured. The lab run compared two DIFFERENT
domains, where every locally allocated RID legitimately differs and the comparison has to
normalise them away (docs/parity-lab-runbook.md). Holding the domain constant here isolates the
one variable this project is about: the language. A difference that survives it is a
localization defect and nothing else.

.NOTES
Tags: Unit, Localization, Completeness
#>

# Dot-sourced HERE, at file scope, and not only inside BeforeAll. Pester 5 runs the file body
# during DISCOVERY and BeforeAll during the run, and the -ForEach below builds its cases from
# the configuration at discovery time. With the helper loaded only in BeforeAll, discovery dies
# on the first Describe that needs it - and the run then reports the tests it did manage to
# discover as a clean pass. That failure mode is CLAUDE.md section 4 trap 1 wearing a different
# hat: a green total over a file that stopped early.
. (Join-Path $PSScriptRoot 'helpers' 'ConfigPrincipals.ps1')

$DiscoveryConfigRoot = Join-Path $PSScriptRoot '..' 'config'
$DiscoveryInventory  = Get-TierModelConfigPrincipalInventory -ConfigRoot $DiscoveryConfigRoot
Add-TierModelCreatedGroup -Inventory $DiscoveryInventory -ConfigRoot $DiscoveryConfigRoot
$DiscoveryReferencedNames = @($DiscoveryInventory.Referenced.Keys | Sort-Object)

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..' 'modules' 'TierModel' 'TierModel.psd1'
    Import-Module $modulePath -Force

    . (Join-Path $PSScriptRoot 'helpers' 'ConfigPrincipals.ps1')

    $script:ConfigRoot = Join-Path $PSScriptRoot '..' 'config'
    $script:Inventory  = Get-TierModelConfigPrincipalInventory -ConfigRoot $script:ConfigRoot
    Add-TierModelCreatedGroup -Inventory $script:Inventory -ConfigRoot $script:ConfigRoot

    $script:ReferencedNames = @($script:Inventory.Referenced.Keys | Sort-Object)

    $script:TestDomainSid = 'S-1-5-21-1111111111-2222222222-3333333333'
    $script:TestDc        = 'dc01.test.local'

    # Principals that take the NAME path on purpose, with the reason. Both are created by the
    # DNS Server role rather than by domain creation: they have no fixed RID to compose and
    # their names are set by the role in English on every language of Windows, so a name lookup
    # is the only path available and is correct. The configuration names them under
    # conditionalGroups, which means "use it if the domain has it" — a domain without the DNS
    # role legitimately resolves neither.
    $script:NamePathByDesign = @('DnsAdmins', 'DnsUpdateProxy')

    # Resolved before the two tables, by composing RID 500 and reading it back, so that a
    # RENAMED built-in Administrator is still found (Resolve-TierModelPrincipalSid.ps1:101-112,
    # Source 'ADUser-RID500'). Neither table knows the name, which is why it is listed here
    # rather than being treated as an unclassified reference.
    $script:Rid500Path = @('Administrator')

    # Keys that carry strings but never a principal name. Listed rather than inferred, because
    # the guard below is only as good as what it refuses to wave through.
    #   comment/gpoComment/description/notes  prose
    #   literalStrings                        machine-local principals, rule 2.4, own test below
    #   identityreference                     ACL delegations, own and stricter test below
    #   emptyGroups/groupSidOrName            restricted-groups entries already written as
    #                                         *S-1-5-32-nnn__Members, i.e. SIDs, not names
    $script:NonPrincipalKeys = @(
        'comment', 'gpoComment', 'description', 'notes',
        'literalStrings', 'identityreference', 'emptyGroups', 'groupSidOrName'
    )

    function Get-DefinedResolutionPath {
        <#
            Classifies a configured principal name by the path the resolver will take, using
            the product's own tables rather than a copy of them. Returns the path name, or
            $null when nothing defined claims it.
        #>
        param([Parameter(Mandatory)][string]$Name)

        if ($script:Rid500Path -contains $Name)       { return 'ADUser-RID500' }
        if ($script:NamePathByDesign -contains $Name) { return 'NamePathByDesign' }

        $canonical = & (Get-Module TierModel) { param($n) Get-TierModelCanonicalPrincipal -Principal $n } $Name
        if ($canonical) { return "Canonical$($canonical.Scope)Rid" }

        $wellKnown = & (Get-Module TierModel) { param($n) Get-WellKnownSid -Principal $n } $Name
        if ($wellKnown) { return 'WellKnown' }

        return $null
    }
}

Describe "Configuration principal inventory" -Tag 'Unit', 'Localization', 'Completeness' {

    # Anti-vacuity first, and it is not decorative: every assertion below is a count over what
    # the walker found, and a walker that silently read nothing would satisfy "no unresolved
    # principals" perfectly. Exact integers throughout, per the house style of the guard tests
    # (CLAUDE.md section 4 trap 6).

    It "reads all 17 configuration files" {
        $script:Inventory.Files.Count | Should -Be 17
    }

    It "collects the 62 principals the configuration names" {
        $script:Inventory.Referenced.Count | Should -Be 62
    }

    It "collects the 58 names of the 29 groups the configuration creates" {
        # 29 groups, each named twice: 'Tier 0 Admins' and 'Tier0Admins'. Both spellings occur
        # in tiermodel-gpos.json and both are the same directory object.
        $script:Inventory.CreatedGroups.Count | Should -Be 58
    }

    It "collects the 33 literalStrings" {
        # The figure CLAUDE.md section 6 item 6 measured against live SYSVOL: 33 declared,
        # 33 distinct non-SID principals found in [Privilege Rights], nothing left over.
        $script:Inventory.LiteralStrings.Count | Should -Be 33
    }

    It "collects the 12 ACL delegation identities" {
        $script:Inventory.IdentityReferences.Count | Should -Be 12
    }

    It "finds at least one principal under the declared key <Key>" -TestCases @(
        @{ Key = 'resolvableGroups' }
        @{ Key = 'forestRootOnly' }
        @{ Key = 'memberGroups' }
        @{ Key = 'denyApplyGroupPolicy' }
        @{ Key = 'memberComputerGroups' }
        @{ Key = 'allowedToAuthenticateFromDeviceGroups' }
        @{ Key = 'readGroup' }
        @{ Key = 'resetGroup' }
        @{ Key = 'decryptorGroup' }
        @{ Key = 'conditionalGroups.names' }
    ) {
        param($Key)
        # A declared key that matches nothing means either the configuration changed or the
        # walker stopped seeing it. Both are worth a failure: the inventory's completeness
        # rests on every key still being reached.
        $sites = $script:Inventory.Referenced.Values | Where-Object { $_ -match [regex]::Escape($Key) }
        @($sites).Count | Should -BeGreaterOrEqual 1 -Because "the key '$Key' must still name at least one principal"
    }

    It "sees the Authentication Policy Silo keys, which the localization report does not" {
        # NOTE: this is the reason this file walks the configuration itself instead of reusing
        # Get-ConfiguredPrincipalName from optional/Test-TierModelLocalizedDeployment.ps1.
        # That walker knows seven keys; the configuration uses eleven. It never sees
        # memberComputerGroups or allowedToAuthenticateFromDeviceGroups, so its "every
        # principal the configuration names" is six principals short — and those keys are the
        # Authentication Policy Silos, which is exactly where the localization defect of
        # CLAUDE.md section 5 lived. Do not "simplify" this file onto that walker.
        foreach ($name in @('Tier0MemberServers', 'Tier0PAWDevices', 'Tier1MemberServers',
                            'Tier1PAWDevices', 'Tier2EUDDevices', 'Tier2PAWDevices')) {
            $script:Inventory.Referenced.ContainsKey($name) | Should -Be $true -Because "$name is named by the silo configuration"
        }
    }
}

Describe "Every configured principal has a defined resolution path" -Tag 'Unit', 'Localization', 'Completeness' {

    It "<Name> is a group the configuration creates, or a built-in with a defined path" -ForEach @(
        # Built from the real configuration at discovery time, so a principal added to config/
        # without a resolution path fails here under its own name rather than inside a loop.
        foreach ($n in $DiscoveryReferencedNames) { @{ Name = $n } }
    ) {
        $createdByConfig = $script:Inventory.CreatedGroups.Contains($Name)
        $definedPath     = Get-DefinedResolutionPath -Name $Name

        # One of the two must hold. A name that is neither is an undeclared dependency: a
        # built-in nobody taught the resolver about, or a typo that will resolve to nothing on
        # deployment day and be reported as a missing entry rather than as a broken reference.
        ($createdByConfig -or $null -ne $definedPath) | Should -Be $true -Because @"
'$Name' is referenced by $(($script:Inventory.Referenced[$Name] | Sort-Object) -join ', ')
but it is neither a group config/tiermodel-groups.json creates nor a principal any defined
resolution path claims. Either add it to the group configuration, or - if it is a localizable
built-in - to the canonical RID table in Resolve-TierModelPrincipalSid.ps1.
"@
    }

    It "no undeclared configuration key names a localizable built-in" {
        # The drift guard, and the one assertion here that looks forward rather than back.
        # A new key carrying 'Domain Admins' would be resolved by whatever code consumes it,
        # on a path nobody checked for language independence - which is how the silo keys came
        # to be missed in the first place. Keys naming only Tier Model groups do not fire: those
        # names are language-independent by construction, so they are not the risk.
        $declared = @(Get-TierModelPrincipalKeyName) + @('conditionalGroups', 'names') + $script:NonPrincipalKeys

        # Anti-vacuity: the key index must actually hold the configuration's keys. An empty
        # index would make "no undeclared key names a built-in" true and meaningless.
        $script:Inventory.KeyValues.Count | Should -Be 98

        $offenders = @()
        foreach ($key in $script:Inventory.KeyValues.Keys) {
            if ($declared -contains $key) { continue }
            foreach ($value in $script:Inventory.KeyValues[$key]) {
                if ($script:Rid500Path -contains $value) { continue }
                $canonical = & (Get-Module TierModel) { param($n) Get-TierModelCanonicalPrincipal -Principal $n } $value
                $wellKnown = & (Get-Module TierModel) { param($n) Get-WellKnownSid -Principal $n } $value
                if ($canonical -or $wellKnown) { $offenders += "$key = '$value'" }
            }
        }

        $offenders | Should -BeNullOrEmpty -Because @"
these configuration keys carry the name of a localizable built-in but are not declared as
principal keys in tests/helpers/ConfigPrincipals.ps1. Whatever consumes them resolves a built-in
by a path this test does not cover. Add the key to Get-TierModelPrincipalKeyName if the product
resolves it through Resolve-TierModelPrincipalSid, or to NonPrincipalKeys with the reason.
"@
    }

    It "no ACL delegation identity is a localizable built-in" {
        # New-TierModelOuAcl.ps1:82-83 builds an NTAccount from identityreference and calls
        # .Translate(). That is the one principal path in the product that is language-DEPENDENT
        # by construction, and it is safe only because every value here is a Tier Model group
        # whose name the configuration itself sets. Put 'BUILTIN\Administrators' in there and
        # the delegation breaks on a German host - which is precisely the shape of the 31 test
        # failures that CLAUDE.md section 6 item 1 was about.
        # Anti-vacuity: this test is a loop over a set, and an empty set passes it perfectly.
        @($script:Inventory.IdentityReferences).Count | Should -Be 12

        $offenders = @()
        foreach ($value in $script:Inventory.IdentityReferences) {
            if ($null -ne (Get-DefinedResolutionPath -Name $value)) { $offenders += $value }
        }
        $offenders | Should -BeNullOrEmpty -Because "identityreference reaches NTAccount(...).Translate(), which is rendered in the host's language"
    }

    It "every ACL delegation identity is a group the configuration creates" {
        # The other half of the same invariant, stated positively so it cannot be satisfied by
        # an identity that is merely not a built-in.
        @($script:Inventory.IdentityReferences).Count | Should -Be 12
        foreach ($value in $script:Inventory.IdentityReferences) {
            $script:Inventory.CreatedGroups.Contains($value) | Should -Be $true -Because "'$value' is delegated on an OU but is not a group this configuration creates"
        }
    }

    It "every literalString is a machine-local principal with no domain SID" {
        # Rule 2.4: NT SERVICE\*, IIS APPPOOL\* and CLIUSR have SIDs derived from a service or
        # application-pool name that exists only on the target machine, so no domain controller
        # can compose them in any language. secedit resolves them on the member server. A plain
        # domain group name appearing here would be written into [Privilege Rights] unresolved
        # and would silently not apply.
        @($script:Inventory.LiteralStrings).Count | Should -Be 33
        foreach ($value in $script:Inventory.LiteralStrings) {
            $value | Should -Match '^(NT SERVICE\\|IIS APPPOOL\\|CLIUSR$)' -Because "literalStrings is for machine-local principals only"
        }
    }
}

Describe "Resolution against an English and a localized directory" -Tag 'Unit', 'Localization', 'Completeness', 'Language' {

    BeforeEach {
        InModuleScope TierModel {
            $script:SidCache = @{}
            $script:CanonicalDomainSidCache = @{}
        }
        Mock Write-TierModelLog { } -ModuleName TierModel

        # Resolve-ADPrincipalSid refuses to run without the ActiveDirectory module and the CI
        # runner has no RSAT. Stub the gate so the name path is reachable for the Tier Model
        # groups, which is the path they are supposed to take.
        Mock Get-Module { [PSCustomObject]@{ Name = 'ActiveDirectory'; Version = [version]'1.0.1.0' } } -ModuleName TierModel -ParameterFilter { $Name -eq 'ActiveDirectory' }
        Mock Import-Module { } -ModuleName TierModel

        Mock Get-ADDomain {
            [PSCustomObject]@{
                DNSRoot           = 'test.local'
                NetBIOSName       = 'TEST'
                DistinguishedName = 'DC=test,DC=local'
                DomainSID         = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1111111111-2222222222-3333333333')
            }
        } -ModuleName TierModel

        Mock Get-ADObject { $null } -ModuleName TierModel
    }

    # NOTE ON THE MOCK BODIES BELOW: every SID and name in them is a LITERAL. A $script:
    # variable set in BeforeAll is $null inside a -ModuleName mock body, because the body runs
    # in the module's session state (CLAUDE.md section 4 trap 2) - and a fixture built from
    # $null does not fail loudly, it sends the code down a fallback path while the test appears
    # to exercise the intended one.

    It "resolves every configured principal to the same SID on both directories" {
        # The central assertion of item 2's second bullet, at the resolver.
        $englishGroup = {
            param($Identity)
            $text = "$Identity"
            $byName = @{
                'Domain Admins' = 512; 'Domain Controllers' = 516; 'Cert Publishers' = 517
                'Group Policy Creator Owners' = 520; 'Read-only Domain Controllers' = 521
                'Cloneable Domain Controllers' = 522; 'Key Admins' = 526
                'Allowed RODC Password Replication Group' = 571
                'Enterprise Admins' = 519; 'Schema Admins' = 518; 'Enterprise Key Admins' = 527
                'Enterprise Read-only Domain Controllers' = 498
            }
            if ($text -match '^S-1-5-21-1111111111-2222222222-3333333333-(\d+)$') {
                return [PSCustomObject]@{ Name = "Group $($Matches[1])"; SID = [System.Security.Principal.SecurityIdentifier]::new($text) }
            }
            if ($byName.ContainsKey($text)) {
                return [PSCustomObject]@{ Name = $text; SID = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-21-1111111111-2222222222-3333333333-$($byName[$text])") }
            }
            $allocated = @{
                'PAWDomainJoin' = 1101
                'Tier0Admins' = 1102; 'Tier0MemberServers' = 1103; 'Tier0Operators' = 1104
                'Tier0PAWDevices' = 1105; 'Tier0ServerOperators' = 1106; 'Tier0ServiceAccounts' = 1107
                'Tier0VpnAccounts' = 1108; 'Tier1Admins' = 1109; 'Tier1MemberServers' = 1110
                'Tier1Operators' = 1111; 'Tier1PAWDevices' = 1112; 'Tier1ServerDomainJoin' = 1113
                'Tier1ServerOperators' = 1114; 'Tier1ServiceAccounts' = 1115; 'Tier1VpnAccounts' = 1116
                'Tier2AccountOperators' = 1117; 'Tier2Admins' = 1118; 'Tier2ComputerQuarantineOperators' = 1119
                'Tier2DeviceOperators' = 1120; 'Tier2EUDDevices' = 1121; 'Tier2EUDDomainJoin' = 1122
                'Tier2GroupOperators' = 1123; 'Tier2HelpdeskOperators' = 1124; 'Tier2LocalDeviceOperators' = 1125
                'Tier2Operators' = 1126; 'Tier2PAWDevices' = 1127; 'Tier2ServiceAccounts' = 1128
                'Tier2VpnAccounts' = 1129
                'Tier 0 Admins' = 1102; 'Tier 0 Server Operators' = 1106; 'Tier 1 Admins' = 1109
                'Tier 1 Server Operators' = 1114; 'Tier 2 Admins' = 1118; 'Tier 2 Device Operators' = 1120
                'DnsAdmins' = 1130; 'DnsUpdateProxy' = 1131
            }
            $key = $allocated.Keys | Where-Object { $_ -ieq $text } | Select-Object -First 1
            if ($key) {
                return [PSCustomObject]@{ Name = $key; SID = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-21-1111111111-2222222222-3333333333-$($allocated[$key])") }
            }
            throw "Cannot find an object with identity: '$text'"
        }

        # The localized directory: identical objects, identical SIDs, but NO built-in answers to
        # its English name. Tier Model groups still do — the configuration named them, not the
        # installer — and so do DnsAdmins / DnsUpdateProxy, which the DNS Server role names in
        # English on every language of Windows.
        $germanGroup = {
            param($Identity)
            $text = "$Identity"
            $german = @{
                '512' = 'Domänen-Admins'; '516' = 'Domänencontroller'; '517' = 'Zertifikatherausgeber'
                '520' = 'Richtlinien-Ersteller-Besitzer'; '521' = 'Schreibgeschützte Domänencontroller'
                '522' = 'Klonbare Domänencontroller'; '526' = 'Schlüssel-Admins'
                '571' = 'Zulässige RODC-Kennwortreplikationsgruppe'
                '519' = 'Organisations-Admins'; '518' = 'Schema-Admins'
                '527' = 'Organisations-Schlüssel-Admins'; '498' = 'Schreibgeschützte Organisationsdomänencontroller'
            }
            if ($text -match '^S-1-5-21-1111111111-2222222222-3333333333-(\d+)$') {
                $rid = $Matches[1]
                $name = if ($german.ContainsKey($rid)) { $german[$rid] } else { "Gruppe $rid" }
                return [PSCustomObject]@{ Name = $name; SID = [System.Security.Principal.SecurityIdentifier]::new($text) }
            }
            $allocated = @{
                'PAWDomainJoin' = 1101
                'Tier0Admins' = 1102; 'Tier0MemberServers' = 1103; 'Tier0Operators' = 1104
                'Tier0PAWDevices' = 1105; 'Tier0ServerOperators' = 1106; 'Tier0ServiceAccounts' = 1107
                'Tier0VpnAccounts' = 1108; 'Tier1Admins' = 1109; 'Tier1MemberServers' = 1110
                'Tier1Operators' = 1111; 'Tier1PAWDevices' = 1112; 'Tier1ServerDomainJoin' = 1113
                'Tier1ServerOperators' = 1114; 'Tier1ServiceAccounts' = 1115; 'Tier1VpnAccounts' = 1116
                'Tier2AccountOperators' = 1117; 'Tier2Admins' = 1118; 'Tier2ComputerQuarantineOperators' = 1119
                'Tier2DeviceOperators' = 1120; 'Tier2EUDDevices' = 1121; 'Tier2EUDDomainJoin' = 1122
                'Tier2GroupOperators' = 1123; 'Tier2HelpdeskOperators' = 1124; 'Tier2LocalDeviceOperators' = 1125
                'Tier2Operators' = 1126; 'Tier2PAWDevices' = 1127; 'Tier2ServiceAccounts' = 1128
                'Tier2VpnAccounts' = 1129
                'Tier 0 Admins' = 1102; 'Tier 0 Server Operators' = 1106; 'Tier 1 Admins' = 1109
                'Tier 1 Server Operators' = 1114; 'Tier 2 Admins' = 1118; 'Tier 2 Device Operators' = 1120
                'DnsAdmins' = 1130; 'DnsUpdateProxy' = 1131
            }
            $key = $allocated.Keys | Where-Object { $_ -ieq $text } | Select-Object -First 1
            if ($key) {
                return [PSCustomObject]@{ Name = $key; SID = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-21-1111111111-2222222222-3333333333-$($allocated[$key])") }
            }
            throw "Cannot find an object with identity: '$text'"
        }

        # BOTH Name and SamAccountName, because two different paths read two different
        # properties of the same object: the RID 500 branch logs SamAccountName
        # (Resolve-TierModelPrincipalSid.ps1:107), and the canonical read-back returns
        # $adObject.Name as ActualName (Resolve-TierModelCanonicalSid, for Guest at RID 501).
        # The module runs under Set-StrictMode -Version Latest, where reading a property the
        # object does not have THROWS - so a mock missing one of them fails the test from
        # inside the product, with a message about the product.
        $user = {
            param($Identity)
            $text = "$Identity"
            if ($text -eq 'S-1-5-21-1111111111-2222222222-3333333333-500') {
                return [PSCustomObject]@{ Name = 'Administrator'; SamAccountName = 'Administrator'; SID = [System.Security.Principal.SecurityIdentifier]::new($text) }
            }
            if ($text -eq 'S-1-5-21-1111111111-2222222222-3333333333-501') {
                return [PSCustomObject]@{ Name = 'Guest'; SamAccountName = 'Guest'; SID = [System.Security.Principal.SecurityIdentifier]::new($text) }
            }
            throw "Cannot find an object with identity: '$text'"
        }

        # The localized counterpart: same objects, same SIDs, German rendered names. Used for
        # the second pass so that nothing in it can answer to an English name.
        $germanUser = {
            param($Identity)
            $text = "$Identity"
            if ($text -eq 'S-1-5-21-1111111111-2222222222-3333333333-500') {
                return [PSCustomObject]@{ Name = 'Administrator'; SamAccountName = 'Administrator'; SID = [System.Security.Principal.SecurityIdentifier]::new($text) }
            }
            if ($text -eq 'S-1-5-21-1111111111-2222222222-3333333333-501') {
                return [PSCustomObject]@{ Name = 'Gast'; SamAccountName = 'Gast'; SID = [System.Security.Principal.SecurityIdentifier]::new($text) }
            }
            throw "Cannot find an object with identity: '$text'"
        }

        $english = @{}
        Mock Get-ADGroup $englishGroup -ModuleName TierModel
        Mock Get-ADUser  $user         -ModuleName TierModel
        foreach ($name in $script:ReferencedNames) {
            $r = Resolve-TierModelPrincipalSid -Principal $name -DomainController $script:TestDc -WarningAction SilentlyContinue
            $english[$name] = @{ Sid = $r.Sid; Source = $r.Source; Success = $r.Success }
        }

        InModuleScope TierModel {
            $script:SidCache = @{}
            $script:CanonicalDomainSidCache = @{}
        }

        $localized = @{}
        Mock Get-ADGroup $germanGroup -ModuleName TierModel
        Mock Get-ADUser  $germanUser  -ModuleName TierModel
        foreach ($name in $script:ReferencedNames) {
            $r = Resolve-TierModelPrincipalSid -Principal $name -DomainController $script:TestDc -WarningAction SilentlyContinue
            $localized[$name] = @{ Sid = $r.Sid; Source = $r.Source; Success = $r.Success }
        }

        # Anti-vacuity: both passes must have produced a full set. A resolver that returned
        # nothing at all would make every comparison below trivially equal.
        $english.Count   | Should -Be 62
        $localized.Count | Should -Be 62
        @($english.Values   | Where-Object { $_.Success }).Count | Should -Be 62
        @($localized.Values | Where-Object { $_.Success }).Count | Should -Be 62

        $differences = @()
        foreach ($name in $script:ReferencedNames) {
            if ($english[$name].Sid -ne $localized[$name].Sid) {
                $differences += "$name : english=$($english[$name].Sid) localized=$($localized[$name].Sid)"
            }
            if ($english[$name].Source -ne $localized[$name].Source) {
                # Source is compared as deliberately as the SID: the same SID reached by a
                # DIFFERENT route means one directory fell back to a name lookup, which is the
                # failure mode this whole change removed. It is invisible if you compare SIDs.
                $differences += "$name : english source=$($english[$name].Source) localized source=$($localized[$name].Source)"
            }
        }
        $differences | Should -BeNullOrEmpty
    }

    It "resolves no localizable built-in through a name lookup on the localized directory" {
        # Stated separately from the equality above because equality alone would be satisfied if
        # BOTH directories fell back to a name lookup.
        $germanGroup = {
            param($Identity)
            $text = "$Identity"
            if ($text -match '^S-1-5-21-1111111111-2222222222-3333333333-(\d+)$') {
                return [PSCustomObject]@{ Name = "Gruppe $($Matches[1])"; SID = [System.Security.Principal.SecurityIdentifier]::new($text) }
            }
            # No built-in and no Tier Model group answers by name here. Anything that still
            # resolves did so without asking the directory for a name.
            throw "Cannot find an object with identity: '$text'"
        }
        Mock Get-ADGroup $germanGroup -ModuleName TierModel
        Mock Get-ADUser {
            param($Identity)
            $text = "$Identity"
            if ($text -match '^S-1-5-21-1111111111-2222222222-3333333333-(500|501)$') {
                return [PSCustomObject]@{ Name = "Benutzer $($Matches[1])"; SamAccountName = "Benutzer $($Matches[1])"; SID = [System.Security.Principal.SecurityIdentifier]::new($text) }
            }
            throw "Cannot find an object with identity: '$text'"
        } -ModuleName TierModel

        $builtIns = @($script:ReferencedNames | Where-Object {
            $path = Get-DefinedResolutionPath -Name $_
            $null -ne $path -and $path -ne 'NamePathByDesign'
        })

        # Anti-vacuity: the set under test must be the 25 built-ins the configuration actually
        # names. 27 are not created by the configuration; DnsAdmins and DnsUpdateProxy take the
        # name path by design and are excluded above.
        $builtIns.Count | Should -Be 25

        foreach ($name in $builtIns) {
            $result = Resolve-TierModelPrincipalSid -Principal $name -DomainController $script:TestDc -WarningAction SilentlyContinue
            $result.Success | Should -Be $true -Because "'$name' must resolve without the directory answering to its English name"
            $result.Source  | Should -Not -BeIn @('ADGroup', 'ADUser', 'ADObject') -Because "'$name' resolved through a name lookup, which a localized directory cannot serve"
        }
    }
}

Describe "[Privilege Rights] parity between an English and a localized directory" -Tag 'Unit', 'Localization', 'Completeness', 'Language' {

    BeforeEach {
        InModuleScope TierModel {
            $script:SidCache = @{}
            $script:CanonicalDomainSidCache = @{}
        }
        Mock Write-TierModelLog { } -ModuleName TierModel
        Mock Get-Module { [PSCustomObject]@{ Name = 'ActiveDirectory'; Version = [version]'1.0.1.0' } } -ModuleName TierModel -ParameterFilter { $Name -eq 'ActiveDirectory' }
        Mock Import-Module { } -ModuleName TierModel
        Mock Get-ADObject { $null } -ModuleName TierModel
        Mock Get-ADDomain {
            [PSCustomObject]@{
                DNSRoot           = 'test.local'
                NetBIOSName       = 'TEST'
                DistinguishedName = 'DC=test,DC=local'
                DomainSID         = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1111111111-2222222222-3333333333')
            }
        } -ModuleName TierModel
        Mock Get-ADUser {
            param($Identity)
            $text = "$Identity"
            if ($text -match '^S-1-5-21-1111111111-2222222222-3333333333-(500|501)$') {
                return [PSCustomObject]@{ Name = "User $($Matches[1])"; SamAccountName = "User $($Matches[1])"; SID = [System.Security.Principal.SecurityIdentifier]::new($text) }
            }
            throw "Cannot find an object with identity: '$text'"
        } -ModuleName TierModel
    }

    It "generates byte-identical [Privilege Rights] from the real GPO configuration" {
        # The second half of item 2's second bullet, and the one that covers what the resolver
        # test cannot: the generated template is what actually lands in SYSVOL.
        $gpoConfig = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' 'config' 'tiermodel-gpos.json') -Raw | ConvertFrom-Json

        $entries = @()
        foreach ($ouProperty in $gpoConfig.gpos.PSObject.Properties) {
            foreach ($sectionProperty in $ouProperty.Value.PSObject.Properties) {
                foreach ($entry in @($sectionProperty.Value)) {
                    if ($entry -isnot [psobject]) { continue }
                    if ($entry.PSObject.Properties['userRightsAssignments'] -or $entry.PSObject.Properties['restrictedGroups']) {
                        $entries += $entry
                    }
                }
            }
        }

        # Anti-vacuity: measured on the real configuration. 23 GPO entries declare these two
        # sections at all; 21 of them carry a non-empty userRightsAssignments and 22 a non-empty
        # restrictedGroups. The count here is by DECLARATION, because an entry that declares an
        # empty section still has to produce the same template on both directories.
        $entries.Count | Should -Be 23

        $groupByName = {
            param($Identity)
            $text = "$Identity"
            $byName = @{
                'Domain Admins' = 512; 'Domain Controllers' = 516; 'Cert Publishers' = 517
                'Group Policy Creator Owners' = 520; 'Read-only Domain Controllers' = 521
                'Cloneable Domain Controllers' = 522; 'Key Admins' = 526
                'Allowed RODC Password Replication Group' = 571
                'Enterprise Admins' = 519; 'Schema Admins' = 518; 'Enterprise Key Admins' = 527
                'Enterprise Read-only Domain Controllers' = 498
            }
            if ($text -match '^S-1-5-21-1111111111-2222222222-3333333333-(\d+)$') {
                return [PSCustomObject]@{ Name = "Group $($Matches[1])"; SID = [System.Security.Principal.SecurityIdentifier]::new($text) }
            }
            if ($byName.ContainsKey($text)) {
                return [PSCustomObject]@{ Name = $text; SID = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-21-1111111111-2222222222-3333333333-$($byName[$text])") }
            }
            if ($text -match '^(PAWDomainJoin|Tier[0-9][A-Za-z]+|Tier [0-9] [A-Za-z ]+|DnsAdmins|DnsUpdateProxy)$') {
                # One stable RID per name, so both passes allocate identically and any
                # difference in the output is the language and nothing else.
                #
                # Summed character codes, NOT String.GetHashCode(): .NET randomises string hash
                # codes per process. Both passes happen to run in one process today, so a hash
                # would agree by accident rather than by contract - and the day they do not, the
                # test fails with a wall of SID differences that read as a product defect. Two
                # names colliding on one RID is harmless: both passes collide the same way, and
                # the SID count asserted below is what guards against an empty comparison.
                $rid = 1100 + (($text.ToLowerInvariant().ToCharArray() | ForEach-Object { [int]$_ } | Measure-Object -Sum).Sum % 800)
                return [PSCustomObject]@{ Name = $text; SID = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-21-1111111111-2222222222-3333333333-$rid") }
            }
            throw "Cannot find an object with identity: '$text'"
        }

        $groupLocalized = {
            param($Identity)
            $text = "$Identity"
            if ($text -match '^S-1-5-21-1111111111-2222222222-3333333333-(\d+)$') {
                return [PSCustomObject]@{ Name = "Gruppe $($Matches[1])"; SID = [System.Security.Principal.SecurityIdentifier]::new($text) }
            }
            if ($text -match '^(PAWDomainJoin|Tier[0-9][A-Za-z]+|Tier [0-9] [A-Za-z ]+|DnsAdmins|DnsUpdateProxy)$') {
                # Same rule as the English fixture above, for the same reason.
                $rid = 1100 + (($text.ToLowerInvariant().ToCharArray() | ForEach-Object { [int]$_ } | Measure-Object -Sum).Sum % 800)
                return [PSCustomObject]@{ Name = $text; SID = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-21-1111111111-2222222222-3333333333-$rid") }
            }
            throw "Cannot find an object with identity: '$text'"
        }

        # -StrictMode is what makes this comparison mean anything. Without it the generator
        # WARNS on a principal it cannot resolve and leaves it out of the URA
        # (New-TierModelGptTmplContent.ps1:189-196), so two runs that both failed to resolve the
        # same principals would produce identical templates and pass. With it, a principal that
        # does not resolve fails the test instead of quietly shrinking both sides of it.
        Mock Get-ADGroup $groupByName -ModuleName TierModel
        $englishContent = foreach ($entry in $entries) {
            New-TierModelGptTmplContent -GPOData $entry -DomainController $script:TestDc -StrictMode
        }

        InModuleScope TierModel {
            $script:SidCache = @{}
            $script:CanonicalDomainSidCache = @{}
        }

        Mock Get-ADGroup $groupLocalized -ModuleName TierModel
        $localizedContent = foreach ($entry in $entries) {
            New-TierModelGptTmplContent -GPOData $entry -DomainController $script:TestDc -StrictMode
        }

        # Anti-vacuity again, and it matters more here than anywhere else in the file: two empty
        # strings are byte-identical. The generator must have produced a template per entry, and
        # those templates must actually carry SIDs.
        @($englishContent).Count   | Should -Be 23
        @($localizedContent).Count | Should -Be 23
        $sidCount = ([regex]::Matches(($englishContent -join "`n"), '\*S-1-5-')).Count
        $sidCount | Should -BeGreaterOrEqual 200 -Because 'the real configuration writes hundreds of SIDs into [Privilege Rights]'

        for ($i = 0; $i -lt $entries.Count; $i++) {
            @($localizedContent)[$i] | Should -Be @($englishContent)[$i] -Because "GPO '$($entries[$i].name)' must produce the same [Privilege Rights] on a localized directory"
        }
    }

    It "writes every configured literalString through verbatim" {
        # The counterpart to the SID assertion: literalStrings must NOT be resolved. They have
        # no domain SID by construction and secedit resolves them on the target machine, so a
        # generator that tried to turn them into SIDs would drop them (rule 2.4).
        $gpoConfig = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' 'config' 'tiermodel-gpos.json') -Raw | ConvertFrom-Json

        Mock Get-ADGroup {
            param($Identity)
            $text = "$Identity"
            if ($text -match '^S-1-5-21-1111111111-2222222222-3333333333-(\d+)$') {
                return [PSCustomObject]@{ Name = "Gruppe $($Matches[1])"; SID = [System.Security.Principal.SecurityIdentifier]::new($text) }
            }
            return [PSCustomObject]@{ Name = $text; SID = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1111111111-2222222222-3333333333-1199') }
        } -ModuleName TierModel

        $rendered = New-Object System.Text.StringBuilder
        $seen = 0
        foreach ($ouProperty in $gpoConfig.gpos.PSObject.Properties) {
            foreach ($sectionProperty in $ouProperty.Value.PSObject.Properties) {
                foreach ($entry in @($sectionProperty.Value)) {
                    if ($entry -isnot [psobject]) { continue }
                    # Non-EMPTY, not merely declared: two of the 23 entries carry an empty
                    # userRightsAssignments, and an empty section writes no literalStrings.
                    if (-not $entry.PSObject.Properties['userRightsAssignments']) { continue }
                    if (@($entry.userRightsAssignments).Count -eq 0) { continue }
                    $seen++
                    $null = $rendered.AppendLine((New-TierModelGptTmplContent -GPOData $entry -DomainController $script:TestDc))
                }
            }
        }

        $seen | Should -Be 21
        $text = $rendered.ToString()

        $inventory = Get-TierModelConfigPrincipalInventory -ConfigRoot (Join-Path $PSScriptRoot '..' 'config')
        $inventory.LiteralStrings.Count | Should -Be 33
        foreach ($literal in $inventory.LiteralStrings) {
            $text | Should -BeLike "*$literal*" -Because "'$literal' is a machine-local principal and must reach [Privilege Rights] unresolved"
        }
    }
}
