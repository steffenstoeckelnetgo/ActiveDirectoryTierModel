<#
.SYNOPSIS
Unit tests for canonical (language-independent) built-in principal resolution.

.DESCRIPTION
Pester v5 tests for the SID-first resolution added to Resolve-TierModelPrincipalSid.ps1:
- Get-TierModelCanonicalPrincipal  - canonical English name to well-known RID
- Resolve-TierModelCanonicalSid    - RID composed against the target domain, then verified
- Resolve-TierModelPrincipalSid    - resolution order and caching
- ConvertTo-TierModelIdentitySid   - identity normalisation for ACL comparison

The central test is the GERMAN DIRECTORY fixture: Get-ADGroup by NAME throws for every
built-in, exactly as it behaves on a localized domain. Every canonical principal must still
resolve to the right SID there. That is the proof that no code path depends on the name.

.NOTES
Tags: Unit, Resolution, Language, Canonical
#>

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\modules\TierModel\TierModel.psd1'
    Import-Module $modulePath -Force

    $script:TestDomainSid = 'S-1-5-21-1111111111-2222222222-3333333333'
    $script:TestDc = 'dc01.test.local'

    # Canonical name -> expected SID. These are the built-ins that config/tiermodel-gpos.json,
    # config/tiermodel-winlaps.json and config/tiermodel-authsilos.json actually reference.
    $script:DomainRidExpectations = @{
        'Domain Admins'                           = "$script:TestDomainSid-512"
        'Domain Users'                            = "$script:TestDomainSid-513"
        'Domain Guests'                           = "$script:TestDomainSid-514"
        'Domain Computers'                        = "$script:TestDomainSid-515"
        'Domain Controllers'                      = "$script:TestDomainSid-516"
        'Cert Publishers'                         = "$script:TestDomainSid-517"
        'Group Policy Creator Owners'             = "$script:TestDomainSid-520"
        'Read-only Domain Controllers'            = "$script:TestDomainSid-521"
        'Cloneable Domain Controllers'            = "$script:TestDomainSid-522"
        'Protected Users'                         = "$script:TestDomainSid-525"
        'Key Admins'                              = "$script:TestDomainSid-526"
        'Allowed RODC Password Replication Group' = "$script:TestDomainSid-571"
    }

    $script:ForestRootRidExpectations = @{
        'Enterprise Admins'                       = "$script:TestDomainSid-519"
        'Schema Admins'                           = "$script:TestDomainSid-518"
        'Enterprise Key Admins'                   = "$script:TestDomainSid-527"
        'Enterprise Read-only Domain Controllers' = "$script:TestDomainSid-498"
    }

    # Built-ins with an absolute SID: served by the static table, no directory read at all.
    $script:AbsoluteSidExpectations = @{
        'Administrators'          = 'S-1-5-32-544'
        'Users'                   = 'S-1-5-32-545'
        'Guests'                  = 'S-1-5-32-546'
        'Account Operators'       = 'S-1-5-32-548'
        'Server Operators'        = 'S-1-5-32-549'
        'Backup Operators'        = 'S-1-5-32-551'
        'Cryptographic Operators' = 'S-1-5-32-569'
        'IIS_IUSRS'               = 'S-1-5-32-568'
        'Authenticated Users'     = 'S-1-5-11'
        'SYSTEM'                  = 'S-1-5-18'
        'Everyone'                = 'S-1-1-0'
        'Local account'           = 'S-1-5-113'
        'SELF'                    = 'S-1-5-10'
    }
}

Describe "Get-TierModelCanonicalPrincipal" -Tag 'Unit', 'Resolution', 'Canonical' {

    BeforeEach {
        # The SID cache and the memoized domain SID persist for the module session; clear both
        # so each test observes its own mocks rather than a neighbour's result.
        InModuleScope TierModel {
            $script:SidCache = @{}
            $script:CanonicalDomainSidCache = @{}
        }
        Mock Write-TierModelLog { } -ModuleName TierModel
    }

    It "maps <Name> to RID <Rid> in scope <Scope>" -TestCases @(
        @{ Name = 'Domain Admins';                           Rid = 512; Scope = 'Domain' }
        @{ Name = 'Domain Controllers';                      Rid = 516; Scope = 'Domain' }
        @{ Name = 'Read-only Domain Controllers';            Rid = 521; Scope = 'Domain' }
        @{ Name = 'Guest';                                   Rid = 501; Scope = 'Domain' }
        @{ Name = 'Enterprise Admins';                       Rid = 519; Scope = 'ForestRoot' }
        @{ Name = 'Schema Admins';                           Rid = 518; Scope = 'ForestRoot' }
        @{ Name = 'Enterprise Read-only Domain Controllers'; Rid = 498; Scope = 'ForestRoot' }
    ) {
        param($Name, $Rid, $Scope)
        $entry = InModuleScope TierModel -Parameters @{ N = $Name } { Get-TierModelCanonicalPrincipal -Principal $N }
        $entry | Should -Not -BeNullOrEmpty
        $entry.Rid | Should -Be $Rid
        $entry.Scope | Should -Be $Scope
    }

    It "matches case-insensitively" {
        $entry = InModuleScope TierModel { Get-TierModelCanonicalPrincipal -Principal 'domain admins' }
        $entry.Rid | Should -Be 512
    }

    It "resolves Guest as a user, not a group" {
        $entry = InModuleScope TierModel { Get-TierModelCanonicalPrincipal -Principal 'Guest' }
        $entry.ObjectClass | Should -Be 'user'
    }

    It "returns nothing for <Name>, which is not a localizable built-in" -TestCases @(
        @{ Name = 'Tier0Admins' }
        @{ Name = 'DnsAdmins' }
        @{ Name = 'DnsUpdateProxy' }
        @{ Name = 'PawDomainJoin' }
        @{ Name = 'svc-pawdomainjoin' }
    ) {
        param($Name)
        $entry = InModuleScope TierModel -Parameters @{ N = $Name } { Get-TierModelCanonicalPrincipal -Principal $N }
        $entry | Should -BeNullOrEmpty
    }

    It "does not claim Administrator, which keeps its own RID 500 path" {
        $entry = InModuleScope TierModel { Get-TierModelCanonicalPrincipal -Principal 'Administrator' }
        $entry | Should -BeNullOrEmpty
    }
}

Describe "Resolve-TierModelPrincipalSid on an ENGLISH directory" -Tag 'Unit', 'Resolution', 'Canonical' {

    BeforeEach {
        InModuleScope TierModel {
            $script:SidCache = @{}
            $script:CanonicalDomainSidCache = @{}
        }
        Mock Write-TierModelLog { } -ModuleName TierModel

    # NOTE: mock bodies must not reference $script: variables from BeforeAll. A mock declared
    # with -ModuleName runs in the MODULE's session state, where $script:TestDomainSid resolves
    # to $null - which silently produced a malformed SID and sent every lookup down the
    # name-resolution fallback. The literal is used inside mock bodies for that reason.
        Mock Get-ADDomain {
            [PSCustomObject]@{
                DNSRoot           = 'test.local'
                NetBIOSName       = 'TEST'
                DistinguishedName = 'DC=test,DC=local'
                DomainSID         = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1111111111-2222222222-3333333333')
            }
        } -ModuleName TierModel

        Mock Get-ADGroup {
            param($Identity)
            [PSCustomObject]@{
                Name = "Group $Identity"
                SID  = [System.Security.Principal.SecurityIdentifier]::new("$Identity")
            }
        } -ModuleName TierModel
    }

    It "resolves domain-relative <Name> by RID" -TestCases @(
        foreach ($k in @('Domain Admins', 'Domain Controllers', 'Cert Publishers', 'Read-only Domain Controllers', 'Key Admins')) {
            @{ Name = $k }
        }
    ) {
        param($Name)
        $result = Resolve-TierModelPrincipalSid -Principal $Name -DomainController $script:TestDc
        $result.Success | Should -Be $true
        $result.Sid | Should -Be $script:DomainRidExpectations[$Name]
        $result.Source | Should -Be 'CanonicalDomainRid'
    }

    It "resolves forest-root <Name> against the forest root domain SID" -TestCases @(
        @{ Name = 'Enterprise Admins' }
        @{ Name = 'Schema Admins' }
    ) {
        param($Name)
        $result = Resolve-TierModelPrincipalSid -Principal $Name -DomainController $script:TestDc
        $result.Success | Should -Be $true
        $result.Sid | Should -Be $script:ForestRootRidExpectations[$Name]
        $result.Source | Should -Be 'CanonicalForestRootRid'
    }

    It "serves absolute built-in <Name> from the static table without a directory read" -TestCases @(
        foreach ($k in @('Administrators', 'Guests', 'Server Operators', 'Cryptographic Operators', 'Authenticated Users', 'SYSTEM')) {
            @{ Name = $k }
        }
    ) {
        param($Name)
        $result = Resolve-TierModelPrincipalSid -Principal $Name -DomainController $script:TestDc
        $result.Success | Should -Be $true
        $result.Sid | Should -Be $script:AbsoluteSidExpectations[$Name]
        $result.Source | Should -Be 'WellKnown'
        Should -Invoke Get-ADDomain -ModuleName TierModel -Times 0 -Exactly
    }

    It "reads the domain SID once no matter how many canonical principals are resolved" {
        foreach ($name in @('Domain Admins', 'Domain Controllers', 'Cert Publishers', 'Key Admins')) {
            $null = Resolve-TierModelPrincipalSid -Principal $name -DomainController $script:TestDc
        }
        Should -Invoke Get-ADDomain -ModuleName TierModel -Times 1 -Exactly
    }
}

Describe "Resolve-TierModelPrincipalSid on a GERMAN directory" -Tag 'Unit', 'Resolution', 'Canonical', 'Language' {

    BeforeEach {
        InModuleScope TierModel {
            $script:SidCache = @{}
            $script:CanonicalDomainSidCache = @{}
        }
        Mock Write-TierModelLog { } -ModuleName TierModel

        Mock Get-ADDomain {
            [PSCustomObject]@{
                DNSRoot           = 'test.local'
                NetBIOSName       = 'TEST'
                DistinguishedName = 'DC=test,DC=local'
                DomainSID         = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1111111111-2222222222-3333333333')
            }
        } -ModuleName TierModel

        # A German domain answers to the LOCALIZED names only. Every lookup by an English name
        # fails, exactly as Get-ADGroup -Identity 'Domain Admins' does there. A SID always works.
        Mock Get-ADGroup {
            param($Identity)
            $identityText = "$Identity"
            if ($identityText -notmatch '^S-1-') {
                throw "Cannot find an object with identity: '$identityText'"
            }
            $germanNames = @{
                'S-1-5-21-1111111111-2222222222-3333333333-512' = 'Domänen-Admins'
                'S-1-5-21-1111111111-2222222222-3333333333-516' = 'Domänencontroller'
                'S-1-5-21-1111111111-2222222222-3333333333-517' = 'Zertifikatherausgeber'
                'S-1-5-21-1111111111-2222222222-3333333333-521' = 'Schreibgeschützte Domänencontroller'
                'S-1-5-21-1111111111-2222222222-3333333333-519' = 'Organisations-Admins'
            }
            [PSCustomObject]@{
                Name = if ($germanNames.ContainsKey($identityText)) { $germanNames[$identityText] } else { "Gruppe $identityText" }
                SID  = [System.Security.Principal.SecurityIdentifier]::new($identityText)
            }
        } -ModuleName TierModel
    }

    It "resolves <Name> to the same SID as on an English directory" -TestCases @(
        foreach ($k in @('Domain Admins', 'Domain Controllers', 'Cert Publishers', 'Read-only Domain Controllers',
                         'Group Policy Creator Owners', 'Cloneable Domain Controllers', 'Key Admins')) {
            @{ Name = $k }
        }
    ) {
        param($Name)
        $result = Resolve-TierModelPrincipalSid -Principal $Name -DomainController $script:TestDc
        $result.Success | Should -Be $true
        $result.Sid | Should -Be $script:DomainRidExpectations[$Name]
    }

    It "resolves forest-root <Name> to the same SID as on an English directory" -TestCases @(
        @{ Name = 'Enterprise Admins' }
        @{ Name = 'Schema Admins' }
        @{ Name = 'Enterprise Key Admins' }
    ) {
        param($Name)
        $result = Resolve-TierModelPrincipalSid -Principal $Name -DomainController $script:TestDc
        $result.Success | Should -Be $true
        $result.Sid | Should -Be $script:ForestRootRidExpectations[$Name]
    }

    It "reports the localized directory name it found, for the log" {
        $result = Resolve-TierModelPrincipalSid -Principal 'Domain Admins' -DomainController $script:TestDc
        $result.ActualName | Should -Be 'Domänen-Admins'
    }

    It "still serves absolute built-ins, which never need the directory" {
        $result = Resolve-TierModelPrincipalSid -Principal 'Server Operators' -DomainController $script:TestDc
        $result.Success | Should -Be $true
        $result.Sid | Should -Be 'S-1-5-32-549'
    }
}

Describe "Resolve-TierModelPrincipalSid when a built-in is absent" -Tag 'Unit', 'Resolution', 'Canonical' {

    BeforeEach {
        InModuleScope TierModel {
            $script:SidCache = @{}
            $script:CanonicalDomainSidCache = @{}
        }
        Mock Write-TierModelLog { } -ModuleName TierModel

        # Resolve-ADPrincipalSid refuses to run without the ActiveDirectory module, and the CI
        # runner has no RSAT. Stub the gate so the name-lookup fallback is reachable.
        Mock Get-Module { [PSCustomObject]@{ Name = 'ActiveDirectory'; Version = [version]'1.0.1.0' } } -ModuleName TierModel -ParameterFilter { $Name -eq 'ActiveDirectory' }
        Mock Import-Module { } -ModuleName TierModel

        Mock Get-ADDomain {
            [PSCustomObject]@{
                DNSRoot           = 'child.test.local'
                NetBIOSName       = 'CHILD'
                DistinguishedName = 'DC=child,DC=test,DC=local'
                DomainSID         = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1111111111-2222222222-3333333333')
            }
        } -ModuleName TierModel
        Mock Get-ADObject { $null } -ModuleName TierModel
        Mock Get-ADUser { throw 'not found' } -ModuleName TierModel
    }

    It "does not resolve forest-root <Name> in a child domain, where RID <Rid> is unallocated" -TestCases @(
        @{ Name = 'Enterprise Admins'; Rid = 519 }
        @{ Name = 'Schema Admins';     Rid = 518 }
    ) {
        param($Name, $Rid)
        # RID 519 / 518 are allocated only in the forest root, so reading them back fails here.
        Mock Get-ADGroup {
            param($Identity)
            throw "Cannot find an object with identity: '$Identity'"
        } -ModuleName TierModel

        $result = Resolve-TierModelPrincipalSid -Principal $Name -DomainController $script:TestDc -WarningAction SilentlyContinue
        $result.Success | Should -Be $false
        $result.Sid | Should -BeNullOrEmpty
    }

    It "does not invent a SID for an optional group the domain never created" {
        # Allowed RODC Password Replication Group can legitimately be missing. Composing
        # <domainSID>-571 without the read-back would write an unresolvable SID into
        # GPO [Privilege Rights] - a security-configuration failure, not a missing entry.
        Mock Get-ADGroup {
            param($Identity)
            throw "Cannot find an object with identity: '$Identity'"
        } -ModuleName TierModel

        $result = Resolve-TierModelPrincipalSid -Principal 'Allowed RODC Password Replication Group' -DomainController $script:TestDc -WarningAction SilentlyContinue
        $result.Success | Should -Be $false
        $result.Sid | Should -BeNullOrEmpty
    }

    It "falls back to the name lookup for a Tier Model group, which is not a built-in" {
        Mock Get-ADGroup {
            param($Identity)
            if ("$Identity" -eq 'Tier0Admins') {
                return [PSCustomObject]@{
                    Name = 'Tier0Admins'
                    SID  = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1111111111-2222222222-3333333333-1105')
                }
            }
            throw "Cannot find an object with identity: '$Identity'"
        } -ModuleName TierModel

        $result = Resolve-TierModelPrincipalSid -Principal 'Tier0Admins' -DomainController $script:TestDc
        $result.Success | Should -Be $true
        $result.Sid | Should -Be "$script:TestDomainSid-1105"
        $result.Source | Should -Be 'ADGroup'
    }
}

Describe "ConvertTo-TierModelIdentitySid" -Tag 'Unit', 'Resolution', 'Language' {

    BeforeEach {
        # The SID cache and the memoized domain SID persist for the module session; clear both
        # so each test observes its own mocks rather than a neighbour's result.
        InModuleScope TierModel {
            $script:SidCache = @{}
            $script:CanonicalDomainSidCache = @{}
        }
        Mock Write-TierModelLog { } -ModuleName TierModel
    }

    It "passes a SID string through unchanged" {
        $sid = InModuleScope TierModel { ConvertTo-TierModelIdentitySid -Identity 'S-1-5-10' }
        $sid | Should -Be 'S-1-5-10'
    }

    It "unwraps a SecurityIdentifier" {
        $sid = InModuleScope TierModel {
            ConvertTo-TierModelIdentitySid -Identity ([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
        }
        $sid | Should -Be 'S-1-5-18'
    }

    It "returns null rather than a false match for an untranslatable name" {
        # An ACE left behind by a deleted group translates to nothing. Callers must treat that as
        # unknown, never as a match.
        $sid = InModuleScope TierModel {
            ConvertTo-TierModelIdentitySid -Identity 'NOSUCHDOMAIN\NoSuchPrincipal-4f2c9a'
        }
        $sid | Should -BeNullOrEmpty
    }

    It "returns null for <Value>" -TestCases @(
        @{ Value = $null }
        @{ Value = '' }
        @{ Value = '   ' }
    ) {
        param($Value)
        $sid = InModuleScope TierModel -Parameters @{ V = $Value } { ConvertTo-TierModelIdentitySid -Identity $V }
        $sid | Should -BeNullOrEmpty
    }
}

Describe "Test-TierModelIdentityMatch" -Tag 'Unit', 'Resolution', 'Language' {

    BeforeEach {
        # The SID cache and the memoized domain SID persist for the module session; clear both
        # so each test observes its own mocks rather than a neighbour's result.
        InModuleScope TierModel {
            $script:SidCache = @{}
            $script:CanonicalDomainSidCache = @{}
        }
        Mock Write-TierModelLog { } -ModuleName TierModel
    }

    It "matches two spellings of the same SID" {
        $match = InModuleScope TierModel {
            Test-TierModelIdentityMatch -Left 'S-1-5-10' -Right ([System.Security.Principal.SecurityIdentifier]::new('S-1-5-10'))
        }
        $match | Should -Be $true
    }

    It "does not match different SIDs" {
        $match = InModuleScope TierModel { Test-TierModelIdentityMatch -Left 'S-1-5-10' -Right 'S-1-5-18' }
        $match | Should -Be $false
    }

    It "falls back to the sAMAccountName when neither side translates" {
        $match = InModuleScope TierModel {
            Test-TierModelIdentityMatch -Left 'NOSUCHDOMAIN\Tier0Admins-4f2c9a' -Right 'OTHERDOMAIN\Tier0Admins-4f2c9a'
        }
        $match | Should -Be $true
    }

    It "does not match unrelated untranslatable names" {
        $match = InModuleScope TierModel {
            Test-TierModelIdentityMatch -Left 'NOSUCHDOMAIN\Tier0Admins-4f2c9a' -Right 'NOSUCHDOMAIN\Tier2Admins-4f2c9a'
        }
        $match | Should -Be $false
    }
}
