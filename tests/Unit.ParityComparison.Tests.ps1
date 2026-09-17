#Requires -Modules Pester
<#
.SYNOPSIS
Unit tests for optional/Compare-TierModelDeploymentReport.ps1 — the English/German parity proof.

.DESCRIPTION
The parity proof compares two Test-TierModelLocalizedDeployment reports, one from an English
domain and one from a localized one, and asserts that localization changed nothing about the
security configuration.

A plain diff cannot do that, and the instruction to attempt one was wrong where it stood
(the report script's closing line and docs/german-lab-runbook.md). Every domain-scoped SID in
[Privilege Rights] carries its own domain's SID as a prefix:

    *S-1-5-21-2230522700-2543936044-3532250090-512      German lab
    *S-1-5-21-1004336348-1177238915-682003330-512       any other domain

Those two ARE the same principal — Domain Admins, RID 512 — and a textual comparison calls them
different. With 1651 SID entries across 29 GPOs in the measured lab data, a naive diff produces
a wall of false differences, and the only conclusion available from it is the wrong one.

So the comparison normalises each report's OWN domain SID to a placeholder first and compares
what remains. The three things that must NOT be normalised away are what these tests pin:

  - a SID belonging to NEITHER domain stays verbatim, because a foreign SID reaching the
    settings is exactly the finding Phase F is looking for;
  - a non-domain well-known SID (S-1-5-32-544, S-1-1-0, S-1-5-10) is already invariant;
  - a literalStrings value (NT SERVICE\*, IIS APPPOOL\*, CLIUSR) has no domain SID by
    construction and is resolved by secedit on the target machine (rule 2.4).

And one difference that must be reported as expected rather than as a defect: the same principal
carries a DIFFERENT DirectoryName on the two domains. That is the whole point of the change —
Domain Admins reads Domänen-Admins — so comparing rendered names would fail the proof it is
meant to establish.

The script is not dot-sourced: its parameters are mandatory, and a dot-source would prompt for
them on an interactive host exactly as the -PreferredDc case in CLAUDE.md §6 item 2 does. The
functions under test are lifted out of its AST, which also keeps these cases free of AD and of
[SecurityIdentifier], so they run on any platform.

.NOTES
Tags: Unit, Localization, Parity
#>

Describe "Compare-TierModelDeploymentReport — SID normalisation" -Tag 'Unit', 'Localization', 'Parity' {

    BeforeAll {
        $script:ScriptPath = Join-Path $PSScriptRoot '..' 'optional' 'Compare-TierModelDeploymentReport.ps1'

        $script:ScriptAst = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptPath, [ref]$null, [ref]$null)

        $script:LiftedNames = @()
        foreach ($name in @('ConvertTo-DomainRelativeSid', 'Get-ReportDomainSid', 'Compare-PrivilegeRightsSection', 'Compare-PrincipalResolutionSection')) {
            $fn = $script:ScriptAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true) | Where-Object { $_.Name -eq $name } | Select-Object -First 1

            if ($fn) {
                . ([scriptblock]::Create($fn.Extent.Text))
                $script:LiftedNames += $name
            }
        }

        # The measured German lab domain SID, and a second one standing in for the English lab.
        $script:DeSid = 'S-1-5-21-2230522700-2543936044-3532250090'
        $script:EnSid = 'S-1-5-21-1004336348-1177238915-682003330'
    }

    It "lifts all four functions out of the script" {
        # Anti-vacuity: without this, every case below passes by calling nothing.
        @($script:LiftedNames).Count | Should -Be 4
    }

    It "replaces the report's own domain SID with a placeholder and keeps the RID" {
        ConvertTo-DomainRelativeSid -Value 'S-1-5-21-2230522700-2543936044-3532250090-512' `
            -DomainSid 'S-1-5-21-2230522700-2543936044-3532250090' |
            Should -Be '<DOMAIN>-512'
    }

    It "keeps secedit's asterisk prefix, because [Privilege Rights] writes it" {
        ConvertTo-DomainRelativeSid -Value '*S-1-5-21-2230522700-2543936044-3532250090-516' `
            -DomainSid 'S-1-5-21-2230522700-2543936044-3532250090' |
            Should -Be '*<DOMAIN>-516'
    }

    It "normalises the two lab domains' Domain Admins to the same value" {
        # The whole reason this script exists: these two strings are the same principal.
        $de = ConvertTo-DomainRelativeSid -Value "*$($script:DeSid)-512" -DomainSid $script:DeSid
        $en = ConvertTo-DomainRelativeSid -Value "*$($script:EnSid)-512" -DomainSid $script:EnSid
        $de | Should -Be $en
    }

    It "leaves a BUILTIN well-known SID untouched" {
        ConvertTo-DomainRelativeSid -Value '*S-1-5-32-544' -DomainSid $script:DeSid |
            Should -Be '*S-1-5-32-544'
    }

    It "leaves Everyone and SELF untouched" {
        ConvertTo-DomainRelativeSid -Value 'S-1-1-0'  -DomainSid $script:DeSid | Should -Be 'S-1-1-0'
        ConvertTo-DomainRelativeSid -Value 'S-1-5-10' -DomainSid $script:DeSid | Should -Be 'S-1-5-10'
    }

    It "leaves a literalStrings machine-local principal untouched" {
        ConvertTo-DomainRelativeSid -Value 'NT SERVICE\himds' -DomainSid $script:DeSid |
            Should -Be 'NT SERVICE\himds'
        ConvertTo-DomainRelativeSid -Value 'CLIUSR' -DomainSid $script:DeSid |
            Should -Be 'CLIUSR'
    }

    It "does NOT normalise a SID from a third domain" {
        # A foreign S-1-5-21 SID in the settings is the finding Phase F hunts for. Rewriting it
        # to <DOMAIN> would hide exactly that.
        ConvertTo-DomainRelativeSid -Value "*$($script:EnSid)-512" -DomainSid $script:DeSid |
            Should -Be "*$($script:EnSid)-512"
    }
}

Describe "Compare-TierModelDeploymentReport — [Privilege Rights] parity" -Tag 'Unit', 'Localization', 'Parity' {

    BeforeAll {
        $script:ScriptPath = Join-Path $PSScriptRoot '..' 'optional' 'Compare-TierModelDeploymentReport.ps1'
        $script:ScriptAst  = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptPath, [ref]$null, [ref]$null)
        foreach ($name in @('ConvertTo-DomainRelativeSid', 'Get-ReportDomainSid', 'Compare-PrivilegeRightsSection')) {
            $fn = $script:ScriptAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true) | Where-Object { $_.Name -eq $name } | Select-Object -First 1
            if ($fn) { . ([scriptblock]::Create($fn.Extent.Text)) }
        }

        # Two reports for the same configuration deployed to two domains. Different domain SIDs,
        # different GPO GUIDs (they are created per domain), identical RIDs.
        $script:ReferenceReport = [PSCustomObject]@{
            Environment     = [PSCustomObject]@{ DomainSid = 'S-1-5-21-1004336348-1177238915-682003330' }
            PrivilegeRights = @(
                [PSCustomObject]@{
                    GpoDisplayName = 'Tier 0 - Domain Controllers'
                    GpoId          = 'aaaaaaaa-1111-2222-3333-444444444444'
                    Rights         = [PSCustomObject]@{
                        SeDenyNetworkLogonRight = @('*S-1-5-21-1004336348-1177238915-682003330-512', '*S-1-5-32-544')
                        SeBatchLogonRight       = @('NT SERVICE\himds')
                    }
                }
            )
        }
        $script:DifferenceReport = [PSCustomObject]@{
            Environment     = [PSCustomObject]@{ DomainSid = 'S-1-5-21-2230522700-2543936044-3532250090' }
            PrivilegeRights = @(
                [PSCustomObject]@{
                    GpoDisplayName = 'Tier 0 - Domain Controllers'
                    GpoId          = 'bbbbbbbb-5555-6666-7777-888888888888'
                    Rights         = [PSCustomObject]@{
                        SeDenyNetworkLogonRight = @('*S-1-5-21-2230522700-2543936044-3532250090-512', '*S-1-5-32-544')
                        SeBatchLogonRight       = @('NT SERVICE\himds')
                    }
                }
            )
        }
    }

    It "reports no difference for the same configuration on two domains" {
        $result = Compare-PrivilegeRightsSection -Reference $script:ReferenceReport -Difference $script:DifferenceReport
        @($result).Count | Should -Be 0
    }

    It "joins on the GPO display name, not on the GPO GUID" {
        # The GUIDs above differ deliberately. If the join used them, nothing would match and the
        # case above would pass for the wrong reason, so assert the match happened.
        $mismatched = $script:DifferenceReport.PrivilegeRights[0]
        $mismatched.Rights.SeBatchLogonRight = @('CLIUSR')
        $result = Compare-PrivilegeRightsSection -Reference $script:ReferenceReport -Difference $script:DifferenceReport
        @($result).Count | Should -Be 1
        $result[0].Gpo   | Should -Be 'Tier 0 - Domain Controllers'
        $result[0].Right | Should -Be 'SeBatchLogonRight'
    }

    It "reports a right present on one side only" {
        $script:DifferenceReport.PrivilegeRights[0].Rights |
            Add-Member -NotePropertyName 'SeServiceLogonRight' -NotePropertyValue @('*S-1-5-32-544') -Force
        $result = Compare-PrivilegeRightsSection -Reference $script:ReferenceReport -Difference $script:DifferenceReport
        @($result | Where-Object { $_.Right -eq 'SeServiceLogonRight' }).Count | Should -Be 1
    }

    It "reports a GPO present on one side only" {
        $script:DifferenceReport.PrivilegeRights += [PSCustomObject]@{
            GpoDisplayName = 'Tier 1 - Servers'
            GpoId          = 'cccccccc-9999-0000-1111-222222222222'
            Rights         = [PSCustomObject]@{ SeDenyBatchLogonRight = @('*S-1-5-32-545') }
        }
        $result = Compare-PrivilegeRightsSection -Reference $script:ReferenceReport -Difference $script:DifferenceReport
        @($result | Where-Object { $_.Gpo -eq 'Tier 1 - Servers' }).Count | Should -Be 1
    }

    It "reports a genuinely foreign SID as a difference" {
        # A third domain's SID in the settings survives normalisation on both sides and must
        # therefore show up.
        $script:DifferenceReport.PrivilegeRights[0].Rights.SeDenyNetworkLogonRight =
            @('*S-1-5-21-9999999999-8888888888-7777777777-512', '*S-1-5-32-544')
        $result = Compare-PrivilegeRightsSection -Reference $script:ReferenceReport -Difference $script:DifferenceReport
        @($result | Where-Object { $_.Right -eq 'SeDenyNetworkLogonRight' }).Count | Should -Be 1
    }
}

Describe "Compare-TierModelDeploymentReport — principal resolution parity" -Tag 'Unit', 'Localization', 'Parity' {

    BeforeAll {
        $script:ScriptPath = Join-Path $PSScriptRoot '..' 'optional' 'Compare-TierModelDeploymentReport.ps1'
        $script:ScriptAst  = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptPath, [ref]$null, [ref]$null)
        foreach ($name in @('ConvertTo-DomainRelativeSid', 'Get-ReportDomainSid', 'Compare-PrincipalResolutionSection')) {
            $fn = $script:ScriptAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true) | Where-Object { $_.Name -eq $name } | Select-Object -First 1
            if ($fn) { . ([scriptblock]::Create($fn.Extent.Text)) }
        }

        $script:MakeReport = {
            param($DomainSid, $Entries)
            [PSCustomObject]@{
                Environment         = [PSCustomObject]@{ DomainSid = $DomainSid }
                PrincipalResolution = [PSCustomObject]@{ Entries = $Entries }
            }
        }
    }

    It "reports no difference when the same name resolves to the same RID on both domains" {
        $en = & $script:MakeReport 'S-1-5-21-1004336348-1177238915-682003330' @(
            [PSCustomObject]@{ ConfiguredName = 'Domain Admins'; Sid = 'S-1-5-21-1004336348-1177238915-682003330-512'
                               Source = 'CanonicalDomainRid'; DirectoryName = 'Domain Admins'; Resolved = $true }
        )
        $de = & $script:MakeReport 'S-1-5-21-2230522700-2543936044-3532250090' @(
            [PSCustomObject]@{ ConfiguredName = 'Domain Admins'; Sid = 'S-1-5-21-2230522700-2543936044-3532250090-512'
                               Source = 'CanonicalDomainRid'; DirectoryName = 'Domänen-Admins'; Resolved = $true }
        )
        @(Compare-PrincipalResolutionSection -Reference $en -Difference $de).Count | Should -Be 0
    }

    It "does not treat a different directory name as a difference" {
        # Domänen-Admins vs Domain Admins is the expected outcome of the whole change. If the
        # comparison flagged it, the proof would fail on the thing it is meant to demonstrate.
        $en = & $script:MakeReport 'S-1-5-21-1004336348-1177238915-682003330' @(
            [PSCustomObject]@{ ConfiguredName = 'Domain Controllers'; Sid = 'S-1-5-21-1004336348-1177238915-682003330-516'
                               Source = 'CanonicalDomainRid'; DirectoryName = 'Domain Controllers'; Resolved = $true }
        )
        $de = & $script:MakeReport 'S-1-5-21-2230522700-2543936044-3532250090' @(
            [PSCustomObject]@{ ConfiguredName = 'Domain Controllers'; Sid = 'S-1-5-21-2230522700-2543936044-3532250090-516'
                               Source = 'CanonicalDomainRid'; DirectoryName = 'Domänencontroller'; Resolved = $true }
        )
        @(Compare-PrincipalResolutionSection -Reference $en -Difference $de).Count | Should -Be 0
    }

    It "reports a principal that resolves to a different RID" {
        $en = & $script:MakeReport 'S-1-5-21-1004336348-1177238915-682003330' @(
            [PSCustomObject]@{ ConfiguredName = 'Domain Admins'; Sid = 'S-1-5-21-1004336348-1177238915-682003330-512'
                               Source = 'CanonicalDomainRid'; DirectoryName = 'Domain Admins'; Resolved = $true }
        )
        $de = & $script:MakeReport 'S-1-5-21-2230522700-2543936044-3532250090' @(
            [PSCustomObject]@{ ConfiguredName = 'Domain Admins'; Sid = 'S-1-5-21-2230522700-2543936044-3532250090-519'
                               Source = 'CanonicalDomainRid'; DirectoryName = 'Domänen-Admins'; Resolved = $true }
        )
        @(Compare-PrincipalResolutionSection -Reference $en -Difference $de).Count | Should -Be 1
    }

    It "reports a principal resolved through a different source" {
        # Same SID by a different route means one domain fell back to a name lookup. That is a
        # real finding even though the SID matches.
        $en = & $script:MakeReport 'S-1-5-21-1004336348-1177238915-682003330' @(
            [PSCustomObject]@{ ConfiguredName = 'Server Operators'; Sid = 'S-1-5-32-549'
                               Source = 'WellKnown'; DirectoryName = 'Server Operators'; Resolved = $true }
        )
        $de = & $script:MakeReport 'S-1-5-21-2230522700-2543936044-3532250090' @(
            [PSCustomObject]@{ ConfiguredName = 'Server Operators'; Sid = 'S-1-5-32-549'
                               Source = 'ADGroup'; DirectoryName = 'Server-Operatoren'; Resolved = $true }
        )
        $result = Compare-PrincipalResolutionSection -Reference $en -Difference $de
        @($result).Count             | Should -Be 1
        $result[0].ReferenceSource   | Should -Be 'WellKnown'
        $result[0].DifferenceSource  | Should -Be 'ADGroup'
    }

    It "reports a principal that resolves on one domain only" {
        $en = & $script:MakeReport 'S-1-5-21-1004336348-1177238915-682003330' @(
            [PSCustomObject]@{ ConfiguredName = 'Allowed RODC Password Replication Group'
                               Sid = 'S-1-5-21-1004336348-1177238915-682003330-571'
                               Source = 'CanonicalDomainRid'; DirectoryName = 'Allowed RODC Password Replication Group'
                               Resolved = $true }
        )
        $de = & $script:MakeReport 'S-1-5-21-2230522700-2543936044-3532250090' @(
            [PSCustomObject]@{ ConfiguredName = 'Allowed RODC Password Replication Group'
                               Sid = $null; Source = $null; DirectoryName = $null; Resolved = $false }
        )
        @(Compare-PrincipalResolutionSection -Reference $en -Difference $de).Count | Should -Be 1
    }
}
