#Requires -Modules Pester
<#
.SYNOPSIS
Unit tests for optional/Test-TierModelLocalizedDeployment.ps1 — the literalStrings exemption.

.DESCRIPTION
The report's rule is "every principal in [Privilege Rights] must be a SID", because a NAME there
would be a localizable value written into security policy. There is one designed exception: the
machine-local accounts the configuration lists as literalStrings (NT SERVICE\*, IIS APPPOOL\*,
CLIUSR) have no domain SID at all and are resolved by secedit on the target machine.

The German lab report of 2026-09-16 raised 6 problems covering 140 entries, every single one of
them a configured literalStrings value. That buries the one finding that would matter — a plain
name nobody configured — so the rule now exempts what the configuration declares.

The script is NOT dot-sourced: it runs a live deployment report on import. The function under
test is lifted out of its AST, which also keeps these cases free of AD and of
[SecurityIdentifier], so they run on any platform.

.NOTES
Tags: Unit, Localization, Report
#>

Describe "Test-TierModelLocalizedDeployment — literalStrings exemption" -Tag 'Unit', 'Localization', 'Report' {

    BeforeAll {
        $script:ScriptPath = Join-Path $PSScriptRoot '..' 'optional' 'Test-TierModelLocalizedDeployment.ps1'
        $script:ConfigPath = Join-Path $PSScriptRoot '..' 'config' 'tiermodel-gpos.json'

        $script:ScriptAst = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptPath, [ref]$null, [ref]$null)

        $collector = $script:ScriptAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Get-ConfiguredLiteralString'
        }, $true) | Select-Object -First 1

        if ($collector) { . ([scriptblock]::Create($collector.Extent.Text)) }
        $script:CollectorFound = [bool]$collector
    }

    It "the collector exists in the script" {
        # Anti-vacuity: every case below silently passes if the function was never lifted out.
        $script:CollectorFound | Should -BeTrue
    }

    It "collects literalStrings from a nested structure" {
        $sink = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $node = [PSCustomObject]@{
            gpos = @(
                [PSCustomObject]@{
                    name   = 'a'
                    rights = [PSCustomObject]@{ literalStrings = @('CLIUSR', 'NT SERVICE\himds') }
                }
                [PSCustomObject]@{
                    name   = 'b'
                    nested = [PSCustomObject]@{ deeper = [PSCustomObject]@{ literalStrings = @('IIS APPPOOL\DefaultAppPool') } }
                }
            )
        }
        Get-ConfiguredLiteralString -Node $node -Sink $sink
        $sink.Count | Should -Be 3
    }

    It "collects nothing from keys that are not literalStrings" {
        $sink = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $node = [PSCustomObject]@{
            resolvableGroups = @('Domain Admins')
            comment          = 'CLIUSR is mentioned here but is not a literalStrings value'
            denyApplyGroupPolicy = @('Domain Controllers')
        }
        Get-ConfiguredLiteralString -Node $node -Sink $sink
        $sink.Count | Should -Be 0
    }

    It "matches case-insensitively, as the SYSVOL spelling is not guaranteed" {
        $sink = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        Get-ConfiguredLiteralString -Node ([PSCustomObject]@{ literalStrings = @('NT SERVICE\himds') }) -Sink $sink
        $sink.Contains('nt service\HIMDS') | Should -BeTrue
    }

    It "collects exactly the 33 literalStrings the real configuration declares" {
        # The number is measured, not estimated: the German lab run of 2026-09-16 found 33
        # distinct non-SID principals across 29 GPOs in SYSVOL, and all 33 are declared here.
        # If a GPO template gains a machine-local account, this count moves and the report's
        # exemption list has to move with it.
        $sink = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        Get-ConfiguredLiteralString -Node (Get-Content $script:ConfigPath -Raw | ConvertFrom-Json) -Sink $sink

        $sink.Count | Should -Be 33
        $sink.Contains('CLIUSR')                     | Should -BeTrue
        $sink.Contains('NT SERVICE\himds')           | Should -BeTrue
        $sink.Contains('IIS APPPOOL\DefaultAppPool') | Should -BeTrue
    }

    It "raises the problem from the unexpected entries, not from every non-SID entry" {
        # The wiring, asserted on the AST: reporting $nonSid here would reinstate the 140-entry
        # noise the exemption exists to remove.
        $calls = $script:ScriptAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq 'Add-Problem' -and
            $node.Extent.Text -match 'PrivilegeRights' -and
            $node.Extent.Text -match 'non-SID principal'
        }, $true)

        @($calls).Count | Should -Be 1
        $calls[0].Extent.Text | Should -Match '\$unexpectedNonSid'
    }
}
