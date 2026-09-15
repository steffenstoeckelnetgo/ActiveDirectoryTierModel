# German Lab Runbook — verifying localized Active Directory support

Step-by-step verification of the `claude/beautiful-galileo-skfp32` branch on a **German Windows
host against a German Active Directory**.

Why this document exists: the change makes the Tier Model resolve built-in principals by
well-known SID instead of by directory name, so that a localized domain deploys the same
security configuration as an English one. That claim **cannot be proven on Linux** —
`[System.Security.Principal.SecurityIdentifier]` cannot be constructed from a string there
(*"Windows Principal functionality is not supported on this platform"*), and
`ConvertTo-TierModelSidString`, which every SID in this repository passes through, therefore
always throws. Of the 59 tests in `tests/Unit.CanonicalPrincipal.Tests.ps1`, 37 pass on Linux;
**the 22 that do not are exactly the ones that prove this change works.**

Every command below was checked against the `param()` block of the script it calls.

---

## 0. Prerequisites

| Requirement | Note |
|---|---|
| **A lab domain, not production** | Phase D writes real OUs, groups, service accounts, ACLs and GPOs. |
| **Snapshot / checkpoint the DC first** | The Tier Model has no uninstall. |
| Windows installed in German | The point of the exercise. `Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' -Name 'InstallLanguage'` should read `0407`. |
| Active Directory installed in German | Verified in Phase A2 — do not assume it from the host language. |
| RSAT: `ActiveDirectory`, `GroupPolicy` | `Import-Module ActiveDirectory, GroupPolicy` must succeed. |
| `LAPS` module | Only needed for `-IncludeWinLaps`. Present on Windows Server 2019+ and on clients with the Windows LAPS update. |
| Domain Admin | Required by `Test-TierModelPrerequisites`. |
| PowerShell 7 preferred | The suite also runs on 5.1, but CI uses `pwsh`. |

---

## Phase A — Get the code and run the suite

**A1 does not touch Active Directory at all.** It is the single most valuable step in this
runbook: it either proves the SID resolution or finds a real bug, and it costs nothing.

```powershell
git clone https://github.com/steffenstoeckelnetgo/ActiveDirectoryTierModel
cd ActiveDirectoryTierModel
git checkout claude/beautiful-galileo-skfp32

# Pester 5.x only - Pester 6 has a different mock engine and is explicitly out of scope.
# config/dependencies.json pins 5.7.1, which Test-TierModelPrerequisites checks against.
Install-Module Pester -MinimumVersion 5.0.0 -MaximumVersion 5.99.99 -Force -Scope CurrentUser
Install-Module PSScriptAnalyzer -Force -Scope CurrentUser
```

### A1 — Full test suite

```powershell
.\tests\Invoke-AllTests.ps1
```

**What must be true**

| | Expected |
|---|---|
| `tests\Unit.CanonicalPrincipal.Tests.ps1` | **59 of 59 green.** On Linux 22 fail purely because a SID cannot be constructed; here there is no such excuse. |
| Everything else | Green, with the exception noted below. |

**Known and expected to fail:** two tests in `tests\Unit.GpoOperations.Tests.ps1` —
*"Should enter denyApplyGroupPolicy loop and handle ADSI failure gracefully"* and *"Should
process multiple denyApply groups and remain non-fatal for each"*. They assert the **old**
contract, where a failed Deny-Apply ACE was only a console warning. That behaviour was
deliberately changed: a tier-restriction GPO must not deploy without its domain-controller
protection while the run reports success. These two tests need rewriting to the new contract;
that is tracked work, not a surprise.

If anything **else** fails, capture it — it is a genuine finding.

```powershell
.\tests\Invoke-AllTests.ps1 -FailedOnly   # compact list of failures only
```

### A2 — Lint (a CI gate)

```powershell
$excludeRules = @(
  'PSAvoidUsingWriteHost','PSAvoidTrailingWhitespace','PSUseShouldProcessForStateChangingFunctions',
  'PSUseSupportsShouldProcess','PSAvoidUsingPositionalParameters','PSAvoidUsingBrokenHashAlgorithms',
  'PSUseBOMForUnicodeEncodedFile','PSReviewUnusedParameter','PSAvoidUsingEmptyCatchBlock',
  'PSUseOutputTypeCorrectly','PSUseSingularNouns','PSAvoidUsingConvertToSecureStringWithPlainText',
  'PSUseDeclaredVarsMoreThanAssignments'
)
$results = @()
foreach ($t in @('modules/TierModel','Deploy-TierModel.ps1','Audit-TierModel.ps1')) {
  $results += Invoke-ScriptAnalyzer -Path $t -Recurse -Severity Error,Warning,Information -ExcludeRule $excludeRules
}
$results | Format-Table Severity, RuleName, ScriptName, Line, Message -AutoSize
$results | Export-Csv scriptanalyzer-results.csv -NoTypeInformation
```

CI fails on **any** finding. `optional/` is deliberately not linted.

### A3 — Record the directory's language

Before deploying anything, establish what you are deploying against. These are read-only:

```powershell
$dc = 'dc01.<your-domain>'
$d  = Get-ADDomain -Server $dc
"Domain SID : $($d.DomainSID)"
"DC OU      : $($d.DomainControllersContainer)"   # <- open question, see the end
Get-ADGroup -Identity "$($d.DomainSID)-512" -Server $dc | Select-Object Name   # Domänen-Admins?
Get-ADGroup -Identity 'S-1-5-32-549'        -Server $dc | Select-Object Name   # Server-Operatoren?
Get-ADGroup -Identity 'S-1-5-32-548'        -Server $dc | Select-Object Name   # Konten-Operatoren?
```

If those three come back with German names, the directory is localized — which is exactly the
case the old code refused to run against.

---

## Phase B — Planning run (writes nothing)

`Deploy-TierModel.ps1` runs in planning mode unless `-ConfirmApply` is passed. Nothing is
written here.

```powershell
.\Deploy-TierModel.ps1 -PreferredDc $dc -FullDeployment -IncludeWinLaps -IncludeAuthSilos
```

**What must be true**

- The prerequisite check **passes**. Previously it stopped here with *"Non-English host
  operating system detected"* or *"Non-English Active Directory detected"*.
- No `RequiredGroupNotFound` for `Domain Admins`. That was the Windows LAPS blocker: a name
  filter returns an empty result rather than throwing on a localized domain.
- The plan lists the expected OUs, groups, users, ACLs and GPOs.

Keep the console output. If the run stops here, **stop** and send it — there is no point
deploying a plan that is already wrong.

---

## Phase C — Deploy

```powershell
.\Deploy-TierModel.ps1 -PreferredDc $dc -FullDeployment -IncludeWinLaps -IncludeAuthSilos `
    -ConfirmApply -Logging -OutputFileBase "TierModel-Deploy-DE-01"
```

One `Y` confirmation (two if you add `-EnableAuditing`).

---

## Phase D — Second run: idempotency

The single most informative step after the deployment itself. Run **exactly the same command
again**:

```powershell
.\Deploy-TierModel.ps1 -PreferredDc $dc -FullDeployment -IncludeWinLaps -IncludeAuthSilos `
    -ConfirmApply -Logging -OutputFileBase "TierModel-Deploy-DE-02"
```

**Required: `Converged` with zero actions.** That is constitution principle III, and it is the
direct test for the Windows LAPS SELF defect this branch fixes — SELF detection used to compare
`NT AUTHORITY\SELF` against a string that German Windows renders as `NT-AUTORITÄT\SELBST`, so
the ACE looked absent and the delegation was re-applied on every single run.

Any non-zero action count in run 2 is a finding. Note which resource type it names.

---

## Phase E — Collect the evidence

```powershell
.\optional\Test-TierModelLocalizedDeployment.ps1 -PreferredDc $dc `
    -IncludeWinLaps -IncludeAuthSilos -IncludeAudit
```

Read-only. Writes one JSON file containing:

| Section | What it proves |
|---|---|
| `Environment` | Host install language, domain SID, the container DNs the directory reports, and the three canary groups with their **actual** names. |
| `PrincipalResolution` | Every configured principal → SID → source → the name the directory carries. `Domain Admins → S-1-5-21-…-512 → Domänen-Admins` becomes visible instead of assumed. |
| `DenyApplyAcl` | Whether the Deny-Apply ACE is genuinely on the GPC. **Nothing in the product audits this** — the module and `Audit-TierModel.ps1` only ever write it. |
| `PrivilegeRights` | The `[Privilege Rights]` SID sets from SYSVOL, per GPO. |
| `Problems` | Every failure with area, subject and message. |

`-IncludeAudit` additionally runs `Audit-TierModel.ps1 -OutputFormat Json`, which must report
**zero drift** right after a successful deployment.

### Optional but decisive: the parity proof

If an **English** lab domain is also available, run the same script there and diff the
`PrivilegeRights` sections of the two reports. **Identical SID sets** mean localization changed
nothing about the security configuration — the claim this whole branch rests on, and the one
thing no unit test can establish.

---

## What to send back

1. `.\tests\Invoke-AllTests.ps1` output — totals plus the failure list.
2. `scriptanalyzer-results.csv`.
3. Phase B console output (planning run).
4. The deploy log / report from Phase C.
5. Phase D output — the action count of the second run.
6. The JSON from Phase E (and the audit JSON it references).

---

## Open questions this run answers

These are recorded in `CLAUDE.md` as **unverified**. Do not guess them — read them off the run.

**1. Is the `Domain Controllers` OU localized on a German domain?**
Look at `Environment.DomainControllersContainer` in the Phase E report. The code assumes
neither answer: `Resolve-TierModelDelegationOuDn` uses the configured DN when it resolves and
falls back to the `wellKnownObject`-backed container when it does not. If the OU keeps its
English name, that fallback is dead weight and can be removed.

**2. Does `Import-GPO` carry the source lab's `<SecurityGroups>` names into the imported GPO?**
`config/gpo/**/Backup.xml` contains the *source* domain's `Domain Admins` / `Enterprise Admins`
with their original SIDs. This is expected to be inert, because `Import-GPO` imports settings
rather than the GPO security descriptor — expected, not verified. After Phase C, inspect the
imported GPOs' delegation for principals that do not belong to this domain. If any appear, a
migration table is needed.

**3. Does the Windows LAPS holder allow-list need a name fallback?**
`Test-TierModelWinLapsAcl` compares rights holders **only** by SID. If translation fails, a
legitimate administrative holder is reported as drift. On Windows translation normally
succeeds, so this may never surface — but if the Phase E audit flags `Domänen-Admins` or
`VORDEFINIERT\Administratoren` as an unexpected LAPS holder, the allow-list needs a name
fallback alongside the SID comparison.
