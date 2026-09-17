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

**Phase A has been run and passed** (2026-09-15, German Windows 11 / PowerShell 7.6.6 against a
German domain): all 59 are green. Phases B onwards — everything that actually writes to a
directory — are still open, and no unit test substitutes for them.

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
| `Pester` 5.9.0 and `PSScriptAnalyzer` | Not shipped with Windows. Both are installed by the setup block in Phase A below — Pester for A1, PSScriptAnalyzer for A2. Skipping that block is why A2 fails with *"The term 'Invoke-ScriptAnalyzer' is not recognized"*. |

---

## Phase A — Get the code and run the suite

**A1 does not touch Active Directory at all.** It is the single most valuable step in this
runbook: it either proves the SID resolution or finds a real bug, and it costs nothing.

```powershell
git clone https://github.com/steffenstoeckelnetgo/ActiveDirectoryTierModel
cd ActiveDirectoryTierModel
git checkout claude/beautiful-galileo-skfp32

# Pester 5.9.0 exactly. tests/Invoke-AllTests.ps1 pins that version as known-good and warns
# "suite may not be fully green" on anything else; a version range installs the newest 5.x and
# triggers the warning. Pester 6 has a different mock engine and is explicitly out of scope.
Install-Module Pester -RequiredVersion 5.9.0 -Force -Scope CurrentUser
Install-Module PSScriptAnalyzer -Force -Scope CurrentUser
```

**Refreshing a copy from an earlier run.** The branch moves; a second run against a stale
working copy proves nothing.

```powershell
# With git:
git fetch origin
git reset --hard origin/claude/beautiful-galileo-skfp32

# Without git: re-download and expand into a FRESH directory. Expand-Archive does not
# reliably overwrite into an occupied target, so an existing folder silently keeps old files.
$url = 'https://github.com/steffenstoeckelnetgo/ActiveDirectoryTierModel/archive/refs/heads/claude/beautiful-galileo-skfp32.zip'
Invoke-WebRequest $url -OutFile "$env:TEMP\tiermodel.zip"
Remove-Item C:\Temp\TierModel -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive "$env:TEMP\tiermodel.zip" -DestinationPath C:\Temp\TierModel
cd (Get-ChildItem C:\Temp\TierModel -Directory | Select-Object -First 1).FullName
```

A ZIP copy has no `git log`, so confirm the revision from its content instead. **Eight hits is
the expected answer** — one per Windows LAPS SELF fixture:

```powershell
(Select-String "Value = 'S-1-5-10'" .\tests\Unit.WinLapsAclOperations.Tests.ps1).Count   # must be 8
```

### A1 — Full test suite

**Start it with `-NonInteractive`.** One test calls `Test-TierModelCanonicalAcl` with no
parameters and asserts that the missing mandatory `-PreferredDc` produces a binding error. An
interactive host does not raise that error — it prompts for the parameter and the whole run
stops there, waiting. `-NonInteractive` restores the behaviour CI sees.

```powershell
pwsh -NonInteractive -File .\tests\Invoke-AllTests.ps1
```

If you do end up at a `PreferredDc:` prompt, **press Enter on an empty line**. An empty string
fails the binding, which is the error the test wants, so the test passes and the run continues.
Typing a DC name is the wrong answer: the cmdlet then runs, spends ~20 s on an LDAP timeout,
catches the failure and returns an object — no exception, and the test fails.

**Ignore the console output until the very end. It looks far worse than it is.** The integration
tests drive the real `Deploy-TierModel.ps1` and `Audit-TierModel.ps1` with mocked prerequisites
and fixture data, so the suite deliberately prints things that read like a broken environment:

| What you see | What it is |
|---|---|
| `Preferred DC: testdc.contoso.local` | A fixture name hard-coded in the integration tests (`Integration.Audit.Tests.ps1:25` and three others). It is **not** read from your environment and has nothing to do with your DC. |
| `PowerShell version too old` / `Not running as Domain Admin` | A **mocked** `Test-TierModelPrerequisites` result (`Integration.Audit.Tests.ps1:330-336`). The test asserts that the script prints the remediation and exits 1. Your host is not being checked here. |
| `Failed to resolve the domain distinguished name from 'testdc.contoso.local'` | The failure path under test. That host does not exist, which is the point. |
| Dozens of `Configuration validation completed … Valid=False` warnings | The fixture configs (`TestOU1`, `TestGroup1`, `TestUser1`) are intentionally incomplete. |
| `Deployment cancelled by user` | A mocked `Read-Host` answering "no", to cover the cancel branch. |

None of it means the run is going wrong. **The run takes roughly eight minutes**; the only line
that decides anything is the summary at the end:

```
Tests completed in <n>s
Tests Passed: 2021, Failed: 32, Skipped: 0, ...
```

Let it finish. Aborting mid-way tells you nothing.

**What must be true**

| | Expected |
|---|---|
| `tests\Unit.CanonicalPrincipal.Tests.ps1` | **59 of 59 green.** This is the acceptance gate for the resolver. On Linux 22 of them fail purely because a SID cannot be constructed there; here there is no such excuse. Confirmed green on 2026-09-15. |
| `Unit.WinLapsAclOperations`, `Integration.WinLapsDeployment`, `Unit.GpoOperations` | Green. |
| Total | **2021 of 2053**, with the 32 known failures below and nothing else. Measured 2026-09-15. |

**Known to fail, and not this branch's doing.** All 32 also fail on `origin/main` on the same
host. They are English-only test fixtures meeting a German Windows host, plus one that reads the
session's real token. CI never sees them because it runs English. They have their own issue;
do not chase them here.

| File | × | Cause |
|---|--:|---|
| `Unit.OuAclOperations` | 10 | fixture `'BUILTIN\Administrators'` / `'BUILTIN\Users'` — German Windows has `VORDEFINIERT\Administratoren`, so `NTAccount(...).Translate()` throws |
| `Unit.MsaAclOperations` | 7 | same |
| `Unit.GmsaAclOperations` | 7 | same |
| `Unit.DmsaAclOperations` | 4 | same |
| `Unit.CanonicalAcl` | 3 | asserts `Everyone\|S-1-1-0`; the directory renders `Jeder` |
| `Unit.Prerequisites` | 1 | *"… report not-admin"* — `IsDomainAdmin` comes from `[WindowsIdentity]::GetCurrent()`, and this session really is a Domain Admin. No mock can change that. |

A 33rd, *"ByBytes does not require -PreferredDc"*, is on this list only when the suite is started
without `-NonInteractive`; see the note above.

If anything **else** fails, capture it — that is a genuine finding.

```powershell
pwsh -NonInteractive -File .\tests\Invoke-AllTests.ps1 -FailedOnly   # failures only
```

### A2 — Lint (two CI gates, not one)

`.github/workflows/ci.yml` runs PSScriptAnalyzer **twice**, and both have to pass. Run from the
repository root, or the relative paths below analyse nothing.

**The module comes from the setup block in Phase A** (`Install-Module PSScriptAnalyzer -Force
-Scope CurrentUser`), which is easy to skip when the clone is already there from an earlier run.
Confirm it before anything else — the same line the anti-vacuity check below uses:

```powershell
Get-Module PSScriptAnalyzer -ListAvailable | Select-Object Name, Version
```

Nothing back means the module is missing, and `Invoke-ScriptAnalyzer` then fails with *"The term
'Invoke-ScriptAnalyzer' is not recognized"*. Install it the way CI does:

```powershell
Set-PSRepository PSGallery -InstallationPolicy Trusted
Install-Module PSScriptAnalyzer -Force -Scope CurrentUser
```

If the PowerShell Gallery is unreachable from the lab host, fetch it on a machine that does have
access and carry the folder over — `Save-Module -Name PSScriptAnalyzer -Path <dir>`, then copy
the resulting `PSScriptAnalyzer` directory into `$HOME\Documents\PowerShell\Modules` on the lab
host. There is no usable package mirror for this module: unlike Pester it is not obtainable from
`api.nuget.org`.

**A2a — the main gate.** Fails on *any* finding. `optional/` is deliberately not linted.

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
"Findings: $($results.Count)"      # CI exits with this count; 0 is the pass
$results | Format-Table Severity, RuleName, ScriptName, Line, Message -AutoSize
$results | Export-Csv scriptanalyzer-results.csv -NoTypeInformation
```

**An empty `scriptanalyzer-results.csv` is the pass** — zero findings means an empty array means
an empty file. But an empty result and *"the analyzer never read anything"* look identical, so
confirm the scan actually happened. Two of the excluded rules match this repository in bulk
(`PSAvoidUsingWriteHost`: ~1150 `Write-Host` calls in the linted scope; `PSAvoidTrailingWhitespace`:
~2000 lines), so the same scan **without** `-ExcludeRule` must return thousands:

```powershell
Get-Module PSScriptAnalyzer -ListAvailable | Select-Object Name, Version
(Invoke-ScriptAnalyzer -Path modules/TierModel -Recurse -Severity Error,Warning,Information |
    Measure-Object).Count                     # expect several thousand, NOT 0
```

If that comes back 0 too, the module or the working directory is wrong and the empty CSV means
nothing.

**A2b — the security gate.** A separate CI step over `modules/TierModel` with an explicit rule
list. This one fails the build only on findings of severity **Error**; warnings are tolerated
there.

```powershell
$sec = Invoke-ScriptAnalyzer -Path "modules/TierModel" -Recurse -IncludeRule `
  PSAvoidUsingPlainTextForPassword, PSAvoidUsingUserNameAndPasswordParams, `
  PSAvoidUsingComputerNameHardcoded, PSUsePSCredentialType, PSAvoidGlobalVars, `
  PSUseShouldProcessForStateChangingFunctions
"Security findings: $($sec.Count), of which Error: $(@($sec | Where-Object Severity -eq 'Error').Count)"
$sec | Format-Table Severity, RuleName, ScriptName, Line -AutoSize
$sec | Export-Csv security-analysis.csv -NoTypeInformation
```

Note that `PSUseShouldProcessForStateChangingFunctions` is *excluded* from A2a but *included*
here — it can still report, and at Warning severity it does not fail the build.

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
.\Deploy-TierModel.ps1 -PreferredDc $dc -FullDeployment `
    -IncludeMsa -IncludeGmsa -IncludeDmsa -IncludeWinLaps -IncludeAuthSilos
```

**What must be true**

- The prerequisite check **passes**. Previously it stopped here with *"Non-English host
  operating system detected"* or *"Non-English Active Directory detected"*.
- No `RequiredGroupNotFound` for `Domain Admins`. That was the Windows LAPS blocker: a name
  filter returns an empty result rather than throwing on a localized domain.
- The plan lists the expected OUs, groups, users, ACLs and GPOs.

Keep the console output. If the run stops here, **stop** and send it — there is no point
deploying a plan that is already wrong.

**Why `-IncludeMsa -IncludeGmsa -IncludeDmsa` are in that line.** `-FullDeployment` does *not*
imply them — they are separate scopes and have to be asked for. They are worth asking for here:
`New-TierModelMsaAcl`, `New-TierModelGmsaAcl` and `New-TierModelDmsaAcl` resolve their delegate
through `NTAccount(...).Translate()`, exactly like `New-TierModelOuAcl`, and the 28 unit tests
covering those four cmdlets are precisely the ones that cannot run on a German host (the
*Known to fail* table in A1). So these paths have never been exercised against a localized
directory — not in a test, not in a lab.

They are *expected* to be fine: every `identityreference` in `config/*.json` names a Tier Model
group (`Tier0Admins`, `PAWDomainJoin`, …), never a built-in, and those names are the same in
every language. That is a reading of the configuration, not a measurement. This run is what
turns it into one.

Note the limit: `optional/Test-TierModelLocalizedDeployment.ps1` (Phase E) has no MSA switches
and does **not** report on them. For those three, the deploy log and the action count of the
second run are the whole record.

---

## Phase C — Deploy

```powershell
.\Deploy-TierModel.ps1 -PreferredDc $dc -FullDeployment `
    -IncludeMsa -IncludeGmsa -IncludeDmsa -IncludeWinLaps -IncludeAuthSilos `
    -ConfirmApply -Logging -OutputFileBase "TierModel-Deploy-DE-01"
```

One `Y` confirmation (two if you add `-EnableAuditing`).

### If Phase C ends with errors

The first run of this phase (2026-09-15) did, and the three causes it exposed are fixed in this
branch. What to expect now, and what to check if something still fails:

**The deploy is expected to repair itself.** A GPO whose create succeeded and whose import
failed used to be invisible to every later run — the planner only re-planned a GPO that did not
exist. It now re-plans Import (and Configure) for a GPO whose policy folder in SYSVOL is
provably empty, so simply running Phase C again is the repair. The log names the GPO with
`Re-import GPO (policy is empty)`.

**A transient SYSVOL failure is retried.** `Import-GPO` clears the target policy folder before
copying into it, and a run does 123 imports back to back, several from the same backup source.
The retry logs `Transient failure - retrying` with `Attempt`, `DelayMs` and the `HResult`. If you
see four attempts and then a failure, it is not a timing artefact — check Defender real-time
protection on SYSVOL and `dfsrdiag ReplicationState`, then run Phase C again.

**One failed configure still skips all GPO links.** `Deploy-TierModel.ps1` returns from the GPO
deployment when any configure action fails, and phase 4 (linking) comes after phase 3. That
fail-fast is deliberate and was left in place. The practical consequence: as long as `Errors` is
not 0, assume no GPO is linked, and do not read anything into the OU structure looking complete.

**`Converged: False` on a first run is expected, and is not an error.** Since the green-field
run of 2026-09-16 both summaries derive the flag from their own totals — `applied = 0 and
errors = 0` — instead of AND-ing each executor's own flag, because those flags mean "nothing
was applied" in two places and "nothing failed" in the other twelve (CLAUDE.md §4 trap 9). A
deployment that writes anything therefore reads `Converged: False` next to `Errors: 0`. The line
to judge is `Errors`; `Converged` is the question Phase D answers.

**A skipped auth silo phase is now an error.** If `Test-TierModelAuthSiloPrerequisite` fails,
the run prints the missing groups in red and skips the whole silo phase — and the summary counts
that skip, so `Errors` is non-zero and `Converged` is `False`. It used to end
`Deploy script completed successfully` with no silo deployed. A failure naming
`Domain Controllers` or `Read-only Domain Controllers` means you are running code from before
those groups were resolved by SID; pull the branch.

**Reading the counts.** `Applied` and `Errors` now count each result once. Before this branch a
result that published both an `Errors` array and a `Failed` integer was counted twice, so two
failed GPO actions printed `Errors: 4`.

**If the probe says SYSVOL could not be read.** The log line
`GPO policy content could not be read from SYSVOL - assuming it is intact` means the re-plan
declined on purpose: re-importing overwrites settings, so it must never act on a state it could
not read. The exception text says which. Two cases:

- *Path not replicated / temporarily unreachable* — run Phase C again.
- *Access to the path … is denied*, reproducibly, even as a Domain Admin — the policy folder's
  ACL is broken. That is not transient and no retry will clear it. Capture the evidence
  **before** deleting anything, because deleting the GPO destroys it:

  ```powershell
  $dc = 'DC1.int.promiseIT.de'
  $g  = '<guid>'
  $p  = "\\$dc\SYSVOL\<domain>\Policies\{$g}"

  (Get-GPO -Guid $g -Server $dc) | Select-Object DisplayName, Id, GpoStatus
  Get-ChildItem $p -Recurse -Force -ErrorAction Continue | Select-Object FullName, Length
  (Get-Acl $p).Access | Format-Table IdentityReference, FileSystemRights, AccessControlType
  icacls "$p\Machine"
  icacls "$p\Machine\Microsoft\Windows NT\SecEdit"
  whoami /groups | Select-String 'S-1-5-21-.*-512'
  ```

  Run the two ACL queries against a healthy sister GPO as well — the difference between them is
  the answer. Then clean up as below.

**This path has been walked.** On 2026-09-16 a template GPO's SYSVOL folder denied reads even
to a Domain Admin, across two runs on two days. Deleting the GPO and repeating Phase C rebuilt it
cleanly — create, import and configure all with `FailedActions: 0`, `GptTmpl.inf` 3302 bytes
under a new GUID.

**Last resort, if a GPO is still not repaired.** The template GPOs
(`*- Tier Model Template ...`) are never linked to an OU and affect no machine, so deleting one
and letting the next run recreate it is free. Confirm it is unlinked first:

```powershell
(Get-GPOReport -Guid <guid> -ReportType Xml -Server $dc) -match '<LinksTo>'   # must be False
Remove-GPO -Guid <guid> -Server $dc
# If the SYSVOL folder survives - that is what ERROR_DIR_NOT_EMPTY is about - remove it too:
Remove-Item "\\$dc\SYSVOL\<domain>\Policies\{<guid>}" -Recurse -Force
```

**If Phase C cannot be made to finish at all**, the optional features still run on their own,
because the `-Include*` switches are also valid standalone (without any scope switch) and that
path does not consult the standard deployment's error state:

```powershell
.\Deploy-TierModel.ps1 -PreferredDc $dc `
    -IncludeMsa -IncludeGmsa -IncludeDmsa -IncludeWinLaps -IncludeAuthSilos -ConfirmApply -Logging
```

That is how to reach the Windows LAPS SELF evidence without a green Phase C. It is a fallback,
not the goal.

---

## Phase D — Second run: idempotency

The single most informative step after the deployment itself. Run **exactly the same command
again**:

```powershell
.\Deploy-TierModel.ps1 -PreferredDc $dc -FullDeployment `
    -IncludeMsa -IncludeGmsa -IncludeDmsa -IncludeWinLaps -IncludeAuthSilos `
    -ConfirmApply -Logging -OutputFileBase "TierModel-Deploy-DE-02"
```

Required: `Applied: 0`, `Errors: 0`, `Converged: True`. Every action is a finding, and each one
points at a specific mechanism:

| Action that appears | What it would mean |
|---|---|
| `CreateGPO` / `ImportGPO` / `ConfigureGPO` | The SYSVOL probe called a populated policy folder empty — its re-plan is too eager |
| `AuthPolicy` / `AuthSilo` create | The policies and silos created in the previous run are not being recognised |
| Auth silo membership > 0 | Membership runs only for silos created in the same run; expect `Already deployed — nothing to create` |
| Any Windows LAPS action | A regression: the previous run reported `TotalActions: 0` against 27 existing delegations |

The console summary (`Applied / Skipped / Errors / Converged`) is **not** in the JSON log — read
it off the console.

**Result on a green-field `int.promiseIT.de`, 2026-09-16 13:59: passed.** The domain had been
rebuilt from scratch and Phase C had just applied 689 actions with `Errors: 0`; the immediate
repeat printed `No actions required - all components are up to date.` →
`Applied: 0 / Skipped: 0 / Errors: 0 / Converged: True`. That is the strongest form of this
check: every object in the directory had been created by the run before it.

**Result on `int.promiseIT.de`, 2026-09-16 11:00: passed.** Every planner reported zero, so the
run never entered an execution phase and printed `Applied: 0 / Skipped: 0 / Errors: 0 /
Converged: True` — the branch `Deploy-TierModel.ps1` takes when the plan is empty. 48 seconds
end to end. Windows LAPS `TotalActions: 0, ExistingCount: 27` after applying 17 actions the run
before, and the auth policies and silos read `AlreadyExist: 4` each.

**Required: `Converged` with zero actions.** That is constitution principle III, and it is the
direct test for the Windows LAPS SELF defect this branch fixes — SELF detection used to compare
`NT AUTHORITY\SELF` against a string that German Windows renders as `NT-AUTORITÄT\SELBST`, so
the ACE looked absent and the delegation was re-applied on every single run.

Any non-zero action count in run 2 is a finding. Note which resource type it names.

Since this branch the second run also carries a second meaning: the planner checks whether each
GPO's policy folder in SYSVOL actually holds settings, so **zero actions now implies no GPO was
left half-built**. A re-planned `ImportGPO` or `ConfigureGPO` here says the opposite — either a
GPO really is empty, or the emptiness check is too eager and is re-importing a policy that is
fine. Either way it is a finding, and the GPO it names is the one to look at in SYSVOL.

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

If an **English** lab domain is also available, run this whole runbook there too and then compare
the two reports. That comparison is the claim this work rests on, and the one thing no unit test
can establish. **`docs/parity-lab-runbook.md` has the procedure.**

> **Do not diff the two reports as text.** An earlier version of this section said to diff the
> `PrivilegeRights` sections directly; that was wrong. Every domain-scoped principal there carries
> its own domain's SID as a prefix, so `*S-1-5-21-<A>-512` and `*S-1-5-21-<B>-512` — the same
> Domain Admins — read as a difference. In the measured lab data that is 1651 SID entries across
> 29 GPOs of false differences. `optional/Compare-TierModelDeploymentReport.ps1` normalises each
> report's own domain SID first and leaves a *foreign* one verbatim, because a foreign SID is a
> finding rather than noise.

---

## What to send back

1. `.\tests\Invoke-AllTests.ps1` output — totals plus the failure list.
2. `scriptanalyzer-results.csv` and `security-analysis.csv`, plus the two counts A2 prints.
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
