# CLAUDE.md — Active Directory Tier Model

Working notes for AI assistants and new contributors. Everything here is drawn from files in
this repository or from commands actually executed against it; where something is unverified it
says so explicitly.

---

## 1. What this project is

A declarative PowerShell framework that **deploys and audits an Active Directory Tier Model**
(Tier 0/1/2 privileged-access tiering) from version-controlled JSON: OUs, groups, service
accounts, ACL delegations, GPOs, ADMX templates, MSA/gMSA/dMSA permissions, Windows LAPS
delegations and Authentication Policy Silos.

Two entry scripts, one module:

| Path | Role |
|---|---|
| `Deploy-TierModel.ps1` | Deploy with scoped execution (`-IncludeMsa`, `-IncludeGmsa`, `-IncludeDmsa`, `-IncludeWinLaps`, `-IncludeAuthSilos`, `-EnableAuditing`) |
| `Audit-TierModel.ps1` | Audit / drift detection, same scope switches |
| `modules/TierModel/` | 82 public functions, one per file under `public/` |
| `config/*.json` | 19 config files — the declarative source of truth |
| `config/gpo/` | 260 files of GPO backups (binary-ish; `.gitattributes` marks `*.admx`/`*.adml` binary) |
| `optional/` | Scripts that are not part of a normal run |

This is **upstream `microsoft/ActiveDirectoryTierModel`, forked**. The fork is
`steffenstoeckelnetgo/ActiveDirectoryTierModel`.

---

## 2. Hard rules — read before changing anything

These are not style preferences. Each one is enforced by CI, by a test, or by
`CONTRIBUTING.md`.

### 2.1 Issue-first. Always.

`CONTRIBUTING.md` is explicit: *"Pull requests without a linked, pre-agreed issue will be
closed."* Every change — feature, fix, refactor, config, docs — starts with an issue and a
maintainer go-ahead **before code is written**. This applies to the upstream project; a fork
may work differently, but anything intended to go back upstream must follow it.

### 2.2 Never turn a fail-fast into a warn-and-continue

`CONTRIBUTING.md`, PR requirement 3, verbatim: *"changes that turn a deliberate fail-fast /
hard-stop into a 'warn and continue' weaken safety and require explicit design sign-off."* The
rejection list repeats it: *"Changes that relax security-relevant validation (for example,
converting a fail-fast prerequisite gate into a silent skip)."*

> **This rule was knowingly broken on the `claude/beautiful-galileo-skfp32` branch**, with the
> repository owner's explicit instruction, when the two English-only language gates in
> `Test-TierModelPrerequisites` were removed. See §5. If that work is ever offered upstream it
> needs design sign-off for exactly this reason. Do not treat it as precedent.

### 2.3 Never pass `-Debug` or `@PSBoundParameters` to an AD or GroupPolicy cmdlet

Enforced by `tests/Unit.DebugProhibition.Tests.ps1`, which parses the AST of every product file
rather than grepping, so a splat cannot hide it. Reason recorded in that file: forwarding
`-Debug` to those cmdlets throws *"Object reference not set to an instance of an object"* on a
non-interactive host, because the cmdlet tries to raise a debug prompt. The supported way to
raise diagnostics is the **preference variable** (`$DebugPreference` / `$VerbosePreference`),
which the entry scripts already set.

### 2.4 Resolve built-in principals by SID, never by directory name

Active Directory localizes the names of its built-in principals at domain creation and an
administrator can rename them. `Get-ADGroup -Identity 'Domain Admins'` finds nothing on a German
domain — and `Get-ADGroup -Filter "Name -eq 'Domain Admins'"` is worse: a filter that matches
nothing **returns an empty result instead of throwing**, so the failure is silent.

Use `Resolve-TierModelPrincipalSid` (`modules/TierModel/public/Resolve-TierModelPrincipalSid.ps1`).
Its order: direct SID → `Administrator` via RID 500 → session cache → `Get-WellKnownSid` (absolute
SIDs, no directory read) → canonical RID composition → name lookup.

Why, with citations, and which principal classes are affected:
`docs/language-support.md` § *Which names are localized — and which are not*. Short version:
the SID is invariant and the **name is fixed at install time** — of the OS for machine-local
principals, of the *domain* for domain principals. Microsoft's own guidance is to build the SID
from constants rather than use the name, *"because the names of well-known SIDs can vary"*.

**Do not add a bare built-in alias to `Get-WellKnownSid` without a configuration entry that needs
it.** A bare name such as `Remote Desktop Users` or `Event Log Readers` is a legal name for a
*customer's own domain group*; listing it shadows their group and silently resolves it to the
BUILTIN SID. The `BUILTIN\...` prefixed form cannot collide and is safe to list in full.
`tests/Unit.CanonicalPrincipal.Tests.ps1` pins this.

`literalStrings` in `config/tiermodel-gpos.json` is **not** an exception to this rule and not a
localization mechanism. `NT SERVICE\*`, `IIS APPPOOL\*` and `CLIUSR` are not directory
principals at all: their SIDs are a SHA-1 over a service or application-pool name that exists
only on the target machine, so the DC cannot compose them for any language. They are written
into `[Privilege Rights]` unprefixed and resolved by the Security Configuration Engine on the
member server — deferred resolution, upstream-original since v1.0.0.

### 2.5 Never compare identities by their rendered name

`IdentityReference.Value`, `NTAccount` strings and `Find-LapsADExtendedRights`
`ExtendedRightHolders` are rendered by the **local machine's** translation. On German Windows the
same ACE reads `NT-AUTORITÄT\SELBST`, `VORDEFINIERT\Administratoren`, `<DOM>\Domänen-Admins`.
Comparing those to English literals fails silently. Use `ConvertTo-TierModelIdentitySid` /
`Test-TierModelIdentityMatch`.

### 2.6 Test-first, and tests are not optional

`.specify/memory/constitution.md`, principle II, marked **NON-NEGOTIABLE**: define tests →
validate they fail → implement → green → refactor. Required kinds: unit tests for pure
functions, contract tests for exported functions, **idempotency tests** (a second run yields zero
changes and reports `Converged`), and **drift audit tests**.

### 2.7 Idempotency and no-op are product requirements

Constitution III and IV: a second immediate run must yield 0 changes and mark the run
`Converged`; every run must be safe with nothing pending; `-WhatIf` must emit a plan.

### 2.8 Keep the diff focused

`CONTRIBUTING.md`: one concern per PR, no bundled changes, no incidental reformatting, no
mass config reformatting. New public parameters and alternate topologies are rejected unless
they were the agreed subject of the issue.

---

## 3. CI gates (`.github/workflows/ci.yml`)

Runs on `windows-latest`. Triggers: push to `main`/`develop`, PRs to `main`/`develop`, and a
daily 02:00 UTC schedule.

| Job | Gate |
|---|---|
| Lint | `Invoke-ScriptAnalyzer` over `modules/TierModel`, `Deploy-TierModel.ps1`, `Audit-TierModel.ps1`. Exits non-zero on any finding that is not in the exclude list. **`optional/` is not linted.** |
| Test | Pester, pinned `>= 5.0.0` and `<= 5.99.99`. Pester 6 is explicitly out of scope. |
| Coverage | **80% minimum**, hard failure below. Population: `modules/TierModel/*.psm1`, `modules/TierModel/public/*.ps1`, `optional/Update-TierModelMembership.ps1`. |

The workflow, not `Invoke-AllTests.ps1`, dot-sources `tests/helpers/ADStubs.ps1` and configures
JUnit XML output.

> **In this fork, GitHub Actions is currently disabled.** `list_workflows` returns 0, which is
> GitHub's default for forks. Until someone enables it in *Settings → Actions*, **no CI runs at
> all**, not even on a pull request.

---

## 4. Test suite — conventions and traps

Run: `.\tests\Invoke-AllTests.ps1` (`-TestType Unit|Integration`, `-FailedOnly`, `-Detailed`,
`-PassThru`). Tests use mocks and need no live AD.

### Traps that have actually bitten (all verified by execution)

1. **A `BeforeEach` directly in the file container is illegal in Pester 5.** It aborts the whole
   file during discovery with *"Each test setup is not supported in root (directly in the block
   container)"* and reports every test in the file as failed. Put it inside a `Describe`.
2. **`$script:` variables from `BeforeAll` are invisible inside `-ModuleName` mock bodies.** The
   mock runs in the *module's* session state, so the variable resolves to `$null` there — which
   produces a plausible-looking but wrong fixture and sends the code down a fallback path while
   appearing to test the intended one. Use literals inside mock bodies.
3. **`Get-ADGroup -Filter` does not throw when nothing matches.** It returns empty. A `catch`
   around it is not a not-found handler. `Resolve-ADPrincipalSid` documents this at its
   `Get-ADObject` call.
4. **`tests/Unit.ModuleManifest.Tests.ps1` counts *files* in `public/` against
   `FunctionsToExport`,** not runtime exports. So: a new **file** in `public/` needs a manifest
   entry; extra **unexported functions inside an existing file** are fine and are the normal way
   to add private helpers. `TierModel.psm1` lines 24-40 explain this.
5. **Release notes must carry an entry for the manifest's own `ModuleVersion`.** Bumping
   `ModuleVersion` without adding a matching `ReleaseNotes` entry fails a test — and three places
   pin the version: `TierModel.psd1`, `tests/Unit.ModuleManifest.Tests.ps1`,
   `tests/Integration.Module.Tests.ps1`.
6. **Test house style in the guard tests** (`Unit.DebugProhibition`, `Unit.ModuleManifest`,
   `Unit.AuditReporting`): assert exact integers, never `-BeGreaterThan 0`, and include an
   **anti-vacuity assertion** proving the scan actually read files. Follow it when extending them.
7. **A hard-coded NTAccount name in a test fixture does not survive a localized host.** Rule 2.5
   applies to tests exactly as it does to product code. `'BUILTIN\Administrators'`,
   `'NT AUTHORITY\SELF'` and `'Everyone'` cannot be translated on German Windows — the accounts
   read `VORDEFINIERT\Administratoren`, `NT-AUTORITÄT\SELBST` and `Jeder` there — so
   `NTAccount(...).Translate()` throws and the code under test takes a path the test did not
   intend. Write the SID (`'S-1-5-10'`, `'S-1-5-32-544'`) into the fixture, or derive the name
   from the SID at run time. Comments in the suite claiming these names *"resolve on any Windows
   machine"* are wrong; **31 tests fail on German Windows for exactly this reason** (§6) — 28
   through `NTAccount(...).Translate()` and 3 through an assertion on the rendered name.
8. **`IsDomainAdmin` cannot be mocked.** `Test-TierModelPrerequisites` reads it from the caller's
   own logon token (`[WindowsIdentity]::GetCurrent()`), deliberately, so that a string-typed SID
   from the compatibility shim cannot fake membership. On a host where the session really *is* a
   Domain Admin, the test *"… report not-admin"* therefore fails and nothing in the test can
   prevent it. Expected; CI does not run as a Domain Admin.

### Running the suite on Linux

The suite is Windows-authored and CI runs it on `windows-latest`. It is *possible* to run most of
it on Linux, but the result is not a substitute:

- **`[System.Security.Principal.SecurityIdentifier]` cannot be constructed from a string on
  Linux** — *"Windows Principal functionality is not supported on this platform."* Since
  `ConvertTo-TierModelSidString` validates every SID that way, **no SID-dependent code path can be
  verified on Linux at all.**
- ~26 test files build paths with literal backslashes and `Modules` vs. the real `modules`, which
  aborts them in `BeforeAll`.
- `Invoke-AllTests.ps1` emits no machine-readable result and never dot-sources `ADStubs.ps1`.
- `Test-NetConnection` is not stubbed; `Get-Acl`/`Set-Acl` stubs are not exported globally, so
  `Mock ... -ModuleName TierModel` cannot resolve them.

Measured on `origin/main` with a normalizing harness: 1994 tests discovered, 1680 passed, 314
failed for platform reasons. Useful as a **regression baseline by diffing two revisions under the
same harness** — not as proof of correctness.

---

## 5. Current branch state

Branch: **`claude/beautiful-galileo-skfp32`** — German/localized Active Directory support.
Target version **2.2.0**. Spec and plan: `specs/008-german-language-support/`.

**Config is untouched:** 0 of 19 JSON files, 0 of 260 GPO backup files. The English names in the
configuration became canonical *identifiers* resolved to well-known SIDs, instead of being
translated per language. Production diff: ~1018 lines added, 149 existing lines removed across 15
files; `Resolve-TierModelPrincipalSid.ps1` is +564/−3.

Two defects fixed that also affect English deployments:

- `New-TierModelGpo` downgraded a failed **Deny-Apply ACE** to a console warning while the run
  reported success — a tier-restriction GPO could deploy without its domain-controller
  protection. Now SID-based and fails the GPO action. **This direction (warn → hard-stop) is a
  strengthening, but it is still a behaviour change for existing English deployments.**
- Windows LAPS SELF detection and the holder allow-list compared translated names, making the
  delegation non-idempotent and reporting every legitimate administrative holder as drift.

Three further fixes came out of actually executing the code rather than reading it:

- The well-known SID table had grown 15 bare built-in aliases the configuration never uses
  (`Remote Desktop Users`, `Event Log Readers`, …). Those are legal names for a *customer's own
  domain group*, so listing them would have silently shadowed it. Narrowed to the three the
  configuration needs; see rule 2.4.
- `Resolve-TierModelDelegationOuDn` no longer trusts the literal `OU=Domain Controllers` — it
  uses the configured DN when it resolves and the `wellKnownObject`-backed container when it
  does not. Neither answer to "is that OU localized" is assumed.
- `Resolve-TierModelLapsPrincipal` discarded an already-read `sAMAccountName` when the SID
  normalisation in the same `try` failed, which blocked the entire Windows LAPS deployment.

`optional/Test-TierModelLocalizedDeployment.ps1` is also part of this branch: a read-only
post-deployment report covering what the product audit does not (§6 item 6).

Two test files were then brought onto the new contracts, after the German Windows run showed
what the Linux harness could not:

- `Unit.GpoOperations` ×2 — rewritten from "a failed Deny-Apply ACE is a warning and the GPO
  still counts as executed" to "it fails the GPO action". Deliberate, and the reason is spelled
  out in the `NOTE:` block above that Context so nobody relaxes it back by accident.
- `Unit.WinLapsAclOperations` ×8 + `Integration.WinLapsDeployment` ×1 — the SELF ACE fixtures
  carried the literal `'NT AUTHORITY\SELF'`, which German Windows cannot translate, so the
  product's (correct) SID comparison saw no SELF ACE and reported the delegation as
  non-compliant. They now carry `'S-1-5-10'`. One of them additionally needed a domain SID in
  its `Get-ADDomain` mock, because Domain Admins is recognised by RID 512 and not by name.

### Three GPO robustness fixes — from the lab deploy, not from localization

The first German lab deployment (2026-09-15) applied 518 actions and failed on exactly one of
123 GPO imports with `0x80070091 ERROR_DIR_NOT_EMPTY`, 19 ms after the preceding import **from
the same backup source** finished. Nothing about it is language-specific; all three defects hit
English deployments identically. Fixed here because the branch owner asked for it — the commit
is written so it can be split out again for upstream.

1. **No retry around the SYSVOL writes.** `Import-GPO` clears the target policy folder before
   copying into it, and a run does 123 imports back to back. `Invoke-TierModelTransientRetry`
   (module-scope, inline in `TierModel.psm1` for the reason documented at
   `Initialize-TierModelLogging`) now wraps the `Import-GPO` call and the three SYSVOL writes in
   `Update-TierModelGPOConfig`. Backoff is the one already used in `New-TierModelOu.ps1`.
   Classification is by **HRESULT, never by message text** — the same failure reads *"Das
   Verzeichnis ist nicht leer."* on a German host (rule 2.5). A non-transient error still throws
   on the first attempt and an unrecoverable transient one still fails the action: **no
   fail-fast was softened** (rule 2.2).
   *Trap for the next reader:* PowerShell parses `0x80070091` as a **signed Int32**
   (`-2147024751`), which is exactly what `Exception.HResult` carries. Masking it to 32 unsigned
   bits — the obvious defensive move — makes every comparison fail silently.
2. **A half-built GPO was never repaired.** `Get-TierModelGpo` emitted Create/Import/Configure
   only inside `if (-not $existingGPO)`, so the GPO whose create succeeded and whose import
   failed was seen as existing on the next run, got only its link planned, and the deployment
   reported `Converged` over an empty policy — a direct breach of constitution principle III.
   `Test-TierModelGpoPolicyPopulated` (unexported, inside `Get-TierModelGpo.ps1`) now reads the
   policy folder in SYSVOL and the planner re-plans Import/Configure when it is provably empty.
   The check is **deliberately asymmetric**: a folder that has not replicated to this host, or a
   SYSVOL that cannot be read, changes nothing. Re-importing overwrites settings, so it must
   never act on a state it could not read. That asymmetry is also what keeps the second run at
   zero actions.
   *Trap:* `Join-Path` resolves a path provider and throws on a UNC root where no drive can be
   derived (on Linux), which sent every probe into its catch and silently disabled the feature.
   UNC paths are composed as plain strings.
3. **`Errors:` and `Applied:` were double-counted.** The GPO result publishes both an `Errors`
   array and a `Failed` integer for the same failures and the summary added both — two failed
   actions printed `Errors: 4`. Each result is now counted from exactly one source. The
   standalone `-Include*` aggregation already did this correctly and was left alone.

**Not changed, on purpose:** `Deploy-TierModel.ps1:1694` returns from the GPO deployment when
*any* configure action fails — which is why that single failure also skipped all **131** planned
GPO links. Turning it into a warn-and-continue is exactly what rule 2.2 forbids without design
sign-off. With the retry and the re-plan in place it stops being the practical problem.

### Authentication Policy Silos — the defect the second lab run found

The hardened Phase C run (2026-09-16) got as far as the silo phase and stopped there:
`AuthSiloPrerequisiteGroupMissing … GroupName: "Domain Controllers"`, twice, then
`Passed: false, FailureCount: 2, Checked: 8` — the six Tier Model-owned groups resolved, the two
built-ins did not. A textbook breach of rule 2.4, found only because the GPO fixes let the run
reach that far.

The SDDL half of the silo code was already correct (`New-TierModelAuthPolicy.ps1:74`,
`Test-TierModelAuthPolicy.ps1:151` go through `Resolve-TierModelPrincipalSid`). The membership
half was not, in four places: the prerequisite gate, the membership planner
(`Get-TierModelAuthSiloMembershipFd`), the membership assignment
(`Set-TierModelAuthSiloMembership`) and the silo audit (`Test-TierModelAuthSilo`). All four now
go through `Resolve-TierModelGroupIdentity` — module-scope and unexported, inline in
`TierModel.psm1` next to `Invoke-TierModelTransientRetry`, for the same manifest-test reason.

Two things are deliberate:

- **The gate keeps its `Get-ADGroup` read-back.** Only the `-Identity` became SID-based. The
  resolver's last resort is `Resolve-ADPrincipalSid`, which tries `Get-ADUser` *before*
  `Get-ADGroup` (`Resolve-TierModelPrincipalSid.ps1:996`), so dropping the read-back would let a
  *user account* named `Tier0PAWDevices` satisfy a group prerequisite. That is a relaxation of
  security-relevant validation — rule 2.2 territory — for one saved directory read out of eight.
- **In the audit the old behaviour was worse than an error.** `Test-TierModelAuthSilo.ps1:169`
  turns a failed group expansion into a *compliance issue string*, so a localized domain audited
  as non-compliant on principle rather than reporting a read failure.

Alongside it, `Deploy-TierModel.ps1:2717`: a failed gate printed red and was not counted, so the
run ended `Deploy script completed successfully` with no silo deployed. The standalone
`-Include*` path already counted it (`:3458`); the `-FullDeployment` path now does too. That is a
tightening, not a relaxation — the control flow is unchanged.

The C3 run then showed a third, smaller thing: `AuthSiloPrerequisiteGroupOk … ActualName: null`.
The SID cache stored only `Sid`/`Source`/`Success`/`Error`, so the *directory* name — the whole
point of the log line — survived only until the first cache hit, and the GPO phase warms the
cache long before the gate runs. It is carried through the cache now.
*Trap:* the module runs under `Set-StrictMode -Version Latest`, where reading a key a hashtable
does not have **throws** instead of returning `$null`, and the `Get-WellKnownSid` entries
legitimately have none. Use `ContainsKey`.

**The SID-composition core is verified.** `tests/Unit.CanonicalPrincipal.Tests.ps1` ran
**59 of 59 green on a German Windows host against a German directory** — the 22 tests that
cannot even execute on Linux are precisely the ones that carry this proof. What remains
unverified is the *deployment*, not the resolver: see §6 item 5 and
`docs/german-lab-runbook.md`.

---

## 6. Next steps

Ordered. Items 1–3 are the actual acceptance gate.

1. ~~**Run the suite on Windows.**~~ **Done, twice.** German Windows 11 / PowerShell 7.6.6
   against a German domain, as a Domain Admin. First run: 2012 passed of 2053, 41 failed.
   After the eight fixes in §5: **2021 passed of 2053, 32 failed**, all of them the
   pre-existing ones listed below. `tests/Unit.CanonicalPrincipal.Tests.ps1` was
   **59 of 59 green** both times — that file is the acceptance gate for the resolver and it is
   met. `docs/german-lab-runbook.md` Phase A is the repeatable form of this run.
2. **The 41 failures, classified.** Eight belonged to this branch and are fixed (§5). The
   remaining **32 are pre-existing** — they fail on `origin/main` on the same host, they live in
   files this branch does not touch, and their causes are the host's language and the session's
   own token, not this change:

   | File | × | Cause |
   |---|--:|---|
   | `Unit.OuAclOperations` | 10 | fixture `'BUILTIN\Administrators'` / `'BUILTIN\Users'` — untranslatable on German Windows (§4 trap 7) |
   | `Unit.MsaAclOperations` | 7 | same |
   | `Unit.GmsaAclOperations` | 7 | same |
   | `Unit.DmsaAclOperations` | 4 | same |
   | `Unit.CanonicalAcl` | 3 | `Should -Match 'Everyone\|S-1-1-0'` against the directory's `Jeder` |
   | `Unit.Prerequisites` | 1 | `IsDomainAdmin` comes from the real logon token (§4 trap 8) |

   The 41st, *"ByBytes does not require -PreferredDc"*, is not in that table because it is not a
   property of the host at all: it asserts that a missing mandatory `-PreferredDc` raises a
   binding error, and an interactive host **prompts** for the parameter instead of raising it, so
   the whole run stops there. Start the suite as `pwsh -NonInteractive -File
   .\tests\Invoke-AllTests.ps1` — that is what CI does, and the test passes. (At the prompt,
   an empty line also produces a binding error and passes; a typed DC name does not.)

   **Fixing the other 32 is a separate concern** (CONTRIBUTING: one concern per PR) and needs its
   own issue. They are invisible to CI, which runs English — which is why they survived this long.

   Measured figures. Windows, after the fixes: **2021 passed of 2053**, and the 32 failures are
   the table above line for line — nothing outside it. `Unit.CanonicalPrincipal` 59 of 59,
   `Unit.WinLapsAclOperations`, `Integration.WinLapsDeployment` and `Unit.GpoOperations` all
   green. Before the fixes it was 2012 of 2053 with 41 failures. Linux harness: baseline 1680
   passed of 1994; HEAD **1715 of 2053**, 0 regressions against the pre-fix HEAD.

   Not a regression, and not open: `Unit.ModuleManifest` is already only 6 of 63 green on the
   **baseline** under Linux, so that file is platform-broken rather than affected by this change.
3. **Run PSScriptAnalyzer.** Not obtainable in the Linux container (absent from nuget.org;
   PowerShell Gallery and GitHub releases blocked by the network policy). It is a CI gate, so it
   must run somewhere before merge.
4. **Coverage** against the CI population, ≥ 80%. The population and the gate are in
   `.github/workflows/ci.yml:133-136` and `:155-173`: `modules/TierModel/*.psm1`,
   `modules/TierModel/public/*.ps1`, `optional/Update-TierModelMembership.ps1`.

   **Linux floor, measured on `4812e17`: 78.35% (13472 of 17195 commands), with 1719 of 2082
   tests passing.** That is a *lower bound*, not the CI number: the 363 tests that cannot run
   off Windows are exactly the ones that would execute the SID-dependent paths, so every
   command they reach is counted as missed. It says the real figure is somewhere above 78.35%
   — it does **not** say the gate passes.

   The authoritative number has to come from the Windows lab, with the CI configuration
   reproduced verbatim (run it as `pwsh -NonInteractive`, or the suite stops at the
   `-PreferredDc` prompt — see item 2):

   ```powershell
   Import-Module Pester -MinimumVersion 5.0.0 -MaximumVersion 5.99.99
   $c = [PesterConfiguration]::Default
   $c.Run.Path                  = './tests'
   $c.Run.PassThru              = $true
   $c.CodeCoverage.Enabled      = $true
   $c.CodeCoverage.Path         = "modules/TierModel/*.psm1","modules/TierModel/public/*.ps1","optional/Update-TierModelMembership.ps1"
   $c.CodeCoverage.OutputFormat = 'JaCoCo'
   $c.CodeCoverage.OutputPath   = 'coverage.xml'
   $r = Invoke-Pester -Configuration $c
   '{0}% ({1} / {2})' -f [math]::Round(($r.CodeCoverage.CommandsExecutedCount / $r.CodeCoverage.CommandsAnalyzedCount) * 100, 2),
       $r.CodeCoverage.CommandsExecutedCount, $r.CodeCoverage.CommandsAnalyzedCount
   ```

   If Windows also lands below 80%, the commands missed on Linux cluster in a short list, and
   it is the place to start rather than a guess: `Test-TierModelPrerequisites.ps1` (485),
   `New-TierModelOu.ps1` (478), `optional/Update-TierModelMembership.ps1` (414),
   `Repair-TierModelCanonicalAcl.ps1` (182), `Test-TierModelAdmx.ps1` (140),
   `TierModel.psm1` (137). Those counts are themselves Linux figures and shrink on Windows.

   Then update the README test table — it is deliberately still at its last *measured* values
   rather than estimated.
5. **Add the completeness tests** designed but not yet written (`specs/008-german-language-support/plan.md`,
   phase D): every principal in the real config must resolve by a defined path; English and
   German fixtures must produce **identical SID sets**, both at the resolver and in the generated
   `[Privilege Rights]`.
6. **German lab acceptance.** Phases A–E are done; F is open.

   **Phase B (plan) passed** on `int.promiseIT.de`: prerequisites validated, 718 actions, no
   `RequiredGroupNotFound` — the two blockers the old code stopped at are gone. The canary
   groups read `Domänen-Admins` / `Server-Operatoren` / `Konten-Operatoren`, so this is a
   genuinely localized directory and everything measured on it counts.

   **Phase C (deploy) applied 518 of the planned actions**, including **105 OU ACLs with zero
   failures**, each logged with the SID it resolved to — the first live evidence that the
   `NTAccount(...).Translate()` ACL paths work against a German directory. It then failed on
   1 of 123 GPO imports and reported `Errors: 4 / Converged: False`. All three causes were
   product defects unrelated to language and are fixed in this branch (§5): the run is to be
   repeated on the fixed code, which is itself the acceptance test for those fixes. 518 is
   exactly `31 + 29 + 3 + 105 + 146 + 122 + 22 + 60` — no GPO link was applied, because the
   configure failure returns before phase 4.

   **Phase C repeated (2026-09-16) on the fixed code — the GPO fixes are accepted.** All
   **131 GPO links applied**, `FailedActions: 0`, closing the gap from the first run. MSA, gMSA
   and dMSA applied 4 of 4 each. **Windows LAPS ran for the first time at all**:
   `AppliedActions: 17, FailedActions: 0` — SELF on 6 OUs and decryptors on 6 GPOs against a
   German directory. The standard scopes were already converged: OUs `ToCreate: 0 /
   ExistingCount: 31`, groups `0 / 29`, users `0`, OU ACLs `TotalActions: 0 / ExistingAcls: 105`
   (all "already exists with exact match"), ADMX `0 / 0`.

   Two findings from that run, **both now closed**:

   - **The half-built GPO `{60718cf3-…}` was not repaired, correctly.** The SYSVOL probe threw
     *"Access to the path … GptTmpl.inf is denied"* — `Test-Path` raises on a denied path instead
     of returning `$false` — so the deliberate asymmetry declined to re-plan
     (`ImportActions: 0, ConfigureActions: 0`). The denial was persistent, across two runs on two
     days, so the retry could not help either. This was the documented fallback, not a defect;
     the operator deleted the unlinked template GPO and the next run recreated it. Diagnose the
     ACL **before** deleting; `docs/german-lab-runbook.md` has the sequence.
   - **The auth silo localization defect** (§5), fixed in `bc3500f`.

   **Phase C, third run (2026-09-16 10:35–10:37, commit `bc3500f`) — the fixes are accepted on
   the live German domain.** Exactly 11 actions, everything else already converged:

   - **Auth silo gate green:** `AuthSiloPrerequisiteGroupOk … GroupName: "Domain Controllers",
     Sid: "S-1-5-21-2230522700-2543936044-3532250090-516"`, the same for `-521` →
     `Passed: true, FailureCount: 0, Checked: 8`. Then 4 policies and 4 silos created, both
     `ErrorCount: 0`.
   - **`Get-ADGroupMember -Identity <SID>` works against the German directory:**
     `AuthSiloAccessGranted … SamAccountName: "DC1$"` — DC1 was found *through* the group
     resolved by RID 516, `Converged: true`.
   - **The GPO was rebuilt end to end:** create, import (2.2 s) and configure each
     `FailedActions: 0`, new GUID `527b777a-…`, `GptTmpl.inf` 3302 bytes.
   - **Windows LAPS is idempotent — the direct proof for the SELF defect this branch fixes:**
     `WinLapsAclFdPlanningComplete … TotalActions: 0, ExistingCount: 27`, logged twice in the
     run. The previous run had applied 17 LAPS actions.
   - Everything else at zero: OUs `0 / 31`, groups `0 / 29`, users `0`, OU ACLs
     `TotalActions: 0 / ExistingAcls: 105`, ADMX `0 / 0` of 30, MSA/gMSA/dMSA `0 / 4` each, and
     **`TotalGPOsToLink: 0`** — all 131 links are in place.

   **Phase D (idempotency) passed — 2026-09-16 11:00, the same command again.** Every planner
   reported zero, so the run never reached an execution phase at all and printed
   `Applied: 0 / Skipped: 0 / Errors: 0 / Converged: True` (`Deploy-TierModel.ps1:2841-2849`,
   the branch taken when the plan is empty). The whole run took 48 seconds.

   | Planner | Result |
   |---|---|
   | OUs / groups / users | `ToCreate: 0` of 31, 0 of 29, 0 of 3 |
   | OU ACLs | `TotalActions: 0, ExistingAcls: 105` |
   | **GPOs, including links** | `GPO Full Deployment planning completed … TotalActions: 0` |
   | ADMX | `AdmxToUpdate: 0, AdmlToUpdate: 0` of 30 |
   | MSA / gMSA / dMSA | `TotalActions: 0, ExistingAcls: 4` each |
   | **Windows LAPS** | `TotalActions: 0, ExistingCount: 27` |
   | **Auth policies / silos** | `AlreadyExist: 4` each, `ToCreate: 0` — four `AuthPolicyFdPlanAlreadyExists` and four `AuthSiloFdPlanAlreadyExists` entries |

   That is constitution principle III met on a localized directory, and it settles the two
   things this branch changed most: the Windows LAPS SELF comparison (17 actions on the first
   run, 0 on the second) and the GPO re-plan probe (it did **not** call a populated policy
   folder empty). The auth silo objects created in the previous run were recognised by name —
   they are Tier Model-owned objects, so no SID resolution is involved there.

   **Phase E, first half (audit) passed — 2026-09-16 11:04.** `Audit-TierModel.ps1
   -FullDeployment` with every `-Include*` switch: **`TotalChecked: 433, DriftCount: 0,
   ErrorCount: 0, UnverifiedCount: 0`**.

   | Scope | Result |
   |---|---|
   | OUs / groups / users | 31 / 29 / 3, no drift |
   | OU ACLs | `Compliant: 105, Mismatched: 0, CompliancePercentage: 100.0` |
   | GPOs | `TotalChecked: 146, TotalPassed: 146, TotalFailed: 0` — existence, links **and** GptTmpl content |
   | ADMX | 60 of 60 |
   | MSA / gMSA / dMSA | 2 each, compliant |
   | **Windows LAPS** | ACLs `Compliant: 7`, decryptors `Compliant: 6`, `Drift: 0` |
   | **Auth policies** | `Compliant: 4, NonCompliant: 0` — the `Member_of_any` SDDL compared against the live directory |
   | **Auth silos** | `Compliant: 4, NonCompliant: 0` |

   Two of those rows had never run against a localized directory before. The auth silo audit
   expands `Domain Controllers` to enumerate expected computer members; before the SID fix that
   expansion threw and `Test-TierModelAuthSilo.ps1:169` turned the failure into a compliance
   issue, so the verdict would have been NonCompliant on principle. The Windows LAPS rows are
   the audit-side counterpart of the SELF/holder comparison. The rebuilt template GPO
   (`… Tier 1 Servers Account Restrictions - Override - Deny Remote Desktop`) passes content
   validation with a 1648-byte GptTmpl, and no GPO reports a missing GptTmpl.inf — the SYSVOL
   repair is confirmed from the other side.

   **Phase E, second half (localization report) passed — 2026-09-16 11:05.**
   `optional/Test-TierModelLocalizedDeployment.ps1 -IncludeWinLaps -IncludeAuthSilos
   -IncludeAudit`, read-only, covering what the product audit does not:

   - **Environment.** Host `de-DE`, install language `0407`, domain `int.promiseIT.de`
     (`Windows2025Domain`, forest root), `DirectoryLanguage: localized`. Canaries:
     `Domänen-Admins`, `Server-Operatoren`, `Konten-Operatoren`.
   - **Principal resolution: `Total: 56, Unresolved: 0, LocalizedNameCount: 42`.** Every
     principal the configuration names resolves, and 42 of them carry a *German* directory
     name — `Domain Controllers → …-516 (Domänencontroller)`,
     `Enterprise Admins → …-519 (Organisations-Admins)`,
     `Allowed RODC Password Replication Group → …-571
     (Zulässige RODC-Kennwortreplikationsgruppe)`. Sources are `CanonicalDomainRid`,
     `CanonicalForestRootRid`, `WellKnown` and `ADGroup`; not one falls back to a name lookup
     of an English built-in.
   - **The Deny-Apply ACE is on the GPC: `Checked: 2, Missing: 0`,** `AcePresent: true` for both
     `…-516` and `…-521` on `CN={cdfe6fce-…},CN=Policies,CN=System,DC=int,DC=promiseIT,DC=de`.
     That is the live confirmation of the security fix in `New-TierModelGpo` — the product audit
     does **not** check this ACE, only this report does
     (`optional/Test-TierModelLocalizedDeployment.ps1:386`).
   - **`[Privilege Rights]` from SYSVOL: 1651 of 1791 entries across 29 GPOs are SIDs.** The
     140 that are not are 33 distinct machine-local principals — `NT SERVICE\*`,
     `IIS APPPOOL\*`, `CLIUSR` — and every one of them is a configured
     `literalStrings` entry in `config/tiermodel-gpos.json` (`:715`, `:757`, `:3979` …). They
     have no domain SID by construction; `secedit` resolves them on the target machine. The
     report flagged all 140 as `Problems` because its rule was "everything should be a SID".
     **Fixed:** the rule now reads the configured `literalStrings` and reports only entries
     nobody declared, so the next run shows 0 problems and a stray plain name stands out.
     Measured against the lab data: the configuration declares exactly 33 `literalStrings`, and
     all 33 distinct non-SID principals in that SYSVOL match one — nothing left over.
     `tests/Unit.LocalizedVerification.Tests.ps1` pins the count.
   - Third independent confirmation that `DomainControllersContainer` is
     `OU=Domain Controllers,DC=int,DC=promiseIT,DC=de` — **not** localized on this domain.

   **Still open in Phase E:** nothing, other than running the same report on an English domain
   and diffing the `PrivilegeRights` sections, which is the parity proof. Use
   `tests/Manual.Integration.Tests.xlsx` for the manual checklist.
7. **German ADML content.** `optional/New-TierModelAdmlManifest.ps1` and the procedure in
   `docs/admx-management.md` are ready; the `.adml` files are Microsoft redistributables and must
   be supplied by the operator. `download.microsoft.com` is blocked from the build environment
   (403 on CONNECT).
8. **Enable GitHub Actions in the fork** so CI becomes the authoritative Windows check.

### Open questions that must not be answered by assumption

- ~~**Is the `Domain Controllers` OU localized on a German domain?**~~ **Answered, measured.**
  On `int.promiseIT.de` (German Windows, German directory) `Get-ADDomain` reports
  `DomainControllersContainer = OU=Domain Controllers,DC=int,DC=promiseIT,DC=de` — the OU keeps
  its English name. One domain is not every domain, so the fallback in
  `Resolve-TierModelDelegationOuDn` stays; it simply never fires here. Removing it needs a
  second localized domain to confirm against, not this one measurement.
- **Does `Import-GPO` carry the source lab's `<SecurityGroups>` names into the imported GPO?**
  `config/gpo/**/Backup.xml` contains the source domain's `Domain Admins` / `Enterprise Admins`
  with their original SIDs. Expected to be inert because `Import-GPO` imports settings rather
  than the GPO security descriptor — **still expected, not verified.**

  The localization report narrows it but does not close it. Every `[Privilege Rights]` SID it
  read from SYSVOL carries this domain's prefix `S-1-5-21-2230522700-2543936044-3532250090`, so
  no foreign SID reached the *settings*. What nobody has looked at is the GPC's full DACL: the
  report checks only that the two Deny-Apply ACEs are present, not that nothing else is there.
  Two read-only commands settle it — a foreign SID has no local translation and therefore shows
  up as a raw `S-1-5-21-…` string:

  ```powershell
  $dc  = 'DC1.int.promiseIT.de'
  $own = (Get-ADDomain -Server $dc).DomainSID.Value
  $dn  = (Get-ADDomain -Server $dc).DistinguishedName

  Get-GPO -All -Server $dc | Where-Object DisplayName -like '`*- Tier*' | ForEach-Object {
      $acl = Get-Acl -Path "AD:CN={$($_.Id)},CN=Policies,CN=System,$dn"
      $foreign = $acl.Access | Where-Object {
          $_.IdentityReference.Value -match '^S-1-5-21-' -and
          $_.IdentityReference.Value -notlike "$own*"
      }
      if ($foreign) { [PSCustomObject]@{ Gpo = $_.DisplayName; Foreign = ($foreign.IdentityReference.Value -join ', ') } }
  }

  Get-ChildItem "\\$dc\SYSVOL\int.promiseIT.de\Policies" -Recurse -Filter GptTmpl.inf |
      Select-String -Pattern "S-1-5-21-(?!$($own -replace '^S-1-5-21-'))" |
      Select-Object -First 20 Path, Line
  ```

  No output from either means inert, and the question is answered by measurement.

---

## 7. Environment notes for this container

- No PowerShell by default. Installable: `packages.microsoft.com` is reachable (Ubuntu 24.04
  `noble`), giving `powershell` 7.6.x.
- Pester is **not** obtainable from the PowerShell Gallery (blocked), but **is** on
  `api.nuget.org` as a complete module: `pester.<version>.nupkg` → `tools/` contains
  `Pester.psd1`, `Pester.psm1` and `bin/netstandard2.0/Pester.dll`. No build needed.
- PSScriptAnalyzer is not obtainable by any reachable route.
- `download.microsoft.com`, `www.powershellgallery.com` and `codeload.github.com` are blocked;
  `git clone`/`push` over `github.com` works.
- PowerShell 7.6 on Linux **does** ship `System.DirectoryServices`, so its type and enum literals
  resolve — but runtime directory operations and `SecurityIdentifier` construction do not.

---

## 8. Style

- German is fine for conversation with the repository owner; **all repository content — code,
  comments, commit messages, documentation — is English.**
- Comments explain *why*, especially where the code defends against something non-obvious. The
  existing codebase does this well (see `ConvertTo-TierModelSidString` and
  `Unit.DebugProhibition.Tests.ps1`); match that density rather than adding narration.
- Structured logging goes through `Write-TierModelLog` with `-Level` and `-Data`, and carries a
  correlation ID (constitution VI).
- Timestamps use `InvariantCulture` so log and report filenames do not vary with host locale.
