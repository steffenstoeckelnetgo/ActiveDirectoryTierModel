# CLAUDE.md — Active Directory Tier Model

Working notes for AI assistants and new contributors. Everything here is drawn from files in
this repository or from commands actually executed against it; where something is unverified it
says so explicitly.

---

## 0. What this working copy is for — read this first

**The goal.** Make `Deploy-TierModel.ps1` and `Audit-TierModel.ps1` deploy and audit against an
Active Directory installed in **any** language, from a host installed in any language — in
practice, and as actually tested, **German Windows against a German domain**. Upstream refuses to
run outside English and enforces that with two fail-fast prerequisite gates.

**The one design decision everything else follows from:** the configuration is **not translated**.
`config/` is untouched — 0 of 19 JSON files, 0 of 260 GPO backup files. The English names in it
became canonical *identifiers* resolved through the **invariant SID** (rule 2.4), so one
configuration set deploys in any language and keeps working where a built-in group has been
renamed.

**Where the work is: on `main`.** It landed there on 2026-09-17 through
[PR #1](https://github.com/steffenstoeckelnetgo/ActiveDirectoryTierModel/pull/1) — 8 new and 39
changed files, version 2.2.0, spec in `specs/008-german-language-support/`. There is no
long-lived feature branch left to check out.

**How to work here, decided by the repository owner on 2026-09-17:**

| Change | Where |
|---|---|
| **Code — product *or* tests** | a **short-lived branch, then a pull request**. One concern per branch, merged promptly, branch deleted after. |
| **Documentation-only corrections** | directly on `main`. |

**The reason, because it is what carries the rule:** GitHub Actions is disabled in this fork (§3),
so **nothing checks a commit before it is on `main`** — no lint, no Pester, no coverage gate. And
there are no release tags, so `main` *is* the deployable state of a tool that writes ACLs, GPOs and
authentication policies into a production directory. The pull request is therefore the only place a
change is ever read as a whole. Run the repo's own checks yourself before pushing; do not push and
find out.

**Status: functionally complete, verified end to end on a live green-field German domain — and,
since 2026-09-24, proven equal to an English one.** The parity run put both domains side by side
at commit `ce528e4` and `optional/Compare-TierModelDeploymentReport.ps1` reported
**`No differences.`**: the same configuration produces the same security configuration on both,
only the rendered names differ. That is the claim this whole fork rests on, and it is now measured
rather than argued — §6 item 6, Phase F, carries both domain SIDs and the figures.

The per-phase headline below is the green-field German cycle (`int.promiseIT.de`, German
Windows 11 / PowerShell 7.6.6, 2026-09-16); the authoritative tables are in §6's *final* numbered
list, item 1 — not in *Start here* item 1, which is the ACL fixture work. The English side
reproduced every one of these numbers on 2026-09-24.

| Phase | Result |
|---|---|
| Test suite, Windows | **2056 passed of 2088** — the 32 failures were pre-existing, classified in §6 item 2. 31 of them are fixed since 2026-09-25 (§6 *Start here* item 1), so this figure now understates by that much; it is left as measured rather than re-derived |
| Plan | 719 actions |
| Deploy | **`Applied: 689, Skipped: 0, Errors: 0`** |
| Idempotency, second run | `Applied: 0, Errors: 0, Converged: True` |
| Audit | `TotalChecked: 433, Drift 0, Errors 0` — 100 % |
| Localization report | 56 principals, 0 unresolved, 42 of them carrying a German directory name; **`No problems found.`** |

**Where the standard stands.** The code is merged, the three CI gates are measured (coverage
included, §6 item 4) and parity is proven. The standard the repository owner set on 2026-09-17 —
**the product must be demonstrably correct on a German Active Directory, at every change, not once
by observation** — was met by the lab cycle for one domain but not by the suite. Both halves of
that gap closed on 2026-09-25:

| Half | Closed by |
|---|---|
| **ACL behaviour** — 31 tests could not execute on a German host at all | `33e4e11`, §6 *Start here* item 1. 280 → **311 of 311** on the German host, 311 of 311 unchanged on the English one |
| **Principal resolution** — no test asserted that every principal the real `config/` names resolves by a defined path, or that English and German fixtures produce identical SID sets | `e057e62`, §6 *Start here* item 2. **86 of 86**, and 83 of them run on Linux, so CI can carry them |

**What is still open** is §6 *Start here* item 3: the GPC DACL half of the `Import-GPO`
`<SecurityGroups>` question, which is two read-only commands away from an answer and until then an
open security question. **Do not tag a release until it is closed** — the repository carries no
tags yet, so the first one should mean something. Item 4, a second German domain, is not a gate
but belongs in the release notes as an accepted limit if none is available.

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
| `modules/TierModel/` | **83 exported functions**: 80 files under `public/`, one function each, plus `Get-TierModel`, `Get-TierModelPlan` and `Test-TierModelConfig` defined inline in `TierModel.psm1`. `Unit.ModuleManifest.Tests.ps1` compares `FunctionsToExport` against **files + inline**, which is why 80 files and 83 exports are consistent (§4 trap 4). |
| `config/*.json` | 19 config files — the declarative source of truth |
| `config/gpo/` | 260 files of GPO backups (binary-ish; `.gitattributes` marks `*.admx`/`*.adml` binary) |
| `optional/` | Scripts that are not part of a normal run |

This is **upstream `microsoft/ActiveDirectoryTierModel`, forked**. The fork is
`steffenstoeckelnetgo/ActiveDirectoryTierModel`, and it exists to lift the English-only
restriction — see §0.

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
4. **`tests/Unit.ModuleManifest.Tests.ps1` counts *files in `public/` plus functions defined
   inline in `TierModel.psm1`* against `FunctionsToExport`,** not runtime exports. That is why
   **80 files and 83 exports are consistent**: `Get-TierModel`, `Get-TierModelPlan` and
   `Test-TierModelConfig` live in the `.psm1` (§1). So: a new **file** in `public/` needs a
   manifest entry, and so does a new **exported** function added inline; extra **unexported**
   functions inside an existing file are fine and are the normal way to add private helpers.
   `TierModel.psm1` lines 24-40 explain this.
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
   intend. Comments in the suite claiming these names *"resolve on any Windows machine"* were
   wrong; **31 tests failed on German Windows for exactly this reason** — 28 through
   `NTAccount(...).Translate()` and 3 through an assertion on the rendered name. All 31 are fixed
   since 2026-09-25 (§6 *Start here* item 1, `33e4e11`). Literals of this shape still occur
   elsewhere in the suite — 17 of them across six files, measured on `33e4e11` — and none of
   those files fails on a German host today, because there the literal is an *expected* value or
   sits in a mock nothing translates. Do not read that as "these are fine": each is this trap
   waiting for the read path to change. Check what reads the fixture before adding another.

   **There are two routes and they are not interchangeable — picking the wrong one costs a lab
   cycle.** Write the SID into the fixture *only* where the fixture is read by product code that
   accepts a SID string: `ConvertTo-TierModelIdentitySid` returns one unchanged
   (`Resolve-TierModelPrincipalSid.ps1:506`), which is why `4c84f4a` could put `'S-1-5-10'` into
   eight mocked `Get-Acl` fixtures. Where the fixture reaches a **real** cmdlet that constructs
   `New-Object System.Security.Principal.NTAccount($value)` and calls `.Translate(...)` — as
   `New-TierModelOuAcl.ps1:82-83` does with `Plan.Actions[].Data.identityreference` — a SID
   literal throws too, because `NTAccount` takes a *name* and no account is called
   `S-1-5-32-544`. There, **derive the name from the SID at run time**:
   `Get-TestPrincipalName -Sid 'S-1-5-32-544'` in `tests/helpers/LocalizedPrincipals.ps1`, which
   translates and then round-trips the result back to the SID and throws if it does not match —
   a fixture resolving to the *wrong* principal would otherwise leave every test using it green.
8. **`IsDomainAdmin` cannot be mocked.** `Test-TierModelPrerequisites` reads it from the caller's
   own logon token (`[WindowsIdentity]::GetCurrent()`), deliberately, so that a string-typed SID
   from the compatibility shim cannot fake membership. On a host where the session really *is* a
   Domain Admin, the test *"… report not-admin"* therefore fails and nothing in the test can
   prevent it. Expected; CI does not run as a Domain Admin.
9. **`Converged` means two different things across the module, and the summaries no longer
   mix them.** `New-TierModelOu.ps1:502` and `New-TierModelGroup.ps1:206` compute it from
   *"nothing was applied"* (idempotency); the other ~12 executors set `$true` and flip it only
   on failure (*"nothing failed"*). Both consolidated summaries in `Deploy-TierModel.ps1` now
   derive the flag from their own totals instead of AND-ing the results', so a run that applies
   anything reports `Converged: False` — which is what the green-field lab run of 2026-09-16
   shows next to `Errors: 0`. The per-executor flags are unchanged and still carry their own
   meaning; when you read one, check which of the two you are looking at.

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

## 5. What the localization change actually did

Merged to `main` on 2026-09-17 (PR #1); this section is the record of the change, not of a branch.
Version **2.2.0**, spec and plan in `specs/008-german-language-support/`.

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

`optional/Test-TierModelLocalizedDeployment.ps1` came with this change: a read-only
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

### The one thing the green-field run exposed: `Converged` mixed two meanings

The verification run on a **freshly built** `int.promiseIT.de` (2026-09-16, §6's final list,
item 1) ended
`Applied: 689, Errors: 0, Converged: False`. Counted out of `DE-neu-C-091626-1349.log`, exactly
two results reported `Converged: false`, both with `ErrorCount: 0` — `OuCreateComplete`
(`AppliedCount: 31`) and `GroupCreateComplete` (`AppliedCount: 29`). No third.

For that run the verdict was right — something *was* changed — but only by accident. The
summaries AND-ed flags that mean different things (§4 trap 9), so the strictest executor that
happened to run decided the answer. A run that touches only GPOs, ADMX, MSA/gMSA/dMSA, Windows
LAPS or the silos would have printed `Converged: True` after writing hundreds of objects, and a
permanently non-idempotent GPO import — the defect class fixed above in `Get-TierModelGpo` —
would never have shown up in the console summary. Constitution III measures convergence in
changes, so both summaries (`Deploy-TierModel.ps1:2836` and `:3556`) now derive it from the
totals they already compute: `applied -eq 0 -and errors -eq 0`. Strictly a tightening — no run
that read `False` before reads `True` now.

Alongside it, `New-TierModelGroup.ps1:206` gained the error term it was missing: a group phase
in which every create failed and nothing was applied reported `Converged = true`.
`New-TierModelOu.ps1:502` always counted errors too.

`Integration.Deploy.Tests.ps1` changed one expectation for this deliberately — the case that
asserted `Converged: True` after applying now asserts `False`, with a `NOTE:` block above it in
the style of the `Unit.GpoOperations` rewrite, so nobody relaxes it back by accident.

*Not part of this change, found while writing the tests:* `New-TierModelGroup` with an **empty**
plan raises `GroupApplyFailed` — `$Plan.Actions | Where-Object` collapses to `$null` and
`.Count` on it throws under `Set-StrictMode`. Pre-existing, its own concern, not touched here.

**The SID-composition core is verified.** `tests/Unit.CanonicalPrincipal.Tests.ps1` ran
**59 of 59 green on a German Windows host against a German directory** — the 22 tests that
cannot even execute on Linux are precisely the ones that carry this proof. What remains
unverified is the *deployment*, not the resolver: see §6 item 5 and
`docs/german-lab-runbook.md`.

---

## 6. Next steps

### Start here — state of `main`, 2026-09-25

The localization work is **merged** (PR #1) and all three CI gates are measured: suite
**2056 of 2088** on a German host (2026-09-16, and now known to understate by the 31 of item 1),
PSScriptAnalyzer **0 findings / 0 errors**, coverage **85.73 %** against the CI population
(item 4). Work happens on `main` directly (§0). The repository carries **no tags**, so nothing has
been released.

**The standard the repository owner set on 2026-09-17, and the reason this list exists:**

> The product must be **demonstrably** correct on a German Active Directory. Not observed once —
> re-established by the suite at every change.

Two numbers get confused here, so both are written down. **Coverage is not a pass rate:** 85.73 %
says that share of commands was executed by some test at least once; it says nothing about
correctness. The functional evidence is separate, and on the one domain measured it is complete —
deploy 689/689 with 0 errors, second run 0 actions, audit **433 of 433** with 0 drift, principals
**56 of 56** resolved, OU ACLs 105/105, GPOs 146/146 (§6's final list, item 1). What the standard
above is missing is not that evidence. It is that **the suite could not reproduce it**, and that
it rests on a single domain.

**Items 1 and 2 both closed on 2026-09-25.** The 31 ACL tests execute on a German host
(`33e4e11`), and the resolution claim is now a standing guarantee rather than one measured report
(`e057e62`): every principal the real `config/` names is asserted to resolve by a defined path,
and the English and localized fixtures are asserted to produce identical SID sets at the resolver
and in the generated `[Privilege Rights]`. The suite carries both halves of the standard above.

**What is left is item 3** — a security question that is two read-only commands away from an
answer. **Do not tag a release until it is closed.**

#### The work, ordered

**~~1. Bring 31 ACL tests onto SIDs so they execute on a German host.~~ Done, 2026-09-25, merged
as `33e4e11` ([PR #5](https://github.com/steffenstoeckelnetgo/ActiveDirectoryTierModel/pull/5)).**
*Tests only, no product code.* `Unit.OuAclOperations`, `Unit.MsaAclOperations`,
`Unit.GmsaAclOperations`, `Unit.DmsaAclOperations` and `Unit.CanonicalAcl` carried **34 hard-coded
principal names** between them (`'BUILTIN\Administrators'`, `'BUILTIN\Users'`, `'Everyone'`).
German Windows cannot translate those, `NTAccount(...).Translate()` throws, and the code under
test took a path the test did not intend (§4 trap 7) — so ACL behaviour, the security-relevant
part, was not verified on the platform this project exists for. It is now.

| Host | Install language | Revision | Result |
|---|---|---|---|
| `DC1` | `0407` | `main` @ `d4be5e3` | **280 of 311** — the 31, broken down per file in §6's final list, item 2 |
| `DC1` | `0407` | `fix/localized-acl-test-fixtures` @ `6e8a213` | **311 of 311** |
| `SERVER` | `0409` | `main` @ `d4be5e3` | **311 of 311** |
| `SERVER` | `0409` | `fix/localized-acl-test-fixtures` @ `6e8a213` | **311 of 311**, unchanged |

Per file after the change, identical on both hosts: `Unit.OuAclOperations` 103,
`Unit.MsaAclOperations` 65, `Unit.GmsaAclOperations` 62, `Unit.DmsaAclOperations` 59,
`Unit.CanonicalAcl` 22.

**Both halves were required and both were run.** The German run is the point. The English run is
the control: on an English host the old literals resolve, so the file was already green there —
had the fixtures simply gone vacuous, that would look identical. `311 of 311` before *and* after
on `SERVER` is what excludes it.

**The discriminating variable is the install language, not the culture.** Both hosts ran culture
`de-DE`; only `InstallLanguage` differed, `0407` against `0409`. That is the correct line to draw:
`NTAccount.Translate()` renders built-in principals in the **operating system's install
language**, not in the user's culture, so the English run changed exactly one thing. Read a lab
host's `HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language\InstallLanguage`, not `Get-Culture`,
when you need to know which case you are in.

> **This item used to say the fix was "mechanical and the pattern is proven" — replace the name
> with the SID, as commit `4c84f4a` did for 8 WinLAPS tests. That was checked against the code on
> 2026-09-25 and it is wrong: it holds for 3 of the 34 sites and fails for the other 31.** The
> record stays because the two cases look identical and are not, and the next reader will meet
> them again. In the WinLAPS fixtures the literal sat in a **mocked** `Get-Acl` and was read back
> through `ConvertTo-TierModelIdentitySid`, which returns a SID string unchanged
> (`Resolve-TierModelPrincipalSid.ps1:506`). In these four files the literal is
> `Plan.Actions[].Data.identityreference` and reaches the **real, unmocked** cmdlet, which does
> `New-Object System.Security.Principal.NTAccount($identityReference)` then `.Translate(...)`
> (`New-TierModelOuAcl.ps1:82-83`). `NTAccount` takes a **name**: given `'S-1-5-32-544'` it looks
> for an account literally called that, finds none, and throws. The test would still have failed,
> for a new reason.

**What was done instead** is the *other* route §4 trap 7 allows: the fixture holds the invariant
SID and asks the host what it calls it, through `Get-TestPrincipalName` in the new
`tests/helpers/LocalizedPrincipals.ps1`. There,
`([SecurityIdentifier]'S-1-5-32-544').Translate([NTAccount]).Value` yields
`BUILTIN\Administrators` on an English host and `VORDEFINIERT\Administratoren` on a German one,
and the product translates either back to the same SID. No product code changed: the real
`config/` only ever names Tier Model groups in `identityreference`, which are language-independent
by construction, so the product was never the broken part — the tests had simply chosen built-ins
as fixtures.

**The anti-vacuity guard is in the helper, and it stayed silent.** `Get-TestPrincipalName`
round-trips the rendered name back to the SID it came from and throws, naming the SID, when it
does not match. It sits there rather than in a test on purpose: a fixture that silently resolved
to a *different* principal would leave every test using it green. Across four SIDs and two host
languages it never fired — that silence is the evidence the fixtures still name what they claim
to, and it is why the English control run means something.

`Unit.CanonicalAcl` was a separate case inside the same item. Its fixtures already carried SIDs;
its 3 failures were the **assertion** `Should -Match 'Everyone|S-1-1-0'`.
`Test-TierModelCanonicalAcl.ps1:117-121` translates the SID to a name and falls back to the SID
string *only when translation throws* — `S-1-1-0` always translates, so on a German host the value
is `Jeder` and matched neither alternative. The three are now exact against the rendered name,
which also brings them onto the guard-test house style (§4 trap 6).

*No suite total was measured on the day, deliberately.* Owner's decision, 2026-09-25: the
acceptance this item defines is the **+31 in these five files**, and that is what is recorded. A
whole-suite figure must be *measured*, never derived — this item once said "2056 to 2087", which
came from `5ebe784`, while the English host had already discovered 2111 at `ce528e4` before PR #3
added 17 more. `README.md` and `docs/test-coverage.md` therefore keep their `2026-09-16` suite
line with a note that it is now known to understate by these 31. A German
`pwsh -NonInteractive -File .\tests\Invoke-AllTests.ps1` on `main` refreshes it whenever it is
worth a run.

*The 32nd failure stays, and it is not a language difference at all.* `Unit.Prerequisites` is not
a fixture problem: `Test-TierModelPrerequisites` reads `IsDomainAdmin` from the real logon token
on purpose, so a string-typed SID cannot fake membership (§4 trap 8) — it fails precisely
**because the lab session is a Domain Admin**, which is why it is the single failure in the
English host's `2110 of 2111` as well. Making it pass on a DA host means weakening exactly that
check, which is rule 2.2 territory. Owner's decision, 2026-09-25: leave it, and write it into the
record rather than hiding it. It is outside the five files above and does not appear in their
311.

**~~2. Write the completeness tests.~~ Done, 2026-09-25, merged as `e057e62`
([PR #6](https://github.com/steffenstoeckelnetgo/ActiveDirectoryTierModel/pull/6)).** *Tests only,
no product code, 0 files changed under `config/`.* `tests/Unit.PrincipalCompleteness.Tests.ps1`
and `tests/helpers/ConfigPrincipals.ps1`. **86 of 86 on the English lab host `SERVER`** (install
language `0409`); 83 of 86 in the Linux container, the three that fail there being the ones that
construct `[SecurityIdentifier]` from a string.

This is what turns "observed once in a lab" into "asserted at every change", which is the owner's
actual requirement. The two things it asserts:

- every principal named in the **real** `config/` resolves through a *defined* path — not a name
  lookup fallback;
- **English and German fixtures produce identical SID sets**, both at the resolver and in the
  generated `[Privilege Rights]`.

The lab report's `Total: 56, Unresolved: 0` is the same claim as the first bullet, but measured
once against one directory. This makes it a standing guarantee.

> *This item used to say "designed in `specs/008-german-language-support/plan.md` phase D". There
> is no phase D:* `plan.md` *has Phases 1–9, and Phase 8 is the tests phase. Phase 8's own named
> items are done — among them* `tests/Unit.CanonicalPrincipal.Tests.ps1`*, which already asserts
> that every §2.2(A) name resolves to the same SID against an English fixture and a German one
> where every name lookup throws. What this item asks for is not in* `plan.md` *at all: driving the
> assertion from the **real** `config/` rather than from a hand-built list, and the
> `[Privilege Rights]` half. It was never written because it was never designed there.*

**What the real configuration contains**, measured by the tests themselves and asserted as exact
integers (§4 trap 6):

| | |
|---|--:|
| Configuration files read | 17 |
| Principals referenced | **62** |
| Names for the 29 groups the configuration creates (`name` + `samaccountname`) | 58 |
| `literalStrings` | 33 |
| `identityreference` values (ACL delegations) | 12 |
| Keys carrying string values | 98 |

Of the **27** referenced principals the configuration does not create, **all 27 are genuine
built-ins** — no typos, no undeclared dependencies: 13 `Canonical…Rid`, 11 `WellKnown`,
`Administrator` via `ADUser-RID500`, and `DnsAdmins` / `DnsUpdateProxy` on the name path **by
design**. Those last two are created by the DNS Server role rather than by domain creation, so
they have no fixed RID to compose and their names are English on every language of Windows; the
configuration names them under `conditionalGroups`, i.e. "use it if the domain has it".

**Three guards, each proven red on an injected defect** — the defect was injected into a *copy* of
`config/`, never the real one:

| Guard | Fired on |
|---|---|
| no undeclared configuration key names a localizable built-in | `someNewKey = 'Domain Admins'` |
| no `identityreference` value is a localizable built-in | `BUILTIN\Administrators` |
| every referenced principal is created by the configuration or has a defined path | `Tier9Phantoms` |

The second one is the load-bearing one. `New-TierModelOuAcl.ps1:82-83` builds an `NTAccount` from
`identityreference` and calls `.Translate()` — the **only** principal path in the product that is
language-*dependent* by construction. It is safe solely because all 12 values are Tier Model
groups the configuration itself names. A built-in there breaks the delegation on a German host,
which is the exact shape of the 31 failures item 1 was about.

**Two things about the fixtures, before anyone changes them.** The English and localized fixtures
describe the **same domain answering in two languages** — same domain SID, same allocated RIDs,
only the rendered names differ. That is deliberately *not* what the parity lab run measured (two
different domains, where every locally allocated RID differs and has to be normalised away,
`docs/parity-lab-runbook.md`); holding the domain constant isolates the one variable this project
is about. And `Source` is compared as deliberately as the SID, because the same SID reached by a
*different route* means one side fell back to a name lookup — invisible if you compare SIDs alone.
"No built-in resolves by name" is asserted separately again, since equality would be satisfied if
**both** sides fell back.

*On the host, stated plainly rather than rounded up.* The acceptance ran on the **English** host.
That is sufficient here and it is not the compromise it would have been for item 1: this file has
no host-language dependency by construction — it mocks both directories and never asks the host to
translate anything — which is precisely what it exists to make checkable. But "sufficient by
construction" is an argument, not a measurement. One German run of the same single command would
convert it, and it costs one command.

*Also new, and worth more than it looks:* **83 of the 86 run on Linux**, so they run in CI. Every
localization assertion in this repository before this one needed a Windows host.

*A finding this work produced rather than closed:* the localization report's own walker is six
principals short — see *Housekeeping* below. It is its own concern and its own pull request, and
the test deliberately does not depend on it.

**3. Run the two read-only commands in §6 *Open questions*** — the GPC DACL half of the
`Import-GPO` `<SecurityGroups>` question. **The settings half is answered:** the parity run of
2026-09-24 read every `[Privilege Rights]` entry out of SYSVOL on both domains and found
**0 foreign domain SIDs**, so nothing from the source lab reached the settings. What nobody has
looked at is the GPC's full DACL. Minutes of work, and until then it is an open security
question.

**4. A second German domain, or say plainly that there is not one.** Everything measured comes
from `int.promiseIT.de`: forest root, Windows 2025 domain, one DC, German Windows 11 as the admin
host. Untested: child domains, multi-DC replication, RODC, an **English host against a German
domain** (the mixed case the docs explicitly permit), and any language other than German. This is
the difference between "works on that domain" and "works on German AD". If no second domain is
available, that belongs in the release notes as an accepted limit, not left unsaid.

**5. ~~The English parity run.~~ Done, 2026-09-24, commit `ce528e4`.** The change altered
behaviour for English deployments too — a failed Deny-Apply ACE is now a hard stop, `Converged`
means something different, the GPO import retries — so a live English run was owed. Both domains
were deployed green-field from the same commit and compared:
`optional/Compare-TierModelDeploymentReport.ps1` reports **`No differences.`**, exit 0. The full
figures, both domain SIDs and what the run does *not* prove are in item 6 under Phase F.

Two things that run left behind, both now fixed and merged: the comparison itself reported 84
false differences from domain-allocated RIDs (`ef972d5`, `292d9b7`), and
`Test-TierModelLocalizedDeployment.ps1`'s `-IncludeAudit` was auditing 21 checks instead of 433
(`fc7242b`). Neither touches product code.

#### Housekeeping, not gating

- ~~**README and `docs/test-coverage.md` carry stale figures.**~~ **Refreshed 2026-09-17** with the
  measured numbers and their host: suite **2,056 of 2,088** on German Windows, coverage
  **85.73 % (14,742 / 17,195)** from the German lab host, owner-confirmed. Both files now say what
  was measured on what, and both record that the figures predate the 18 tests added with the
  parity comparison rather than deriving a newer total by arithmetic. **Item 1 landed on
  2026-09-25 and the suite line was deliberately not recalculated**: no whole-suite run was made
  that day, and a total that is derived rather than measured is exactly what this bullet exists to
  prevent. Both files now carry a note that the figure understates by the 31 ACL tests. One German
  `pwsh -NonInteractive -File .\tests\Invoke-AllTests.ps1` on `main` replaces the note with a
  number.
- **The localization report's principal walker is six principals short.** Measured 2026-09-25
  while writing the item 2 tests: `Get-ConfiguredPrincipalName` in
  `optional/Test-TierModelLocalizedDeployment.ps1` knows **seven** principal-carrying keys and the
  configuration uses **eleven**. It never sees `memberComputerGroups`,
  `allowedToAuthenticateFromDeviceGroups` or `alwaysInclude`, so its docstring claim *"every
  principal the configuration names"* covers **56 of 62** — and the two keys it misses are the
  Authentication Policy Silos, which is where the localization defect of §5 lived.

  **It is a coverage gap, not a wrong result, and not an oversight in the design.**
  `specs/008-german-language-support/spec.md` §2.2(C) names `config/tiermodel-authsilos.json` and
  its two built-ins explicitly; the product was fixed for them (§5). Only the *report's* inventory
  never learned the keys. The six principals it misses are all Tier Model groups, language-
  independent by construction, so `0 unresolved` held for what it did measure.

  Fix: add the three keys to `$principalKeys` and `tiermodel-authsilos.json` to the files it
  walks. Its own concern and its own PR. **`tests/helpers/ConfigPrincipals.ps1` must not become
  its source** — a test that depended on the script it checks would certify the gap instead of
  closing it.
- **`New-TierModelGroup` with an empty plan** raises `GroupApplyFailed`: `$Plan.Actions |
  Where-Object` collapses to `$null` and `.Count` throws under `Set-StrictMode`. Pre-existing, its
  own concern, own issue.
- **Enabling GitHub Actions** (item 8) would run all three gates automatically on every push to
  `main` — which, given that work now happens directly on `main` with no other safety net, is worth
  more here than in a repository that branches.

---

Ordered. Items 1–3 were the acceptance gate for the localization work itself; all three are done.

1. ~~**Run the suite on Windows.**~~ **Done, twice.** German Windows 11 / PowerShell 7.6.6
   against a German domain, as a Domain Admin. First run: 2012 passed of 2053, 41 failed.
   After the eight fixes in §5: **2021 passed of 2053, 32 failed**, all of them the
   pre-existing ones listed below. `tests/Unit.CanonicalPrincipal.Tests.ps1` was
   **59 of 59 green** both times — that file is the acceptance gate for the resolver and it is
   met. `docs/german-lab-runbook.md` Phase A is the repeatable form of this run.

   **Third run: a green-field domain, 2026-09-16 (commit `5ebe784`).** `int.promiseIT.de` was
   rebuilt from scratch and the whole runbook executed against it, which is the evidence the
   two earlier runs could not give — they ran on a directory this branch had already touched.
   Suite `pwsh -NonInteractive`: **2056 passed of 2088**, and the 32 failures are the table in
   item 2 line for line. `tests/Unit.LocalizedVerification.Tests.ps1` green (974 ms).

   | Phase | Measured |
   |---|---|
   | B plan | `Action count: 719` |
   | **C deploy** | **`Applied: 689, Skipped: 0, Errors: 0, 6m 11s`** — 31 OUs, 29 groups, 3 users, 105 OU ACLs, 146 GPOs created + 123 imported + 23 configured + **131 links**, 60 ADMX/ADML (central store created), MSA/gMSA/dMSA 4 each, 17 LAPS, 4 policies + 4 silos, `DC1$` enrolled. Deny-Apply ACEs logged with `…-516` / `…-521`. `Converged: False` — see §5, it means "this run changed the directory". |
   | **D idempotency** | `No actions required` → `Applied: 0, Errors: 0, Converged: True` |
   | **E audit** | `TotalChecked: 433, Missing 0, Mismatched 0, Unverified 0, Drift 0, Errors 0, 100 %` — OU 31, canonical ACL 32, groups 29, users 3, OU ACLs 105, GPOs 146, ADMX 60, MSA/gMSA/dMSA 2 each, WinLaps ACL 7 + decryptor 6, policies 4, silos 4 |
   | **E report** | `directory language: localized`, `56 principals, 0 unresolved, 42 carrying a different directory name`, `2 ACE check(s), 0 missing`, 29 GPOs with `[Privilege Rights]`, **`No problems found.`** |

   `689` reconciles exactly: 31 + 29 + 3 + 105 + 423 + 60 + 4 + 4 + 4 + 17 + 4 + 4 + 1.
   The gap to the plan's 719 is two planners that legitimately re-plan once their prerequisites
   exist — GPO `442 → 423` and Windows LAPS `25 → 17`, both logged, the latter after seven
   `LAPS GPO not present during FD planning (expected; created by GPO phase)` entries — plus the
   silo membership, which `Deploy-TierModel.ps1:2477` counts only in plan mode. The exact split
   across those three is not derivable from the uploaded logs, because the plan phase records
   the GPO sub-counts only as the sum 442.
2. **The 41 failures, classified.** Eight belonged to this branch and are fixed (§5). The
   remaining **32 are pre-existing** — measured against the pre-localization baseline, which at
   the time was `origin/main`, they failed there on the same host too; they live in files the
   change does not touch; and their causes are the host's language and the session's own token,
   not this change. (`main` now *carries* the localization work, so re-checking that baseline
   today means checking out a commit before PR #1, not `main`.):

   | File | × | Cause | Since |
   |---|--:|---|---|
   | `Unit.OuAclOperations` | 10 | fixture `'BUILTIN\Administrators'` / `'BUILTIN\Users'` — untranslatable on German Windows (§4 trap 7) | **fixed `33e4e11`** |
   | `Unit.MsaAclOperations` | 7 | same | **fixed `33e4e11`** |
   | `Unit.GmsaAclOperations` | 7 | same | **fixed `33e4e11`** |
   | `Unit.DmsaAclOperations` | 4 | same | **fixed `33e4e11`** |
   | `Unit.CanonicalAcl` | 3 | `Should -Match 'Everyone\|S-1-1-0'` against the directory's `Jeder` | **fixed `33e4e11`** |
   | `Unit.Prerequisites` | 1 | `IsDomainAdmin` comes from the real logon token (§4 trap 8) | **open, and staying open** |

   **31 of the 32 are fixed as of 2026-09-25** — §6 *Start here* item 1 carries the measurement,
   on both a German and an English host. The table is kept whole rather than trimmed: it is the
   measured history, and the one row still standing is only legible next to the rows that went.
   That row stays by the owner's decision of the same day, because making it pass on a Domain
   Admin host means weakening the very check it covers (rule 2.2).

   The 41st, *"ByBytes does not require -PreferredDc"*, is not in that table because it is not a
   property of the host at all: it asserts that a missing mandatory `-PreferredDc` raises a
   binding error, and an interactive host **prompts** for the parameter instead of raising it, so
   the whole run stops there. Start the suite as `pwsh -NonInteractive -File
   .\tests\Invoke-AllTests.ps1` — that is what CI does, and the test passes. (At the prompt,
   an empty line also produces a binding error and passes; a typed DC name does not.)

   **Fixing the other 32 was a separate concern** (CONTRIBUTING: one concern per PR) and got its
   own pull request, #5. They were invisible to CI, which runs English — which is why they
   survived this long, and why the English control run in item 1 was worth the second lab cycle.

   Measured figures. Windows, after the fixes: **2021 passed of 2053**, and the 32 failures are
   the table above line for line — nothing outside it. `Unit.CanonicalPrincipal` 59 of 59,
   `Unit.WinLapsAclOperations`, `Integration.WinLapsDeployment` and `Unit.GpoOperations` all
   green. Before the fixes it was 2012 of 2053 with 41 failures. Linux harness: baseline 1680
   passed of 1994; HEAD **1715 of 2053**, 0 regressions against the pre-fix HEAD.

   Not a regression, and not open: `Unit.ModuleManifest` is already only 6 of 63 green on the
   **baseline** under Linux, so that file is platform-broken rather than affected by this change.
3. ~~**Run PSScriptAnalyzer.**~~ **Done — both gates pass on the German lab host,
   2026-09-17, commit `c58dbcf`.** Still not obtainable in the Linux container (absent from
   nuget.org; PowerShell Gallery and GitHub releases blocked by the network policy), so it runs
   on the lab. `docs/german-lab-runbook.md` A2 is the repeatable form.

   | Gate | CI definition | Measured |
   |---|---|---|
   | **A2a** — main | `ci.yml:64-83`, fails on *any* finding (`exit $results.Count`) | **`Findings: 0`** over `modules/TierModel`, `Deploy-TierModel.ps1`, `Audit-TierModel.ps1` with the 13 excluded rules |
   | **A2b** — security | `ci.yml:290-305`, fails **only** on `Severity -eq 'Error'` | **3 findings, 0 of them Error** |

   The A2a zero is confirmed, not assumed: the identical scan **without** `-ExcludeRule`
   returned **2757** findings, so the analyzer demonstrably read the files. That check is not
   optional — an empty result and "the analyzer never ran" produce the same empty CSV.

   The three A2b warnings are all `PSUseShouldProcessForStateChangingFunctions`, the rule that
   A2a excludes and A2b includes on purpose: `New-TierModel` (`TierModel.psm1:870`),
   `Set-TierModel` (`:970`) and `New-TierModelGptTmplContent` (`:1`). The last one only builds an
   INF string and changes nothing — the rule judges the verb, not the behaviour. Nothing to fix.
4. ~~**Coverage** against the CI population, ≥ 80%.~~ **Measured 2026-09-17: `85.73 %
   (14742 / 17195)` — the gate is met with 5.7 points to spare.** The population and the gate are
   in `.github/workflows/ci.yml:133-136` and `:155-173`: `modules/TierModel/*.psm1`,
   `modules/TierModel/public/*.ps1`, `optional/Update-TierModelMembership.ps1`.

   The figure is internally consistent with the Linux run below: **the same 17195 commands
   analysed** — coverage analysis is static, so the population does not vary by platform — with
   **1270 more executed**, which is what the SID-dependent tests do when they can actually run.
   **Host confirmed by the repository owner: the German lab host** (2026-09-17). The figure is
   carried into `README.md` and `docs/test-coverage.md` as measured.

   It does **not** say the product is 85.73 % correct. Coverage counts commands a test touched at
   least once; correctness is the lab cycle in item 1 and the suite. See §6 *Start here*.

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

5. ~~**Add the completeness tests.**~~ **Done, 2026-09-25, `e057e62`.** The same work as
   *Start here* item 2, stated twice in this file; that item is the one to read — it carries the
   measured figures, the three guards, and the correction of the "phase D" reference this line
   used to repeat.
6. **German lab acceptance.** Phases A–F are done. Phase F is the parity proof and it
   passed on 2026-09-24; the entry is at the end of this item.

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

   **Phase F (parity) passed — 2026-09-24, commit `ce528e4`. The claim this work rests on is
   established.** Two independently built domains, both forest root, both single-DC,
   `Windows2025Domain`, both answering to the DNS name `int.promiseIT.de` and distinguished by
   their domain SIDs:

   | | localized | English |
   |---|---|---|
   | DC | `DC1`, SID `…-2230522700-2543936044-3532250090` | `server`, SID `…-1937235960-408727578-445444486` |
   | Host | `de-DE`, install language `0407` | install language `0409` |
   | Plan | 719 actions | 719 actions, same breakdown, `Already exist: 2` on both |
   | Deploy | `Applied: 689, Errors: 0`, 2m 57s | `Applied: 689, Errors: 0`, 2m 40s |
   | Second run | `Applied: 0, Converged: True` | `Applied: 0, Converged: True` |
   | Audit | `433 / Drift 0 / Errors 0` | `433 / Drift 0 / Errors 0` |
   | Report | 56 principals, 0 unresolved, `No problems found.` | same, `No problems found.` |

   Both deploy logs are 2045 lines with 170 Debug and 1875 Info entries and **not one Warning or
   Error**; both second runs are 321 lines. Every phase count matches: 31 OUs, 29 groups, 105 OU
   ACLs, GPO 146 created / 123 imported / 23 configured / 131 linked, 60 ADMX, MSA/gMSA/dMSA 4
   each, Windows LAPS 25 planned → 17 applied → 0 on the second run, silo gate 8 of 8.

   **`optional/Compare-TierModelDeploymentReport.ps1`: `No differences.`, exit 0**, with 31
   principals compared by identity rather than by RID. Read by `Kind`, there were none of any
   class, and **0 foreign domain SIDs on either side** — which settles the settings half of the
   `Import-GPO` `<SecurityGroups>` question in *Open questions* below, on two domains. The GPC
   DACL half is still open.

   *Read the first run of that comparison as a lesson, not a footnote:* against these same two
   reports it first printed **84 differences**, 31 `SidDiffers` and 53 `ValuesDiffer`, every one
   of them noise from domain-allocated RIDs that differed by exactly one. That defect is fixed
   (`ef972d5`), and the `No differences.` above is from the fixed script. A comparison tool that
   cries wolf on identical deployments is worse than none, because the only conclusion available
   from its output is the wrong one.

   Two things the localized figures do **not** carry over to: 17 principals resolve to a German
   directory name on one domain and an English one on the other — `Domain Admins →
   Domänen-Admins`, `Enterprise Admins → Organisations-Admins` — and the reports' own
   `LocalizedNameCount` (42 vs 25) counts that *together with* principals having no directory
   object at all, so the meaningful number is the difference, not either figure.

   **What this does not prove.** That either deployment is *correct* — that is what each domain's
   own audit shows. Nothing about a third language, and nothing about topologies neither domain
   has: child domains, multi-DC replication, RODC, or an English host against a localized domain.

   **Also measured that day, on the English host: the suite is 2110 of 2111 green.** The single
   failure is `Unit.Prerequisites` / `IsDomainAdmin`, §4 trap 8. That settled what *Start here*
   item 1 asserted: the 31 ACL failures are a fixture problem and not a product defect — same
   code, same tests, a host whose `NTAccount(...).Translate()` can resolve the English literals.
   It did **not** close item 1, because those tests still could not execute on a German host,
   which is the platform this project exists for. **That closed on 2026-09-25** (`33e4e11`), and
   this same English host then served as the control for it: 311 of 311 in the five files before
   *and* after, which is what shows the fixtures did not simply go vacuous.
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
  than the GPO security descriptor.

  **The settings half is answered, on two domains.** The parity run of 2026-09-24 read every
  `[Privilege Rights]` entry out of SYSVOL on both the localized and the English domain and found
  **0 SIDs belonging to neither** — 1242 of 1791 entries carry the reading domain's own SID and
  the rest are well-known or the declared `literalStrings`. Nothing from the source lab reached
  the settings. The comparison is built to surface exactly this: a foreign SID is deliberately
  left verbatim while each report's own domain SID is normalised, so it would have shown up.

  **The GPC DACL half is still not verified.** The localization report checks only that the two
  Deny-Apply ACEs are present, not that nothing else is. The two commands below settle it.

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

### The Linux regression harness — how to rebuild it

Every change in the localization work was gated on *"0 regressions against the previous
commit"* measured
by a small harness that **lives in the session scratchpad and dies with the session**. It is not
in the repository, on purpose: it is Linux tooling for a Windows-authored suite, and §4 is
explicit that its result is a **comparison instrument, never proof of correctness**. Rebuilding
it takes minutes if you know what it has to do.

Four parts:

1. **`normalize.py`** — makes a *throwaway copy* of the repo runnable on Linux. Critically it is
   a **fixed, enumerated list of replacements, not a blanket backslash rewrite**, so the same
   transform applied to two revisions leaves the outcomes comparable; each replacement reports
   its count, and one that matches nothing reports 0 rather than being silently skipped. It
   fixes exactly: `$PSScriptRoot\..\Modules\...` → `/../modules/...` (separator **and** the
   `Modules` vs. real `modules` casing) in `tests/`, the same for `config`, `Helpers` and the
   relative `..\Deploy-TierModel.ps1` / `..\Audit-TierModel.ps1` forms, plus four
   `Join-Path` literals in `modules/` and the two root scripts. Never run it on the working tree.
2. **`run-suite.ps1`** — runs Pester **one test file at a time** and writes a flat per-test JSON
   (`File`, `Path`, `Result`). One file at a time because a file that dies in `BeforeAll` must
   not take the run with it: a crashed container has to be *recorded*, not fatal.
   `tests/Invoke-AllTests.ps1` is deliberately not used — it emits no machine-readable result
   and never dot-sources `tests/helpers/ADStubs.ps1` (on Windows the CI workflow loads the stubs
   separately). It also sets `$env:TEMP`/`$env:TMP`, which are unset on Linux and which 14
   `BeforeAll` blocks build paths from.
3. **`regress.sh`** — `git archive HEAD` into one directory as the baseline, the working tree
   into another as the head, normalize both, run both, write two JSONs.
4. **`diff.py`** — compares the two JSONs keyed by `(File, Path)` and prints
   `Passed → Failed` as regressions, plus new/disappeared tests. **Key it on the pair**, and be
   aware that a handful of tests share a `Path` string, so a dict keyed that way collapses ~48
   duplicates and its totals will not match Pester's own count — the regression list is still
   correct, the totals are not.

Expected output shape: **0 regressions**, and the head/base counts differ only by
tests you added. Roughly 350 of ~2090 fail on Linux for platform reasons on *both* sides
(§4, *Running the suite on Linux*).

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
