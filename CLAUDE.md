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

**Do not add a bare built-in alias to `Get-WellKnownSid` without a configuration entry that needs
it.** A bare name such as `Remote Desktop Users` or `Event Log Readers` is a legal name for a
*customer's own domain group*; listing it shadows their group and silently resolves it to the
BUILTIN SID. The `BUILTIN\...` prefixed form cannot collide and is safe to list in full.
`tests/Unit.CanonicalPrincipal.Tests.ps1` pins this.

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

**Not verified yet:** the SID-composition core. See §6.

---

## 6. Next steps

Ordered. Items 1–3 are the actual acceptance gate.

1. **Run the suite on Windows.** The 22 open tests in `tests/Unit.CanonicalPrincipal.Tests.ps1`
   are exactly the SID-dependent ones; they cannot pass on Linux and are the proof this change
   needs. Clone, check out the branch, RSAT + GroupPolicy present, `.\tests\Invoke-AllTests.ps1`.
   No harness needed — the backslash paths are correct there.
2. **Resolve the remaining baseline delta.** Under the Linux harness, 17 tests moved
   `Passed → Failed` against `origin/main`. Known causes, to be confirmed on Windows:
   - `Unit.GpoOperations` ×2 still assert the old "Deny-Apply failure is only a warning"
     contract. They must be rewritten to the new contract deliberately, not quietly.
   - `Unit.WinLapsAclOperations` / `Integration.WinLapsDeployment` — needs checking whether these
     are genuine or artifacts of the Linux SID wall.
   - `Unit.ModuleManifest` "Has current version" returned `$null` under the harness although the
     manifest parses standalone — **unexplained, must be investigated.**
3. **Run PSScriptAnalyzer.** Not obtainable in the Linux container (absent from nuget.org;
   PowerShell Gallery and GitHub releases blocked by the network policy). It is a CI gate, so it
   must run somewhere before merge.
4. **Coverage** against the CI population, ≥ 80%. Then update the README test table — it is
   deliberately still at its last *measured* values rather than estimated.
5. **Add the completeness tests** designed but not yet written (`specs/008-german-language-support/plan.md`,
   phase D): every principal in the real config must resolve by a defined path; English and
   German fixtures must produce **identical SID sets**, both at the resolver and in the generated
   `[Privilege Rights]`.
6. **German lab acceptance.** No mock replaces this: deploy → second deploy (idempotency, which
   is exactly the LAPS SELF bug) → audit reporting zero drift → verify the Deny ACE on the GPC
   against `Domänencontroller`. Use `tests/Manual.Integration.Tests.xlsx`, and run
   `optional/Test-TierModelLocalizedDeployment.ps1 -PreferredDc <dc> -IncludeWinLaps -IncludeAuthSilos -IncludeAudit`.
   That script is read-only and writes one JSON report covering what the product audit does not:
   the directory's language, every configured principal with the SID and the *directory* name it
   resolved to, whether the Deny-Apply ACE is actually on the GPC, and the `[Privilege Rights]`
   SID sets from SYSVOL. Running it on an English domain as well and diffing the
   `PrivilegeRights` sections is the parity proof.
7. **German ADML content.** `optional/New-TierModelAdmlManifest.ps1` and the procedure in
   `docs/admx-management.md` are ready; the `.adml` files are Microsoft redistributables and must
   be supplied by the operator. `download.microsoft.com` is blocked from the build environment
   (403 on CONNECT).
8. **Enable GitHub Actions in the fork** so CI becomes the authoritative Windows check.

### Open questions that must not be answered by assumption

- **Is the `Domain Controllers` OU localized on a German domain?** Unknown. Not assumed either
  way: `Resolve-TierModelDelegationOuDn` uses the configured DN when it resolves and falls back
  to the `wellKnownObject`-backed `DomainControllersContainer` when it does not. Confirm on the
  German lab and simplify if the answer makes it unnecessary.
- **Does `Import-GPO` carry the source lab's `<SecurityGroups>` names into the imported GPO?**
  `config/gpo/**/Backup.xml` contains the source domain's `Domain Admins` / `Enterprise Admins`
  with their original SIDs. Expected to be inert because `Import-GPO` imports settings rather
  than the GPO security descriptor — **expected, not verified.** If it is not inert, a migration
  table is needed.

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
