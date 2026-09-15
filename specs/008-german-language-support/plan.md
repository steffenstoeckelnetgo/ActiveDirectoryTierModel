# Implementation Plan: German (de-DE) Windows and Active Directory Support

**Spec**: `specs/008-german-language-support/spec.md`
**Target version**: 2.2.0
**Branch**: `claude/beautiful-galileo-skfp32`

---

## Implementation status

Phases 1-5 and 7-9 are implemented. Two decisions taken during review differ from the
design sketch below, and the text of those phases should be read against this table.

| Phase | Status | Deviation |
|---|---|---|
| 1 Canonical SID resolution | Done | The forest-root SID is composed against the **target domain** SID rather than looked up separately. RID 519/518 is unallocated in a child domain, so the read-back reproduces the previous "not found" behaviour with no extra directory call and no referral risk. |
| 2 SID-based ACL comparison | Done | The four `NTAccount` sites in `New-TierModelOuAcl` and the MSA/gMSA/dMSA appliers were **left unchanged**: they operate only on Tier Model-owned group names, which no language localizes. Changing them would be robustness-only churn in untestable code. `Test-TierModelWinLapsDecryptor` likewise, for the same reason. |
| 3 Deny-Apply ACE | Done | Implemented as "fails the GPO action" (the per-GPO handler records the error, increments `Failed`, clears `Converged`) rather than aborting the run mid-estate. |
| 4 Well-known containers | Done | `Test-TierModelWellKnownContainer` **keeps** the English literal match and adds the directory-reported DNs, so a directory hiccup degrades to today's behaviour. The `{{DC_OU_DN}}` placeholder and the config changes were **not** made: the literal-plus-directory match covers the code paths, and rewriting config keys is a migration concern for its own change. |
| 5 Language gate | Done | Gate **removed entirely** (user decision), not narrowed to an allow-list. No `-AllowUnsupportedLanguage` switch. |
| 6 German ADML content | Partial | `download.microsoft.com` is blocked by this environment's network policy (403 on CONNECT), so the files could not be fetched. Shipped instead: `optional/New-TierModelAdmlManifest.ps1` and the operator procedure in `docs/admx-management.md`. No code change was needed — `-AdmlLanguage` already routes to `config\tiermodel-adml-<lang>.json`. |
| 7 Invariant timestamps | Done | 14 call sites. |
| 8 Tests | Done | The gate tests are inverted; `tests/Unit.CanonicalPrincipal.Tests.ps1` is new. **The suite has not been run**: PowerShell is unavailable in this environment and could not be installed. CI on `windows-latest` is the first execution. |
| 9 Documentation | Done | Plus `ModuleVersion` 2.1.0 → 2.2.0 and the three version assertions that pin it. |

---

## Phase 1 — Canonical SID resolution (the load-bearing change)

### 1.1 New lookup table in `modules/TierModel/public/Resolve-TierModelPrincipalSid.ps1`

Add an unexported `Get-TierModelCanonicalPrincipal` returning, for a canonical English name,
either an absolute SID or a `{Scope; Rid}` pair:

```
Domain-RID scope   (needs <domainSID>)     512 Domain Admins · 513 Domain Users
                                           514 Domain Guests · 515 Domain Computers
                                           516 Domain Controllers · 517 Cert Publishers
                                           520 Group Policy Creator Owners
                                           521 Read-only Domain Controllers
                                           522 Cloneable Domain Controllers
                                           525 Protected Users · 526 Key Admins
                                           571 Allowed RODC Password Replication Group
                                           572 Denied RODC Password Replication Group
                                           500 Administrator · 501 Guest
ForestRoot-RID     (needs <forestRootSID>) 518 Schema Admins · 519 Enterprise Admins
                                           527 Enterprise Key Admins
                                           498 Enterprise Read-only Domain Controllers
Absolute SID       (extends Get-WellKnownSid)
                                           S-1-5-32-569 Cryptographic Operators
                                           S-1-5-32-568 IIS_IUSRS
                                           S-1-5-32-548/549/550/551 Account/Server/Print/
                                                                    Backup Operators (bare form)
                                           S-1-5-32-554/555/556/573/578/579/580
                                           S-1-5-10 SELF · S-1-5-9 Enterprise Domain Controllers
                                           S-1-5-17 IUSR
```

Every entry carries the RID/SID as the identity and the English string only as the key.

### 1.2 Resolution order in `Resolve-TierModelPrincipalSid`

Insert **between** the existing `Administrator` special case and the cache lookup:

1. Direct SID passthrough *(unchanged)*
2. `Administrator` RID-500 path *(unchanged; becomes one row of the new table)*
3. **NEW — canonical table.** On hit: `Get-ADDomain -Server $DomainController` for the domain
   SID; for `ForestRoot` scope `Get-ADForest` → `Get-ADDomain <RootDomain>` for the forest-root
   SID. Compose `<SID>-<RID>` (or take the absolute SID), then **confirm the object exists** with
   `Get-ADGroup/-ADUser -Identity <SID>`. Return `Source = 'Canonical'`, plus `ActualName` for
   the log so a German run shows `Domain Admins → S-1-5-21-…-512 (Domänen-Admins)`.
4. `Get-WellKnownSid` *(unchanged)*
5. `Resolve-ADPrincipalSid` name lookup *(unchanged — Tier* groups, `DnsAdmins`)*

Cache keyed per-name as today; forest-root SID memoized in `$script:` alongside `$script:SidCache`.

**Existence confirmation is required, not optional.** `forestRootOnly` entries must still be
skipped in a child domain, and `Allowed RODC Password Replication Group` may be absent — today
that is expressed by a name lookup that returns nothing. Composing a SID blindly would inject
unresolvable SIDs into `[Privilege Rights]`.

**Fixes by construction:** all of §2.2(A), (B) via `Set-Laps*Permission -AllowedPrincipals <SID>`,
and (C).

### 1.3 Robustness cleanup found in passing

`Resolve-ADPrincipalSid` (same file, L409-419 / L436-472) uses `-Server $DomainController`
three times, but declares only `$Principal` and `$CorrelationId`. It works today purely
through PowerShell's dynamic scoping — the value leaks in from the caller
`Resolve-TierModelPrincipalSid`. Not a live defect, but it silently binds to `$null` for any
other caller. Declare `$DomainController` as an explicit parameter and pass it at L150.

## Phase 2 — SID-based ACL comparison

New unexported helper `Test-TierModelIdentityMatch` (SID-normalizing; accepts
`IdentityReference`, `NTAccount`, SID string):

| File | Line | Change |
|---|---|---|
| `Get-TierModelWinLapsAcl.ps1` | 344 | `-eq 'NT AUTHORITY\SELF'` → translate `IdentityReference` to `SecurityIdentifier`, compare `S-1-5-10` |
| `Get-TierModelWinLapsAclFd.ps1` | 290 | same |
| `Test-TierModelWinLapsAcl.ps1` | 188 | same |
| `Test-TierModelWinLapsAcl.ps1` | 239-244 | allow-list → SID set `S-1-5-10`, `S-1-5-18`, `S-1-5-32-544`, `<dom>-512`, `<forestroot>-519` |
| `Test-TierModelWinLapsAcl.ps1` | 225-232, 258-264 | `$holder -like "*\$sam"` — keep as fallback, prefer SID match |
| `New-TierModelOuAcl.ps1` | 82 | `NTAccount` → `Resolve-TierModelPrincipalSid` + `SecurityIdentifier` |
| `New-TierModelMsaAcl.ps1` | 96 | same |
| `New-TierModelGmsaAcl.ps1` | 97 | same |
| `New-TierModelDmsaAcl.ps1` | 107 | same |

`Find-LapsADExtendedRights` returns `ExtendedRightHolders` as **display strings**; where no SID
is available, translate `NTAccount → SecurityIdentifier` on the Tier Model side before comparing.

## Phase 3 — Deny-Apply GPO ACE (highest severity)

`New-TierModelGpo.ps1` L231-270:

- Replace `New-Object NTAccount("$domainNetbios", $denyGroup)` with
  `[SecurityIdentifier](Resolve-TierModelPrincipalSid -Principal $denyGroup …).Sid`.
- `ActiveDirectoryAccessRule` accepts a `SecurityIdentifier` directly — no translation at all.
- **Change the failure mode**: a Deny-Apply ACE that cannot be written must raise a terminating
  error (or at minimum set the GPO action to `Failed` and mark the deployment non-convergent),
  not a yellow warning. Deploying `Tier Model Account Restrictions` without its DC Deny-Apply ACE
  is a tier-boundary regression that must never pass silently.

## Phase 4 — Well-known containers from the directory

New unexported `Get-TierModelWellKnownContainer -DomainController <dc>` wrapping `Get-ADDomain`
and caching `DomainControllersContainer`, `UsersContainer`, `ComputersContainer`, plus
`CN=Builtin,<domainDN>` and `CN=System,<domainDN>`.

- `Get-TierModelGpoFd.ps1:168,287` and `Get-TierModelGpo.ps1:121` — replace the three
  `-match '^OU=Domain Controllers,DC='` / `'^CN=Builtin,DC='` / `'^CN=Users,DC='` literals with
  a case-insensitive DN comparison against the resolved container DNs.
- `Resolve-TierModelPlaceholder.ps1` — add `{{DC_OU_DN}}`, `{{USERS_CN_DN}}`, `{{COMPUTERS_CN_DN}}`.
- `config/tiermodel-gpos.json:315` key and `config/tiermodel-winlaps.json:6` `ouDn` — switch to
  `{{DC_OU_DN}}`. Keep `OU=Domain Controllers,{{DOMAIN_DN}}` accepted as a legacy alias so
  existing user-modified configs do not break.

## Phase 5 — Prerequisites: from English gate to language detection

`Test-TierModelPrerequisites.ps1`:

- **L144-175 (host OS)** — keep the `InstallLanguage` read and the `HostInstallLanguage` /
  `HostOsEnglish` snapshot fields (tests and support depend on them). Add `HostOsLanguage`
  (LCID → culture name). Replace the early `return` with: pass for `0x09` (English) and `0x07`
  (German); for anything else emit a **warning** naming the language plus
  `-AllowUnsupportedLanguage` as the override, and continue. Add `HostOsLanguageSupported`.
- **L494-553 (AD)** — keep the three SID-resolved canaries, but reinterpret them: rather than
  asserting equality with English, compare against a per-language expectation set
  (`en`: Domain Admins / Server Operators / Account Operators; `de`: Domänen-Admins /
  Server-Operatoren / Konten-Operatoren) to *identify* the directory language. Record
  `AdLanguage`, `AdLanguageEnglish` (kept for compatibility), `AdLanguageSupported`,
  `AdLanguageCanaryNames`. Unrecognized names → warning, not error; still no hard block,
  because Phase 1 makes resolution name-independent.
- **L381 / L457** — `Get-ADGroup -Identity "Domain Admins"` / `"Enterprise Admins"` → resolve by
  SID via the Phase 1 table. L473 (`DnsAdmins`) unchanged.
- New `-AllowUnsupportedLanguage` switch threaded from `Deploy-TierModel.ps1` and
  `Audit-TierModel.ps1`.

## Phase 6 — German ADML content

- Add `config/admx/de-DE/*.adml` — the German counterpart of every one of the 39 files in
  `config/admx/en-US/`, from the same Microsoft sources recorded in
  `config/tiermodel-adml-en-US.json` (`downloadLink` per file).
- Add `config/tiermodel-adml-de-DE.json`: identical shape, `destinationPath` ending `\de-DE`,
  `sourcePath` `config\admx\de-DE`, MD5 per file.
- No code change — `-AdmlLanguage de-DE` already routes to
  `config\tiermodel-adml-$AdmlLanguage.json` (`Get-TierModelAdmx.ps1:70`, `Test-TierModelAdmx.ps1:69`).
- **Blocker to confirm**: the ADML files must be fetched from Microsoft. If this environment
  cannot reach those downloads, Phase 6 ships as the manifest plus a documented operator
  procedure, and the code/test phases proceed independently.
- Consider allowing `-AdmlLanguage` to accept a list so a central store can carry `en-US` and
  `de-DE` side by side (German admins and English tooling on the same domain).

## Phase 7 — Culture-invariant timestamps

Replace `Get-Date -Format '<fmt>'` with
`[datetime]::UtcNow.ToString('<fmt>', [CultureInfo]::InvariantCulture)` (local time where the
current call is local) at: `Write-TierModelLog.ps1:54`; `Deploy-TierModel.ps1:320,444,733`;
`Audit-TierModel.ps1:291,674,833,2540`; `optional/Update-TierModelMembership.ps1:223,251,276,351,356,2298`.

## Phase 8 — Tests

Rewrite, in `tests/Unit.Prerequisites.Tests.ps1`:

- L286-335 `Host OS Language Enforcement` → `Host OS Language Detection`. `0407` must now
  **pass** with `HostOsLanguageSupported = $true`; keep `0409`/`0809` passing; an unsupported
  LCID warns and continues; unreadable registry still non-fatal.
- L337-437 `AD Language Enforcement` → `AD Language Detection`. The German canary fixture
  (`Domänen-Admins`, `Server-Operatoren`) must yield `AdLanguage = 'de'`, `Valid = $true`.

New `tests/Unit.CanonicalPrincipal.Tests.ps1`:

- Every §2.2(A) name resolves to the expected SID against an English fixture **and** a German
  fixture where `Get-ADGroup -Identity <name>` throws for every localized name — proving no
  code path depends on the name.
- `forestRootOnly` names return no SID in a child-domain fixture.
- `Allowed RODC Password Replication Group` absent → no SID, no error.
- `DnsAdmins`, `Tier0Admins` still take the name path.

Extend:

- `tests/Unit.WinLapsAclOperations.Tests.ps1` — SELF detection and the holder allow-list with
  `NT-AUTORITÄT\SELBST` / `VORDEFINIERT\Administratoren` / `<DOM>\Domänen-Admins` identities.
- `tests/Unit.GpoOperations.Tests.ps1` — Deny-Apply ACE built from a SID; unresolvable
  Deny-Apply group fails the deployment.
- `tests/Unit.Resolution.Tests.ps1` — `{{DC_OU_DN}}` placeholder and the legacy alias.
- `tests/helpers/ADStubs.ps1` — add a reusable German-domain stub set.
- `tests/Unit.ModuleManifest.Tests.ps1` counts `public\*.ps1` against `FunctionsToExport`
  (noted at `TierModel.psm1:24-40`): new helpers stay **unexported and inside existing files**,
  or the manifest and that test's expected count are updated together.

## Phase 9 — Documentation

- Rewrite `docs/language-support.md`: English-only gate → supported-language matrix
  (`en-*`, `de-DE` validated; others best-effort with `-AllowUnsupportedLanguage`), and replace
  the "community language packs" roadmap with the SID-resolution rationale.
- `README.md` — drop "English only today" from the Language Support bullet.
- `CHANGELOG.md` — new `## [2.2.0]` section.
- `modules/TierModel/TierModel.psd1` — `ModuleVersion` `2.1.0` → `2.2.0`.
- `docs/faq.md`, `docs/detailed-deployment-guide.md` — German-domain prerequisites and the
  `-AdmlLanguage de-DE` central-store note.

## Validation

1. `.\tests\Invoke-AllTests.ps1` green; coverage ≥ 80% (CI gate in `.github/workflows/ci.yml`).
2. English regression: unchanged deploy/audit results on an `en-US` domain — Phase 1 must be a
   no-op there (identical resolved SIDs; only `Source` changes from `ADGroup` to `Canonical`).
3. German lab (manual, `tests/Manual.Integration.Tests.xlsx`): `Deploy-TierModel -WhatIf`,
   full deploy, `Audit-TierModel` reporting zero drift on a freshly deployed German domain, and
   a second deploy proving idempotency (the LAPS SELF re-application bug in §2.2(D)).
4. Verify §2.2(J): confirm `Import-GPO` on a German domain does not carry the source
   `<SecurityGroups>` names into the imported GPO, or add a migration table if it does.

## Risk Register

| Risk | Mitigation |
|---|---|
| A composed well-known SID does not exist in the target domain (child domain, absent optional group) | Existence confirmation in Phase 1.2 before returning; falls through to the name path |
| Phase 3 turning a warning into a hard failure breaks an existing English deployment where the ACE legitimately could not be written | Gate the strict behaviour and land it with an explicit CHANGELOG note; verify against the English lab first |
| `Set-Laps*Permission -AllowedPrincipals` may not accept a SID string on all LAPS module versions | Verify on the German lab; fall back to `<NETBIOS>\<sAMAccountName>` read from the SID-resolved object (never from the config literal) |
| German ADML files unobtainable in this environment | Phase 6 decouples from Phases 1-5, 7-9; ship the manifest and operator procedure if needed |
| Divergence from upstream `microsoft/ActiveDirectoryTierModel` | Changes are additive and English-neutral; upstream's issue-first contribution process (`CONTRIBUTING.md`) applies if this is ever offered back |

## Suggested Sequencing

Phases 1-3 together are the functional core and can be validated by unit tests alone.
Phase 4-5 make the run pass end-to-end. Phases 7-9 are cleanup and documentation. Phase 6 is
content and runs in parallel.
