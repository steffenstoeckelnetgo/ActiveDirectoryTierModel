# Feature Specification: German (de-DE) Windows and Active Directory Support

**Feature Branch**: `claude/beautiful-galileo-skfp32`
**Created**: 2026-09-15
**Status**: DESIGN — awaiting implementation approval
**Input**: "Build a version that also works on German Windows and on a German Active Directory."

---

## 1. Problem Statement

`Deploy-TierModel.ps1` and `Audit-TierModel.ps1` **refuse to run** on a German host OS or
against a German-installed Active Directory. `Test-TierModelPrerequisites` enforces two
unconditional fail-fast gates (`modules/TierModel/public/Test-TierModelPrerequisites.ps1`):

| Gate | Location | Behaviour |
|------|----------|-----------|
| Host OS install language | L144-175 | Reads `HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language\InstallLanguage`; anything but primary language `0x09` returns early with `Valid = $false` |
| AD well-known group names | L494-553 | Resolves *Domain Admins* (`<domainSID>-512`), *Server Operators* (`S-1-5-32-549`), *Account Operators* (`S-1-5-32-548`) **by SID** and compares each `Name` to its English literal |

On a German domain the canaries read `Domänen-Admins`, `Server-Operatoren`,
`Konten-Operatoren`, so gate 2 always fails. `docs/language-support.md` documents this as
intentional and proposes *"community language packs"* — translated copies of every config
file — as the future model.

**This spec rejects the translated-config model.** Translating names is both high-maintenance
and *still wrong*, because it breaks again whenever an administrator has renamed a built-in
group. Every principal the Tier Model references is a **well-known SID**, which is
language-independent and rename-independent. The correct fix is to resolve by SID.

## 2. Scope of Actual Breakage

The gate hides how little is genuinely locale-dependent. Measured across the repository:

### 2.1 Locale-independent already (no change needed)

| Area | Evidence |
|------|----------|
| GPO security templates | All 16 `config/gpo/**/GptTmpl.inf` express `[Privilege Rights]` values as `*S-1-...` SIDs; no principal name appears |
| GptTmpl write encoding | `Set-TierModelGpoTemplate.ps1:122`, `Update-TierModelGPOConfig.ps1:124,130` use `-Encoding Unicode` (UTF-16LE), correct for `secedit` |
| Schema/extended-right GUIDs | `Resolve-DomainSpecificGuid.ps1:84,123` filter on `ldapDisplayName` (never localized); `config/tiermodel-guid-mappings.json` is static GUIDs |
| OU / group / user / ACL config | `tiermodel-ous.json`, `tiermodel-groups.json`, `tiermodel-users.json`, `tiermodel-acls.json` reference only Tier Model-owned names (`Tier0Admins`, …) |
| Auth silo/policy SDDL | `Build-TierModelAuthSddl` resolves through `Resolve-TierModelPrincipalSid`; `Compare-TierModelAuthSddl.ps1:124-128` already maps SDDL aliases to RIDs |
| Audit SACL | `tiermodel-audit.json` uses `"trusteeSid": "S-1-1-0"` |
| Fixed-CN containers | `CN=Policies,CN=System`, `CN=Builtin` are schema-fixed in every language |
| ADML language plumbing | `-AdmlLanguage` parameter already exists end-to-end (`Deploy-TierModel.ps1:227`, `Audit-TierModel.ps1:204`, `Get/Test/Copy-TierModelAdmx`), loading `config/tiermodel-adml-<lang>.json` |

### 2.2 Genuinely locale-dependent (must change)

**(A) Well-known principal names in `config/tiermodel-gpos.json`**

Resolved by name through `Resolve-TierModelPrincipalSid` → `Get-ADGroup -Identity <name>`,
which fails on a German domain. Distinct localized names and their occurrence counts:

| Config key | Name | Occurrences | Canonical SID |
|---|---|---|---|
| resolvableGroups | Domain Admins | 30 | `<domainSID>-512` |
| resolvableGroups | Domain Controllers | 30 | `<domainSID>-516` |
| resolvableGroups | Cert Publishers | 29 | `<domainSID>-517` |
| resolvableGroups | Group Policy Creator Owners | 30 | `<domainSID>-520` |
| resolvableGroups | Read-only Domain Controllers | 30 | `<domainSID>-521` |
| resolvableGroups | Cloneable Domain Controllers | 30 | `<domainSID>-522` |
| resolvableGroups | Key Admins | 30 | `<domainSID>-526` |
| resolvableGroups | Allowed RODC Password Replication Group | 2 | `<domainSID>-571` |
| resolvableGroups | Administrator | 17 | `<domainSID>-500` (already special-cased) |
| resolvableGroups | Administrators | 38 | `S-1-5-32-544` (already in `Get-WellKnownSid`) |
| resolvableGroups | Guests | 48 | `S-1-5-32-546` (already mapped) |
| resolvableGroups | Backup Operators | 2 | `S-1-5-32-551` (only the `BUILTIN\` form is mapped) |
| resolvableGroups | Cryptographic Operators | 29 | `S-1-5-32-569` (**not** mapped) |
| resolvableGroups | IIS_IUSRS | 4 | `S-1-5-32-568` (not localized, but only `BUILTIN\` form mapped) |
| forestRootOnly | Enterprise Admins | 30 | `<forestRootSID>-519` |
| forestRootOnly | Schema Admins | 30 | `<forestRootSID>-518` |
| forestRootOnly | Enterprise Key Admins | 30 | `<forestRootSID>-527` |
| forestRootOnly | Enterprise Read-only Domain Controllers | 30 | `<forestRootSID>-498` |
| memberGroups | Domain Admins | 4 | `<domainSID>-512` |
| memberGroups | Guest | 7 | `<domainSID>-501` |
| denyApplyGroupPolicy | Domain Controllers, Read-only Domain Controllers | 2 | RIDs 516 / 521 |

Not localized and correct as-is: `DnsAdmins`, `DnsUpdateProxy` (created by the DNS Server
role with fixed names), `IUSR`, all `NT SERVICE\*` and `IIS APPPOOL\*` `literalStrings`,
`CLIUSR`, and all `Tier*` / `PawDomainJoin` Tier Model groups.

**(B) `config/tiermodel-winlaps.json`** — `readGroup`/`resetGroup` = `"Domain Admins"` on
the DC delegation entry (L6-11); passed to `Set-LapsADReadPasswordPermission
-AllowedPrincipals` (`New-TierModelWinLapsAcl.ps1:99,104`).

**(C) `config/tiermodel-authsilos.json`** — references `Domain Controllers` and
`Read-only Domain Controllers`; resolved via `Resolve-TierModelPrincipalSid`, so fixed by (A).

**(D) Name-string ACL comparisons in code** — these compare a *client-side translated*
`IdentityReference.Value`, which German Windows renders as `NT-AUTORITÄT\SELBST`,
`VORDEFINIERT\Administratoren`, `<DOM>\Domänen-Admins`:

| File | Line | Expression |
|---|---|---|
| `Get-TierModelWinLapsAcl.ps1` | 344 | `$_.IdentityReference.Value -eq 'NT AUTHORITY\SELF'` |
| `Get-TierModelWinLapsAclFd.ps1` | 290 | same |
| `Test-TierModelWinLapsAcl.ps1` | 188 | same |
| `Test-TierModelWinLapsAcl.ps1` | 239-244 | allow-list: `'NT AUTHORITY\SELF'`, `'NT AUTHORITY\SYSTEM'`, `'BUILTIN\Administrators'`, `'*\Domain Admins'`, `'*\Enterprise Admins'`, `'*\Administrators'` |

Consequence on a German domain: the SELF ACE is never detected (non-idempotent — the
delegation is re-applied on every run) and every legitimate administrative holder is
reported as **drift**.

**(E) Deny-Apply GPO ACE built from a localized name** — `New-TierModelGpo.ps1:248`
constructs `NTAccount($domainNetbios, $denyGroup)` with `$denyGroup = "Domain Controllers"`.
On a German domain `AddAccessRule` throws `IdentityNotMappedException`, which is caught at
L262 and downgraded to a **yellow console warning**. The Tier Model Account Restrictions GPO
then deploys *without* its Deny-Apply protection for Domain Controllers — a silent
tier-boundary weakening, the single highest-severity finding in this analysis.

**(F) Hardcoded well-known container DNs**

| File | Line | Expression |
|---|---|---|
| `Get-TierModelGpoFd.ps1` | 168, 287 | `-match '^OU=Domain Controllers,DC='` |
| `Get-TierModelGpo.ps1` | 121 | same |
| `config/tiermodel-gpos.json` | 315 | key `"OU=Domain Controllers,{{DOMAIN_DN}}"` |
| `config/tiermodel-winlaps.json` | 6 | `"ouDn": "OU=Domain Controllers,{{DOMAIN_DN}}"` |

The authoritative, language-proof source is `(Get-ADDomain).DomainControllersContainer`
(likewise `.UsersContainer`, `.ComputersContainer`).

**(G) Prerequisite lookups by English literal** — `Test-TierModelPrerequisites.ps1:381`
(`Get-ADGroup -Identity "Domain Admins"`) and `:457` (`"Enterprise Admins"`). L473
(`"DnsAdmins"`) is correct as-is.

**(H) ADML content** — only `config/admx/en-US/` and `config/tiermodel-adml-en-US.json` ship.
A German central store needs `PolicyDefinitions\de-DE\*.adml` or GPMC on a German admin host
shows "resource not found" for every ADMX-backed setting.

**(I) Culture-sensitive timestamp formatting** — `Get-Date -Format` without an explicit
culture in `Write-TierModelLog.ps1:54`, `Deploy-TierModel.ps1:320,444,733`,
`Audit-TierModel.ps1:291,674,833,2540`, `optional/Update-TierModelMembership.ps1` (6 sites).
`:` and `.` in a .NET custom format string are culture-replaceable separators. Low severity
under de-DE, but log/report filenames and JSON timestamps should be invariant by contract.

**(J) GPO backup `Backup.xml` `<SecurityGroups>`** — carries the *source lab* domain's
`Domain Admins` / `Enterprise Admins` as `<SamAccountName>` with source SIDs
(`S-1-5-21-3172251048-…-512/-519`). `Import-GPO` imports settings, not the GPO security
descriptor, so this is expected to be inert — but it must be **verified** on a German domain
rather than assumed.

## 3. Design Decision

**Canonical English names stay in the configuration; they are resolved to SIDs, not looked
up by name.** The config becomes language-neutral rather than language-specific.

Rationale over the translated-config-pack model in `docs/language-support.md`:

1. **One config set, all languages.** No `config/de-DE/` fork, no N-language release matrix,
   no per-feature multiplier on every future change — the objection that made upstream defer
   localization indefinitely.
2. **Rename-proof.** A domain where an admin renamed *Domain Admins* works identically — the
   same class of bug a translation pack cannot fix.
3. **Consistent with existing code.** `Compare-TierModelAuthSddl` already maps SDDL aliases
   to RIDs; `Resolve-TierModelPrincipalSid` already special-cases `Administrator` via RID 500
   *precisely because the name can differ*. This generalizes an established pattern.
4. **Smaller diff, security-reviewable.** ~15 code sites and one new lookup table versus
   several thousand translated JSON lines that no reviewer can verify by inspection.

The language gate is **deleted**, not narrowed (decided during implementation review): with
resolution made name-independent, a supported-language allow-list would only re-introduce a
gate the mechanism no longer needs. The host and directory language are still detected and
recorded in `EnvironmentSnapshot` as diagnostics, and nothing blocks. `-AllowUnsupportedLanguage`
is therefore not needed and was not added.

## 4. Functional Requirements

- **FR-001** A canonical well-known principal table MUST map every name in §2.2(A) to a
  well-known SID or a domain/forest-root RID.
- **FR-002** `Resolve-TierModelPrincipalSid` MUST consult that table (domain-SID and
  forest-root-SID aware) **before** any AD name lookup, and MUST return the resulting SID
  without a name query.
- **FR-003** Where the table does not apply (Tier Model-owned groups, `DnsAdmins`), existing
  name-based resolution MUST be unchanged.
- **FR-004** All ACL-holder comparisons MUST compare SIDs, never translated account names.
- **FR-005** The Deny-Apply GPO ACE MUST be built from a `SecurityIdentifier`, and a
  resolution failure MUST fail the deployment rather than emit a warning.
- **FR-006** Well-known container DNs MUST come from `Get-ADDomain`, not string literals.
- **FR-007** `Test-TierModelPrerequisites` MUST pass on a German host OS and a German
  directory, and MUST record the detected host and directory language in
  `EnvironmentSnapshot`. No language may block the run.
- **FR-008** Adding a `de-DE` ADML set MUST require no code change, and the manifest MUST be
  generable from a folder of ADML files. *(The ADML files are Microsoft redistributables; the
  Microsoft download hosts are unreachable from the build environment, so the files themselves
  are an operator content drop — see `optional/New-TierModelAdmlManifest.ps1` and
  `docs/admx-management.md`.)*
- **FR-009** All emitted timestamps MUST use `InvariantCulture`.
- **FR-010** No English-language behaviour may regress: the existing suite must stay green
  and coverage at or above the 80% CI gate.

## 5. Out of Scope

- Translating console output, logs, or documentation into German (the tool speaks English).
- Languages beyond `en-*` and `de-DE` (the design supports them; only German is validated).
- Renaming Tier Model-owned OUs/groups to German.
