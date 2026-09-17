# Language Support

> **Status: language-independent.** The Tier Model deploys and audits against a domain
> installed in any language, from a host installed in any language. English (`en-US`)
> and German (`de-DE`) are the regression-tested combinations; other languages use the
> same mechanism and are expected to work, but are not validated by the project.

Earlier releases refused to run outside English: `Test-TierModelPrerequisites` enforced
two fail-fast gates, one on the host's Windows installation language and one on the
names of three well-known Active Directory groups. Both gates are gone. This page
explains what replaced them, and why the replacement is not a translation.

## The problem the gates were guarding

Active Directory stores the **names** of its well-known security principals — *Domain
Admins*, *Server Operators*, *Account Operators* and the rest — as real directory
attributes. Those names are **localized once, at domain creation**, from the
installation language of the first domain controller, and then replicated to every
domain controller in the domain.

Two consequences follow:

1. **The domain's language is fixed and independent of the machine you run from.**
   Opening *Active Directory Users and Computers* (`dsa.msc`) from an English
   Windows 11 client against a German domain still shows `Domänen-Admins`, not
   `Domain Admins` — the name comes from the directory, not the client. A domain
   controller later installed with an **English** OS and joined to that German domain
   still serves the **German** names, because they are replicated, not recreated.
2. **The configuration set names these principals in English.** `config/tiermodel-gpos.json`
   alone refers to them in hundreds of places. Looking each one up by name
   (`Get-ADGroup -Identity 'Domain Admins'`) finds nothing on a localized domain, so
   deployments failed or — worse — silently skipped security configuration.

That was real. The gates were a correct response to it at the time; they were just the
blunt one.

## What replaced them

**The English names stay in the configuration, but they are treated as canonical
identifiers rather than as directory names.**

Every built-in principal the Tier Model references has a **well-known SID**: either an
absolute SID (`BUILTIN\Administrators` is `S-1-5-32-544` in every language) or a
well-known **RID** under the domain SID (*Domain Admins* is always RID `512`). SIDs are
not localized and do not change when a group is renamed.

`Resolve-TierModelPrincipalSid` resolves in this order:

| # | Step | Example |
|---|------|---------|
| 1 | Direct SID passthrough | `S-1-5-32-544` |
| 2 | `Administrator` via RID 500 | handles the renamed built-in account |
| 3 | Session cache | — |
| 4 | Static well-known SID table | `Server Operators` → `S-1-5-32-549`, no directory read |
| 5 | **Canonical RID composition** | `Domain Admins` → `<domainSID>-512`, then read back by SID |
| 6 | Name lookup | `Tier0Admins`, `DnsAdmins`, service accounts |

Step 5 is the change. The SID is composed against the domain being deployed to and then
**read back by that SID** to confirm the object exists. The read-back is not a
formality: it is what keeps forest-root groups (*Enterprise Admins*, *Schema Admins*)
unresolvable in a child domain and lets an optional group that a domain never created
(*Allowed RODC Password Replication Group*) resolve to nothing, so callers skip it
instead of writing an unresolvable SID into a GPO's `[Privilege Rights]`.

This generalizes a pattern the project already used: `Administrator` has always been
resolved via RID 500, precisely because that account can be renamed.

## Why not translated configuration files?

Earlier versions of this page proposed *community language packs*: a `config/de-DE/`
tree with `Domänen-Admins` substituted throughout, maintained per language. That model
was not adopted, for four reasons.

1. **One configuration set now covers every language.** No fork, no *N*-language release
   matrix, no per-feature multiplier on every future change. That multiplier was the
   stated reason localization kept being deferred.
2. **SIDs are rename-proof; translations are not.** A domain where an administrator
   renamed *Domain Admins* breaks a translation pack exactly as a localized domain broke
   the English one. The SID keeps working.
3. **It is reviewable.** The change is one lookup table and roughly fifteen call sites,
   against several thousand translated JSON lines that no reviewer can verify by reading.
4. **It matches what the product already did.** GPO security templates
   (`config/gpo/**/GptTmpl.inf`) have always expressed `[Privilege Rights]` as
   `*S-1-...` SIDs, the audit SACL is configured as `"trusteeSid": "S-1-1-0"`, schema
   GUIDs resolve through `ldapDisplayName`, and Authentication Policy Silos compare
   SDDL. SID-first resolution is the rule here; name lookup was the exception.

## What the prerequisite check does now

Nothing blocks, but the language is still **detected and recorded** in
`EnvironmentSnapshot`, because it is the first useful fact when triaging a report from a
non-English estate:

| Field | Meaning |
|-------|---------|
| `HostInstallLanguage` | Raw `InstallLanguage` LCID from `HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language` |
| `HostOsLanguage` | That LCID resolved to a culture name, e.g. `de-DE` |
| `HostOsEnglish` | Kept for compatibility with existing tooling that reads the snapshot |
| `AdLanguage` | `en` or `localized`, from the canary groups below |
| `AdLanguageEnglish` | Kept for compatibility |
| `AdLanguageMismatches` | The localized names that were found, e.g. `Domain Admins is named 'Domänen-Admins'` |

The canaries are the same three groups as before, still resolved **by SID** and read
from Active Directory rather than translated client-side (a client-side translation is
localized by the *local* OS and would describe the wrong machine):

| Canary group | SID / RID | Scope |
|--------------|-----------|-------|
| Domain Admins | `<DomainSID>-512` | Domain — exists in every domain |
| Server Operators | `S-1-5-32-549` | BUILTIN — exists in every domain |
| Account Operators | `S-1-5-32-548` | BUILTIN — exists in every domain |

## Which languages this affects

Microsoft fully localizes the Windows **Server** user interface — including Active
Directory built-in group names — for
[18 languages](https://learn.microsoft.com/windows-hardware/manufacture/desktop/available-language-packs-for-windows).
Those 18 are the domains whose built-in names differ from English:

Chinese (Simplified and Traditional), Czech, Dutch, English, French, German, Hungarian,
Italian, Japanese, Korean, Polish, Portuguese (Brazil and Portugal), Russian, Spanish,
Swedish, Turkish.

Every other install — Language Interface Packs such as Hindi or Indonesian, and non-bold
full Language Packs such as Arabic, Greek, Hebrew, Danish, Finnish, Norwegian or Thai —
keeps **English** Active Directory names.

All of them resolve the same way now: by SID. The list matters only for knowing what
`AdLanguage: localized` will look like in a report.

## Which names are localized — and which are not

This is documented Windows behaviour, not something a deployment has to discover. Two
sentences from Microsoft's own documentation carry the whole design:

> Well-known SIDs have values that remain constant across all operating systems. […] They're
> created when the operating system or domain is installed.
> — [Security identifiers (AD DS)](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers)

> Because the names of well-known SIDs can vary, you should use the functions to build the SID
> from predefined constants rather than using the name of the well-known SID. For example, the
> U.S. English version of the Windows operating system has a well-known SID named
> `BUILTIN\Administrators` that might have a different name on international versions of the
> system.
> — [Security Identifiers (Win32)](https://learn.microsoft.com/windows/win32/secauthz/security-identifiers)

**The SID is invariant, the name is not, and the name is fixed at install time** — of the
operating system for machine-local principals, of the *domain* for domain principals. That is
why a domain installed from a German first domain controller serves `Domänen-Admins` forever and
cannot be switched afterwards, and why this project treats the English names in `config/*.json`
as identifiers rather than as directory names.

The mechanics are spelled out for one account in particular:

> While the security subsystem localizes this account name, the SCM does not support localized
> names. Therefore, you will receive a localized name for this account from the
> `LookupAccountSid` function, but the name of the account must be `NT AUTHORITY\LocalService`
> when you call `CreateService` or `ChangeServiceConfig`, regardless of the locale, or
> unexpected results can occur.
> — [LocalService Account](https://learn.microsoft.com/windows/win32/services/localservice-account)

Three things follow: the LSA *does* return localized names for SID→name; some interfaces
nevertheless demand the invariant English form; and Microsoft documents localization where it
exists.

### The classes this project touches

| Class | Example | SID | Name localized | Resolved where |
|---|---|---|---|---|
| BUILTIN aliases | `Administrators` | `S-1-5-32-544` | **yes** — `VORDEFINIERT\Administratoren` | on the DC, at deploy time |
| NT AUTHORITY principals | `SELF`, `SYSTEM` | `S-1-5-10`, `S-1-5-18` | **yes** — `NT-AUTORITÄT\SELBST` | on the DC, at deploy time |
| Domain built-ins | `Domain Admins` | `<domainSID>-512` | **yes** — `Domänen-Admins` | on the DC, at deploy time |
| Tier Model's own groups | `Tier0Admins` | `<domainSID>-11xx` | no — the Tier Model creates them | on the DC, at deploy time |
| Virtual service accounts | `NT SERVICE\himds` | `S-1-5-80-<SHA1(service name)>` | see below | **on the target machine, at policy application** |
| Application pool identities | `IIS APPPOOL\DefaultAppPool` | `S-1-5-82-<SHA1(pool name)>` | see below | **on the target machine** |
| Cluster local account | `CLIUSR` | machine-local | no | **on the target machine** |

The first four are resolved by `Resolve-TierModelPrincipalSid` and written into policy as
`*S-1-…`. The German lab report of 2026-09-16 measured the result: 56 configured principals,
0 unresolved, 42 of them carrying a German directory name.

### The last three rows are not an exception to the SID rule

They are a different question altogether: **they are not directory principals.** An
`S-1-5-80-…` SID is a SHA-1 over a *service* name and an `S-1-5-82-…` SID a SHA-1 over an
*application pool* name — identifiers that exist only on the machine where that service or pool
is installed. The domain controller a deployment runs against has no `himds` and no
`MSSQLSERVER`, so it cannot compose those SIDs at all. Not for a language reason: the principal
simply is not there.

So `New-TierModelGptTmplContent` writes them into `[Privilege Rights]` **unprefixed**, next to
the `*S-1-…` entries it resolved. That is the INF convention — a leading `*` means "this is a
SID", no prefix means "this is a name, resolve it locally" — and the Security Configuration
Engine on the target member server does the resolution, where the service does exist.

`literalStrings` in `config/tiermodel-gpos.json` is therefore **deferred resolution, not a
localization loophole**, and it is original upstream behaviour (commit `f8270cd`, v1.0.0), not
something the SID work introduced. `optional/Test-TierModelLocalizedDeployment.ps1` exempts
exactly the declared ones and reports any other plain name, which is the finding that would
matter.

### What documentation does not settle

Whether the domain label `NT SERVICE` itself is localized on a German host.

In favour of invariant: [MS-LSAT] requires a row for the `"NT SERVICE"` domain in the
Configurable Translation Database — a protocol-defined identifier, not a UI string; the
resolvable part of the name is a registry service name and is not translated; and Microsoft's
own *German-language* documentation instructs German administrators to enter exactly
`NT SERVICE\<SERVICENAME>`. Against certainty: Microsoft documents localization where it exists
(see `LocalService` above) and there is no such note for `NT SERVICE`, which is an indication
rather than a proof.

It also does not change anything the Tier Model controls. That string comes from the GPO
templates, it is resolved on the member server rather than by this tool, and it is the same
string every Windows administrator on a German system is told to type. If it did not resolve
there, that would be a Windows-wide problem rather than a Tier Model one. A single
`LookupAccountName` call on a German member server settles it:

```powershell
[System.Security.Principal.NTAccount]::new('NT SERVICE', 'TrustedInstaller').
    Translate([System.Security.Principal.SecurityIdentifier])
```

## Administrative templates (ADMX/ADML)

This is the one place where language is still a **content** question rather than a code
one. ADMX files are language-neutral; the human-readable strings live in per-language
ADML files under `PolicyDefinitions\<language>`. Only `en-US` ships with this repository.

On a German admin host, a central store containing only `en-US` makes the Group Policy
editor report *"resource not found"* for every ADMX-backed setting.

`Deploy-TierModel.ps1` and `Audit-TierModel.ps1` already accept `-AdmlLanguage` and load
`config\tiermodel-adml-<language>.json`, so adding a language is a content drop plus one
command — see [ADMX Management](admx-management.md) for the procedure and
`optional/New-TierModelAdmlManifest.ps1` for the manifest generator.

## What is still English

The tool itself speaks English: console output, log messages, findings and this
documentation are not localized, and localizing them is not planned. Only the
*directory* and the *host OS* are language-independent.

The OUs, groups and service accounts the Tier Model creates also keep their English
names (`Tier 0 Member Servers`, `Tier0Admins`, `svc-pawdomainjoin`). They are objects
the Tier Model owns, not built-ins it has to find, so their names are a naming
convention rather than a compatibility question.

## Validation status

| Combination | Status |
|-------------|--------|
| English host, English directory | Regression-tested (automated suite + manual integration workbook) |
| German host, German directory | Target of this work — see `specs/008-german-language-support/` |
| Mixed (English host, German directory, or the reverse) | Supported by design; the host and the directory are resolved independently |
| Any other localized language | Same mechanism, not validated by the project |

Contributing a validated language means running the manual integration workbook
(`tests/Manual.Integration.Tests.xlsx`) against a domain installed in it — no
configuration files to translate and maintain.
