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
