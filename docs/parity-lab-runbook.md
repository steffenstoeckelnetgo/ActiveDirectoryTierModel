# Parity lab runbook — English and localized domain, compared

The claim this project's localization work rests on is narrow and testable:

> The **same** configuration, deployed to an English domain and to a localized one, produces the
> **same** security configuration. Only the rendered names differ.

No unit test can establish that. It needs two live domains, and this runbook is how they are
compared. It assumes `docs/german-lab-runbook.md` for everything that happens *inside* one
domain; nothing here replaces it.

---

## 0. What you need

| | |
|---|---|
| Two domains | one English, one localized. Each needs its own DC, RSAT, Windows LAPS schema and a Domain Admin session, exactly as the German runbook's §0 lists. |
| The same commit on both | note it down. A report pair from two different commits proves nothing. |
| PowerShell 7, Pester 5.x, PSScriptAnalyzer | per the German runbook §0. |

**The two domains do not need the same topology, and the comparison does not assume it.** They do
need the same `config/` — which is the point, since `config/` is never edited per language.

---

## 1. Run the full runbook on each domain

`docs/german-lab-runbook.md`, phases A–E, once per domain. Keep the two report files apart and
name them so nobody has to guess later:

```powershell
# on each domain, from the repository root
.\optional\Test-TierModelLocalizedDeployment.ps1 -PreferredDc $dc `
    -IncludeMsa -IncludeGmsa -IncludeDmsa -IncludeWinLaps -IncludeAuthSilos -IncludeAudit `
    -OutputPath .\parity-en.json      # ...or parity-de.json on the localized domain
```

The script detects the directory's language itself, from three canary groups read **by SID** and
read back for their actual name. `Environment.DirectoryLanguage` comes back `en` or `localized`;
you do not tell it which domain it is on, and it is worth checking that it agrees with you.

**Per domain, both of these must hold before the comparison is worth doing:**

- the deploy finished with `Errors: 0`, and the **second** run reported `Applied: 0` and
  `Converged: True` — a domain that is not converged is not describable by one report;
- the audit reported `DriftCount: 0` and `ErrorCount: 0`.

Otherwise you are comparing a finished deployment against a half-finished one, and every
difference the comparison finds will be that, not localization.

---

## 2. Compare

Bring both JSON files to one machine and run:

```powershell
.\optional\Compare-TierModelDeploymentReport.ps1 `
    -ReferencePath .\parity-en.json `
    -DifferencePath .\parity-de.json
```

Read-only. Writes one JSON and sets an exit code — `0` when the two agree, `1` when they do not,
so it can gate a pipeline later.

### Why this is not a text diff

Every domain-scoped principal in `[Privilege Rights]` is written with its own domain's SID as a
prefix:

```
*S-1-5-21-2230522700-2543936044-3532250090-512     one domain
*S-1-5-21-1004336348-1177238915-682003330-512      the other
```

Both are **Domain Admins, RID 512**. A textual diff calls them different, and in the measured lab
data that is 1651 SID entries across 29 GPOs — a wall of false differences whose only available
conclusion is the wrong one. Earlier guidance in this repository said to diff the sections
directly; it was mistaken and has been corrected.

The comparison therefore replaces **each report's own** domain SID with `<DOMAIN>` before
comparing. Three things deliberately survive untouched, and `tests/Unit.ParityComparison.Tests.ps1`
pins each:

| Survives | Why |
|---|---|
| a SID belonging to **neither** domain | a foreign SID in the settings is the finding, not noise — it is what the open `Import-GPO` `<SecurityGroups>` question is looking for |
| `S-1-5-32-*`, `S-1-1-0`, `S-1-5-10` | invariant already; no domain prefix to strip |
| `NT SERVICE\*`, `IIS APPPOOL\*`, `CLIUSR` | machine-local `literalStrings`; no domain SID by construction, resolved by secedit on the target (rule 2.4) |

### And normalising the domain SID is not enough either

Below the domain SID sits a second, independent source of exactly the same kind of false
difference, and it is the one that is easy to miss. Active Directory allocates a RID when an
object is created, from a pool that starts at **1000**. A Tier Model group's RID therefore records
how many objects its domain had created before it — not anything the configuration says:

```
<DOMAIN>-2602     Tier 0 Admins on one domain
<DOMAIN>-2603     Tier 0 Admins on the other
```

The parity run of 2026-09-24 is what made this concrete. The two lab domains differed by exactly
one object before the first Tier Model container was created, so **every** locally allocated RID
was off by one, and the comparison reported **84 differences — 31 `SidDiffers` and 53
`ValuesDiffer` — against two deployments that were identical**. 31 of the 56 configured principals
and 894 of the 1791 `[Privilege Rights]` entries carry such a RID.

A SID at or above the pool is therefore mapped back to the name the configuration gave it, through
**the report's own `PrincipalResolution` table**, and compared by that name — which is what the
configuration actually asserts. Two things keep their number on purpose:

| Keeps its RID | Why |
|---|---|
| a RID **below** 1000 | fixed by the protocol — 500, 512, 516, 571 … — so a difference there is a real resolution defect |
| a locally allocated SID the report does **not** name | it cannot be compared by identity, so it stays comparable by RID and is still reported. Measured on both lab domains: zero such SIDs. This is a guard, not a routine path |

### What is compared, and what is deliberately not

| Compared | Not compared |
|---|---|
| `PrincipalResolution`: per configured name, the **SID** (normalised) and the **Source** | the **DirectoryName** — `Domain Admins` vs `Domänen-Admins` is the intended outcome; flagging it would fail the proof on the very thing it exists to show |
| `PrivilegeRights`: per GPO **display name**, per right, the normalised value set | the GPO **GUID** — a GPO is created per domain, so its GUID differs by construction |

`Source` is compared deliberately: the same SID reached by a *different route* means one domain
fell back to a name lookup. That is a real finding even when the SID matches, and it is invisible
if you only compare SIDs.

---

## 3. Read the result

**`No differences.`** — the claim holds for these two domains. That is the parity proof, and it is
the sentence to quote.

Anything else, by `Kind`:

| Kind | What it means |
|---|---|
| `SidDiffers` | a configured principal resolved to a different **built-in** RID (below 1000), a different well-known SID, or changed class — built-in on one domain, locally created on the other. A real defect in resolution. It no longer fires for a locally allocated RID; see below. |
| `SourceDiffers` | same SID, different route. One domain fell back — usually to a name lookup, which is what this project removed. Look at which side. |
| `ResolutionDiffers` | the principal resolved on one domain and not on the other, with the same SID and the same source. Read the report's `Resolved` and `Error` fields for that entry. |
| `LocalRidNotCompared` | **not a difference, and not counted.** The principal resolved to a domain-allocated RID (≥ 1000) on both sides, so it was compared by identity instead of by number — see §2. Expect one per Tier Model-owned group; on the measured lab pair, 31. The console prints the count. A number far from what you expect is worth a look; the entries themselves are in the result JSON under `LocalRidNotCompared`. |
| `PrincipalMissingIn…` | a principal resolved on one domain and not the other. Expected **only** for forest-root groups read from a child domain and for optional groups such as `Allowed RODC Password Replication Group`; anything else is a defect. |
| `ValuesDiffer` | a right carries different principals. If a raw `S-1-5-21-…` appears on one side, that is a **foreign** SID — go to the `Import-GPO` question in `CLAUDE.md` §6. |
| `RightMissingIn…` | a privilege right exists in one deployment only. Usually means the two runs were not at the same commit or one deployment is incomplete. |
| `GpoMissingIn…` | a GPO exists on one domain only. Same causes. |

---

## 4. What this proves, and what it does not

**Proves:** for these two domains, at this commit, localization changed nothing about the security
configuration that lands in the directory and in SYSVOL.

**Does not prove:**

- anything about a *third* language. The mechanism is language-independent by construction — SIDs
  and RIDs, never names — but only these two combinations have been measured.
- anything about topologies neither domain has: child domains, multi-DC replication, RODC, or an
  English host administering a localized domain.
- that the deployment is correct. It proves the two are the **same**. Both being identically wrong
  would pass. The per-domain audit in phase E is what establishes correctness; this establishes
  parity.

Record all three in the release notes rather than letting a green run imply more than it shows.
