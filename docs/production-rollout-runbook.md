# Production rollout runbook — a populated, multi-DC domain

Every figure this project publishes comes from an **empty, single-DC lab domain**. A production
domain is neither. This runbook is for the gap between the two, and it exists because the other
guides do not cover it: `quick-deployment-guide.md` and `detailed-deployment-guide.md` describe the
mechanics, `german-lab-runbook.md` and `parity-lab-runbook.md` describe lab acceptance, and only
`canonical-acl.md` treats a pre-existing directory as a first-class case.

**What a plan run cannot tell you.** A plan run and a collision check establish that the deployment
*can start* and *what it would do*. Neither writes anything, so neither can fail the way a write
fails — a GPO import into your SYSVOL, an ACL on an OU with a grown DACL, a LAPS delegation.
"Does this work here" is answered only by deploying. Where a restorable copy of production exists,
rehearse on it. This runbook is written for the case where one does not.

---

## 0. The one thing to read before deciding anything

**A full deployment restricts no logon.** That surprises people, and it changes how much of this is
a change window and how much is preparation:

- `*- Tier Model Account Restrictions` at the domain root ships **`linkEnabled: false`**. It is the
  documented go-live switch and it is off.
- Every authentication policy and silo ships **`enforce: false`**. They are created in audit mode.
- All 105 OU ACL delegations target **Tier Model OUs only** — not one touches
  `OU=Domain Controllers` or the domain root (`config/tiermodel-acls.json`).

What *does* take effect at the next policy refresh is the GPOs that ship `linkEnabled: true` on
`OU=Domain Controllers`. There are **five** of fourteen; the other nine ship link-disabled.

| GPO | Effect |
|---|---|
| `*- Tier 0 DCs Authentication Silo - Computer` | Enables the `AuthenticationPolicyFailures-DomainController` event channel. Benign, and it is the evidence you need *before* ever enforcing a silo. Link it early. |
| `*- Tier 0 DCs PowerShell Audit Policy - Computer` | PowerShell logging. Modest volume. |
| `*- Tier 0 DCs MSFT Edge Version v139 - Computer` | Browser hardening. |
| `*- Tier 0 DCs MSFT Internet Explorer 11 - Computer` | Browser hardening. |
| **`*- Tier 0 DCs Advanced Audit Policy - Computer`** | **See §0.1. This one deserves its own change.** |

### 0.1 The one setting that needs its own change window

That GPO sets **33 audit subcategories, 27 of them *Success and Failure*** — counted from
`config/gpo/domain_controller/Advanced Audit Policy/…/DomainSysvol/GPO/Machine/Microsoft/Windows NT/Audit/audit.csv`
— including Kerberos service ticket operations, Kerberos authentication, credential validation,
directory service access, directory service changes and process creation.

On busy production domain controllers that is an order-of-magnitude increase in Security event
volume. The practical failure is not an outage: it is a Security log that wraps in hours, taking
your forensic window with it, or a SIEM ingestion bill nobody approved. The policy itself is
defensible — roughly the Microsoft baseline — but arriving as a side effect of "deploy the Tier
Model" is not how it should arrive.

**Set `"linkEnabled": false` on that one entry in your `config/tiermodel-gpos.json` before you
run**, and link it later as its own change, after raising the Security log size and confirming SIEM
headroom. This is an operator choice in your own configuration, not a change to the product, and it
does not stage your deployment — everything else still goes out in one run. The audit will report
that one link as drift until you enable it, which is the correct signal for "not yet". Write down
that you did it so it is re-enabled deliberately rather than forgotten.

---

## 1. Multi-DC: which domain controller does what

Read out of the code, not assumed:

| Operation | Which DC | Where |
|---|---|---|
| `New-GPO`, `Import-GPO`, `New-GPLink`, `Set-GPLink`, every AD read | the **`-PreferredDc` you pass** | `Import-TierModelGpo.ps1:84`, `New-TierModelGPOLink.ps1:132` |
| **GptTmpl.inf and the other SYSVOL writes** | the **PDC emulator** | `Update-TierModelGPOConfig.ps1:94` |
| The "is this GPO's policy populated?" probe | the **PDC emulator** | `Get-TierModelGpo.ps1:41` |

On a single-DC lab those are one machine, so this could never surface there. On a multi-DC domain,
if `-PreferredDc` is not the PDC emulator, the GPO object is created on one DC and its policy files
are written to another's SYSVOL — and **23 GPOs take a `configure` action**, each of which needs
the GPC to have replicated first.

**So: use the PDC emulator, for every phase and every command in this runbook.**

```powershell
$dc = (Get-ADDomain).PDCEmulator
```

That aligns all three rows, removes the race, and matches where GPMC writes anyway. It also
satisfies the probe's deliberate asymmetry — an unreadable or unreplicated folder changes nothing,
because re-importing overwrites settings — which assumes you keep asking the same host.

Between the deployment and its verification, let replication converge. The repository's only
published figure is ~15 minutes and it is stated for the SACL feature
(`detailed-deployment-guide.md:497`); nothing here has been measured across DCs, so treat it as a
floor rather than a guarantee.

---

## 2. Phase 0 — read-only, no change window

None of this writes.

### 2.1 Back up first

DC snapshot or System State backup. **There is no uninstall and no rollback.** `faq.md:88`
recommends delete-and-redeploy and justifies it with "all objects created by the Tier Model are new
objects not in production use" — true on the day you deploy, false the moment accounts and
computers move into the tier structure.

### 2.2 Collision check — the highest-value item here

```powershell
.\optional\Test-TierModelCollision.ps1 -PreferredDc $dc
```

Groups and service accounts are adopted by **sAMAccountName, searched domain-wide, with no check of
location, group scope or category**. A hit means **nothing is planned** — the object is taken as-is,
wherever it sits and whatever it is. OUs are matched by full distinguished name, so they are
path-aware, but an adopted OU keeps whatever accidental-deletion protection and inheritance it
already has, because no action is planned for it. GPOs are matched by display name.

The audit afterwards checks properties the planner does not. So the failure mode in a populated
domain is: **deploy reports "already exists" and `Converged`, audit reports drift, and no command
in the tool closes the gap.**

The script is read-only — `Get-*` only — and reports which of the 31 OUs, 29 groups, 3 service
accounts and 146 GPO names already exist here and whether they match. Resolve every conflict by
hand — rename, move, or adjust your configuration — before deploying.

### 2.3 Canonical ACL gate — the most likely day-one blocker

```powershell
Test-TierModelCanonicalAcl -PreferredDc $dc
```

A non-canonical DACL on the domain root is a **fatal, non-bypassable** pre-flight stop:
`Deploy-TierModel.ps1` never passes `-SkipRootCanonicalCheck`, although the switch exists on
`Test-TierModelPrerequisites.ps1:61`. On a domain administered for years this is not exotic.

Remediation is manual, and `canonical-acl.md:411` is explicit about the reason: *"Reordering can
expand effective permissions. Rights that were silently blocked by the disordered ACL may suddenly
be granted after the fix."* Own change window, own backup, read that
document first.

### 2.4 Windows LAPS schema

Only for `-IncludeWinLaps`. The tool checks for the `ms-LAPS-Password` attribute and hard-stops; it
never extends the schema itself (`faq.md:236`).

### 2.5 The imported GPOs' source DACLs

`config/gpo/**/Backup.xml` carries **78** `bkp:Source="FromDACL"` entries — Domain Admins and
Enterprise Admins (RID 512 and 519 only) of five source domains: `security.local` (Microsoft's SCT
build domain), `TAILSPIN.COM`, `tailspintoys.com`, `wingtiptoys.com` and `tierlab.internal`. They
appear in `Backup.xml` and in **no settings file**.

The settings half is measured clean: the parity run read every `[Privilege Rights]` entry from
SYSVOL on two domains and found 0 foreign SIDs. What is unverified is whether `Import-GPO` puts any
of these on the imported GPO's **GPC DACL**. Run the two read-only commands in `CLAUDE.md` §6
*Open questions* against a domain that already carries these GPOs — the lab — searching for those
five prefixes. No output means inert. Do this before the production import, not after.

### 2.6 Plan run

```powershell
.\Deploy-TierModel.ps1 -PreferredDc $dc -FullDeployment `
    -IncludeMsa -IncludeGmsa -IncludeDmsa -IncludeWinLaps -IncludeAuthSilos
```

Writes nothing. An empty domain plans **719** actions. A materially different number here is a
finding to understand before applying — it is the arithmetic consequence of whatever §2.2 found.

**Gate:** collisions resolved, canonical gate green, LAPS schema present, §2.5 silent, plan count
understood.

---

## 3. The deployment

```powershell
.\Deploy-TierModel.ps1 -PreferredDc $dc -FullDeployment `
    -IncludeMsa -IncludeGmsa -IncludeDmsa -IncludeWinLaps -IncludeAuthSilos `
    -ConfirmApply -Logging -OutputFileBase "prod-01-full"
```

The lab's shape, for comparison: 31 OUs, 29 groups, 3 service accounts, 105 OU ACLs, 146 GPOs
(123 imported, 23 configured, 131 linked), 60 ADMX/ADML, MSA/gMSA/dMSA 4 each, 17 Windows LAPS
actions, 4 policies and 4 silos — **689 applied, 0 errors**.

Three things to read rather than skim:

- **`Canonical remediation: N OU DACL(s) auto-corrected during disable-inheritance.`** That is
  `Repair-TierModelCanonicalAcl` running inline on OUs the tool just created. Permission-neutral by
  design, reordering only. Read the number.
- **ADMX always overwrites** (`deployment-methodology.md:186`). If you keep a curated central
  store, diff the 30 bundled `.admx` and 30 `.adml` files against
  `\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions` **before** this run — a newer vendor ADMX
  of the same name is replaced by the bundled one, silently and by design.
- **A single `0x80070091` (`ERROR_DIR_NOT_EMPTY`) during the GPO imports** is the transient
  `Invoke-TierModelTransientRetry` exists for. Repeated ones are a finding, not weather.

`Converged: False` on this run is correct: it means the directory changed.

If a configure action fails, the run returns before the link phase and **no GPO link is applied**
(`Deploy-TierModel.ps1:1694`). That is deliberate and is not a warn-and-continue. Fix the cause and
re-run; the deployment is idempotent.

---

## 4. Verification — not optional

```powershell
# byte-identical to the deployment command
.\Deploy-TierModel.ps1 -PreferredDc $dc -FullDeployment `
    -IncludeMsa -IncludeGmsa -IncludeDmsa -IncludeWinLaps -IncludeAuthSilos `
    -ConfirmApply -Logging -OutputFileBase "prod-02-idempotency"

.\Audit-TierModel.ps1 -PreferredDc $dc -FullDeployment `
    -IncludeMsa -IncludeGmsa -IncludeDmsa -IncludeWinLaps -IncludeAuthSilos -OutputFormat Json

.\optional\Test-TierModelLocalizedDeployment.ps1 -PreferredDc $dc `
    -IncludeMsa -IncludeGmsa -IncludeDmsa -IncludeWinLaps -IncludeAuthSilos -IncludeAudit
```

| Check | Expected |
|---|---|
| Second deployment run | **`Applied: 0 / Errors: 0 / Converged: True`** |
| Audit | **`Drift 0 / Errors 0`**, except the one DC audit-policy link disabled in §0.1 |
| Localization report | `0 unresolved`, `No problems found.` |

The second run is constitution principle III and the only evidence that nothing was left
half-built — a GPO whose create succeeded and whose import failed looks identical to a finished one
from the outside.

The localization report is the **only** thing that checks the Deny-Apply ACE is genuinely on the
GPC. The product audit never looks at it.

**Let replication converge before the verification**, and keep `$dc` on the PDC emulator.

---

## 5. Go-live — one lever at a time

Nothing above restricts a single logon. Each of these does. Each is its own change window, and each
is individually reversible — which stops being true once real accounts and computers move into the
tier structure.

1. **DC audit policy** (§0.1). Raise the Security log size and confirm SIEM headroom **first**,
   then enable the link. Watch event volume for a full business cycle before the next lever.
2. **`*- Tier Model Account Restrictions`** at the domain root. This is tier separation taking
   effect. Review how Block Inheritance and Enforced interact with your existing GPOs first
   (`detailed-deployment-guide.md:575`).
3. **Authentication silo enforcement, last.** Read the failure channel that the silo GPO enabled in
   §0 until it is quiet, then follow the checklist in `auth-silos-operations-guide.md:136`. Moving
   admin accounts into silos is an out-of-band operator task; the Tier Model does not manage user
   silo membership.

Populating the tier groups and moving computers into the tier OUs is a migration project, not this
deployment.

---

## 6. What this rollout still does not establish

Record these rather than letting a green run imply more than it shows.

- **Multi-DC replication.** Every published measurement binds one DC. §1 removes the known race by
  pinning the PDC emulator; that is a mitigation, not a measurement.
- **A populated directory.** The lab evidence is green-field. §2.2 narrows this — it finds name
  collisions, not every way a grown directory differs from an empty one.
- **Child domains and RODCs.** Untested. In a child domain the forest-root RIDs (518, 519) resolve
  out of a different domain than the rest, on the `CanonicalForestRootRid` path, which has only
  ever been measured from a forest root.
- **Rollback after §5.** There is none. Snapshots age; by go-live a restore means losing everything
  since.
