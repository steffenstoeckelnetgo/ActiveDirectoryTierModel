# SMB Reference Architecture

Scoping this Tier Model for organisations too small to run the full three-tier topology, without
turning the boundary into decoration.

---

## 1. What this document is

The Tier Model ships an enterprise topology: three tiers, three PAW populations, 31 OUs, 29 groups,
105 OU ACL delegations and 146 GPOs. Smaller organisations routinely ask whether that can be
reduced — fewer administrative workstations, fewer tiers, administration from a machine people
already have.

The answer is yes, within limits that are specific and worth stating precisely. This document is
the scoping guide: which reductions preserve the property the Tier Model exists to provide, which
ones remove it, and how to tell the difference before a customer is committed.

**Nothing here changes the tool.** Every reduction described below is an edit in the *customer's*
copy of `config/`. This repository's own `config/` is not modified by any of it.

**What is measured and what is judgement.** Section 2 is read out of `config/` and cited by file.
Everything from section 3 onward is an architectural judgement, informed by those facts but not
derived from them. Section 9 says so again, because the two get confused when a document is
quoted out of context.

---

## 2. What the tool enforces today

The tier boundary is locked twice. Both locks matter for what follows, because a reduction that
opens one and not the other produces a configuration that looks separated and is not.

### Lock 1 — logon rights, per PAW tier

Three GPOs, one per tier, each linked to that tier's PAW device OU:

| GPO | Linked to |
|---|---|
| `*- Tier 0 PAWs Account Restrictions` | `OU=Tier 0 PAW Devices,OU=Tier 0,OU=Tier Model Administration,<domain>` |
| `*- Tier 1 PAWs Account Restrictions` | `OU=Tier 1 PAW Devices,OU=Tier 1,…` |
| `*- Tier 2 PAWs Account Restrictions` | `OU=Tier 2 PAW Devices,OU=Tier 2,…` |

All three are `mode: createImportAndConfigure`, and their `userRightsAssignments` live in
`config/tiermodel-gpos.json` — **not** inside the GPO backup. That is the single most important
fact for everything below: **the logon boundary is editable as configuration, with no change to
product code and no repackaging of a GPO backup.**

What they grant and deny (counts include `forestRootOnly` entries):

| | `SeInteractiveLogonRight` allows | `SeDenyInteractiveLogonRight` |
|---|---|--:|
| Tier 0 PAW | `Administrators`, `Tier0Operators` | 19 groups — every `Tier1*` and `Tier2*` |
| Tier 1 PAW | `Administrators`, `Tier1Operators` | 31 groups — every `Tier0*` and `Tier2*`, plus `Domain Admins`, `Enterprise Admins`, `Schema Admins` |
| Tier 2 PAW | `Administrators`, `Tier2Operators` | 26 groups — every `Tier0*` and `Tier1*`, plus the same built-ins |

Note the asymmetry: the Tier 0 PAW does **not** deny `Domain Admins` or `Enterprise Admins`. It is
the machine where those accounts belong. The Tier 1 and Tier 2 PAWs deny them, which is what makes
the boundary directional rather than merely partitioned.

### Lock 2 — Kerberos TGT issuance, per device

`config/tiermodel-authsilos.json`, `allowedToAuthenticateFromDeviceGroups`:

| Policy | TGT issued only from |
|---|---|
| `*- Tier 0 Authentication Policy` | `Domain Controllers`, `Read-only Domain Controllers`, `Tier0MemberServers`, `Tier0PAWDevices` |
| `*- Tier 1 Authentication Policy` | `Tier1MemberServers`, `Tier1PAWDevices` |
| `*- Tier 2 Authentication Policy` | `Tier2PAWDevices` |
| `*- Tier 2 EUD Authentication Policy` | `Tier2EUDDevices` |

This is the stronger of the two locks, and the one that matters most when someone outside the
organisation administers it: **a member of `Tier0Admins` receives no TGT at all unless the logon
originates from a computer object in `Tier0PAWDevices`.** Not a policy, not an undertaking —
Kerberos declines to issue the ticket.

All four policies ship `enforce: false`. They are created in audit mode and enforcement is a
separate, deliberate step; see `auth-silos-operations-guide.md`.

**One documented gap, and it is load-bearing for sections 4 and 8:** silos restrict the Kerberos
AS (TGT) origin decision only. They do not block NTLM, LDAP simple bind, cached/offline logon, or
Entra / cloud authentication paths (`auth-silos-operations-guide.md:271-272`). A silo constrains
Kerberos; it says nothing about a cloud authentication path into the same environment, and nothing
about NTLM.

---

## 3. Decision 1 — how many tiers

### The question that decides it

> **Is there anyone — today or foreseeably — who should administer something but should not own
> the domain?**

An apprentice. A helpdesk role. An application owner. The printer person. **An external service
provider.** That last one is the most frequent hit and the one most often forgotten, because the
answer is usually "well, obviously, but they're our IT partner".

| Answer | Variant |
|---|---|
| Yes | **A — Tier 0 alone, Tier 1 and Tier 2 merged.** Two PAW populations |
| No, it is exactly one person and they are a Domain Admin | **C — Tier 0 only.** One PAW population |

### Why A is the default, even when C looks sufficient

Not because A is safer — both are internally coherent. Because of the **conversion path**.

Going from C to A later is not a configuration change; it is a migration. By then accounts exist,
computers sit in OUs, service accounts are issued, and each one has to be re-sorted with the
outage risk that carries. A costs one additional machine now and is then finished. The trigger for
the conversion arrives reliably in small organisations: a new service provider, growth, a cyber
insurance questionnaire, an audit.

A is also the smallest variant in which this toolset earns its operational cost.

### If C genuinely applies, say so plainly

With exactly one administrator and no delegation requirement, deploying 31 OUs, 105 ACL
delegations and 146 GPOs produces a structure where most of it separates nothing. That is
operational overhead without a corresponding control, and worse, it suggests a boundary to
auditors and insurers that does not exist.

For C, the proportionate answer is: a dedicated administrative device, separate administrative
accounts, Windows LAPS, no Domain Admin service accounts, and a sound baseline. That is a fraction
of the work and covers the same risk.

Recommending against your own toolset where it does not fit is a better position than deploying it
and explaining later why the structure was hollow.

### Variant A — the exact configuration change

Tier 1 and Tier 2 administration both happen from the Tier 1 PAW. The rule is derivable rather
than hand-listed, which is what makes it checkable:

> **On the Tier 1 PAW, treat the `Tier2*` groups the way the Tier 2 PAW already treats them.**

Applied to `*- Tier 1 PAWs Account Restrictions` in `config/tiermodel-gpos.json`:

**Add** — `Tier2Operators` to `SeInteractiveLogonRight` and to `SeRemoteInteractiveLogonRight`.
(`Tier2Admins` needs no entry; it reaches the machine through local `Administrators`, exactly as
on the Tier 2 PAW.)

**Remove** from `SeDenyInteractiveLogonRight` and `SeDenyRemoteInteractiveLogonRight` — the eight
groups the Tier 2 PAW does not deny:

```
Tier2AccountOperators   Tier2Admins                 Tier2ComputerQuarantineOperators
Tier2DeviceOperators    Tier2EUDDomainJoin          Tier2GroupOperators
Tier2HelpdeskOperators  Tier2Operators
```

**Keep denied**, because the Tier 2 PAW keeps them denied too:
`Tier2LocalDeviceOperators`, `Tier2ServiceAccounts`, `Tier2VpnAccounts`.

**Remove** from `SeDenyNetworkLogonRight` — all eleven `Tier2*` entries; the Tier 2 PAW denies none
of them there.

**Do not touch `SeDenyBatchLogonRight` or `SeDenyServiceLogonRight`.** Mirroring would remove
`Tier2ServiceAccounts`, i.e. permit a Tier 2 service account to run a service on a PAW. The
mirror rule is a convenience for the three logon rights; it is not a principle, and keeping a deny
is never the less safe choice.

Then, in `config/tiermodel-authsilos.json`, add `Tier1PAWDevices` to
`allowedToAuthenticateFromDeviceGroups` of `*- Tier 2 Authentication Policy` — otherwise lock 1 is
open and lock 2 is still closed, and Tier 2 accounts silently fail to authenticate from the shared
PAW.

**Never changed, in any variant:** `Tier0Admins`, `Tier0Operators`, `Domain Admins` and
`Enterprise Admins` stay in the deny lists of every Tier 1 and Tier 2 machine. That is the line.

The Tier 2 PAW OU and its GPO stay deployed and unused. They cost nothing, and the boundary can be
re-established later without redeploying.

---

## 4. Decision 2 — where the PAWs run

### Tier 1 and Tier 2 as Azure Virtual Desktop: yes

Under variant A this introduces no inversion, and the reason is worth stating because it is easy
to get wrong: **variant A has already declared Tier 1 and Tier 2 to be one trust level.**
Administering Tier 1 from a Tier 2 device is therefore inside a level, not across a boundary.

The gains are real: no administrative tooling or data on the endpoint, reverse-connect transport
(no inbound RDP, no published port), central management, and a rebuild measured in minutes.

Configurationally the session host is unremarkable: a computer object in the PAW device OU, member
of the corresponding device group, covered by the silo. `SeRemoteInteractiveLogonRight` is already
granted to `Administrators` and the tier's operators on every PAW GPO, so RDP is anticipated. It
requires AD DS join, hence network line of sight to domain controllers.

### Tier 0 as Azure Virtual Desktop: only under two conditions

An AVD session host is an Azure VM. Whoever holds the subscription holds the machine — Run
Command, VM extensions, disk snapshot, local administrator reset — and the AVD agent runs as
SYSTEM taking instruction from the Azure control plane. That is remote code execution by design,
bounded only by Azure RBAC.

Hosting the Tier 0 PAW there makes **Entra ID and Azure RBAC a Tier 0 dependency of on-premises
Active Directory**, and section 2 already noted that the silos do not reach cloud authentication
paths.

The honest counter-argument, which applies to most small organisations: if the environment already
runs Microsoft 365, **Entra ID is already the higher control plane**, above on-premises AD. AVD
then uses a dependency that exists rather than adding one. Whether that holds is decided by one
thing:

| Entra privileged access | Verdict |
|---|---|
| PIM, phishing-resistant MFA, no standing Global Administrators | Defensible — the risk profile barely moves |
| Standing Global Administrator, SMS or push MFA | A downgrade presented as modernisation |

Answer that before the AVD decision, not after.

### Non-negotiable for a Tier 0 session host

1. **No multi-session.** Windows Enterprise multi-session places several administrators in one OS
   instance. Personal host pool, 1:1, persistent.
2. **No FSLogix on Azure Files with storage key access enabled.** The key bypasses every AD
   permission, and the profile holds RDP history, browser state and credential artefacts.
3. **Redirection off** — drive, clipboard, USB, printer — in the host pool's RDP properties.

---

## 5. Decision 3 — the endpoint

This is where scoping conversations stall: dedicated administrative hardware is said to be
unrealistic. The objection is legitimate and the requirement it rejects is misstated.

### The requirement is a device state, not a device count

> **No untrusted code may run on the machine from which Tier 0 is administered.**

Two devices are the cheapest and most auditable way to guarantee that state. They are not the
requirement. Microsoft's Enterprise Access Model frames the same thing as a progression of device
states — Enterprise, Specialized, Privileged — rather than a count.

### Three ways to satisfy it

| | Covers | Does not cover | Price |
|---|---|---|---|
| **Two devices** | everything | — | one device per administrator, typically €300–600 for a small form-factor PC on a KVM |
| **The laptop becomes the Tier 0 device; everyday work moves into the AVD session** | everything — the direction is correct | nothing structural | no hardware; ongoing discipline |
| **Boot separation** — one machine, two Windows installations, never concurrent, separate BitLocker keys | the software boundary | **shared firmware and UEFI** — an implant there crosses. Microsoft withdrew the dual-boot PAW for this reason | a reboot per tier switch, which is why it fails in practice |

### The middle option in detail, because it costs nothing extra

```
Physical laptop      =  Tier 0.  Windows, administrative tooling, nothing else.
Tier 1/2 AVD session =  Everyday. Mail, Teams, Office, browsing, ticketing.
```

Everyday work moves into the session that section 4 builds anyway. The direction rule holds, the
state requirement is satisfiable, and the untrusted workload is the one that gets contained rather
than the privileged one.

Enforced on the laptop: no local administrator for the user; App Control (WDAC) in enforcement
with a managed allowlist; ASR rules; Defender for Endpoint; no mail client and no Office; a
browser restricted by allowlist to administrative portals, with general browsing only in the
session; passkey plus token binding (section 6).

**The honest price: this is more expensive to operate, not less.** It trades a one-time hardware
cost for permanent discipline. WDAC in enforcement means every new tool needs a rule. The
recurring failure point is always the same — a driver or utility from a vendor site, and the
allowlist is bypassed "just this once". That needs a defined path (download in the session,
verification, controlled transfer), or the control decays within months.

So this option answers *"no budget for hardware"*. It does not answer *"no capacity for
discipline"*. Where neither exists, see section 9.

### What cannot be argued away

**The same OS instance for untrusted work and for Tier 0.** No passkey, MFA, EDR or Conditional
Access configuration changes this, because **a single Tier 0 session is sufficient for permanent
access** — an account added to `Domain Admins`, an ACE on the domain root, a GPO, `krbtgt`
material — and that access is thereafter decoupled from any authentication.

*Where* the separation runs is negotiable. *That* it exists is not.

---

## 6. Authentication

Passkeys (FIDO2 / phishing-resistant credentials) belong on every path into a PAW, internal and
external. They are necessary and they are not sufficient, and the boundary between those two is
precise.

| Eliminates | Does not eliminate |
|---|---|
| a password to capture — the private key does not leave the authenticator | input injection into the open session |
| phishing and AitM proxying — the assertion is origin-bound | screen capture |
| reuse from attacker infrastructure | **token theft after authentication** |
| persistence of the credential | an attacker who simply waits until you are signed in |

**Token binding is mandatory, not an enhancement.** A passkey secures the sign-in; what remains in
memory afterwards is an ordinary bearer token. Without device-bound sessions (Entra token
protection or equivalent) half the benefit is given back at the door.

With both in place, the attack changes shape: from *steal the credential, use it anywhere, later*
to *be present on the compromised device while the administrator works*. That is materially more
expensive, noisier, and hard to automate at scale. It removes the dominant real-world attack class
against administrative access.

**For Tier 1 and Tier 2 that time-bounding is a genuine reduction. For Tier 0 it is not**, for the
reason in section 5: one session is enough, and permanence survives the session.

---

## 7. External service providers

### The structural position

Once administration is performed from outside, the customer's domain security is **bounded** by the
service provider's — not supplemented, bounded. And the provider's administrative platform is Tier
0 of every customer it serves, simultaneously. A provider therefore needs its own tier model, with
the administrative environment separated from the ticketing, mail and browsing environment.

### What the tool already settles

The silo answers *from where may an external administrator be Tier 0* as a technical fact rather
than an undertaking (section 2, lock 2). The question then narrows to exactly one thing: **which
computer object is in `Tier0PAWDevices`?**

### The chain — two links solving different problems

```
clean administrative device        PAW inside the                Tier 0
(service provider)           →     customer network        →     of the customer
solves: the input path             solves: enforcement (silo)
(keyboard, screen)                 and verifiability
```

The provider's clean device solves the input problem but cannot be the enforcement point, because
the customer cannot inspect it. The customer-side PAW is inspectable and carries the silo, but it
does not help if the input arrives from a compromised machine. Neither link substitutes for the
other.

**Exception worth knowing:** for a single large customer, the provider's device can itself be
joined to that domain and placed in `Tier0PAWDevices` — one hop instead of two, and the customer
can see and remove it. This does not scale across twenty customers, which is what the two-link
chain is for.

### Accounts

Named per-technician accounts in the customer's directory. Never shared accounts — no log
reconstructs who acted afterwards. A trust or federation to the provider's own directory makes the
provider's Tier 0 directly the customer's Tier 0, and needs a much better reason than convenience.

### The one requirement beyond the internal standard: tenant separation

An internal administrator's PAW is Tier 0 of one domain. A provider's administrative device is
Tier 0 of many — a bridge between customers that no customer agreed to, and the pattern behind the
well-known managed-service compromises. It is not a hardening problem: the device can be perfectly
configured and still have this property.

What addresses it is separation *within* the clean environment: separate sessions or profiles per
customer, no credential caching, no cross-customer credential store.

With that in place the economics invert in the provider's favour — fifteen technicians, fifteen
devices, across every customer served, makes clean separation **cheaper per customer** than in-house.
Without it, the scale effect becomes the scale damage.

### Processes that are missing more often than the technology

- **Offboarding tied to the provider's HR process** — a departing technician's accounts disabled at
  every customer the same day, by defined procedure rather than by notification.
- **Logging to the customer as well**, not only to the provider. The party being audited should not
  be the sole custodian of the audit data.
- **Break-glass held by the customer** — at least one Tier 0 account the provider does not have, in
  a safe, documented, tested annually. Without it the customer has no agency when the provider
  fails, is compromised, or the relationship ends.

### Inventory this before any PAW discussion

RMM, backup, monitoring and patching agents run as SYSTEM on every server and endpoint, driven
from a central console. That console is effectively Domain Admin on every customer, permanently,
and no PAW architecture touches it. This is the path by which ransomware arrives at scale — not
stolen technician passwords.

**A backup service account holding Domain Admin defeats variant A, B and C equally.**

---

## 8. Assurance across an organisational boundary

A customer cannot inspect a service provider's workstation. That is a real limit and should not be
talked around. But it is smaller than it first appears, and it is locatable.

| | Inspectable by the customer |
|---|---|
| The customer-side PAW — computer object, silo membership, applied GPOs, LAPS, logon records | **yes** |
| The state of the technician's endpoint | **no** |

Everything else follows from putting the PAW on the customer's side. The residual is one line long,
which means it can be written into a risk assessment instead of standing as a diffuse act of faith.

**Narrowing it, where Entra is present:** cross-tenant access settings let the customer require and
evaluate device-compliance and MFA claims from the provider's tenant. The customer still relies on
that claim being truthful — but it is an enforced signal rather than an assurance, and a false one
is a demonstrable misstatement rather than a misunderstanding. On-premises-only environments have
no equivalent; there the customer-side PAW carries it alone.

**The certification question almost nobody asks:**

> **Is the administrative environment inside the scope statement?**

Many provider certifications cover the data centre and the managed-services platform and exclude
the workstations from which customer systems are administered — which is precisely the question at
issue. That is the line to read in the certificate.

### Shift from prevention to visibility

Prevention on someone else's hardware is not inspectable. So the assurance moves to where it is —
the customer's own equipment:

| Control | Runs on | Inspectable by customer |
|---|---|---|
| Session recording on the PAW | customer device | yes |
| Logs to the customer's SIEM | customer infrastructure | yes |
| Just-in-time elevation with customer approval | customer directory / process | yes |
| Break-glass held by the customer | customer safe | yes |
| Four-eyes on destructive operations | process | yes |
| State of the technician's endpoint | provider | **no** |

None of this prevents the attack. It makes it visible and bounded, using controls the customer
operates and can verify at any time. That is how assurance across an organisational boundary is
achieved everywhere else: not by inspecting the counterparty, but by making outcomes evidential on
your own side.

For a provider, offering that inspectability voluntarily is a differentiator rather than a
concession. In a tender, the firm working from a ticketing laptop with a shared account looks
identical to one doing it properly — until someone asks for evidence.

---

## 9. What this document does not claim

- **None of this is measured.** Section 2 is read out of `config/` and cited; sections 3 to 8 are
  architectural judgements. Cost figures, "the usual case" and market observations are opinions
  stated as such.
- **No variant here has been deployed and verified.** Every figure published in this repository
  comes from a single-domain-controller green-field laboratory. Variants A and C, the AVD topology
  and the merged Tier 1/2 PAW have not been built and audited end to end.
- **The configuration changes in section 3 are described, not supplied.** They belong in a
  customer's configuration. This repository's `config/` is unmodified — its purpose is language
  support, not topology variants.
- **Residual risk is named, not resolved.** Where an option is weaker, section 5 says what it does
  not cover. An accepted residual risk belongs in writing in the customer's documentation; it does
  not become an architecture by being deployed.

---

## Related reading

- [`production-rollout-runbook.md`](production-rollout-runbook.md) — deploying into a populated,
  multi-DC production domain
- [`auth-silos-operations-guide.md`](auth-silos-operations-guide.md) — deploying, auditing and
  enforcing Authentication Policy Silos, including the pre-enforcement checklist
- [`gpo-management-guidance.md`](gpo-management-guidance.md) — baseline selection and the SOE
  override model
- [`best-practices.md`](best-practices.md) — hardening that sits beside the tier boundary rather
  than inside it
