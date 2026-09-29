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
derived from them — section 9, on the cloud control plane, is outside this tool's scope entirely
and rests on no file here. Section 9 says so again, because the two get confused when a document is
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

The opposite reduction — **one PAW for Tier 0 and Tier 1**, the context chosen at logon — is its
own document, because it adds a door into a Tier 0 device rather than merging two lower tiers:
[`shared-paw-tier0-tier1.md`](shared-paw-tier0-tier1.md).

### Decision 1b — where to enforce the silos

Deploying the silos and *enforcing* them are separate decisions, and the second one has a different
answer in a small organisation than in a large one. Both arguments get stronger here, which is
counter-intuitive and worth unpacking.

**What makes silos easier in a small environment:**

| | Enterprise | Small organisation |
|---|---|---|
| Privileged accounts to maintain | hundreds, constant churn | **two to five** |
| Approved origin devices | hundreds of servers, moving | **the DCs, one or two servers, a PAW** |
| Maintenance | needs `optional/Update-TierModelMembership.ps1` as a scheduled task on a writable GC domain controller, PowerShell 7, a mandatory exclusion decision | **by hand, three commands** |

That is the actual simplification: at this size the reconciliation script is unnecessary. It exists
for a scale that is not present, and direct policy assignment on a handful of accounts is both
simpler to reason about and simpler to reverse. The guide already recommends choosing one model per
account rather than stacking direct assignment and silo membership.

The deeper argument: **a small organisation has no security operations centre.** Nearly every other
control in this stack requires somebody to notice something. A silo notices nothing — it declines.
A control the domain controller enforces with no human in the loop is exactly what suits an
organisation that cannot watch.

**What makes them harder here:** the blind spots from section 2 are the small-environment
landscape. NTLM, LDAP simple bind, RADIUS/NPS, cached logon — the old NAS, the legacy line-of-
business application, the VPN. Under enforcement, NTLM that cannot satisfy the policy can be
rejected and logged as Event 101, **with no Event 305 warning beforehand**. And the audit period
runs for weeks; if nobody triages Event 305, the outcome is either never enforcing (the silos are
decoration) or enforcing blind (an outage nobody can diagnose).

> Silos are cheap to deploy and expensive to **operate correctly**. The operating cost is the
> disciplined audit period, and that is precisely what tends to be skipped at this size.

**Recommendation:**

| | |
|---|---|
| Deploy all 4 policies and 4 silos, audit mode | **yes, always** — it costs nothing and starts the clock, and weeks of observation cannot be back-dated |
| Assign the policy to Tier 0 accounts, by hand | **yes** |
| Enforce **Tier 0** after a clean audit period | **yes** |
| Enforce Tier 1 / Tier 2 / Tier 2 EUD | **no**, not at this size |

Tier 0 enforcement is a handful of accounts against a handful of enumerable devices: the largest
gain and the smallest, most predictable blast radius. Tier 1 and Tier 2 are where the service
accounts, legacy applications and NTLM paths live — dozens of systems, none of them inventoried —
and the gain over the URA deny lists is small against a large outage risk. Tier 2 EUD is the least
controlled device class of all and its policy does not even shorten the TGT lifetime.

Three things are owed before enforcing Tier 0 at this size, because there is no second team to call:
break-glass tested beforehand (never assign a policy to RID 500), the positive control run, and a
rehearsed rollback — `Enforce = false` on the silo **and** the policy, both.

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
discipline"*. Where neither exists, see section 10.

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

## 9. The cloud control plane

Everything above assumes the thing being administered sits in a server room. For most
organisations of this size the more valuable control plane is a Microsoft 365 tenant, and the
question that arrives with it is: *a PAW is supposed to have no internet access — but
administering the tenant **is** internet access.*

### 9.1 "No internet" was never the rule

The rule is the one from section 5: no untrusted code on the machine from which administration
happens. "No internet" is a coarse proxy for it — it means arbitrary browsing, mail, downloads.
Administering a tenant is HTTPS to a small, named, enumerable set of Microsoft endpoints. That is
not internet access in the sense the rule intends.

The implementation is therefore an **egress allowlist, not an internet ban**: the PAW reaches
`login.microsoftonline.com`, the Entra, Microsoft 365, Azure, Defender and Purview admin portals,
`graph.microsoft.com` and the endpoints in Microsoft's published 365 URL/IP list. Nothing else. No
mail client, no browser extensions, no profile sync, no password manager with cloud
synchronisation.

That resolves the apparent contradiction. What follows is the part that is genuinely harder than
the on-premises case.

### 9.2 What actually changes: there is no network boundary

On premises, a Tier 0 PAW can be isolated at the network layer. A domain controller is reachable
only from the network it sits in.

A tenant is reachable from anywhere on earth by anyone holding the credential. No firewall, VLAN or
site boundary applies. Which produces the single most important sentence for this section:

> **Conditional Access replaces the authentication silo. It is the only control that answers
> "from where may this account administer".**

| On premises | Microsoft 365 |
|---|---|
| `allowedToAuthenticateFromDeviceGroups` — Kerberos declines to issue the TGT | Conditional Access — *this role, only from a compliant device with phishing-resistant MFA* |
| Lock 2 of 2 (logon rights are lock 1) | **Lock 1 of 1** |

And because it is the only lock: **Conditional Access policies are themselves Tier 0 objects.** Who
may edit them is the real control question. A CA misconfiguration is the equivalent of an open
firewall rule, minus the network diagram on which somebody would have noticed it. Gate the roles
that can change CA behind PIM with approval, and alert on policy changes.

### 9.3 Identity

Four items. Three of them are routinely skipped.

1. **Cloud-only administrative accounts** (`adm-…@tenant.onmicrosoft.com`), **not** synchronised
   from on-premises AD. A synchronised admin account falls with the on-premises directory. This is
   the only way to break the dependency direction, and it is Microsoft's own guidance.
2. **Phishing-resistant MFA** — FIDO2/passkey or certificate. Not push, not SMS. With token
   binding, for the reason in section 6: the passkey secures the sign-in, what remains afterwards
   is an ordinary bearer token.
3. **PIM — no standing Global Administrator.** Time-bound activation, with approval and
   justification. A permanent Global Administrator is a finding, not an operating model.
4. **Break-glass:** two emergency accounts, cloud-only, deliberately excluded from Conditional
   Access, long random credentials in a safe, **alerting on use**, tested annually. Identical in
   role to the customer-held break-glass account in section 7, and for the same reason: whoever
   locks themselves out has no agency left.

### 9.4 The blind spot — this is section 7's agent problem, in the cloud

For a service provider it was the RMM agent running as SYSTEM. In a tenant it is the **service
principal**.

An app registration holding `RoleManagement.ReadWrite.Directory` or `Application.ReadWrite.All` is
effectively Global Administrator — with no user, no MFA, and ordinary user-scoped Conditional
Access does not apply to it. No PIM. Often a client secret that is valid for years and belongs to
nobody in particular.

This is the path taken by the well-known tenant compromises, and it is skipped in most hardening
conversations because it appears in no role report.

- Disable user consent, or restrict it to verified publishers with low-risk permissions, and route
  the rest through an admin consent workflow.
- Inventory every app role assignment carrying high Graph permissions — **recurring**, not once.
- Track secret and certificate lifetimes on service principals.
- Apply workload-identity Conditional Access where licensed; at minimum bind the critical service
  principals to a location.

### 9.5 Dependency direction — this decides whether you have two tiers or one

| Configuration | Consequence |
|---|---|
| Administrative accounts synchronised from AD | on-premises compromise ⇒ tenant compromise |
| Cloud management reaches Tier 0 systems (DCs in Intune, Azure Arc, Autopilot) | tenant compromise ⇒ on-premises compromise |
| **Both** | **there is one tier**, whatever the diagram says |

And one server almost nobody classifies: **the Entra Connect server is Tier 0 on both sides.** It
holds directory synchronisation rights in AD and a service principal in the tenant. Treat it like a
domain controller, not like an application server.

**Design decision:** cloud-only administrative accounts, and do not extend cloud management onto
on-premises Tier 0 systems. Then there really are two planes. Otherwise there is one — which is not
a failure, but it has to be known and written down rather than assumed away.

### 9.6 For a small organisation: one PAW, two control planes

> **The same Tier 0 PAW administers the on-premises directory and the tenant.** The egress
> allowlist gains the Microsoft administrative endpoints; nothing else changes.

No inversion, because both control planes are Tier 0. And in nearly every tenant of this size the
two are already coupled through Entra Connect and cloud-managed endpoints — they are already **one**
trust level. Splitting them across two devices then draws a boundary that does not exist, which is
worse than an honest shared one.

The recommendation from section 5 is therefore unchanged. The clean device simply does more.

### 9.7 The Conditional Access set

In order of effect:

| # | Policy |
|--:|---|
| 1 | **Block legacy authentication**, tenant-wide. Without it everything below is bypassable |
| 2 | **Administrative roles → phishing-resistant MFA + compliant or hybrid-joined device.** Target the admin portals *and* the directory roles themselves |
| 3 | **Block the device code flow.** Underrated — device-code phishing bypasses the device requirement entirely |
| 4 | **Token protection** for administrative sign-ins, with continuous access evaluation |
| 5 | Session controls: no persistent browser session, short sign-in frequency for administrative roles |
| 6 | Break-glass accounts excluded — **and alerted on** |
| 7 | MFA for all users, not only administrators |
| 8 | Workload identities: location binding for the critical service principals |

**Before enforcing any of it:** report-only mode first, and use the what-if evaluator. A policy that
locks out the administrator is the one mistake in this list that cannot be undone from inside —
which is what item 6 exists for.

### 9.8 Delegated administration by a service provider

Section 7 applies unchanged, with one substitution: **the enforcement point is Conditional Access
and delegated role assignment (GDAP), not the Kerberos silo.** Granular delegated administration is
role-scoped and time-bound, which is a genuine improvement over what preceded it — but the
structural position is identical. The partner tenant's compromise reaches the customer tenant, so
the partner's administrative platform is the customer's control plane, and the customer-side
controls that remain inspectable are the same ones: logging into the customer's own tenant,
approval on elevation, break-glass the partner does not hold.

The one cloud-specific addition: **review the partner's delegated role assignments on a schedule
and let them expire.** A relationship that ended and a delegation that did not is the cloud
equivalent of an account nobody offboarded.

### 9.9 A caveat specific to this section

Product names, licensing tiers and portal locations in this area move quickly. The architecture
above does not depend on them, but the individual switches do — verify each against current
Microsoft documentation before building, not against a document of this age.

---

## 10. What this document does not claim

- **None of this is measured.** Section 2 is read out of `config/` and cited; sections 3 to 9 are
  architectural judgements. Cost figures, "the usual case" and market observations are opinions
  stated as such. Section 9 rests on no file in this repository at all — the tool does not touch a
  tenant — and carries its own caveat at 9.9.
- **No variant here has been deployed and verified.** Every figure published in this repository
  comes from a single-domain-controller green-field laboratory. Variants A and C, the AVD topology,
  the merged Tier 1/2 PAW and the shared Tier 0/Tier 1 PAW (`shared-paw-tier0-tier1.md`) have not
  been built and audited end to end.
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
