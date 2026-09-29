# Shared administration hosts — one set per tier, used by every administrator over RDP

A pattern for small organisations, and for environments operated by a managed service provider,
where a privileged access workstation *per administrator* is not practical. Instead, each tier gets
**one or more administration hosts**, shared by every administrator of that tier and reached over
RDP. The administrator chooses the context deliberately: the **Tier 0 account on a Tier 0 host**
for directory work, the **Tier 1 account on a Tier 1 host** for server work. People who hold only a
Tier 1 account — typically the provider's technicians — only ever reach the Tier 1 hosts.

**The principle: the device class stays, the device count goes.** A shared administration host is a
PAW in every respect the tool knows about. It sits in the tier's PAW device OU and device group, and
it receives exactly the GPOs, logon rights and authentication policy the shipped configuration
already defines for PAWs. What changes is how many there are and how people reach them — and that
change has consequences this document names rather than argues away.

**What is measured and what is not.** Section 1 is read out of `config/` and cited. Sections 2–8
are the design derived from it and architectural judgement. **Nothing here has been deployed and
audited end to end**; section 9 is the acceptance test that has to run on the first host of each
tier before anyone relies on it.

**Nothing here changes the tool or this repository's `config/`.** The pattern needs no change to
the shipped PAW configuration at all (section 1); the optional additions in section 7 are edits in
the *customer's* copy.

---

## 1. What the shipped configuration already provides

| Fact | Consequence | Source |
|---|---|---|
| Tier 0 PAW: `SeRemoteInteractiveLogonRight` = `Administrators`, `Tier0Operators`; local `Administrators` = `Tier0Admins`, `Domain Admins`; `Remote Desktop Users` = `Tier0Operators`. Tier 1 PAW the same with `Tier1Admins`, `Tier1Operators` | RDP works in both contexts without a change | `config/tiermodel-gpos.json`, `*- Tier 0 PAWs Account Restrictions`, `*- Tier 1 PAWs Account Restrictions` |
| The Tier 0 PAW denies every `Tier1*` and `Tier2*` group; the Tier 1 PAW denies every `Tier0*` group, `Domain Admins`, `Enterprise Admins`, `Schema Admins` and the other Tier 0 built-ins | **The wrong account on the wrong host is a refused logon**, enforced by the tool, not by discipline | same GPOs, `SeDeny*LogonRight` |
| `*- Tier 0 Authentication Policy` issues TGTs only from `Domain Controllers`, `Read-only Domain Controllers`, `Tier0MemberServers`, `Tier0PAWDevices`; the Tier 1 policy from `Tier1MemberServers`, `Tier1PAWDevices` | A host in the tier's PAW device group is an approved origin device | `config/tiermodel-authsilos.json` |
| The PAW device OUs carry the **Windows 11 client baselines** (`MSFT Windows 11 25H2 - Computer`, `- BitLocker`, `- Credential Guard`, `- Defender Antivirus`) plus `MSFT Windows Server 2025 v2506 - Domain Security` | A Windows 11 Enterprise host matches exactly; a Windows Server host would receive client baselines (section 2) | `tiermodel-gpos.json`, `OU=Tier 0 PAW Devices` / `OU=Tier 1 PAW Devices` |
| `PAW BitLocker` *allows* TPM-only startup — a PIN is allowed, not required | Works on a virtual machine with a virtual TPM | `config/gpo/common/PAW BitLocker` report, *Require additional authentication at startup* |
| `*- Tier 0 PAWs SOE - Computer` sets *Restrict delegation of credentials to remote servers* and denies removable storage; the Credential Guard baseline is linked | Outbound RDP from the host uses Restricted Admin / Remote Credential Guard; Credential Guard needs virtualisation-based security (a generation 2 VM with a virtual TPM) | `config/gpo/common/PAW Computer SOE` report |
| `PAW Internet Access` is a **user-level** proxy setting | Browsing from an administrative session is constrained; services running as `SYSTEM` (updates, EDR, agents) are not affected by it | `config/gpo/common/PAW Internet Access` report |
| `Tier1Admins` holds `GenericAll` on `OU=Tier 1 PAW Devices` | Tier 1 manages its own hosts — within one tier | `config/tiermodel-acls.json` |
| A **new** `mode: create` GPO is created and linked by any later run; only an **existing** GPO is never reconfigured | The optional additions in section 7 do not have to precede the first deployment | `Get-TierModelGpo.ps1:672`, self-heal branch after `:746` |

---

## 2. Platforms — the tool's rules are the same on all three

| Platform | Sessions | Fits the linked baselines | Additional Tier 0 dependency |
|---|---|---|---|
| **Windows 11 Enterprise**, VM or PC — the default | one at a time; a second RDP logon displaces the first, so the host is shared *sequentially* | yes, exactly | whoever controls its hypervisor, VM management and backup |
| **Windows Server** | *Remote Desktop for Administration* allows two concurrent sessions; more needs the RD Session Host role and client access licences — check licensing | **no** — the client baselines on a server are untested (test B9) | hypervisor, VM management, backup |
| **Azure Virtual Desktop** — pooled, Windows 11 Enterprise multi-session, AD DS-joined | many concurrent sessions | yes | **Entra ID and Azure RBAC** — see section 8 |

**For every platform: whoever controls the virtualisation, the backup or the subscription of the
Tier 0 hosts is Tier 0.** Run Command, a snapshot, a disk copy, a console session on the
hypervisor — each is full control of every session on the host. An on-premises host avoids the
Entra dependency; it does not avoid the hypervisor. Put the Tier 0 hosts on a virtualisation layer
that only Tier 0 administers, or accept in writing that the virtualisation layer is Tier 0.

---

## 3. The deliberate context

- **One account per person per tier.** No shared accounts — not for the provider either. A shared
  host is acceptable; a shared identity destroys the accountability the whole model rests on.
- **Hosts named and marked by tier.** A host name that states the tier, a distinct desktop
  background per tier, a logon message naming the device class.
- **One connection per tier.** A separate RDP connection file or workspace for "Tier 0
  administration" and "Tier 1 administration", so that choosing the context is choosing the
  connection and the account together.
- **A mistake is a refusal, not a boundary crossing.** Section 1, row 2: the Tier 0 account on a
  Tier 1 host and the Tier 1 account on a Tier 0 host are both denied by the logon rights the tool
  deploys.

---

## 4. The RDP client — where this pattern is weakest

**Whoever controls a Tier 0 session over RDP turns the client device into a Tier 0 device in
fact.** Keyboard, screen and clipboard of the session pass through it. This is the price of not
having a device per administrator, and it is paid on the client, not on the host.

It also meets the Tier 0 authentication policy head on:

- With a direct RDP connection and Network Level Authentication, the **client** requests the
  Kerberos ticket for the user. Under an *enforced* Tier 0 policy, that request comes from a device
  outside `Tier0PAWDevices` and is refused.
- The connection may then still succeed through an **NTLM fallback**. Authentication policies do
  not constrain NTLM (`auth-silos-operations-guide.md:271-272`), so the enforced policy would look
  effective and not be.
- With the Tier 0 accounts in **Protected Users**, which forbids NTLM, the connection would fail
  altogether.

None of this is measured. Tests B5 and B6 measure it, and the choice below follows from them:

| Option | What carries the boundary | Cost |
|---|---|---|
| **(a)** Add the administrators' client devices to the Tier 0 policy as their own device group, and hold them to the Tier 0 device standard | both locks, honestly | that is one Tier 0 device per administrator again |
| **(b)** Leave the Tier 0 policy in audit mode | lock 1 (logon rights) and the client standard below | the Kerberos lock is not enforced; Event 305 still shows every deviation |
| **(c)** Azure Virtual Desktop, where the session host — not the client — authenticates the user to the domain | both locks, if B5 confirms it for this path | Entra ID and Azure RBAC become Tier 0 dependencies (section 8) |

Recommendation: run B5 and B6 first, then choose **(b)** or **(c)** deliberately and in writing.

**The minimum for every client that opens a Tier 0 session**, whichever option:

- managed, fully patched, with EDR; the user is not a local administrator on it;
- phishing-resistant MFA at the entry point — an RD Gateway with MFA on premises, Conditional
  Access for Azure Virtual Desktop;
- drive, clipboard, printer and USB redirection off, enforced on the host side (section 7);
- Restricted Admin or Remote Credential Guard where the target supports it.

---

## 5. Multi-session, placed honestly

`smb-reference-architecture.md` §4 rules out multi-session for a Tier 0 session host, because it
puts several administrators into one operating system instance. With one host set per tier, the
administrators sharing an instance are **peers of the same tier**, which is why this pattern accepts
it — as a deliberate deviation, with the residual risk written down:

- **Session takeover.** A local administrator can take over another user's session on the same
  host, running as `SYSTEM`. On a Tier 0 host every `Tier0Admins` member is a local administrator
  (section 1, row 1). Credential Guard protects the logon secrets in LSA; it does not protect a
  session.
- **One compromised session reaches every concurrent session on the host.**

What reduces it:

- disconnected sessions end after a few minutes; an idle limit ends forgotten ones;
- local profiles are deleted at logoff; no FSLogix profile containers on a share reachable with a
  storage key;
- hosts are rebuilt on a schedule (drain, reimage, rejoin);
- EDR on every host;
- optionally, administrators do not log on as local administrators: grant their tier's admin group
  logon and `Remote Desktop Users` membership instead of local `Administrators`. That is a
  customer-configuration change to the PAW `restrictedGroups`, and it only helps for accounts that
  are not members of `Domain Admins`, which reach the host's `Administrators` group anyway.

A Windows 11 Enterprise host (section 2) is single-session, so none of this section applies to it.
That is the other reason it is the default.

---

## 6. Application control — optional

AppLocker enforcement on the PAW OUs ships link-disabled (`*- Tier 0 PAWs Devices Base AppLocker -
Enforcement`, `linkEnabled: false`) and stays optional here. Enabling it is a `Set-GPLink -LinkEnabled
Yes`; no deploy run enables a link (`production-rollout-runbook.md` §0).

Without it, the path to be aware of is **code in any session plus a local privilege escalation**,
which on a multi-session host reaches every other session. What compensates:

- no general internet access from the sessions (the proxy GPO in section 1);
- no mail client, no office suite;
- EDR;
- the rebuild schedule from section 5.

---

## 7. Optional additions to the customer configuration

Two placeholder GPOs, in the same pattern as the shipped `SOE` and `SHF` placeholders. The tool
creates and links them; their content is set in GPMC and is neither written nor checked by the tool,
so it survives every run. Append each to the `ImportOnlyGpo` array of its PAW device OU in the
customer's `config/tiermodel-gpos.json`. `linkOrder` 18 is the next free one in both OUs: the
`ImportOnlyGpo` entries there run to 17, and the account restrictions GPO holds 1.

```json
{
  "name": "*- Tier 0 PAWs Admin Host - Computer",
  "mode": "create",
  "gpoStatus": "UserSettingsDisabled",
  "linkOrder": 18,
  "linkEnabled" : true,
  "gpoComment": "",
  "comment": "Shared administration hosts: session limits, profile clean-up, logon message, host-side redirection off. Configured post-deployment in GPMC."
}
```

The Tier 1 entry is identical apart from the name, `*- Tier 1 PAWs Admin Host - Computer`, and it
goes under `OU=Tier 1 PAW Devices`. Content to set in GPMC:

| Setting | Value |
|---|---|
| Remote Desktop Session Host → Session Time Limits: *disconnected sessions* | a few minutes |
| … *active but idle sessions* | per operational need |
| … *End session when time limits are reached* | Enabled |
| Remote Desktop Session Host → Device and Resource Redirection | drive, clipboard, printer, COM, LPT, Plug and Play, smart card as needed — **off** |
| User Profiles: delete cached copies of roaming profiles, or delete profiles older than *n* days | as the platform allows |
| Interactive logon: message title and text | "Tier 0 administration host" / "Tier 1 administration host" |

Cost: 4 plan actions (a create and a link each). The only other customer-configuration change for
the rollout is the one that was already required: `linkEnabled: false` on the domain controllers'
Advanced Audit Policy (`production-rollout-runbook.md` §0.1).

---

## 8. Azure Virtual Desktop — only if chosen

- **Identities.** AD DS-joined session hosts serve users who exist in Entra ID as hybrid
  (synchronised) identities — verify against current Microsoft documentation. That makes Entra ID
  a Tier 0 dependency, and `smb-reference-architecture.md` §4 already states the condition under
  which that is defensible: privileged access in Entra with PIM, phishing-resistant MFA and no
  standing Global Administrator. The synchronised administrative accounts hold **no** Entra roles.
- **Conditional Access** for the Azure Virtual Desktop apps: phishing-resistant MFA, a device
  requirement — with an explicit decision for the provider's devices — and a short sign-in
  frequency.
- **Single sign-on through Entra Kerberos** is expected to fail for members of privileged groups,
  because the password replication policy on its Kerberos server object denies them. The Tier 0
  context then signs in with a password. **Do not relax that policy** to make sign-on convenient.
- **Azure RBAC per pool.** Separate resource groups, better separate subscriptions. The provider
  receives eligible, time-bound access, and the activity logs stay in the customer's tenant.
- **Host pool RDP properties:** redirection off, screen capture protection and watermarking on.

---

## 9. Acceptance test on the first host of each tier

Deploy and verify as usual first: second run `Applied: 0 / Converged: True`, audit
`Drift 0 / Errors 0`, localization report `No problems found.` Then, with the first host joined
into its tier's PAW device OU and a member of `Tier0PAWDevices` or `Tier1PAWDevices`:

| # | Test | Expected |
|---|---|---|
| B1 | Tier 0 account over RDP to a Tier 0 host | logon succeeds |
| B2 | Tier 1 account over RDP to a Tier 1 host | logon succeeds |
| B3 | Tier 1 account to a Tier 0 host | refused (logon rights) |
| B4 | Tier 0 account to a Tier 1 host | refused |
| B5 | Tier 0 account over RDP from an ordinary client, Tier 0 policy assigned, audit mode | **record**: Event 305 on the DC or not; the authentication package in Event 4624 on the host (Kerberos or NTLM) |
| B6 | as B5, the account temporarily in Protected Users | **record**: succeeds or fails — decides section 4 (a)/(b)/(c) |
| B7 | Credential Guard running (`Win32_DeviceGuard`, `SecurityServicesRunning` contains 1); BitLocker on with a TPM protector | yes |
| B8 | a disconnected session ends at the limit; the profile is gone after logoff; redirection has no effect | yes |
| B9 | Windows Server hosts only: `gpresult /h` and the GroupPolicy event log after applying the client baselines | record what fails, if anything |
| B10 | who holds rights on the hypervisor, the backup and the subscription of the Tier 0 hosts | Tier 0 only; the provider time-bound |

Record the results. Until they exist, this pattern is a design, not a measurement.

---

## 10. What this pattern gives up, and what it keeps

- **Given up:** a device per administrator. The client that opens a Tier 0 session becomes part of
  Tier 0 (section 4), and on multi-session hosts peers share an operating system (section 5).
- **Kept:** the tier boundary as the tool enforces it. No Tier 1 identity logs on to a Tier 0 host
  and no Tier 0 identity to a Tier 1 host. The deny lists of every other machine are untouched.
  The Kerberos lock is available in full on hosts that authenticate users themselves.
- **Not measured:** everything in sections 2–9. The figures in this repository come from a
  single-DC green-field laboratory without any PAW computer object.
