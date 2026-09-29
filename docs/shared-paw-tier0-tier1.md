# One PAW, two contexts — sharing the Tier 0 PAW with Tier 1

A variant for small organisations: **one** privileged access workstation serves Tier 0 and Tier 1
administration, and the administrator chooses the context **deliberately, at logon** — the Tier 0
account for directory work, the Tier 1 account for server work. It is written for the case where
people who hold *only* a Tier 1 account (a service provider, a second administrator) use the same
device, and where the device is also reached over RDP.

**The principle everything below follows from: the device stays a Tier 0 device.** Tier 1 is a
guest on it with standard-user rights — never a local administrator, never able to manage who else
gets in. Nothing in this variant moves a Tier 0 boundary; it adds one narrowly scoped door into a
Tier 0 device and names who holds the key.

**What is measured and what is not.** Section 1 is read out of `config/` and cited. Sections 2–6
are the design derived from it. **None of it has been deployed and audited end to end** — section 7
is the acceptance test that has to run on the first device before anyone relies on it.

**Nothing here changes the tool or this repository's `config/`.** Every change is an edit in the
*customer's* copy of the configuration, in the same way as variant A in
[`smb-reference-architecture.md`](smb-reference-architecture.md) §3.

---

## 1. What the shipped configuration does today

| Fact | Source |
|---|---|
| Local `Administrators` on a Tier 0 PAW is **only** `Tier0Admins` and `Domain Admins`, enforced as a restricted group. `Remote Desktop Users` (`S-1-5-32-555`) is only `Tier0Operators` | `config/tiermodel-gpos.json`, `*- Tier 0 PAWs Account Restrictions`, `restrictedGroups` |
| The same GPO denies `Tier1Admins`, `Tier1Operators`, `Tier1ServerOperators`, `Tier1ServiceAccounts`, `Tier1VpnAccounts` and every `Tier2*` group interactive, remote-interactive, network, batch and service logon | same GPO, `userRightsAssignments` |
| `SeNetworkLogonRight` on the Tier 0 PAW is `Authenticated Users` | same GPO |
| **`Tier1Admins` holds `GenericAll` on `OU=Tier 1 Accounts` and on `OU=Tier 1 Groups`** — every Tier 1 administrator can reset any password and change any membership there | `config/tiermodel-acls.json` |
| `OU=Tier 0 Accounts` and `OU=Tier 0 Groups` carry no delegation; only `Tier0Admins` controls them, through `GenericAll` inherited from `OU=Tier Model Administration` | `config/tiermodel-acls.json` |
| The user-side GPOs of Tier 0 and Tier 1 import the **same** backups — `PAW Internet Access`, `MSFT Windows 11 25H2 - User`, `MSFT Internet Explorer 11 - User` | `importPath` of the `*- Tier 0 PAWs …- User` and `*- Tier 1 PAWs …- User` entries |
| `*- Tier 0 PAWs SOE - Computer` already sets *Restrict delegation of credentials to remote servers* (Restricted Admin / Remote Credential Guard for outbound RDP) and denies removable storage; `*- Tier 0 PAWs MSFT Windows 11 25H2 - Credential Guard` is linked | `config/gpo/common/PAW Computer SOE` report; `tiermodel-gpos.json` |
| `DontDisplayLastUserName` and `HideFastUserSwitching` appear in **none** of the 260 GPO backup files | searched, content decoded as both 8-bit and UTF-16 |
| `*- Tier 0 PAWs Devices Base AppLocker - Enforcement` ships `linkEnabled: false`; the audit-mode GPO is linked | `tiermodel-gpos.json` |
| Authentication policies are built as `Member_of_any` over the configured device groups; an additional policy in the configuration is created like the four shipped ones | `Build-TierModelAuthSddl.ps1`, `New-TierModelAuthPolicy.ps1:73` |

Two facts about the tool decide *when* this has to be done:

- **An existing GPO is never reconfigured.** The planner plans Configure for a GPO only when it
  does not exist, or when its policy folder is provably empty (`Get-TierModelGpo.ps1`, the
  self-heal branch after `:746`). Changing `userRightsAssignments` after the GPO exists does
  nothing on the next run.
- **An existing authentication policy is never modified** (`Get-TierModelAuthPolicyFd.ps1:11-12`).

Both audits compare against the configuration — GPO content at `Test-TierModelGPOAudit.ps1:266`,
policy SDDL at `Test-TierModelAuthPolicy.ps1:150` — so a change made *after* the deployment is
reported as drift that no deploy run repairs. **Put this variant into the configuration before the
first deployment run.**

---

## 2. Who may enter the Tier 1 context

Not `Tier1Admins` or `Tier1Operators` as a whole. A dedicated group, and a dedicated place for the
accounts in it:

| Object | Where | Why there |
|---|---|---|
| Group **`Tier0PAWSharedTier1Users`** | `OU=Tier 0 Groups` | Only Tier 0 can change who is in it. In `OU=Tier 1 Groups`, every Tier 1 administrator could add themselves (section 1, row 4) |
| Its member accounts | new OU **`OU=Tier 1 Shared PAW Accounts,OU=Tier 0 Accounts,OU=Tier 0,OU=Tier Model Administration`** | In `OU=Tier 1 Accounts`, every Tier 1 administrator could **reset the password** of an admitted account and log on to the Tier 0 device with it. Under `Tier 0 Accounts`, only Tier 0 manages these accounts |

The second row is the one that is easy to miss and the one that matters most. A group controlled by
Tier 0 whose members can be taken over by any Tier 1 administrator is not controlled by Tier 0.

In the customer's `config/tiermodel-ous.json`, **after** the `Tier 0 Accounts` entry (its parent has to exist first):

```json
{
  "name": "Tier 1 Shared PAW Accounts",
  "path": "OU=Tier 0 Accounts,OU=Tier 0,OU=Tier Model Administration",
  "protectFromAccidentalDeletion": true,
  "disableInheritance": false,
  "blockGpoInheritance": false,
  "comment": "Tier 1 accounts admitted to the shared Tier 0 PAW. Managed by Tier 0 only."
}
```

In the customer's `config/tiermodel-groups.json`, next to the other Tier 0 groups:

```json
{
  "name": "Tier 0 PAW Shared Tier 1 Users",
  "samaccountname": "Tier0PAWSharedTier1Users",
  "description": "Tier 1 accounts admitted to interactive and RDP logon on the Tier 0 PAWs, as standard users. Members must be located in OU=Tier 1 Shared PAW Accounts.",
  "groupscope": "Global",
  "groupcategory": "Security",
  "path": "OU=Tier 0 Groups,OU=Tier 0,OU=Tier Model Administration,{{DOMAIN_DN}}",
  "comment": "Shared Tier 0/Tier 1 PAW variant, docs/shared-paw-tier0-tier1.md"
}
```

The accounts stay Tier 1 in every other respect: they are members of `Tier1Admins` or
`Tier1Operators` for their server rights, carry a Tier 1 authentication policy, and are denied on
domain controllers and Tier 0 servers by those memberships exactly as before. The user-side GPOs
they inherit from `OU=Tier 0 Accounts` are content-identical to the Tier 1 ones (section 1, row 6).

---

## 3. Lock 1 — logon rights on `*- Tier 0 PAWs Account Restrictions`

In the customer's `config/tiermodel-gpos.json`, entry `*- Tier 0 PAWs Account Restrictions` under
`OU=Tier 0 PAW Devices,OU=Tier 0,OU=Tier Model Administration,{{DOMAIN_DN}}`, section
`PostConfigureGpo`:

| Right | Change |
|---|---|
| `SeInteractiveLogonRight` | **add** `Tier0PAWSharedTier1Users` |
| `SeRemoteInteractiveLogonRight` | **add** `Tier0PAWSharedTier1Users` |
| `SeDenyInteractiveLogonRight` | **remove** `Tier1Admins`, `Tier1Operators` |
| `SeDenyRemoteInteractiveLogonRight` | **remove** `Tier1Admins`, `Tier1Operators` |
| `SeDenyNetworkLogonRight` | **remove** `Tier1Admins`, `Tier1Operators` |
| `SeNetworkLogonRight` | **replace** `Authenticated Users` by `Administrators`, `Tier0Operators`, `Tier0PAWSharedTier1Users` |
| restricted group `*S-1-5-32-555__Members` | **add** `Tier0PAWSharedTier1Users` to `memberGroups` |

Why the removals are needed, and why they do not open the device to all of Tier 1:

- A deny always wins over an allow. An admitted account is also a member of `Tier1Admins` or
  `Tier1Operators`; as long as those are denied, the allow for the dedicated group never takes
  effect.
- Removing the deny does **not** admit a Tier 1 account outside the group, because that account
  has no *allow*: the interactive and remote-interactive allow lists stay `Administrators`,
  `Tier0Operators` and the dedicated group.
- The network deny is removed because RDP with Network Level Authentication requires network logon
  on the target. **That is to be confirmed on the first device, test V6.** The allow list for
  network logon is narrowed in the same change, so the removal again does not reach Tier 1 accounts
  outside the group. Narrowing it is a tightening of the shipped configuration and has its own
  test, V7.

**Unchanged, and this is the line:**

- local `Administrators` stays `Tier0Admins` and `Domain Admins`. A Tier 1 session on this device
  is a standard user;
- `Tier1ServerOperators`, `Tier1ServiceAccounts`, `Tier1VpnAccounts` and every `Tier2*` group stay
  denied on all five logon types;
- `SeDenyBatchLogonRight` and `SeDenyServiceLogonRight` are not touched at all.

**Two traps in the file.** The file writes `"linkEnabled" : true` with a space before the colon, so
a search for the usual spelling misses entries. And the file must be edited in an editor: a round
trip through `ConvertFrom-Json | ConvertTo-Json` rewrites the whole file.

---

## 4. Lock 2 — Kerberos

Add a **fifth** authentication policy to the customer's `config/tiermodel-authsilos.json`,
alongside the four shipped ones:

```json
{
  "name": "*- Tier 1 Shared PAW Authentication Policy",
  "description": "Authentication Policy for Tier 1 accounts admitted to the shared Tier 0 PAW. Restricts Kerberos TGT issuance to Tier 1 origin devices plus the Tier 0 PAWs, and lowers the Kerberos TGT lifetime to 4 hours (240 minutes).",
  "userTGTLifetimeMinutes": 240,
  "allowedToAuthenticateFromDeviceGroups": [
    "Tier1MemberServers",
    "Tier1PAWDevices",
    "Tier0PAWDevices"
  ],
  "enforce": false,
  "protectedFromAccidentalDeletion": true,
  "comment": "Assigned by hand, only to accounts in OU=Tier 1 Shared PAW Accounts. The shipped Tier 1 policy stays unchanged, so lock 2 is exactly as narrow as lock 1."
}
```

- **Do not** add `Tier0PAWDevices` to the shipped `*- Tier 1 Authentication Policy`. That would let
  every Tier 1 account obtain a ticket from the Tier 0 device, and lock 2 would be wider than
  lock 1.
- **The device stays in `Tier0PAWDevices` and in the Tier 0 silo**, never in `Tier1PAWDevices`.
- Assign the policy to each admitted account by direct assignment, as
  `auth-silos-operations-guide.md` describes for user accounts. The deployment enrols computers
  only.

---

## 5. Making the context deliberate

The tool deploys the boundary. The *deliberateness* of the context is a property of the logon
experience, and none of it exists in the shipped backups (section 1, row 8). Add two placeholder
GPOs to the customer configuration — `mode: create`, the same pattern as the shipped `SOE`
placeholders — and fill them in GPMC after the deployment:

| GPO (new) | Linked to | Settings |
|---|---|---|
| `*- Tier 0 PAWs Shared Context - Computer` | `OU=Tier 0 PAW Devices` (`ImportOnlyGpo`) | *Interactive logon: Do not display last signed-in* = Enabled, so every logon starts with choosing the account. *Hide entry points for Fast User Switching* = Enabled. Remote Desktop session time limits: disconnected sessions end after 1 minute, and the session ends when a limit is reached — **never two contexts on the device at once**. A logon message naming the device class: "Tier 0 device — choose your context" |
| `*- Tier 0 PAWs Shared Tier 1 Context - User` | `OU=Tier 1 Shared PAW Accounts` (new OU key) | A distinct desktop background or banner for the Tier 1 context. The Tier 0 context gets its own in the shipped placeholder `*- Tier 0 PAWs SOE - User` |

As configuration, in the customer's `config/tiermodel-gpos.json`: append the first entry to the
`ImportOnlyGpo` array of `OU=Tier 0 PAW Devices,OU=Tier 0,OU=Tier Model Administration,{{DOMAIN_DN}}`
with the next free `linkOrder` there, and add a new key for the second:

```json
{
  "name": "*- Tier 0 PAWs Shared Context - Computer",
  "mode": "create",
  "gpoStatus": "UserSettingsDisabled",
  "linkOrder": 18,
  "linkEnabled" : true,
  "gpoComment": "",
  "comment": "Shared Tier 0/Tier 1 PAW: deliberate-context logon settings, configured post-deployment in GPMC"
}
```

```json
"OU=Tier 1 Shared PAW Accounts,OU=Tier 0 Accounts,OU=Tier 0,OU=Tier Model Administration,{{DOMAIN_DN}}": {
  "ImportOnlyGpo": [
    {
      "name": "*- Tier 0 PAWs Shared Tier 1 Context - User",
      "mode": "create",
      "gpoStatus": "ComputerSettingsDisabled",
      "linkOrder": 1,
      "linkEnabled" : true,
      "gpoComment": "",
      "comment": "Shared Tier 0/Tier 1 PAW: Tier 1 context identification, configured post-deployment in GPMC"
    }
  ]
}
```

Both are linked enabled from the start. They are empty until filled in, and the OUs they are linked
to hold no objects on the day of the deployment.

Content in a `mode: create` GPO is not written by the tool and not checked by the audit, so it
survives every run. That is the reason it goes there and not into an imported GPO, which a self-heal
re-import would overwrite.

---

## 6. Rules that no configuration enforces

- **AppLocker enforcement before the first Tier-1-only person uses the device.** Enable the link
  of `*- Tier 0 PAWs Devices Base AppLocker - Enforcement` with `Set-GPLink -LinkEnabled Yes`
  (no deploy run enables a link, `production-rollout-runbook.md` §0). The realistic path from a
  Tier 1 session to Tier 0 is code running as that standard user plus a local privilege escalation
  to `SYSTEM` — after which the next Tier 0 logon on the device is exposed. Application control is
  what closes it.
- **The RDP client becomes part of the context.** Whoever reaches the device over RDP controls the
  session from their client.
  - The **Tier 0 context is used at the console**, or from another Tier 0 device. Once the Tier 0
    silo is enforced, an RDP logon from a device outside `Tier0PAWDevices` should fail anyway,
    because the ticket is requested by the client — test V8 checks this.
  - The **Tier 1 context over RDP** makes the client device part of the Tier 1 chain. Accept that
    in writing. Under the SMB recommendation, Tier 1 policies stay in audit mode
    (`smb-reference-architecture.md` §3, *Decision 1b*), so lock 2 does not constrain the client
    there.
- **No Azure Virtual Desktop for this device.** `smb-reference-architecture.md` §4 requires a
  Tier 0 session host to be personal, one-to-one and single-session. A host shared by several
  people across two contexts contradicts that. AVD for administration stays a separate decision,
  checked against current Microsoft documentation (§9.9 there).
- **Tier-1-only people are admitted by name.** The residual risk — console and RDP access to a
  Tier 0 device, as a standard user — is written into the customer's documentation, and membership
  of `Tier0PAWSharedTier1Users` is reviewed on a schedule.
- **A context switch is a logoff.** No files carried from one context to the other.

---

## 7. Acceptance test on the first device

Deploy and verify as usual first: second run `Applied: 0 / Converged: True`, audit
`Drift 0 / Errors 0`. The audit compares against the customer configuration, so it also covers
the changed logon rights and the fifth policy.

Then, with the first PAW joined into `OU=Tier 0 PAW Devices` and a member of `Tier0PAWDevices`,
the admitted accounts created in `OU=Tier 1 Shared PAW Accounts`, and the fifth policy assigned to
them:

| # | Test | Expected |
|---|---|---|
| V1 | Tier 0 account at the console | logon succeeds; `whoami /groups` shows `BUILTIN\Administrators` in the logon token |
| V2 | Admitted Tier 1 account at the console | logon succeeds; the account is **not** a local administrator (`net localgroup` on SID `S-1-5-32-544`) |
| V3 | Tier 1 account **not** in the group (in `OU=Tier 1 Accounts`) | logon refused |
| V4 | Tier 2 account; `Tier1ServerOperators` member | logon refused |
| V5 | Admitted Tier 1 account over RDP with NLA | logon succeeds |
| V6 | V5 with `Tier1Admins`/`Tier1Operators` put back into `SeDenyNetworkLogonRight` | refused — confirms that NLA needs network logon. If it succeeds, keep the network deny and drop that removal |
| V7 | `\\<paw>\c$` and `Enter-PSSession` as a Tier 1 account outside the group; Group Policy, Windows LAPS, Defender and updates on the device after the network-logon tightening | refused; still working |
| V8 | Tier 0 account over RDP from a device outside `Tier0PAWDevices`, Tier 0 policy assigned | Event 305 in audit mode; refused once enforced |
| V9 | Tier 0 session open, attempt a Tier 1 logon | no Fast User Switching entry point; a disconnected session ends after one minute |
| V10 | Admitted Tier 1 account: ticket from the PAW / from an ordinary client | no Event 305 / Event 305 — the positive control (`auth-silos-operations-guide.md:143-146`) |

Run V1–V10 before AppLocker enforcement and again after it. Record the results; until they exist,
this variant is a design, not a measurement.

---

## 8. What this variant gives up, and what it does not

- **Given up:** the physical separation between a Tier 0 and a Tier 1 device. What is left is
  separation by session, rights and application control on one Tier 0 device. For an organisation
  that would otherwise administer Tier 1 from an ordinary workstation, that is an improvement. For
  one that could afford a second device, it is a trade-off, and it belongs in writing.
- **Not given up:** no Tier 1 identity is ever a local administrator of the device; no Tier 1
  administrator can admit themselves or take over an admitted account; the Tier 0 accounts'
  restrictions and the deny lists of every Tier 1 and Tier 2 machine are unchanged.
- **Not measured:** everything in sections 2–7. The figures in this repository come from a
  single-DC green-field laboratory without any PAW computer object.
