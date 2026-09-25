# 🏛️ Tier Model

Declarative PowerShell framework to deploy and audit an Active Directory Tier Model (OUs, Groups, Users, ACL Delegations, GPOs, ADMX, MSA/gMSA/dMSA Permissions, Windows LAPS Permissions) from a single version-controlled JSON configuration file. Supports idempotent re-runs, drift detection, and reproducible builds via pinned dependency versions.

> 🏗️ **Built with the Specify Framework** - Test-driven development ensuring quality and reliability

## 🎯 Goals
- 🔒 Safe, repeatable deployments (WhatIf planning + convergent apply)
- 📊 Drift auditing & reporting (hash provenance + structured findings)
- 🧩 Modular, test-first architecture (Pester enforced)
- 📦 Version governance for dependencies & configuration schema

## 📚 Documentation

> 📖 **Full documentation**: [GitHub Pages - Active Directory Tier Model](https://microsoft.github.io/ActiveDirectoryTierModel)

To get started with TierModel, please refer to our comprehensive documentation:

### 🚀 Getting Started
- **[Quick Deployment Guide](https://microsoft.github.io/ActiveDirectoryTierModel/quick-deployment-guide/)** - Fast-track deployment for experienced administrators
- **[Detailed Deployment Guide](https://microsoft.github.io/ActiveDirectoryTierModel/detailed-deployment-guide/)** - Step-by-step deployment with explanations
- **[FAQ](https://microsoft.github.io/ActiveDirectoryTierModel/faq/)** - Frequently asked questions covering upgrades, migration from previous versions, troubleshooting, and Sentinel integration

### 📖 Core Documentation
- **[Deployment Methodology](https://microsoft.github.io/ActiveDirectoryTierModel/deployment-methodology/)** - Understanding the deployment approach
- **[Drift Detection Details](https://microsoft.github.io/ActiveDirectoryTierModel/drift-detection-details/)** - Comprehensive drift auditing and remediation
- **[Tier Model Logging](https://microsoft.github.io/ActiveDirectoryTierModel/tiermodel-logging/)** - Structured logging, diagnostics, and the new v2.1.0 `-EnableVerbose` and `-EnableDebug` switches for troubleshooting deployment and audit failures
- **[GPO Management Strategy](https://microsoft.github.io/ActiveDirectoryTierModel/gpo-management-strategy/)** - Group Policy Object management
- **[GPO Management Guidance](https://microsoft.github.io/ActiveDirectoryTierModel/gpo-management-guidance/)** - Best practices, baseline selection, the SOE override model, firewall lockdown, and upgrade lifecycle
- **[Best Practices & Hardening](https://microsoft.github.io/ActiveDirectoryTierModel/best-practices/)** - Governance rules (group manager tiering) and post-deployment AD hardening guidance
- **[Authentication Policy Silos - Operations Guide](https://microsoft.github.io/ActiveDirectoryTierModel/auth-silos-operations-guide/)** - Deploy, audit, enforce, and maintain Authentication Policy Silos (`-IncludeAuthSilos`); includes the v1.x → v2.0.0 migration appendix
- **[ADMX Management](https://microsoft.github.io/ActiveDirectoryTierModel/admx-management/)** - Administrative template handling
- **[Conditional Principals](https://microsoft.github.io/ActiveDirectoryTierModel/conditional-principals/)** - Domain-specific principal resolution
- **[CI/CD Integration](https://microsoft.github.io/ActiveDirectoryTierModel/ci-cd/)** - Pipeline integration and automation
- **[Test Tag Matrix](https://microsoft.github.io/ActiveDirectoryTierModel/test-tag-matrix/)** - Pester test organization
- **[Test Coverage](https://microsoft.github.io/ActiveDirectoryTierModel/test-coverage/)** - Comprehensive test coverage analysis and roadmap
- **[Language Support](https://microsoft.github.io/ActiveDirectoryTierModel/language-support/)** - Running against a localized (e.g. German) Active Directory: built-in principals resolve by well-known SID, so one configuration set works in any language
- **[Sentinel Monitoring](https://microsoft.github.io/ActiveDirectoryTierModel/sentinel-monitoring/)** - Out-of-the-box Microsoft Sentinel monitoring for a deployed Tier Model (Content Hub solution)
- **[Event ID Schema](https://microsoft.github.io/ActiveDirectoryTierModel/event-id-schema/)** - Windows Event Log schema for SIEM integration and operational monitoring

### 🔧 Technical Specifications
- **[Feature Specification](specs/001-tier-model-module/spec.md)** - Complete requirements and user stories
- **[Implementation Plan](specs/001-tier-model-module/plan.md)** - Technical architecture and design decisions

## 🧪 Testing & Quality Assurance

**Current test status: 2,056 passing / 32 known failures** — measured on **German Windows 11
against a German Active Directory**, 2026-09-16, commit `5ebe784`.

> **This figure now understates.** 31 of those 32 failures were fixed on 2026-09-25 (`33e4e11`)
> and measured green on a German host; the whole suite was not re-run that day, so the total is
> left as it was measured rather than recalculated. See *About the 32 failures* below.

| Measure | Value | Measured on |
|---|---|---|
| **Automated tests** | **2,056 passing of 2,088** | German Windows 11 / PowerShell 7.6.6, Pester 5.9.0, 2026-09-16 |
| **Command coverage** | **85.73%** (14,742 / 17,195) — clears the 80% CI gate | German lab host, `pwsh -NonInteractive`, 2026-09-17 |
| **Manual integration tests** | 384, 100% pass | `tests/Manual.Integration.Tests.xlsx` |
| **Test files** | 36 Pester files (29 unit, 7 integration) + 1 Excel workbook | counted on `main` |
| **Exported functions** | 80 files in `modules/TierModel/public/` + 3 defined inline in `TierModel.psm1` = **83** | counted on `main` |

**About the 32 failures — 31 are fixed, 1 stays.** They were host-language artefacts in the **test
fixtures**, not product defects, and CI never saw them because CI runs English. 31 of them came
from hard-coded principal names — 34 sites across five files, naming `BUILTIN\Administrators`,
`BUILTIN\Users` and `Everyone` — that German Windows cannot translate, so
`NTAccount(...).Translate()` threw and the code under test took a path the test did not intend.

Those 31 were repaired on **2026-09-25** (`33e4e11`) as their own change: the fixtures now hold the
invariant SID and ask the running host what it calls it, so the same test reads
`BUILTIN\Administrators` on an English host and `VORDEFINIERT\Administratoren` on a German one.
Measured on both, five files, 311 tests:

| Host | Install language | Before | After |
|---|---|---|---|
| German | `0407` | 280 of 311 | **311 of 311** |
| English | `0409` | 311 of 311 | **311 of 311**, unchanged |

The English run is the control, not a formality: on an English host those literals always
resolved, so fixtures that had quietly stopped asserting anything would look exactly like success.
Unchanged before and after is what rules that out.

The 32nd stays. It reads Domain Admin membership from the caller's real logon token —
deliberately, so a string-typed SID cannot fake it — and therefore fails precisely *because* the
lab session is a Domain Admin. Making it pass on such a host would mean weakening that check.
`CLAUDE.md` §6 carries both records.

**About the coverage figure.** It was 87.63% on 2026-09-08 and is 85.73% now. The localization work
added code faster than tests reached it: the analysed population grew by **476 commands**
(16,719 → 17,195). The two runs used different host languages, so the *executed* counts are not
strictly comparable — the analysed count is, because coverage analysis is static. The population is
CI's (`.github/workflows/ci.yml:133-136`): `modules/TierModel/*.psm1`,
`modules/TierModel/public/*.ps1`, `optional/Update-TierModelMembership.ps1` — **82 files**
(1 + 80 + 1). That 82 is a file count for coverage and is not the 83 exported functions above;
the two are different things and both are right.

> Both figures predate the 18 tests added with the parity comparison, so the suite on `main` is
> larger than 2,088 today. The numbers above are what was measured, not what can be derived from
> it by arithmetic.

### Running Tests
```powershell
# Run all tests
.\tests\Invoke-AllTests.ps1

# Run unit tests only
.\tests\Invoke-AllTests.ps1 -TestType Unit

# Run integration tests only
.\tests\Invoke-AllTests.ps1 -TestType Integration

# Show only failures (useful for large test runs)
.\tests\Invoke-AllTests.ps1 -FailedOnly

# Run with detailed output
.\tests\Invoke-AllTests.ps1 -Detailed
```

### Deployment Scripts
| Script | Purpose | Optional Features |
|--------|---------|-------------------|
| `Deploy-TierModel.ps1` | 🚀 Deploy with scoped execution | `-IncludeMsa`, `-IncludeGmsa`, `-IncludeDmsa` (Managed Service Account ACL delegation), `-IncludeWinLaps` (Windows LAPS ACL delegation + GPO decryptor) |
| `Audit-TierModel.ps1` | 📊 Audit and compliance checking | `-IncludeMsa`, `-IncludeGmsa`, `-IncludeDmsa` (Managed Service Account ACL audit), `-IncludeWinLaps` (Windows LAPS ACL + decryptor audit) |

## 🤝 Contributing

Contributions are welcome — but this is a **security-sensitive** project, so we follow an
**issue-first** process. Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** before opening a
pull request.

**The process, in short:**

1. 🗣️ **Open an issue first** describing the problem or proposal — for *any* change (feature, fix, refactor, config, or docs).
2. 🧭 **Discuss and get maintainer agreement** on scope and approach **before writing code**.
3. 🔀 **Then open a focused PR** that links the agreed issue and implements only what was agreed.

> ⚠️ **Pull requests without a linked, pre-agreed issue will be closed.** Unsolicited new
> parameters, alternate deployment topologies, relaxed security validation, or
> bundled / reformat-heavy changes are rejected on sight — not to be unwelcoming, but
> because unreviewed changes to a tiering-security tool can silently weaken tier
> boundaries. See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the full rationale.

When your PR is ready, it must also satisfy:

1. ✅ **All Pester tests pass** — the CI pipeline will reject any PR with failing tests
2. 🧪 **New or updated tests are included** — any new code or bug fix must include corresponding test cases to maintain or improve code coverage
3. 📊 **Code coverage stays at or above 80%** — the CI enforces a minimum coverage threshold; if your changes reduce coverage below 80%, add tests until coverage is restored
4. 📝 Documentation is updated for any new or changed functionality
5. 🎯 Code follows project conventions and keeps the diff focused (no unrelated reformatting)

> **Note:** The packaging step will not produce a release artifact unless all tests pass and coverage meets the minimum threshold.

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Contributor License Agreements](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

### Development Setup
```powershell
# Clone repository
git clone https://github.com/microsoft/ActiveDirectoryTierModel.git
cd ActiveDirectoryTierModel

# Run tests locally before submitting a PR
.\tests\Invoke-AllTests.ps1
```

## 📋 Prerequisites

- **PowerShell**: 7.0+
- **Elevation**: Administrator privileges required
- **Domain Admin**: Membership in Domain Admins group
- **Modules**: ActiveDirectory, GroupPolicy (see `config/dependencies.json`)
- **Language**: any — the **host OS** and **Active Directory** may be installed in any language. Built-in principals resolve by well-known SID rather than by directory name, so one configuration set works everywhere; the host and directory language are recorded as diagnostics and never block a run. `en-US` and `de-DE` are the regression-tested combinations (see [Language Support](https://microsoft.github.io/ActiveDirectoryTierModel/language-support/))

*For detailed prerequisite validation, run `Test-TierModelPrerequisites`*

## 📊 Monitoring

Out-of-the-box Microsoft Sentinel monitoring for a deployed Tier Model is available as a solution in the **Azure Content Hub**. The solution covers Tier Model–specific detection and triage — no custom playbooks or watchlists required. The only hard requirement is that every Domain Controller's Security event logs must be flowing into the Sentinel workspace; any DC not onboarded is a blind spot.

- 📖 [Sentinel Monitoring Guide](https://microsoft.github.io/ActiveDirectoryTierModel/sentinel-monitoring/)
- 🔗 [Content Hub solution source (Azure/Azure-Sentinel)](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/Microsoft%20Active%20Directory%20Tier%20Model)

## 🔗 Additional Resources

- ❓ [Frequently Asked Questions (FAQ)](https://microsoft.github.io/ActiveDirectoryTierModel/faq/)
- 📦 [Dependencies Configuration](config/dependencies.json)
- 🗂️ [Configuration Schema](config/tiermodel.schema.json)
- 📜 [Changelog](CHANGELOG.md)

---

**Version**: 2.1.0 | **License**: MIT | **Status**: ✅ Production Ready

## 🚀 Releasing

This project uses **semantic versioning** (`MAJOR.MINOR.PATCH`) and tag-based releases.

| Bump | When | Example |
|------|------|---------|
| `PATCH` (1.0.**1**) | Bug fix, typo, doc correction | Fix broken ACL rule |
| `MINOR` (1.**1**.0) | New feature, backward-compatible | Add WinLAPS parameter |
| `MAJOR` (**2**.0.0) | Breaking change | Restructure config schema |

### Creating a release

1. Ensure all changes are merged to `main` and CI is green
2. Tag the release:
   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   ```
3. The CI pipeline will automatically:
   - Run all tests and enforce code coverage (80% minimum)
   - Create a `TierModel-1.1.0.zip` release asset
   - Publish a GitHub Release with auto-generated release notes

You can also create a release from the GitHub UI: **Releases → Create a new release → enter the tag name** (e.g. `v1.1.0`).

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.