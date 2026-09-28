# Active Directory Tier Model Documentation

Welcome to the Active Directory Tier Model documentation.

## Contributing

- **[Contributing & Change Process](https://microsoft.github.io/ActiveDirectoryTierModel/contributing/)** - How to propose changes: open an issue first, agree on scope, then submit a focused pull request. **Please read this before opening a PR.**

## Getting Started

- **[Quick Deployment Guide](https://microsoft.github.io/ActiveDirectoryTierModel/quick-deployment-guide/)** - Fast-track deployment instructions for experienced administrators
- **[Detailed Deployment Guide](https://microsoft.github.io/ActiveDirectoryTierModel/detailed-deployment-guide/)** - Comprehensive step-by-step deployment walkthrough

## Core Documentation

- **[Deployment Methodology](https://microsoft.github.io/ActiveDirectoryTierModel/deployment-methodology/)** - Deployment strategy, validation framework, and idempotency principles
- **[Drift Detection](https://microsoft.github.io/ActiveDirectoryTierModel/drift-detection-details/)** - Detecting configuration drift and compliance auditing
- **[Cmdlet Architecture](https://microsoft.github.io/ActiveDirectoryTierModel/cmdlet-architecture/)** - Modular cmdlet design for testing and maintainability
- **[Conditional Principals](https://microsoft.github.io/ActiveDirectoryTierModel/conditional-principals/)** - Managing conditional principals and dynamic group resolution

## Component Management

- **[GPO Management Strategy](https://microsoft.github.io/ActiveDirectoryTierModel/gpo-management-strategy/)** - Group Policy Object configuration and deployment
- **[GPO Management Guidance](https://microsoft.github.io/ActiveDirectoryTierModel/gpo-management-guidance/)** - Best practices, baseline selection, the SOE override model, firewall lockdown, and upgrade lifecycle
- **[Authentication Policy Silos - Operations Guide](https://microsoft.github.io/ActiveDirectoryTierModel/auth-silos-operations-guide/)** - Deploy, audit, enforce, and maintain Authentication Policy Silos (`-IncludeAuthSilos`); includes the v1.x → v2.0.0 migration appendix
- **[ADMX Management](https://microsoft.github.io/ActiveDirectoryTierModel/admx-management/)** - Managing ADMX templates and administrative templates

## Operations & Testing

- **[Tier Model Logging](https://microsoft.github.io/ActiveDirectoryTierModel/tiermodel-logging/)** - Logging configuration and usage for deployment operations
- **[Test Tag Matrix](https://microsoft.github.io/ActiveDirectoryTierModel/test-tag-matrix/)** - Test organization, tagging, and execution strategies
- **[Test Coverage](https://microsoft.github.io/ActiveDirectoryTierModel/test-coverage/)** - Comprehensive test coverage analysis and roadmap
- **[CI/CD Integration](https://microsoft.github.io/ActiveDirectoryTierModel/ci-cd/)** - Continuous Integration and Deployment pipelines

## Monitoring

- **[Sentinel Monitoring](https://microsoft.github.io/ActiveDirectoryTierModel/sentinel-monitoring/)** - Out-of-the-box Microsoft Sentinel monitoring for a deployed Tier Model (Content Hub solution)
- **[Event ID Schema](https://microsoft.github.io/ActiveDirectoryTierModel/event-id-schema/)** - Windows Event Log schema for SIEM integration and operational monitoring

## Reference

- **[Language Support](https://microsoft.github.io/ActiveDirectoryTierModel/language-support/)** - Running against a localized (e.g. German) Active Directory: built-in principals resolve by well-known SID, so one configuration set works in any language

## Added in this fork

Not present upstream, so these are relative links rather than `microsoft.github.io` ones.

- **[SMB Reference Architecture](smb-reference-architecture.md)** - Scoping the Tier Model for organisations too small for the full three-tier topology: how many tiers, where the PAWs run, the administrative endpoint, external service providers, and what each reduction gives up
- **[Production Rollout Runbook](production-rollout-runbook.md)** - Deploying into a populated, multi-DC production domain: pre-flight, the run, verification, and the go-live levers
- **[German Lab Runbook](german-lab-runbook.md)** - The repeatable acceptance cycle against a localized domain, phases A-F
- **[Parity Lab Runbook](parity-lab-runbook.md)** - Comparing a localized and an English deployment built from the same commit
