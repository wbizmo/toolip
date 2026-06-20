# Toolip

<p align="center">
  <strong>Developer-First Supply Chain Security, Security Hygiene, and Secrets Management CLI</strong>
</p>

<p align="center">
  Dependency Intelligence • Security Auditing • Secret Detection • Git Security • Learning Mode • Encrypted Vault
</p>

---

## Overview

Toolip is a TypeScript-powered developer security companion designed to help developers build safer software.

Modern development relies heavily on third-party packages, environment variables, cloud credentials, CI/CD pipelines, and Git workflows. While security tooling often targets enterprise security teams, developers are frequently left with tools that identify problems without explaining them.

Toolip takes a different approach.

Instead of simply reporting findings, Toolip focuses on education, remediation guidance, and practical developer workflows.

Toolip combines:

* Supply Chain Security
* Dependency Intelligence
* Developer Security Auditing
* Secret Detection
* Git Security
* Security Scorecards
* Encrypted Local Secret Storage
* Security Learning Resources

Everything runs locally.

No accounts.

No dashboards.

No SaaS.

No subscriptions.

---

## Why Toolip?

Most tools stop at:

```text
Security issue found.
```

Toolip goes further:

* What is wrong?
* Why does it matter?
* How risky is it?
* How do you fix it?
* What alternatives exist?
* How can you prevent it in future?

The goal is to help developers understand security while improving security posture.

---

## Installation

### npm

```bash
npm install -g toolip
```

Verify installation:

```bash
toolip --version
```

---

## Quick Start

Analyze a project:

```bash
toolip profile

toolip scan

toolip doctor

toolip score
```

Review Git hygiene:

```bash
toolip git-audit

toolip pre-commit
```

Inspect packages:

```bash
toolip inspect express

toolip compare axios got

toolip alternatives request
```

Manage secrets:

```bash
toolip vault init

toolip vault set DATABASE_URL

toolip vault get DATABASE_URL
```

---

# Features

---

## Project Fingerprinting

```bash
toolip profile
```

Detects technologies used within a project.

Examples:

* Node.js
* TypeScript
* Fastify
* Express
* React
* PostgreSQL
* MongoDB
* Redis

Provides technology-aware recommendations.

---

## Dependency Scanning

```bash
toolip scan
```

Analyzes project dependencies.

Detects:

* Deprecated packages
* Outdated packages
* High-risk packages
* Dependency bloat
* Supply chain concerns

Provides actionable recommendations.

---

## Package Inspection

```bash
toolip inspect express
```

Displays:

* Latest version
* Maintainer information
* Deprecation status
* Package metadata
* Risk score

Useful when evaluating new dependencies.

---

## Package Comparison

```bash
toolip compare axios got
```

Compare multiple packages based on:

* Dependency count
* Risk indicators
* Maintenance activity
* General package health

Useful when choosing between alternatives.

---

## Package Alternatives

```bash
toolip alternatives request
```

Suggests safer or more modern replacements for packages that are:

* Deprecated
* Legacy
* Poorly maintained

---

## Dependency Tree Analysis

```bash
toolip tree
```

Provides visibility into dependency structure.

Displays:

* Dependency hierarchy
* Dependency depth
* Transitive relationships

Useful when investigating package risk.

---

## License Analysis

```bash
toolip licenses
```

Analyzes project licensing.

Provides:

* License inventory
* License distribution
* Restrictive license warnings

---

# Security Doctor

```bash
toolip doctor
```

Runs a comprehensive project security audit.

Checks for:

### Secret Exposure

Detects:

* GitHub tokens
* API keys
* JWT secrets
* AWS credentials
* Private keys
* Hardcoded passwords

### Dangerous Code Patterns

Detects:

* eval()
* Function constructor usage
* Unsafe shell execution
* Dangerous runtime patterns

### Configuration Risks

Checks for:

* Open CORS policies
* Insecure configuration patterns
* Weak environment practices

### Security Headers

Identifies missing:

* Content-Security-Policy
* X-Frame-Options
* X-Content-Type-Options
* Strict-Transport-Security

---

# Git Security

---

## Git Audit

```bash
toolip git-audit
```

Analyzes Git hygiene.

Checks for:

* Sensitive files
* Weak ignore rules
* Dangerous artifacts
* Common security mistakes

---

## Pre-Commit Checks

```bash
toolip pre-commit
```

Runs blocking security checks before commits.

Detects:

* Secrets
* Credentials
* Security violations
* Dangerous files

Designed to stop mistakes before they reach Git history.

---

## Git Hook Installation

```bash
toolip hook install
```

Installs Toolip-powered Git hooks.

Allows security checks to run automatically before commits.

---

# Security Scorecards

```bash
toolip score
```

Calculates a security score based on:

* Dependency Health
* Secret Hygiene
* Configuration Security
* Git Safety

Example:

```text
Dependency Health .... 91
Secret Hygiene ....... 84
Configuration ........ 88
Git Safety ........... 95

Overall Score ........ 89
Grade ................ A
```

---

# Learning Mode

One of Toolip's signature features.

```bash
toolip learn cors
```

Toolip teaches while it scans.

Available topics include:

* CORS
* JWT
* XSS
* CSRF
* Authentication
* Authorization
* Secrets Management
* Dependency Security

Each lesson includes:

* Explanation
* Risks
* Common mistakes
* Secure examples
* Best practices

Designed for developers learning secure software engineering.

---

# Toolip Vault

Toolip includes a lightweight encrypted local secrets manager.

---

## Initialize Vault

```bash
toolip vault init
```

Creates an encrypted local vault.

---

## Store Secrets

```bash
toolip vault set DATABASE_URL
```

Stores secrets securely.

---

## Retrieve Secrets

```bash
toolip vault get DATABASE_URL
```

Returns decrypted values after authentication.

---

## List Secrets

```bash
toolip vault list
```

Displays secret names without revealing values.

---

## Delete Secrets

```bash
toolip vault delete DATABASE_URL
```

Removes stored secrets.

---

## Export Environment Variables

```bash
toolip vault export --env development
```

Supports:

* development
* staging
* production

---

## Vault Security Features

* AES-256 Encryption
* Password Protection
* Local Storage Only
* Offline Operation

No cloud storage.

No synchronization.

No accounts.

No remote services.

---

# Command Reference

| Command             | Description                        |
| ------------------- | ---------------------------------- |
| toolip profile      | Fingerprint project technologies   |
| toolip scan         | Analyze dependencies               |
| toolip doctor       | Perform security audit             |
| toolip score        | Generate security scorecard        |
| toolip inspect      | Inspect package metadata           |
| toolip compare      | Compare packages                   |
| toolip alternatives | Suggest replacements               |
| toolip licenses     | Analyze licenses                   |
| toolip tree         | Analyze dependency hierarchy       |
| toolip git-audit    | Audit Git hygiene                  |
| toolip pre-commit   | Run pre-commit security checks     |
| toolip hook install | Install Git hooks                  |
| toolip learn        | Security education mode            |
| toolip vault        | Encrypted local secrets management |

---

# Design Principles

Toolip follows several guiding principles:

* Developer First
* CLI First
* Security Education
* Local Development Friendly
* CI/CD Friendly
* Framework Agnostic
* Actionable Guidance
* Secure by Default

---

# Technology Stack

Built with:

* TypeScript
* Node.js
* Commander.js
* Vitest
* Chalk
* Ora
* Zod
* npm Registry APIs
* Git Integration
* Node Crypto APIs

---

# Use Cases

Toolip is useful for:

* Backend Engineers
* Platform Engineers
* DevOps Engineers
* Open Source Maintainers
* Startup Teams
* Full Stack Developers
* Students Learning Security

---

# Portfolio Positioning

Toolip demonstrates experience with:

* TypeScript Engineering
* CLI Development
* Security Engineering Concepts
* Supply Chain Security
* Secret Management
* Static Analysis
* Git Integration
* Risk Scoring Systems
* Developer Experience Design
* Secure Development Workflows

---

# Author

**Ashibuogwu Williams (wbizmo)**

GitHub: https://github.com/wbizmo

---

# License

MIT License
