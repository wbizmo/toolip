# Open-source security assurance policy and operating procedure

**Scope:** Zivora Labs-supplied Toolip and LaunchStack CLI, including included code, dependencies, packages, shipped templates and supported release versions. **Not yet evidence-verified for ISO/IEC 18974.**

## Threat analysis and prerelease testing

1. At each release and after high-impact architectural changes, record trust boundaries, attacker-controlled inputs, package/build/install scripts, generated projects, CI privileges, downloads, dependency provenance and a threat model. Toolip's untrusted repository scans and LaunchStack's generated API/templates warrant separate review.
2. Determine actual shipped components from complete release inventories. Compare each component against public known-vulnerability advisories using GitHub advisory/Dependabot sources, OSV and the ecosystem audit; record analyzer versions, time, version, advisory IDs and results **including clean/unknown/failed**.
3. Run the repository's full documented build, tests, release checks, CodeQL and dependency audit before publishing. A skipped scan, unavailable feed, untrusted script execution or incomplete inventory cannot count as clean. Tests on `main` do not automatically validate a different release tag.
4. Record each finding's affected version, exploitability, reachability where determinable, severity and business/use-case impact; assign accountable remediation. Use documented justification for “not affected” or no action (VEX-style disposition where relevant); do not mask findings by increasing audit thresholds.
5. Classify risk and decide if a release is blocked, fixed, replaced, isolated, mitigated or accepted by the authorized person. Customer agreement is required where applicable under the standard or contractual commitments. Keep the signed go/no-go result and residual risk register.

## Post-release security monitoring

- Maintain the exact component inventories of **each supported released version** and re-evaluate against newly disclosed advisories on a documented recurring schedule (weekly is a proposed initial cadence).
- Record each scan, even when no advisory matches; escalate newly affecting vulnerabilities, including previously shipped versions.
- Security lead triages inbound reports promptly, assesses severity and impact, creates a private tracking record, assigns owner, determines public and affected-user notice thresholds, verifies fixes and retains an evidence trail.
- Where required, issue advisories and contact users; protect reporter identities and sensitive proof-of-concept details. Keep dated communications or a written rationale for non-disclosure.
- Offer affected parties appropriate security information (e.g. advisory, SBOM, supported version statement or VEX disposition) after review; do not disclose exploit details prematurely.

## Public security contacts and internal response

Each repository must provide a publicly accessible secure reporting route. Confirm the route is **actually enabled and monitored**; the presence of a `SECURITY.md` file does not prove availability. Prefer GitHub private vulnerability reporting when enabled; use an expressly monitored private email alternative where needed. Do not send secrets in public GitHub issues.

For every report record: receipt time, case ID, secure acknowledgement, affected releases/components, reviewer, evidence, assessed impact, decision, mitigation/fix reference, disclosure rationale, affected-party notifications and closure date. Keep private records access-controlled.

## Resources, review and metrics

Appoint trained security reviewers, maintain review coverage and funded time, and establish escalation to specialist expertise. The responsible executive approves the roles, time and budget. Review release coverage, scan failures, time to triage, overdue dispositions, unsupported versions and customer communications quarterly. Update the procedures after incidents or changes in threat intelligence.

**Existing scanners are candidate implementation controls, not complete proof.** For Toolip, inspect its scheduled dependency audit, CodeQL, release scripts, trusted Stage A roadmap and v3.2.1 state. For LaunchStack, CodeQL's weekly schedule does not replace post-release dependency-vulnerability tracking; implement and verify that separately.
