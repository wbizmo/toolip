# OpenChain operational evidence record templates

**Do not fill these fields with invented people, invented assessments or unrun test results.** Retain real, dated records in a controlled evidence store. Use stable links, commit SHAs and artifact hashes, not mutable screenshots alone.

## Programme approval and participant competence

- Record ID / date / document revision / repository or product:
- Executive sponsor name, approval and legal entity:
- Programme owner and organizational role:
- Review boundary, supported releases and excluded software:
- Participant name or secure roster ID, role and assigned responsibilities:
- Competence criteria; training/experience reviewed; assessment date, method and result:
- Policy awareness assessment: policy location, goals, participant contribution and consequences of failure:
- Training delivery/acknowledgement date, version, assessor and evidence URI:
- Budget/time allocation, approved staffing and legal/security expert escalation:
- Periodic policy/role review outcome, improvements and evidence URI:

## Component and license review (one row per shipped component)

| Release + hash | Component, origin and PURL | Actual shipped version | License and copyright | Obligations and incompatibilities | Review outcome / responsible approver | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| (new record) | (required) | (required) | (verified) | (source, notices, modifications, etc.) | OPEN until reviewed | (immutable reference) |

Maintain separate inventories where the CLI and shipped generated template carry distinct dependencies or artifacts.

## Vulnerability disposition (including NO-ACTION)

| Release + component PURL | Check date/source | Advisory or recorded no-known-findings result | Risk, reachability and impact | Fix/mitigation/no-action decision | Owner and approval | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| (new record) | (required) | (required) | (required for findings) | OPEN until reviewed | (required) | (immutable reference) |

Keep a record even when a release scan finds no known vulnerabilities, and distinguish feed unavailable or scanner failure from no findings.

## Release delivery and archive

- Exact repo commit, tag, support window and generated-template versions:
- Scan commands, Node/OS matrix, statuses, date and CI links:
- Archived SBOM(s), output hashes, comparison to release package and any generated API:
- License review decisions, notice texts, modified-source delivery and legal escalations:
- Packaged npm tarball hash / inspection / publication evidence:
- Security issue register, residual-risk decisions, advisory export and customer agreement if applicable:
- Go/no-go authority, signature, timestamp and any outstanding exceptions:
- Evidence archive location, access permissions, retention expiration based on **last offer**, and test retrieval result:

## External inquiry, nonconformance and improvement

- Public intake channel and periodic monitoring test:
- Ticket ID, received/acknowledged dates, response owner and confidentiality:
- Product/component/release, case details and relevant contractual/license terms:
- Risk and root cause, immediate containment, actions and expected dates:
- Notification/export decision and customer-agreement evidence where applicable:
- Reviewer closure proof, changes to process/training and follow-up date:

## Final conformance decision

- All **34 of 34** ISO/IEC 5230 checklist responses reviewed with dated evidence links:
- All **35 of 35** ISO/IEC 18974 checklist responses reviewed with dated evidence links:
- Named accountable representative, actual programme/legal name and scope:
- Independent challenge / documented audit of evidence, unresolved issues and corrective actions:
- Exact validated standards/editions, assessment date, reviewer, signed affirmation:
- Next validation due within **18 months** of actual validation:
- Optional OpenChain Community of Conformance submission reference and result:

**No certification or community-listing claim may be published until the final decision is genuinely signed.**
