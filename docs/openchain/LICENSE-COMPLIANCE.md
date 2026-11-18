# License compliance and open-source content policy

**Scope:** Toolip and LaunchStack CLI supplied software only, within the [programme boundary](README.md). This is a proposed operating procedure; retained execution records and approval are required before ISO/IEC 5230 self-certification.

## Intake, identification and evaluation

1. Before adding or updating any dependency or copied resource, identify publisher/origin, exact version/commit, package URL, direct/transitive relationship, source URL, license expression, copyright and whether it is modified or redistributed.
2. Reconcile the actual release tarball/source checkout against the relevant lockfile(s), checked-in templates, assets, generated output and bundled resources. A bare root lockfile is **not** proof of exhaustive shipped components. For LaunchStack, include the generated API template lockfile and template contents.
3. Produce an SPDX or CycloneDX inventory for each proposed release plus a human-readable register of license determinations. Save exact commit, tarball hash, date, tooling version and the inventory itself.
4. Verify notices/license expressions from authoritative component sources; npm lockfile `license` strings are starting evidence only. Investigate unknown, conflicting, deprecated or custom terms. Never silently interpret missing metadata as MIT.
5. Record granted rights, restrictions, attribution and copyright requirements, license text reproduction, source-availability or file-level source duties, patent/notice implications, redistribution versus use-only distinctions and applicability to binary vs source distribution.
6. Escalate incompatible, unclear or dual-licensed combinations to the designated legal reviewer. Block release until there is a documented accepted alternative, replacement, relicensing, exception from proper authority, or removal.

## Case-specific rules

- **Binary/npm distribution:** inspect the actual packed package, transitive code embedded in output, accompanying files and required notices; provide license texts and source or written offer when applicable.
- **Source distribution:** preserve copyright and license notices, distribute required notices/texts, identify affected derived files and ensure source availability requirements are met.
- **Integration:** review static linking, bundling, generated code, copying source, distribution boundaries, plugins and interoperability where license terms can affect obligations; record the decision.
- **Modified external code:** record upstream source, diff, author, modification date and whether the license requires affected-file publication, change notices or other conditions.
- **Attribution:** ensure release artifacts, LICENSE, bundled notices and documentation meet each included license's terms; inspect package and generated template output.
- **Different licenses:** review any MPL-2.0, CC-BY, BlueOak, BSD/Apache and unknown licensing on their merits rather than assuming all are equivalent to MIT. License decisions must cover actual files, not just npm metadata.

## Required evidence for every released version

A release record contains a component list, classification, per-component license disposition, inventory hash, license and copyright texts, applicable attributions and source offers, shipped npm tarball hash, direct download locations and review/approval signatures. Archive the delivered artifacts for the full required license period measured from the **last offer**, or longer if license obligations or commitments require. Test archive retrieval.

## Inquiries and remediation

Publish a working public license-inquiry channel in the project's README or contribution guide; record that it is monitored. On receipt, log date, component, claimant, license text, shipped versions, responsible reviewer, acknowledgement, corrective action and close-out. Privately handle sensitive or legally privileged material. Pause a noncompliant distribution as necessary; resolve incompatible terms, restore attributions, replace assets, correct notices or publish source when required; record customer notice and prevention review.

A process description or a green CI result **does not** replace actual case/release records.
