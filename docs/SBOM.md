# Software Bill of Materials

Toolip generates local JSON software bills of materials from supported lockfile
graphs. Supported inputs include npm, pnpm, Yarn, Python, Go, Cargo, Maven,
Gradle exports, and Composer where the corresponding exact inventory is
available. Missing or ambiguous resolution stays incomplete; manifest ranges
are not presented as installed versions.

## CycloneDX

```bash
toolip sbom --format cyclonedx --output bom.cdx.json
```

The generated document uses CycloneDX 1.5.

## SPDX

```bash
toolip sbom --format spdx --output bom.spdx.json
```

The generated document uses SPDX 2.3.

Toolip includes package names, exact resolved versions, canonical package URLs,
instance-specific references, direct/development metadata, and root dependency
relationships. Package URLs are parsed through `packageurl-js`; their
identities do not assert that artifact bytes or publisher provenance were
independently verified. Unknown source and integrity remain unknown. No project
source code is uploaded.
