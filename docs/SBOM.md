# Software Bill of Materials

Toolip generates local JSON software bills of materials from resolved npm dependencies.

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

Toolip includes package names, resolved versions, package URLs, direct/development metadata, and root dependency relationships. No project source code is uploaded.
