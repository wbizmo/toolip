# Install-Script Analysis

Toolip inspects installed npm package manifests for `preinstall`, `install`, and `postinstall` lifecycle scripts.

It reports indicators such as:

- network access
- shell execution
- filesystem writes or deletion
- encoded or obfuscated payloads
- credential or environment inspection

## Command

```bash
toolip install-scripts
```

This analysis is static and does not execute package scripts.

For strongest protection, future Toolip versions may inspect package tarballs before installation. Sprint 4 analyzes installed manifests and records clear confidence levels rather than claiming complete behavioral proof.
