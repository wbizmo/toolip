# Reachability Analysis

Toolip analyzes JavaScript and TypeScript imports to show whether installed npm packages are referenced by project source code.

## Command

```bash
toolip reachability
```

## States

- `reachable`: a package import, require, or static dynamic import was observed.
- `possibly-reachable`: a direct dependency was not observed but may be loaded dynamically or by a framework.
- `not-observed`: a transitive dependency was not directly referenced by project source.

Reachability is evidence, not proof that a vulnerability cannot be exploited. Runtime plugins, dependency injection, generated code, reflection, and computed imports may not be statically visible.

For Yarn Plug'n'Play projects, Toolip reads `.pnp.data.json` or statically
extracts Yarn's literal `RAW_RUNTIME_STATE` from `.pnp.cjs`; it never loads the
project's PnP runtime. It cross-checks the PnP package locators and dependency
bindings against the exact Yarn lock graph, then resolves source files to their
own workspace bindings. Missing, dynamic, malformed, inconsistent or
out-of-root PnP state leaves affected package instances `unknown` and scan
coverage incomplete. Virtual peer contexts remain distinct even when they share
one archive. This static relationship check does not verify package archive
contents, prove exploitability, or resolve runtime-generated imports.
