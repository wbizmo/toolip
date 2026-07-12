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
