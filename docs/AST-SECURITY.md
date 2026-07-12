# AST Security Analysis

Toolip uses the TypeScript Compiler API to understand JavaScript and TypeScript syntax before reporting dangerous-code findings.

## Command

```bash
toolip ast-scan
```

## Supported Source Files

- JavaScript
- JSX
- TypeScript
- TSX
- ESM `.mjs`
- CommonJS `.cjs`

Declaration files, source maps, and compiled `dist` output are excluded.

## Current Rules

- `TLP-AST-001`: direct `eval()` execution
- `TLP-AST-002`: dynamic `Function` construction
- `TLP-AST-003`: resolved `child_process.exec()` execution
- `TLP-AST-004`: resolved `child_process.execSync()` execution

Toolip resolves named imports, aliased imports, namespace imports, CommonJS destructuring, and common `require(...).exec` assignments.

## Why AST Analysis

Raw string matching cannot distinguish regular-expression parsing from shell execution. AST analysis keeps those operations separate and avoids the false positive previously found in Toolip v1.

## Limits

AST resolution is static. Dynamic module loading, runtime mutation, generated code, framework-specific injection, and indirect values may require lower-confidence analysis in future releases.
