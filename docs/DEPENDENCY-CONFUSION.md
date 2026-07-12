# Dependency Confusion Detection

Toolip checks internal-looking dependency declarations against the public npm registry.

## Command

```bash
toolip dependency-confusion
```

Candidates include local, workspace, linked, Git-backed, and weakly versioned scoped dependencies. A public name collision is evidence of exposure, not proof that an attack has occurred.
