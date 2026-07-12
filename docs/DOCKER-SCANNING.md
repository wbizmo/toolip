# Dockerfile Security

Run:

```bash
toolip docker-scan
```

Toolip checks Dockerfiles for root execution, secret-like ARG/ENV declarations, unpinned images, remote ADD instructions, and package-install cleanup issues.
