import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

describe('OCI distribution candidate trust boundary', () => {
  it('requires operator-selected immutable images and a non-root runtime', async () => {
    const file = path.resolve('distribution/oci/Dockerfile');
    const source = await readFile(file, 'utf8');
    expect(source).toContain('ARG BUILDER_IMAGE');
    expect(source).toContain('ARG RUNTIME_IMAGE');
    expect(source).toContain('FROM ${BUILDER_IMAGE}');
    expect(source).toContain('FROM ${RUNTIME_IMAGE}');
    expect(source).toContain('USER 65532:65532');
    expect(source).toContain('npm ci --ignore-scripts');
    expect(source).not.toContain('ENTRYPOINT ["/bin/sh"');
    expect(source).not.toContain('ADD https://');
  });

  it('keeps the executable wrapper available for CI without running repository install scripts', async () => {
    const source = await readFile(
      path.resolve('distribution/oci/Dockerfile'), 'utf8'
    );
    expect(source).toContain('COPY --from=builder --chown=0:0 /toolip/toolip /usr/local/bin/toolip');
    expect(source).toContain('exec node /app/dist/src/index.js "$@"');
    expect(source).toContain("printf '#!/bin/sh\\nexec node");
    expect(source).not.toContain('npm install --unsafe-perm');
  });
});
