import { describe, expect, it } from 'vitest';
import {
  goSourceFileMatchesTarget,
  parseGoTargetProfile,
  parseGoTargetProfileJson
} from '../../src/core/dependencies/go-target.js';

const linuxAmd64 = parseGoTargetProfile({
  id: 'linux-amd64-go124',
  goos: 'linux',
  goarch: 'amd64',
  cgo: true,
  goVersion: '1.24.1',
  tags: ['enterprise']
});

describe('Go build target profiles', () => {
  it('requires bounded valid platform, version, and tag identities', () => {
    expect(() =>
      parseGoTargetProfile({
        id: 'bad',
        goos: 'fakeos',
        goarch: 'amd64',
        cgo: true
      })
    ).toThrow('identity is invalid');
    expect(() =>
      parseGoTargetProfile({
        id: 'bad',
        goos: 'linux',
        goarch: 'amd64',
        cgo: true,
        tags: ['bad tag']
      })
    ).toThrow('build tags are invalid');
    expect(() =>
      parseGoTargetProfile({
        id: 'bad',
        goos: 'linux',
        goarch: 'amd64',
        cgo: true,
        tags: ['untrusted-tag']
      })
    ).toThrow('build tags are invalid');
    expect(() => parseGoTargetProfileJson('x'.repeat(4097))).toThrow(
      'exceeds 4 KiB'
    );
  });

  it('selects GOOS/GOARCH filename suffixes and modern constraints', () => {
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/file_linux_amd64.go',
        '//go:build linux && (amd64 || arm64)\n\npackage lib\n',
        linuxAmd64
      )
    ).toBe(true);
    const android = parseGoTargetProfile({
      id: 'android-arm64',
      goos: 'android',
      goarch: 'arm64',
      cgo: true,
      goVersion: '1.24'
    });
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/file_linux_arm64.go',
        'package lib\n',
        android
      )
    ).toBe(true);
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/file_windows_amd64.go',
        'package lib\n',
        linuxAmd64
      )
    ).toBe(false);
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/file.go',
        '//go:build windows || (linux && amd64)\n\npackage lib\n',
        linuxAmd64
      )
    ).toBe(true);
  });

  it('evaluates cgo, custom, and Go release tags and legacy constraints', () => {
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/cgo.go',
        '//go:build cgo && enterprise && go1.22\n\npackage lib\n',
        linuxAmd64
      )
    ).toBe(true);
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/nocgo.go',
        '//go:build !cgo\n\npackage lib\n',
        linuxAmd64
      )
    ).toBe(false);
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/legacy.go',
        '// +build linux,amd64\n\npackage lib\n',
        linuxAmd64
      )
    ).toBe(true);
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/legacy.go',
        '// +build windows\n// +build amd64\n\npackage lib\n',
        linuxAmd64
      )
    ).toBe(false);
  });

  it('selects explicit architecture feature levels and leaves absent levels unknown', () => {
    const amd64v3 = parseGoTargetProfile({
      id: 'linux-amd64-v3',
      goos: 'linux',
      goarch: 'amd64',
      cgo: false,
      goVersion: '1.24',
      tags: ['amd64.v3']
    });
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/feature.go',
        '//go:build amd64.v2\n\npackage lib\n',
        amd64v3
      )
    ).toBe(true);
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/feature.go',
        '//go:build amd64.v3\n\npackage lib\n',
        linuxAmd64
      )
    ).toBe(undefined);
  });

  it('leaves unknown target/version selection incomplete', () => {
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/file_linux.go',
        'package lib\n',
        undefined
      )
    ).toBe(undefined);
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/file.go',
        '//go:build go1.25\n\npackage lib\n',
        parseGoTargetProfile({
          id: 'linux-amd64',
          goos: 'linux',
          goarch: 'amd64',
          cgo: false
        })
      )
    ).toBe(undefined);
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/mismatch.go',
        '//go:build windows\n// +build linux\n\npackage lib\n',
        linuxAmd64
      )
    ).toBe(undefined);
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/overflow.go',
        '//go:build go1.999999999999999999999\n\npackage lib\n',
        linuxAmd64
      )
    ).toBe(undefined);
  });

  it('excludes test-only imports from runtime dependency selection', () => {
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/lib_test.go',
        'package lib\nimport "example.test/test-only"\n',
        linuxAmd64
      )
    ).toBe(false);
  });

  it('fails closed for invalid build tag identifiers', () => {
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/file.go',
        '//go:build !enterprise-tag\n\npackage lib\n',
        linuxAmd64
      )
    ).toBe(undefined);
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/file.go',
        '// +build enterprise-tag\n\npackage lib\n',
        linuxAmd64
      )
    ).toBe(undefined);
    expect(
      goSourceFileMatchesTarget(
        'vendor/example.test/lib/no-blank.go',
        '//go:build linux\npackage lib\n',
        linuxAmd64
      )
    ).toBe(undefined);
  });
});
