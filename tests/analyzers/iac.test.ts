import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { InfrastructureAnalyzer } from '../../src/analyzers/iac/analyzer.js';

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

async function rootFixture(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'toolip-iac-'));
  roots.push(root);
  return root;
}

describe('InfrastructureAnalyzer', () => {
  it('scans captured local Terraform modules through the shared project snapshot', async () => {
    const root = await rootFixture();
    await mkdir(path.join(root, 'modules/network'), { recursive: true });
    await writeFile(
      path.join(root, 'main.tf'),
      'module "network" {\n  source = "./modules/network"\n}\n'
    );
    await writeFile(
      path.join(root, 'modules/network/main.tf'),
      [
        'resource "aws_security_group" "admin" {',
        '  ingress {',
        '    from_port = 22',
        '    to_port = 22',
        '    cidr_blocks = ["0.0.0.0/0"]',
        '  }',
        '}'
      ].join('\n')
    );

    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.coverage).toMatchObject({ state: 'complete', scanned: 2 });
    expect(result.findings.map((item) => item.ruleId)).toContain(
      'TLP-IAC-TF-002'
    );
    expect(result.warnings).toBeUndefined();
  });

  it('marks remote, dynamic, missing and escaping Terraform module sources incomplete', async () => {
    const root = await rootFixture();
    await writeFile(
      path.join(root, 'main.tf'),
      [
        'module "remote" {',
        '  source = "terraform-aws-modules/vpc/aws"',
        '}',
        'module "dynamic" {',
        '  source = var.module_source',
        '}',
        'module "missing" {',
        '  source = "./modules/missing"',
        '}',
        'module "escape" {',
        '  source = "../outside"',
        '}'
      ].join('\n')
    );

    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.coverage).toMatchObject({ state: 'partial', skipped: 4 });
    expect(result.warnings).toEqual(
      expect.arrayContaining([
        expect.stringContaining('terraform-remote-module-unresolved'),
        expect.stringContaining('terraform-module-source-dynamic'),
        expect.stringContaining('terraform-local-module-unavailable'),
        expect.stringContaining('terraform-local-module-outside-project')
      ])
    );
    expect(result.warnings?.join('\n')).not.toContain('terraform-aws-modules');
  });

  it('detects structured Kubernetes risks through YAML aliases without scanning comments', async () => {
    const root = await rootFixture();
    const file = path.join(root, 'k8s/deployment.yaml');
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(
      file,
      [
        'apiVersion: apps/v1',
        'kind: Deployment',
        'metadata:',
        '  name: api',
        'spec:',
        '  template:',
        '    spec:',
        '      securityContext: &ctx',
        '        runAsNonRoot: false',
        '        privileged: true',
        '        allowPrivilegeEscalation: true',
        '      containers:',
        '        - name: api',
        '          securityContext: *ctx',
        '          # privileged: true is only a comment',
        '      volumes:',
        '        - name: host',
        '          hostPath:',
        '            path: /var/run/docker.sock'
      ].join('\n')
    );

    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.coverage).toMatchObject({
      state: 'complete',
      eligible: 1,
      scanned: 1
    });
    expect(result.findings.map((item) => item.ruleId)).toEqual([
      'TLP-IAC-K8S-001',
      'TLP-IAC-K8S-002',
      'TLP-IAC-K8S-004'
    ]);
    expect(result.findings.every((item) => item.location?.line !== 13)).toBe(
      true
    );
  });

  it('checks GitHub Actions permissions, immutable action refs and shell expression flow', async () => {
    const root = await rootFixture();
    await mkdir(path.join(root, '.github/workflows'), { recursive: true });
    await writeFile(
      path.join(root, '.github/workflows/ci.yml'),
      [
        'name: CI',
        'on: pull_request',
        'permissions:',
        '  contents: write',
        'jobs:',
        '  test:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: actions/checkout@v4',
        '      - run: echo "$' + '{' + '{ github.event.pull_request.title }}"'
      ].join('\n')
    );

    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.coverage.state).toBe('complete');
    expect(result.findings.map((item) => item.ruleId)).toEqual([
      'TLP-IAC-GHA-001',
      'TLP-IAC-GHA-002',
      'TLP-IAC-GHA-003'
    ]);
  });

  it('detects Terraform public bucket and public administrative ingress', async () => {
    const root = await rootFixture();
    await writeFile(
      path.join(root, 'main.tf'),
      [
        'resource "aws_s3_bucket" "public" {',
        '  acl = "public-read"',
        '}',
        'resource "aws_security_group" "admin" {',
        '  ingress {',
        '    from_port = 22',
        '    to_port = 22',
        '    cidr_blocks = ["0.0.0.0/0"]',
        '  }',
        '}'
      ].join('\n')
    );

    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.findings.map((item) => item.ruleId)).toEqual([
      'TLP-IAC-TF-001',
      'TLP-IAC-TF-002'
    ]);
  });

  it('detects modern S3 public-access blocks and legacy public ACL resources', async () => {
    const root = await rootFixture();
    await writeFile(
      path.join(root, 'storage.tf'),
      [
        'resource "aws_s3_bucket_public_access_block" "open" {',
        '  bucket = aws_s3_bucket.data.id',
        '  block_public_acls = true',
        '  block_public_policy = false',
        '  restrict_public_buckets = true',
        '}',
        'resource "aws_s3_bucket_acl" "legacy" {',
        '  bucket = aws_s3_bucket.data.id',
        '  acl = "public-read"',
        '}'
      ].join('\n')
    );
    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(
      result.findings
        .filter((finding) => finding.ruleId === 'TLP-IAC-TF-001')
        .map((finding) => finding.location?.line)
    ).toEqual([4, 9]);
  });

  it('detects issue-comment text interpolated into a workflow shell command', async () => {
    const root = await rootFixture();
    await mkdir(path.join(root, '.github/workflows'), { recursive: true });
    await writeFile(
      path.join(root, '.github/workflows/comment.yml'),
      [
        'name: comment',
        'on: issue_comment',
        'jobs:',
        '  comment:',
        '    steps:',
        "      - run: 'echo $" +
          '{' +
          "{ github.event.issue_comment.comment.body }}'"
      ].join('\n')
    );
    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.findings.map((finding) => finding.ruleId)).toEqual([
      'TLP-IAC-GHA-003'
    ]);
  });

  it('ignores commented-out Terraform security settings', async () => {
    const root = await rootFixture();
    await writeFile(
      path.join(root, 'main.tf'),
      [
        'resource "aws_s3_bucket" "private" {',
        '  # acl = "public-read"',
        '  acl = "private"',
        '}',
        'resource "aws_security_group" "private" {',
        '  # ingress { from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }',
        '  ingress { from_port = 443 to_port = 443 cidr_blocks = ["10.0.0.0/8"] }',
        '}'
      ].join('\n')
    );
    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.findings).toEqual([]);
  });

  it('keeps HCL braces in strings, comments and heredocs out of block structure', async () => {
    const root = await rootFixture();
    await writeFile(
      path.join(root, 'heredoc.tf'),
      [
        'resource "aws_s3_bucket" "public" {',
        '  description = "literal } # is not a delimiter"',
        '  /* ignored block { with close } */',
        '  policy_note = <<-EOT',
        '    } acl = "public-read"',
        '  EOT',
        '  acl = "public-read"',
        '}'
      ].join('\n')
    );
    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.findings.map((finding) => finding.ruleId)).toEqual([
      'TLP-IAC-TF-001'
    ]);
    expect(result.findings[0]?.location?.line).toBe(7);
    expect(result.coverage.state).toBe('complete');
  });

  it('marks unterminated Terraform heredocs incomplete', async () => {
    const root = await rootFixture();
    await writeFile(
      path.join(root, 'broken.tf'),
      [
        'resource "aws_s3_bucket" "broken" {',
        '  description = <<EOF',
        '  closing delimiter is missing',
        '}'
      ].join('\n')
    );
    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.coverage.state).toBe('failed');
    expect(result.warnings?.some((warning) => warning.includes('heredoc'))).toBe(
      true
    );
  });

  it('detects public ingress outside administrative ports', async () => {
    const root = await rootFixture();
    await writeFile(
      path.join(root, 'network.tf'),
      [
        'resource "aws_security_group" "web" {',
        '  ingress {',
        '    from_port = 443',
        '    to_port = 443',
        '    cidr_blocks = ["0.0.0.0/0"]',
        '  }',
        '}'
      ].join('\n')
    );
    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.findings.map((item) => item.ruleId)).toEqual([
      'TLP-IAC-TF-004'
    ]);
  });

  it('requires non-root security context per Kubernetes container or pod', async () => {
    const root = await rootFixture();
    await mkdir(path.join(root, 'k8s'), { recursive: true });
    await writeFile(
      path.join(root, 'k8s/deployment.yaml'),
      [
        'apiVersion: apps/v1',
        'kind: Deployment',
        'spec:',
        '  template:',
        '    spec:',
        '      containers:',
        '        - name: web',
        '          image: nginx:1.27',
        '        - name: metrics',
        '          image: metrics:1.0',
        '          securityContext:',
        '            runAsNonRoot: true'
      ].join('\n')
    );
    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(
      result.findings.filter((item) => item.ruleId === 'TLP-IAC-K8S-005')
    ).toHaveLength(1);
  });

  it('does not let unrelated YAML securityContext fields satisfy the pod policy', async () => {
    const root = await rootFixture();
    await mkdir(path.join(root, 'k8s'), { recursive: true });
    await writeFile(
      path.join(root, 'k8s/deployment.yaml'),
      [
        'apiVersion: apps/v1',
        'kind: Deployment',
        'metadata:',
        '  annotations:',
        '    securityContext:',
        '      runAsNonRoot: true',
        'spec:',
        '  template:',
        '    spec:',
        '      containers:',
        '        - name: web',
        '          image: nginx:1.27'
      ].join('\n')
    );
    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.findings.map((finding) => finding.ruleId)).toEqual([
      'TLP-IAC-K8S-005'
    ]);
  });

  it('does not share pod security context between Kubernetes YAML documents', async () => {
    const root = await rootFixture();
    await mkdir(path.join(root, 'k8s'), { recursive: true });
    await writeFile(
      path.join(root, 'k8s/workloads.yaml'),
      [
        'apiVersion: v1',
        'kind: Pod',
        'metadata:',
        '  name: hardened',
        'spec:',
        '  securityContext:',
        '    runAsNonRoot: true',
        '  containers:',
        '    - name: app',
        '      image: app:1',
        '---',
        'apiVersion: v1',
        'kind: Pod',
        'metadata:',
        '  name: unconfigured',
        'spec:',
        '  containers:',
        '    - name: app',
        '      image: app:1'
      ].join('\n')
    );
    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.findings.map((finding) => finding.ruleId)).toEqual([
      'TLP-IAC-K8S-005'
    ]);
    expect(result.findings[0]?.location?.line).toBe(19);
  });

  it('requires immutable digests for docker:// actions and full SHAs for repository actions', async () => {
    const root = await rootFixture();
    await mkdir(path.join(root, '.github/workflows'), { recursive: true });
    await writeFile(
      path.join(root, '.github/workflows/actions.yml'),
      [
        'name: actions',
        'on: workflow_dispatch',
        'jobs:',
        '  test:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: docker://alpine:3.20',
        `      - uses: docker://alpine@sha256:${'a'.repeat(64)}`,
        `      - uses: actions/checkout@${'b'.repeat(40)}`
      ].join('\n')
    );
    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.findings.map((finding) => finding.ruleId)).toEqual([
      'TLP-IAC-GHA-002'
    ]);
    expect(result.findings[0]?.location?.line).toBe(7);
  });

  it('keeps pod security contexts scoped to their document and container overrides', async () => {
    const root = await rootFixture();
    await mkdir(path.join(root, 'k8s'), { recursive: true });
    await writeFile(
      path.join(root, 'k8s/pods.yaml'),
      [
        'apiVersion: v1',
        'kind: Pod',
        'spec:',
        '  securityContext:',
        '    runAsNonRoot: true',
        '  containers:',
        '    - name: override',
        '      image: app:1',
        '      securityContext:',
        '        runAsNonRoot: false',
        '---',
        'apiVersion: apps/v1',
        'kind: Deployment',
        'spec:',
        '  template:',
        '    spec:',
        '      containers:',
        '        - name: missing',
        '          image: app:2'
      ].join('\n')
    );
    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(
      result.findings
        .filter((item) => item.ruleId === 'TLP-IAC-K8S-005')
        .map((item) => item.location?.line)
    ).toEqual([8, 19]);
  });

  it('detects Terraform wildcard actions and resources together', async () => {
    const root = await rootFixture();
    await writeFile(
      path.join(root, 'iam.tf'),
      [
        'resource "aws_iam_policy" "wide" {',
        '  policy = jsonencode({',
        '    Statement = [{',
        '      Action = ["*"]',
        '      Resource = ["*"]',
        '    }]',
        '  })',
        '}'
      ].join('\n')
    );
    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.findings.map((item) => item.ruleId)).toEqual([
      'TLP-IAC-TF-003'
    ]);
  });

  it('checks public storage and ingress across AWS, Google Cloud and Azure resources', async () => {
    const root = await rootFixture();
    await writeFile(
      path.join(root, 'cloud.tf'),
      [
        'resource "google_storage_bucket_iam_member" "public" {',
        '  role = "roles/storage.objectViewer"',
        '  member = "allUsers"',
        '}',
        'resource "azurerm_storage_account" "public" {',
        '  allow_nested_items_to_be_public = true',
        '}',
        'resource "aws_vpc_security_group_ingress_rule" "ssh" {',
        '  cidr_ipv4 = "0.0.0.0/0"',
        '  from_port = 22',
        '  to_port = 22',
        '  ip_protocol = "tcp"',
        '}',
        'resource "google_compute_firewall" "ssh" {',
        '  source_ranges = ["0.0.0.0/0"]',
        '  allow { protocol = "tcp" ports = ["22"] }',
        '}',
        'resource "google_compute_firewall" "egress" {',
        '  direction = "EGRESS"',
        '  source_ranges = ["0.0.0.0/0"]',
        '  allow { protocol = "all" }',
        '}',
        'resource "azurerm_network_security_rule" "https" {',
        '  direction = "Inbound"',
        '  access = "Allow"',
        '  source_address_prefix = "Internet"',
        '  destination_port_range = "443"',
        '}',
        'resource "google_storage_bucket_iam_member" "private" {',
        '  member = "serviceAccount:app@example.invalid"',
        '}',
        'resource "aws_vpc_security_group_ingress_rule" "private" {',
        '  cidr_ipv4 = "10.0.0.0/8"',
        '  from_port = 22',
        '  to_port = 22',
        '  ip_protocol = "tcp"',
        '}',
        'resource "aws_vpc_security_group_ingress_rule" "all" {',
        '  cidr_ipv4 = "0.0.0.0/0"',
        '  ip_protocol = "-1"',
        '}'
      ].join('\n')
    );

    const result = await new InfrastructureAnalyzer().analyze({ root });

    expect(result.coverage.state).toBe('complete');
    expect(result.findings.map((item) => item.ruleId)).toEqual([
      'TLP-IAC-TF-006',
      'TLP-IAC-TF-007',
      'TLP-IAC-TF-002',
      'TLP-IAC-TF-002',
      'TLP-IAC-TF-004',
      'TLP-IAC-TF-002'
    ]);
    expect(result.findings.map((item) => item.location?.line)).toEqual([
      3, 6, 9, 16, 26, 39
    ]);
  });

  it('flags wildcard S3 principals only for allow policies', async () => {
    const root = await rootFixture();
    await writeFile(
      path.join(root, 'bucket.tf'),
      [
        'resource "aws_s3_bucket_policy" "public" {',
        '  policy = jsonencode({',
        '    Statement = [{ Effect = "Allow", Principal = "*" }]',
        '  })',
        '}',
        'resource "aws_s3_bucket_policy" "denied" {',
        '  policy = jsonencode({',
        '    Statement = [{ Effect = "Deny", Principal = "*" }]',
        '  })',
        '}'
      ].join('\n')
    );
    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.findings.map((item) => item.ruleId)).toEqual([
      'TLP-IAC-TF-005'
    ]);
  });

  it('reports malformed supported manifests as incomplete instead of clean', async () => {
    const root = await rootFixture();
    await mkdir(path.join(root, '.github/workflows'), { recursive: true });
    await writeFile(
      path.join(root, '.github/workflows/broken.yaml'),
      'jobs: [\n  test: {\n'
    );

    const result = await new InfrastructureAnalyzer().analyze({ root });
    expect(result.coverage).toMatchObject({
      state: 'failed',
      eligible: 1,
      scanned: 0,
      failed: 1
    });
  });
});
