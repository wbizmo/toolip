import { describe, expect, it } from 'vitest';
import { analyzeAstSource } from '../../src/analyzers/ast/source-analysis.js';

describe('route authorization candidates', () => {
  it('flags an Express object lookup by a request-controlled ID without a visible policy check', () => {
    const findings = analyzeAstSource(
      'src/routes/users.ts',
      [
        "router.get('/users/:id', async (req, res) => {",
        '  const user = await prisma.user.findUnique({ where: { id: req.params.id } });',
        '  return res.json(user);',
        '});'
      ].join('\n')
    );
    const candidate = findings.find(
      (finding) => finding.ruleId === 'TLP-AUTH-001'
    );
    expect(candidate).toMatchObject({
      category: 'authorization',
      severity: 'medium',
      confidence: 'low',
      location: { file: 'src/routes/users.ts', line: 2 }
    });
    expect(candidate?.evidence?.[0]?.summary).not.toContain('req.params');
    expect(candidate?.metadata?.limitation).toContain('Cross-file middleware');
  });

  it('follows bounded local aliases and destructuring from request identifiers', () => {
    const directAlias = analyzeAstSource(
      'src/routes/alias.ts',
      [
        "router.get('/users/:id', async (req, res) => {",
        '  const params = req.params;',
        '  const requestedId = params.id;',
        '  const alias = requestedId;',
        '  return users.findById(alias);',
        '});'
      ].join('\n')
    );
    const destructured = analyzeAstSource(
      'src/routes/destructure.ts',
      [
        "router.get('/users/:id', async (req, res) => {",
        '  const { id: requestedId } = req.params;',
        '  return users.findById(requestedId);',
        '});'
      ].join('\n')
    );
    const constant = analyzeAstSource(
      'src/routes/constant.ts',
      [
        "router.get('/users/:id', async (req, res) => {",
        "  const requestedId = 'fixed-record';",
        '  return users.findById(requestedId);',
        '});'
      ].join('\n')
    );

    expect(
      directAlias.some((finding) => finding.ruleId === 'TLP-AUTH-001')
    ).toBe(true);
    expect(
      destructured.some((finding) => finding.ruleId === 'TLP-AUTH-001')
    ).toBe(true);
    expect(constant.some((finding) => finding.ruleId === 'TLP-AUTH-001')).toBe(
      false
    );
  });

  it('does not flag a nested tenant predicate or route-level role guard', () => {
    const tenantGuard = analyzeAstSource(
      'src/routes/invoices.ts',
      [
        "router.get('/invoices/:id', async (req, res) => {",
        '  const invoice = await prisma.invoice.findFirst({',
        '    where: { id: req.params.id, tenant: { id: req.user.tenantId } }',
        '  });',
        '  return res.json(invoice);',
        '});'
      ].join('\n')
    );
    const roleGuard = analyzeAstSource(
      'src/routes/admin.ts',
      [
        "router.get('/admin/:id', requireRole('admin'), async (req, res) => {",
        '  const record = await repository.findById(req.params.id);',
        '  return res.json(record);',
        '});'
      ].join('\n')
    );
    expect(
      tenantGuard.some((finding) => finding.ruleId === 'TLP-AUTH-001')
    ).toBe(false);
    expect(roleGuard.some((finding) => finding.ruleId === 'TLP-AUTH-001')).toBe(
      false
    );
  });

  it('recognizes unique authenticated tenant aliases and rejects ambiguous ones', () => {
    const scoped = analyzeAstSource(
      'src/routes/invoices.ts',
      [
        "router.get('/tenants/:tenantId/invoices/:id', async (req, res) => {",
        '  const tenantId = req.user.tenantId;',
        '  const invoiceId = req.params.id;',
        '  return prisma.invoice.findFirst({ where: { id: invoiceId, tenantId } });',
        '});'
      ].join('\n')
    );
    const shadowed = analyzeAstSource(
      'src/routes/ambiguous.ts',
      [
        "router.get('/tenants/:tenantId/invoices/:id', async (req, res) => {",
        '  const tenantId = req.user.tenantId;',
        '  {',
        '    const tenantId = req.query.tenantId;',
        '    return prisma.invoice.findFirst({ where: { id: req.params.id, tenantId } });',
        '  }',
        '});'
      ].join('\n')
    );
    const reassigned = analyzeAstSource(
      'src/routes/reassigned.ts',
      [
        "router.get('/tenants/:tenantId/invoices/:id', async (req, res) => {",
        '  let tenantId = req.user.tenantId;',
        '  tenantId = req.query.tenantId;',
        '  return prisma.invoice.findFirst({ where: { id: req.params.id, tenantId } });',
        '});'
      ].join('\n')
    );

    expect(scoped.some((finding) => finding.ruleId === 'TLP-AUTH-001')).toBe(
      false
    );
    expect(
      shadowed.some((finding) => finding.ruleId === 'TLP-AUTH-001')
    ).toBe(true);
    expect(
      reassigned.some((finding) => finding.ruleId === 'TLP-AUTH-001')
    ).toBe(true);
  });

  it('does not treat ordinary non-route helpers as endpoint authorization findings', () => {
    const findings = analyzeAstSource(
      'src/services/users.ts',
      'export async function loadUser(id: string) { return prisma.user.findUnique({ where: { id } }); }'
    );
    expect(findings.some((finding) => finding.ruleId === 'TLP-AUTH-001')).toBe(
      false
    );
  });

  it('recognizes Nest route parameters, injected identities, tenant scopes and role decorators', () => {
    const findings = analyzeAstSource(
      'src/users.controller.ts',
      `class UsersController {
  @Get(':id')
  async load(@Param('id') id: string) {
    return this.users.findById(id);
  }

  @Get(':id')
  async scoped(@Param('id') id: string, @CurrentUser() user: User) {
    return this.users.findFirst({ where: { id, tenantId: user.tenantId } });
  }

  @Roles('admin')
  @Get(':id')
  async adminOnly(@Param('id') id: string) {
    return this.users.findById(id);
  }
}`
    );
    expect(
      findings
        .filter((finding) => finding.ruleId === 'TLP-AUTH-001')
        .map((finding) => finding.location?.line)
    ).toEqual([4]);
  });

  it('does not let an authorization check after the lookup hide the lookup', () => {
    const findings = analyzeAstSource(
      'src/routes/late-check.ts',
      [
        "router.get('/records/:id', async (req, res) => {",
        '  const record = await records.findById(req.params.id);',
        '  if (req.user.isAdmin) return res.status(403).end();',
        '  return res.json(record);',
        '});'
      ].join('\n')
    );

    expect(findings.some((finding) => finding.ruleId === 'TLP-AUTH-001')).toBe(
      true
    );
  });

  it('does not let an allow branch before the lookup count as a denial guard', () => {
    const findings = analyzeAstSource(
      'src/routes/incorrect-guard.ts',
      [
        "router.get('/records/:id', async (req, res) => {",
        '  if (req.user.isAdmin) return res.status(403).end();',
        '  const record = await records.findById(req.params.id);',
        '  return res.json(record);',
        '});'
      ].join('\n')
    );

    expect(findings.some((finding) => finding.ruleId === 'TLP-AUTH-001')).toBe(
      true
    );
  });

  it('accepts a fail-closed role check that exits before the lookup', () => {
    const findings = analyzeAstSource(
      'src/routes/early-denial.ts',
      [
        "router.get('/records/:id', async (req, res) => {",
        '  if (!req.user.isAdmin) return res.status(403).end();',
        '  const record = await records.findById(req.params.id);',
        '  return res.json(record);',
        '});'
      ].join('\n')
    );

    expect(findings.some((finding) => finding.ruleId === 'TLP-AUTH-001')).toBe(
      false
    );
  });

  it('does not treat an unused authorization boolean as a guard', () => {
    const findings = analyzeAstSource(
      'src/routes/ignored-guard.ts',
      [
        "router.get('/records/:id', async (req, res) => {",
        '  canAccess(req.user, req.params.id);',
        '  const record = await records.findById(req.params.id);',
        '  return res.json(record);',
        '});'
      ].join('\n')
    );
    expect(findings.some((finding) => finding.ruleId === 'TLP-AUTH-001')).toBe(
      true
    );
  });

  it('accepts boolean ownership checks only when the denied branch exits', () => {
    const denied = analyzeAstSource(
      'src/routes/owner-check.ts',
      [
        "router.get('/records/:id', async (req, res) => {",
        '  if (!owns(req.user, req.params.id)) return res.status(403).end();',
        '  const record = await records.findById(req.params.id);',
        '  return res.json(record);',
        '});'
      ].join('\n')
    );
    const ignored = analyzeAstSource(
      'src/routes/allow-only.ts',
      [
        "router.get('/records/:id', async (req, res) => {",
        '  if (canAccess(req.user, req.params.id)) { logAccess(); }',
        '  const record = await records.findById(req.params.id);',
        '  return res.json(record);',
        '});'
      ].join('\n')
    );
    expect(denied.some((finding) => finding.ruleId === 'TLP-AUTH-001')).toBe(
      false
    );
    expect(ignored.some((finding) => finding.ruleId === 'TLP-AUTH-001')).toBe(
      true
    );
  });

  it('recognizes resource-specific indirect ownership helpers but not authentication-only guards', () => {
    const guarded = analyzeAstSource(
      'src/routes/shared.ts',
      [
        "router.get('/workspaces/:workspaceId/documents/:id', async (req, res) => {",
        '  if (!(await canReadWorkspaceDocument(req.user, req.params.workspaceId, req.params.id))) {',
        '    throw new Error("forbidden");',
        '  }',
        '  return documents.findById(req.params.id);',
        '});'
      ].join('\n')
    );
    const authenticationOnly = analyzeAstSource(
      'src/routes/authentication-only.ts',
      [
        "router.get('/documents/:id', async (req, res) => {",
        '  if (!(await isAuthenticated(req.user))) throw new Error("unauthorized");',
        '  return documents.findById(req.params.id);',
        '});'
      ].join('\n')
    );

    expect(guarded.some((finding) => finding.ruleId === 'TLP-AUTH-001')).toBe(
      false
    );
    expect(
      authenticationOnly.some((finding) => finding.ruleId === 'TLP-AUTH-001')
    ).toBe(true);
  });
});
