import ts from 'typescript';
import type { Finding } from '../../contracts/finding.js';

const routeMethods = new Set(['get', 'post', 'put', 'patch', 'delete', 'all']);
const objectLookupMethods = new Set([
  'findbyid',
  'getbyid',
  'findbypk',
  'findunique',
  'finduniqueorthrow',
  'findfirst',
  'findfirstorthrow',
  'findone',
  'find'
]);
const explicitGuards = new Set([
  'authorizeResource',
  'assertOwner',
  'assertPermission',
  'assertTenant'
]);
const booleanGuards = new Set([
  'canAccess',
  'canAccessResource',
  'canRead',
  'canUpdate',
  'canDelete',
  'hasAccess',
  'owns',
  'isOwner',
  'belongsToTenant',
  'hasTenantAccess'
]);
const normalizedBooleanGuards = new Set(
  [...booleanGuards].map((name) => name.replace(/[_-]/gu, '').toLowerCase())
);

function callName(call: ts.CallExpression): string | undefined {
  const target = call.expression;
  return ts.isPropertyAccessExpression(target)
    ? target.name.text
    : ts.isIdentifier(target)
      ? target.text
      : undefined;
}

function isFunction(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return ts.isFunctionLike(node) && 'body' in node && Boolean(node.body);
}

function visitCurrentFunction(
  node: ts.Node,
  visit: (child: ts.Node) => void
): void {
  const walk = (child: ts.Node): void => {
    if (child !== node && ts.isFunctionLike(child)) return;
    visit(child);
    ts.forEachChild(child, walk);
  };
  ts.forEachChild(node, walk);
}

function requestObjectId(expression: ts.Expression): boolean {
  if (ts.isParenthesizedExpression(expression))
    return requestObjectId(expression.expression);
  if (ts.isPropertyAccessExpression(expression)) {
    const parts: string[] = [];
    let current: ts.Expression = expression;
    while (ts.isPropertyAccessExpression(current)) {
      parts.unshift(current.name.text);
      current = current.expression;
    }
    if (!ts.isIdentifier(current)) return false;
    const root = current.text;
    const request = root === 'req' || root === 'request';
    const context = root === 'ctx' || root === 'context';
    const offset = context && parts[0] === 'request' ? 1 : 0;
    return (
      (request || context) &&
      ['params', 'query', 'body'].includes(parts[offset] ?? '') &&
      parts.length > offset + 1
    );
  }
  if (ts.isElementAccessExpression(expression)) {
    return Boolean(
      expression.argumentExpression &&
      (ts.isStringLiteral(expression.argumentExpression) ||
        ts.isNumericLiteral(expression.argumentExpression)) &&
      requestObjectId(expression.expression)
    );
  }
  return false;
}

function hasRequestId(node: ts.Node): boolean {
  let found = false;
  const walk = (child: ts.Node): void => {
    if (found) return;
    if (ts.isExpression(child) && requestObjectId(child)) {
      found = true;
      return;
    }
    if (child !== node && ts.isFunctionLike(child)) return;
    ts.forEachChild(child, walk);
  };
  walk(node);
  return found;
}

function decoratorName(decorator: ts.Decorator): string | undefined {
  const expression = decorator.expression;
  const target = ts.isCallExpression(expression)
    ? expression.expression
    : expression;
  if (ts.isIdentifier(target)) return target.text.toLowerCase();
  return ts.isPropertyAccessExpression(target)
    ? target.name.text.toLowerCase()
    : undefined;
}

/** Returns direct values injected from framework-controlled request fields. */
function frameworkRequestParameters(
  handler: ts.FunctionLikeDeclaration
): ReadonlySet<string> {
  const names = new Set<string>();
  for (const parameter of handler.parameters) {
    const decorators = ts.canHaveDecorators(parameter)
      ? (ts.getDecorators(parameter) ?? [])
      : [];
    if (
      !decorators.some((decorator) =>
        ['param', 'query', 'body'].includes(decoratorName(decorator) ?? '')
      )
    )
      continue;
    const collect = (binding: ts.BindingName): void => {
      if (ts.isIdentifier(binding)) names.add(binding.text);
      else
        for (const element of binding.elements)
          if (!ts.isOmittedExpression(element)) collect(element.name);
    };
    collect(parameter.name);
  }
  return names;
}

function frameworkIdentityParameters(
  handler: ts.FunctionLikeDeclaration
): ReadonlySet<string> {
  const names = new Set<string>();
  for (const parameter of handler.parameters) {
    const decorators = ts.canHaveDecorators(parameter)
      ? (ts.getDecorators(parameter) ?? [])
      : [];
    if (
      !decorators.some((decorator) =>
        [
          'currentuser',
          'currentprincipal',
          'principal',
          'currenttenant'
        ].includes(decoratorName(decorator) ?? '')
      )
    )
      continue;
    if (ts.isIdentifier(parameter.name)) names.add(parameter.name.text);
  }
  return names;
}

function bindingIdentifiers(binding: ts.BindingName): string[] {
  if (ts.isIdentifier(binding)) return [binding.text];
  return binding.elements.flatMap((element) =>
    ts.isOmittedExpression(element) ? [] : bindingIdentifiers(element.name)
  );
}

function identityAliasTarget(name: string): boolean {
  return /^(?:id|auth|account|currenttenant|currentuser|organization|owner|principal|role|tenant|user|workspace)(?:id|key)?$/iu.test(
    name.replace(/[_-]/gu, '')
  );
}

/** Resolves only unique, immutable local aliases of an authenticated identity. */
function authenticatedIdentityAliases(
  handler: ts.FunctionLikeDeclaration,
  initial: ReadonlySet<string>
): ReadonlySet<string> {
  const declarations = new Map<string, number>();
  const assignments = new Set<string>();
  const bindings: Array<{ target: string; expression: ts.Expression }> = [];
  for (const parameter of handler.parameters) {
    for (const name of bindingIdentifiers(parameter.name))
      declarations.set(name, (declarations.get(name) ?? 0) + 1);
  }

  visitCurrentFunction(handler, (node) => {
    if (ts.isVariableDeclaration(node)) {
      const targets = bindingIdentifiers(node.name);
      for (const name of targets)
        declarations.set(name, (declarations.get(name) ?? 0) + 1);
      if (node.initializer)
        for (const target of targets)
          bindings.push({ target, expression: node.initializer });
      return;
    }
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left) &&
      ts.isExpressionStatement(node.parent)
    )
      assignments.add(node.left.text);
  });

  const identities = new Set(
    [...initial].filter((name) => !assignments.has(name))
  );
  const dependents = new Map<string, Set<string>>();
  const validTargets = new Set<string>();
  for (const binding of bindings) {
    if (
      !identityAliasTarget(binding.target) ||
      declarations.get(binding.target) !== 1 ||
      assignments.has(binding.target) ||
      identities.has(binding.target)
    )
      continue;
    validTargets.add(binding.target);
    if (authIdentity(binding.expression, identities)) {
      identities.add(binding.target);
      continue;
    }
    const references = new Set<string>();
    const visit = (node: ts.Node): void => {
      if (ts.isIdentifier(node) && isIdentifierReference(node))
        references.add(node.text);
      ts.forEachChild(node, visit);
    };
    visit(binding.expression);
    for (const source of references) {
      const targets = dependents.get(source) ?? new Set<string>();
      targets.add(binding.target);
      dependents.set(source, targets);
    }
  }

  const queue = [...identities];
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const source = queue[cursor];
    if (!source) continue;
    for (const target of dependents.get(source) ?? []) {
      if (identities.has(target) || !validTargets.has(target)) continue;
      identities.add(target);
      queue.push(target);
    }
  }
  return identities;
}

function authIdentity(
  expression: ts.Expression,
  identityParameters: ReadonlySet<string> = new Set()
): boolean {
  let base: ts.Expression = expression;
  while (ts.isPropertyAccessExpression(base)) base = base.expression;
  if (ts.isIdentifier(base) && identityParameters.has(base.text)) return true;
  const text = expression.getText();
  return /(?:req|request|ctx|context)\s*\.\s*(?:user|auth|principal)|\bcurrentUser\b|\bcurrentTenant\b/iu.test(
    text
  );
}

function containsAuthenticatedIdentity(
  node: ts.Node,
  identityParameters: ReadonlySet<string> = new Set()
): boolean {
  let found = false;
  const walk = (child: ts.Node): void => {
    if (found) return;
    if (ts.isExpression(child) && authIdentity(child, identityParameters)) {
      found = true;
      return;
    }
    ts.forEachChild(child, walk);
  };
  walk(node);
  return found;
}

function propertyKey(property: ts.PropertyAssignment): string | undefined {
  const name = property.name;
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return undefined;
}

/**
 * Ownership must restrict the root resource lookup, not an unrelated include,
 * ordering clause or nested relation projection. In a disjunction EVERY
 * branch needs a scoped predicate; one guarded branch does not protect the
 * unguarded alternatives. This is a bounded syntactic proof, not runtime auth.
 */
function ownershipInsideWhere(
  node: ts.Node,
  identities: ReadonlySet<string>,
  depth = 0
): boolean {
  if (depth > 32 || !ts.isObjectLiteralExpression(node)) return false;
  for (const property of node.properties) {
    if (ts.isShorthandPropertyAssignment(property)) {
      if (
        /^(?:userId|ownerId|tenantId|accountId|organizationId|workspaceId)$/iu.test(
          property.name.text
        ) &&
        authIdentity(property.name, identities)
      )
        return true;
      continue;
    }
    if (!ts.isPropertyAssignment(property)) continue;
    const key = propertyKey(property);
    if (!key) continue;
    if (
      /^(?:userId|ownerId|tenantId|accountId|organizationId|workspaceId)$/iu.test(
        key
      ) &&
      authIdentity(property.initializer, identities)
    )
      return true;
    if (/^(?:AND|and)$/u.test(key)) {
      const value = property.initializer;
      const clauses = ts.isArrayLiteralExpression(value)
        ? value.elements
        : [value];
      if (
        clauses.some((part) =>
          ownershipInsideWhere(part, identities, depth + 1)
        )
      )
        return true;
    }
    if (/^(?:OR|or)$/u.test(key)) {
      const value = property.initializer;
      if (
        ts.isArrayLiteralExpression(value) &&
        value.elements.length > 0 &&
        value.elements.every((part) =>
          ownershipInsideWhere(part, identities, depth + 1)
        )
      )
        return true;
    }
    // Related ownership and explicit share grants can constrain the base
    // record, but a side-loaded include/select relation cannot.
    if (
      /^(?:tenant|account|organization|workspace|owner|user|sharedWith|collaborators|members|accessGrants)$/iu.test(
        key
      ) &&
      ts.isObjectLiteralExpression(property.initializer) &&
      containsAuthenticatedIdentity(property.initializer, identities)
    )
      return true;
  }
  return false;
}

function hasOwnershipPredicate(
  node: ts.Node,
  identityParameters: ReadonlySet<string> = new Set()
): boolean {
  if (!ts.isObjectLiteralExpression(node)) return false;
  for (const property of node.properties) {
    if (
      ts.isPropertyAssignment(property) &&
      propertyKey(property) === 'where' &&
      ownershipInsideWhere(property.initializer, identityParameters)
    )
      return true;
  }
  // Some supported query APIs take the filter object directly.
  return ownershipInsideWhere(node, identityParameters);
}

function hasRoleOrOwnershipGuard(
  handler: ts.FunctionLikeDeclaration,
  registrationGuards: readonly ts.Expression[],
  helperFunctions: ReadonlyMap<string, readonly ts.FunctionLikeDeclaration[]>,
  resourceMiddlewareFunctions:
    WeakMap<ts.Identifier, ts.FunctionLikeDeclaration> | undefined,
  beforePosition: number,
  requestParameters: ReadonlySet<string>,
  identityParameters: ReadonlySet<string>
): boolean {
  const decorators = ts.canHaveDecorators(handler)
    ? (ts.getDecorators(handler) ?? [])
    : [];
  if (
    decorators.some((decorator) =>
      ['authorize', 'authorizeresource'].includes(
        decoratorName(decorator) ?? ''
      )
    )
  )
    return true;
  if (
    registrationGuards.some(
      (guard) =>
        isResourceAuthorizationCall(
          guard,
          requestParameters,
          identityParameters
        ) ||
        isVerifiedResourceMiddleware(
          guard,
          helperFunctions,
          resourceMiddlewareFunctions
        )
    )
  )
    return true;
  let guarded = false;
  visitCurrentFunction(handler, (node) => {
    if (guarded || node.getStart() >= beforePosition) return;
    if (ts.isCallExpression(node)) {
      if (
        node.getEnd() <= beforePosition &&
        isResourceAuthorizationCall(node, requestParameters, identityParameters)
      ) {
        guarded = true;
        return;
      }
    }
    if (!ts.isIfStatement(node) || node.getEnd() > beforePosition) return;
    const guardCondition = unwrapBooleanCondition(node.expression);
    if (guardCondition) {
      const name = callName(guardCondition.call);
      const checksIdentity = guardCondition.call.arguments.some((argument) =>
        authIdentity(argument, identityParameters)
      );
      if (
        isBooleanOwnershipGuard(
          guardCondition.call,
          name,
          requestParameters,
          identityParameters
        ) &&
        checksIdentity
      ) {
        const deniedBranch = guardCondition.negated
          ? node.thenStatement
          : node.elseStatement;
        if (deniedBranch && exitsBeforeContinuation(deniedBranch)) {
          guarded = true;
          return;
        }
      }
    }
  });
  return guarded;
}

function isVerifiedResourceMiddleware(
  expression: ts.Expression,
  helperFunctions: ReadonlyMap<string, readonly ts.FunctionLikeDeclaration[]>,
  resourceMiddlewareFunctions?: WeakMap<
    ts.Identifier,
    ts.FunctionLikeDeclaration
  >
): boolean {
  if (!ts.isIdentifier(expression)) return false;
  const helper = resourceMiddlewareFunctions
    ? resourceMiddlewareFunctions.get(expression)
    : helperFunctions.get(expression.text)?.length === 1
      ? helperFunctions.get(expression.text)?.[0]
      : undefined;
  if (!helper) return false;
  const requests = requestControlledNames(
    helper,
    frameworkRequestParameters(helper)
  );
  const identities = authenticatedIdentityAliases(
    helper,
    frameworkIdentityParameters(helper)
  );
  let verified = false;
  visitCurrentFunction(helper, (node) => {
    if (verified) return;
    if (ts.isCallExpression(node)) {
      if (isResourceAuthorizationCall(node, requests, identities)) {
        verified = true;
        return;
      }
    }
    if (!ts.isIfStatement(node)) return;
    const condition = unwrapBooleanCondition(node.expression);
    if (!condition) return;
    const name = callName(condition.call);
    if (!isBooleanOwnershipGuard(condition.call, name, requests, identities))
      return;
    const denied = condition.negated ? node.thenStatement : node.elseStatement;
    if (denied && exitsBeforeContinuation(denied)) verified = true;
  });
  return verified;
}

/** A guard must bind an authenticated identity to this requested resource. */
function isResourceAuthorizationCall(
  expression: ts.Expression,
  requestParameters: ReadonlySet<string>,
  identityParameters: ReadonlySet<string>
): boolean {
  if (!ts.isCallExpression(expression)) return false;
  const name = callName(expression);
  if (!name || !explicitGuards.has(name)) return false;
  const checksIdentity = expression.arguments.some((argument) =>
    authIdentity(argument, identityParameters)
  );
  const checksRequestedObject = expression.arguments.some(
    (argument) =>
      requestObjectId(argument) ||
      hasRequestId(argument) ||
      hasRequestParameter(argument, requestParameters)
  );
  return checksIdentity && checksRequestedObject;
}

function isBooleanOwnershipGuard(
  call: ts.CallExpression,
  name: string | undefined,
  requestParameters: ReadonlySet<string>,
  identityParameters: ReadonlySet<string>
): boolean {
  if (!name) return false;
  const normalized = name.replace(/[_-]/gu, '').toLowerCase();
  const recognized =
    normalizedBooleanGuards.has(normalized) ||
    /^(?:(?:can|has|is|owns|belongsto|check|authorize|assert|ensure).*(?:access|owner|permission|tenant|resource|record|project|document|member)|(?:is|has).*member)$/iu.test(
      normalized
    );
  if (!recognized) return false;
  const checksIdentity = call.arguments.some((argument) =>
    authIdentity(argument, identityParameters)
  );
  const checksRequestedObject = call.arguments.some(
    (argument) =>
      requestObjectId(argument) ||
      hasRequestId(argument) ||
      hasRequestParameter(argument, requestParameters)
  );
  return checksIdentity && checksRequestedObject;
}

function unwrapBooleanCondition(
  expression: ts.Expression
): { call: ts.CallExpression; negated: boolean } | undefined {
  const unwrap = (value: ts.Expression): ts.Expression => {
    let current = value;
    while (
      ts.isParenthesizedExpression(current) ||
      ts.isAwaitExpression(current)
    )
      current = current.expression;
    return current;
  };
  let current = unwrap(expression);
  let negated = false;
  if (
    ts.isPrefixUnaryExpression(current) &&
    current.operator === ts.SyntaxKind.ExclamationToken
  ) {
    negated = true;
    current = unwrap(current.operand);
  }
  return ts.isCallExpression(current) ? { call: current, negated } : undefined;
}

function exitsBeforeContinuation(node: ts.Statement): boolean {
  if (ts.isReturnStatement(node) || ts.isThrowStatement(node)) return true;
  if (ts.isBlock(node)) {
    const last = node.statements.at(-1);
    return last ? exitsBeforeContinuation(last) : false;
  }
  if (ts.isIfStatement(node))
    return Boolean(
      node.elseStatement &&
      exitsBeforeContinuation(node.thenStatement) &&
      exitsBeforeContinuation(node.elseStatement)
    );
  return false;
}

function isRouteHandler(node: ts.FunctionLikeDeclaration): boolean {
  const name =
    'name' in node && node.name && ts.isIdentifier(node.name)
      ? node.name.text
      : undefined;
  if (
    name &&
    ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(name)
  )
    return Boolean(
      ts.isFunctionDeclaration(node) &&
      node.modifiers?.some(
        (modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword
      )
    );
  const parent = node.parent;
  if (
    ts.isCallExpression(parent) &&
    parent.arguments.includes(node as ts.Expression)
  ) {
    const method = callName(parent)?.toLowerCase();
    if (method && routeMethods.has(method)) return true;
  }
  if (ts.isMethodDeclaration(node)) {
    const decorators = ts.canHaveDecorators(node)
      ? (ts.getDecorators(node) ?? [])
      : [];
    return decorators.some((decorator) => {
      const expression = decorator.expression;
      const target = ts.isCallExpression(expression)
        ? expression.expression
        : expression;
      return (
        ts.isIdentifier(target) && routeMethods.has(target.text.toLowerCase())
      );
    });
  }
  return false;
}

function hasRequestControlledLookup(
  call: ts.CallExpression,
  requestParameters: ReadonlySet<string>
): boolean {
  const name = callName(call)?.toLowerCase();
  if (!name || !objectLookupMethods.has(name)) return false;
  return call.arguments.some((argument) =>
    ts.isObjectLiteralExpression(argument)
      ? hasRequestId(argument) ||
        hasRequestParameter(argument, requestParameters)
      : requestObjectId(argument) ||
        hasRequestParameter(argument, requestParameters)
  );
}

function hasRequestParameter(
  node: ts.Node,
  requestParameters: ReadonlySet<string>
): boolean {
  let found = false;
  const visit = (current: ts.Node): void => {
    if (found) return;
    if (
      ts.isIdentifier(current) &&
      isIdentifierReference(current) &&
      requestParameters.has(current.text)
    ) {
      found = true;
      return;
    }
    if (current !== node && ts.isFunctionLike(current)) return;
    ts.forEachChild(current, visit);
  };
  visit(node);
  return found;
}

function isIdentifierReference(node: ts.Identifier): boolean {
  const parent = node.parent;
  return !(
    (ts.isPropertyAccessExpression(parent) && parent.name === node) ||
    (ts.isPropertyAssignment(parent) && parent.name === node) ||
    (ts.isMethodDeclaration(parent) && parent.name === node) ||
    (ts.isFunctionDeclaration(parent) && parent.name === node) ||
    (ts.isVariableDeclaration(parent) && parent.name === node) ||
    (ts.isParameter(parent) && parent.name === node)
  );
}

function requestContainer(expression: ts.Expression): boolean {
  if (ts.isParenthesizedExpression(expression))
    return requestContainer(expression.expression);
  if (!ts.isPropertyAccessExpression(expression)) return false;
  const parts: string[] = [];
  let current: ts.Expression = expression;
  while (ts.isPropertyAccessExpression(current)) {
    parts.unshift(current.name.text);
    current = current.expression;
  }
  if (!ts.isIdentifier(current)) return false;
  const context = current.text === 'ctx' || current.text === 'context';
  const offset = context && parts[0] === 'request' ? 1 : 0;
  return (
    ['req', 'request', 'ctx', 'context'].includes(current.text) &&
    ['params', 'query', 'body'].includes(parts[offset] ?? '') &&
    parts.length === offset + 1
  );
}

function requestControlledNames(
  handler: ts.FunctionLikeDeclaration,
  initialNames: ReadonlySet<string>
): ReadonlySet<string> {
  const names = new Set(initialNames);
  const dependents = new Map<string, Set<string>>();
  const seeds = new Set<string>();
  const bindingNames = (binding: ts.BindingName): string[] => {
    if (ts.isIdentifier(binding)) return [binding.text];
    return binding.elements.flatMap((element) =>
      ts.isOmittedExpression(element) ? [] : bindingNames(element.name)
    );
  };
  const referencedNames = (expression: ts.Expression): Set<string> => {
    const found = new Set<string>();
    const visit = (child: ts.Node): void => {
      if (child !== expression && ts.isFunctionLike(child)) return;
      if (ts.isIdentifier(child) && isIdentifierReference(child))
        found.add(child.text);
      ts.forEachChild(child, visit);
    };
    visit(expression);
    return found;
  };
  const registerFlow = (
    targetNames: readonly string[],
    expression: ts.Expression
  ): void => {
    const references = referencedNames(expression);
    if (
      requestObjectId(expression) ||
      requestContainer(expression) ||
      [...references].some((name) => names.has(name))
    ) {
      for (const name of targetNames) seeds.add(name);
      return;
    }
    for (const source of references) {
      const values = dependents.get(source) ?? new Set<string>();
      for (const target of targetNames) values.add(target);
      dependents.set(source, values);
    }
  };

  visitCurrentFunction(handler, (node) => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      registerFlow(bindingNames(node.name), node.initializer);
      return;
    }
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left) &&
      ts.isExpressionStatement(node.parent)
    )
      registerFlow([node.left.text], node.right);
  });

  for (const name of seeds) {
    if (names.has(name)) continue;
    names.add(name);
  }
  const queue = [...names];
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const source = queue[cursor];
    if (!source) continue;
    for (const target of dependents.get(source) ?? []) {
      if (names.has(target)) continue;
      names.add(target);
      queue.push(target);
    }
  }
  return names;
}

function createCandidate(
  sourceFile: ts.SourceFile,
  lookup: ts.CallExpression
): Finding {
  const { line, character } = sourceFile.getLineAndCharacterOfPosition(
    lookup.getStart(sourceFile)
  );
  const location = {
    file: sourceFile.fileName,
    line: line + 1,
    column: character + 1
  };
  const fingerprint = `TLP-AUTH-001:${location.file}:${location.line}:${location.column}`;
  return {
    id: fingerprint,
    ruleId: 'TLP-AUTH-001',
    title: 'Request-controlled object lookup without visible ownership check',
    category: 'authorization',
    severity: 'medium',
    confidence: 'low',
    message:
      'A recognized route handler loads an object using a request-controlled identifier, but this handler contains no visible resource ownership, tenant, or permission check. Authentication and role checks alone do not establish access to this object.',
    source: 'typescript-ast-authorization-heuristic',
    location,
    evidence: [
      {
        summary:
          '[request-controlled object identifier; source and record values redacted]',
        fingerprint
      }
    ],
    remediation: {
      summary:
        'Scope the object query by the authenticated owner or tenant, or enforce a resource-specific authorization check before returning or mutating the object.'
    },
    metadata: {
      analysisModel: 'same-handler-resource-authorization-heuristic-v2',
      limitation:
        'Cross-file middleware, policy engines, trusted helper implementations, implicit policies and shared-resource grants may not be resolved; manually verify this low-confidence candidate.'
    }
  };
}

/** Finds low-confidence BOLA candidates in a small set of recognized route shapes. */
export function analyzeAuthorizationSource(
  filePath: string,
  content: string,
  capturedSourceFile?: ts.SourceFile,
  relatedSourceFiles: readonly ts.SourceFile[] = [],
  resourceMiddlewareFunctions?: WeakMap<
    ts.Identifier,
    ts.FunctionLikeDeclaration
  >
): Finding[] {
  const sourceFile =
    capturedSourceFile ??
    ts.createSourceFile(
      filePath,
      content,
      ts.ScriptTarget.Latest,
      true,
      filePath.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS
    );
  const handlers = new Map<ts.FunctionLikeDeclaration, ts.Expression[]>();
  const referencedHandlers = new Map<string, ts.Expression[]>();
  const helperFunctions = new Map<string, ts.FunctionLikeDeclaration[]>();
  for (const related of new Set([sourceFile, ...relatedSourceFiles])) {
    const collectHelpers = (node: ts.Node): void => {
      if (isFunction(node) && ts.isFunctionDeclaration(node) && node.name) {
        const declarations = helperFunctions.get(node.name.text) ?? [];
        declarations.push(node);
        helperFunctions.set(node.name.text, declarations);
      }
      ts.forEachChild(node, collectHelpers);
    };
    collectHelpers(related);
  }
  const routeCalls: ts.CallExpression[] = [];
  const collectRoutes = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const method = callName(node)?.toLowerCase();
      if (method && routeMethods.has(method)) routeCalls.push(node);
    }
    ts.forEachChild(node, collectRoutes);
  };
  collectRoutes(sourceFile);
  for (const route of routeCalls) {
    const handlerIndex = route.arguments.findIndex(
      (argument) =>
        ts.isArrowFunction(argument) || ts.isFunctionExpression(argument)
    );
    const guards = route.arguments
      .slice(0, handlerIndex < 0 ? undefined : handlerIndex)
      .filter((argument) => !ts.isStringLiteral(argument));
    for (const argument of route.arguments) {
      if (ts.isArrowFunction(argument) || ts.isFunctionExpression(argument))
        handlers.set(argument, guards);
      else if (ts.isIdentifier(argument))
        referencedHandlers.set(argument.text, guards);
    }
  }
  const candidates: Finding[] = [];
  const visited = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (isFunction(node)) {
      const functionName =
        'name' in node && node.name && ts.isIdentifier(node.name)
          ? node.name.text
          : undefined;
      const registrationGuards =
        handlers.get(node) ??
        (functionName ? referencedHandlers.get(functionName) : undefined) ??
        [];
      if (
        handlers.has(node) ||
        isRouteHandler(node) ||
        registrationGuards.length > 0
      ) {
        const requestParameters = requestControlledNames(
          node,
          frameworkRequestParameters(node)
        );
        const identityParameters = authenticatedIdentityAliases(
          node,
          frameworkIdentityParameters(node)
        );
        visitCurrentFunction(node, (child) => {
          if (
            !ts.isCallExpression(child) ||
            !hasRequestControlledLookup(child, requestParameters)
          )
            return;
          if (
            child.arguments.some((argument) =>
              hasOwnershipPredicate(argument, identityParameters)
            ) ||
            hasRoleOrOwnershipGuard(
              node,
              registrationGuards,
              helperFunctions,
              resourceMiddlewareFunctions,
              child.getStart(),
              requestParameters,
              identityParameters
            )
          )
            return;
          const key = `${child.getStart(sourceFile)}:${child.getEnd()}`;
          if (visited.has(key)) return;
          visited.add(key);
          candidates.push(createCandidate(sourceFile, child));
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return candidates;
}
