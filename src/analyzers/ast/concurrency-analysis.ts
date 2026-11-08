import ts from 'typescript';
import type { Finding } from '../../contracts/finding.js';

const fileCheckMethods = new Set([
  'access',
  'accessSync',
  'existsSync',
  'stat',
  'statSync',
  'lstat',
  'lstatSync'
]);
const fileUseMethods = new Set([
  'readFile',
  'readFileSync',
  'writeFile',
  'writeFileSync',
  'appendFile',
  'appendFileSync',
  'unlink',
  'unlinkSync',
  'rename',
  'renameSync'
]);
const objectReadMethods = new Set([
  'findUnique',
  'findUniqueOrThrow',
  'findFirst',
  'findFirstOrThrow',
  'findOne',
  'findById',
  'getById'
]);
const objectWriteMethods = new Set([
  'update',
  'updateMany',
  'increment',
  'decrement',
  'save',
  'replace'
]);

type FindingKind =
  | 'filesystem-check-then-use'
  | 'non-atomic-read-check-write'
  | 'unbounded-concurrent-mutation';

function methodName(call: ts.CallExpression): string | undefined {
  const target = call.expression;
  return ts.isPropertyAccessExpression(target)
    ? target.name.text
    : ts.isIdentifier(target)
      ? target.text
      : undefined;
}

function callArgument(call: ts.CallExpression): ts.Expression | undefined {
  return call.arguments[0];
}

function unwrapCall(
  expression: ts.Expression | undefined
): ts.CallExpression | undefined {
  let current = expression;
  while (
    current &&
    (ts.isAwaitExpression(current) || ts.isParenthesizedExpression(current))
  ) {
    current = ts.isAwaitExpression(current)
      ? current.expression
      : current.expression;
  }
  return current && ts.isCallExpression(current) ? current : undefined;
}

function pathKey(expression: ts.Expression | undefined): string | undefined {
  if (!expression) return undefined;
  return expression
    .getText()
    .replace(/\s+/gu, '')
    .replace(/^\((.*)\)$/u, '$1');
}

function mentionsIdentifier(node: ts.Node, name: string): boolean {
  let found = false;
  const walk = (child: ts.Node): void => {
    if (found || (child !== node && ts.isFunctionLike(child))) return;
    if (
      ts.isIdentifier(child) &&
      child.text === name &&
      !(
        (ts.isPropertyAccessExpression(child.parent) &&
          child.parent.name === child) ||
        (ts.isPropertyAssignment(child.parent) && child.parent.name === child)
      )
    ) {
      found = true;
      return;
    }
    ts.forEachChild(child, walk);
  };
  walk(node);
  return found;
}

function containsVersionPredicate(node: ts.Node): boolean {
  let found = false;
  const walk = (child: ts.Node): void => {
    if (found) return;
    if (
      ts.isPropertyAssignment(child) &&
      (ts.isIdentifier(child.name) || ts.isStringLiteral(child.name)) &&
      /^(?:version|revision|etag|updatedAt|rowVersion)$/iu.test(child.name.text)
    ) {
      found = true;
      return;
    }
    if (child !== node && ts.isFunctionLike(child)) return;
    ts.forEachChild(child, walk);
  };
  walk(node);
  return found;
}

function hasAtomicOperation(node: ts.Node): boolean {
  let found = false;
  const walk = (child: ts.Node): void => {
    if (found) return;
    if (ts.isCallExpression(child)) {
      const name = methodName(child);
      if (
        name &&
        /^(?:compareAndSwap|compareExchange|updateIfVersion)$/iu.test(name)
      ) {
        found = true;
        return;
      }
    }
    if (child !== node && ts.isFunctionLike(child)) return;
    ts.forEachChild(child, walk);
  };
  walk(node);
  return found;
}

const concurrentSideEffectMethods = new Set([
  'appendFile',
  'delete',
  'decrement',
  'execute',
  'increment',
  'insert',
  'patch',
  'post',
  'put',
  'remove',
  'rename',
  'save',
  'send',
  'set',
  'unlink',
  'update',
  'write',
  'writeFile'
]);
const concurrencyLimitHelpers = new Set([
  'limit',
  'pLimit',
  'pMap',
  'mapLimit',
  'runLimited',
  'withConcurrency'
]);

function hasStaticArrayBound(mapCall: ts.CallExpression): boolean {
  const receiver = ts.isPropertyAccessExpression(mapCall.expression)
    ? mapCall.expression.expression
    : undefined;
  if (
    !receiver ||
    !ts.isCallExpression(receiver) ||
    methodName(receiver) !== 'slice'
  )
    return false;
  const start = receiver.arguments[0];
  const end = receiver.arguments[1];
  return Boolean(
    (!start || (ts.isNumericLiteral(start) && Number(start.text) === 0)) &&
    end &&
    ts.isNumericLiteral(end) &&
    Number.isSafeInteger(Number(end.text)) &&
    Number(end.text) >= 0
  );
}

function hasSideEffectingCallback(callback: ts.Expression): boolean {
  if (!ts.isArrowFunction(callback) && !ts.isFunctionExpression(callback))
    return false;
  let sideEffect = false;
  let limited = false;
  const walk = (node: ts.Node): void => {
    if (sideEffect || limited) return;
    if (node !== callback && ts.isFunctionLike(node)) return;
    if (ts.isCallExpression(node)) {
      const name = methodName(node);
      if (name && concurrencyLimitHelpers.has(name)) {
        limited = true;
        return;
      }
      if (name && concurrentSideEffectMethods.has(name)) {
        sideEffect = true;
        return;
      }
    }
    ts.forEachChild(node, walk);
  };
  walk(callback.body);
  return sideEffect && !limited;
}

function findUnboundedPromiseAll(
  sourceFile: ts.SourceFile,
  node: ts.Node,
  findings: Finding[]
): void {
  if (!ts.isCallExpression(node)) return;
  const target = node.expression;
  if (
    !ts.isPropertyAccessExpression(target) ||
    target.name.text !== 'all' ||
    !ts.isIdentifier(target.expression) ||
    target.expression.text !== 'Promise'
  )
    return;
  const mapped = callArgument(node);
  if (!mapped || !ts.isCallExpression(mapped) || methodName(mapped) !== 'map')
    return;
  if (hasStaticArrayBound(mapped)) return;
  const callback = mapped.arguments[0];
  if (!callback || !hasSideEffectingCallback(callback)) return;
  findings.push(
    createFinding(sourceFile, node, 'unbounded-concurrent-mutation')
  );
}

function createFinding(
  sourceFile: ts.SourceFile,
  node: ts.Node,
  kind: FindingKind
): Finding {
  const start = sourceFile.getLineAndCharacterOfPosition(
    node.getStart(sourceFile)
  );
  const location = {
    file: sourceFile.fileName,
    line: start.line + 1,
    column: start.character + 1
  };
  const ruleId =
    kind === 'filesystem-check-then-use'
      ? 'TLP-RACE-001'
      : kind === 'non-atomic-read-check-write'
        ? 'TLP-RACE-002'
        : 'TLP-RACE-003';
  const fingerprint = `${ruleId}:${location.file}:${location.line}:${location.column}`;
  return {
    id: fingerprint,
    ruleId,
    title:
      kind === 'filesystem-check-then-use'
        ? 'Filesystem check followed by a separate path operation'
        : kind === 'non-atomic-read-check-write'
          ? 'Read-check-write sequence without visible atomic predicate'
          : 'Unbounded Promise.all fan-out to side-effecting work',
    category: 'concurrency',
    severity: 'medium',
    confidence: 'low',
    message:
      kind === 'filesystem-check-then-use'
        ? 'The same path is checked and later used in a separate filesystem operation. A concurrent replacement can invalidate the earlier check; prefer operating on one opened handle with no-follow and atomic flags.'
        : kind === 'non-atomic-read-check-write'
          ? 'A value is read, checked, then mutated without a visible compare-and-swap or version predicate. Concurrent requests may both pass the check; verify transaction isolation and atomic update conditions.'
          : 'Promise.all maps an unbounded collection to side-effecting asynchronous work. Large inputs can overwhelm downstream services or cause overlapping updates; use a bounded concurrency pool and make writes idempotent or atomic.',
    source: 'typescript-ast-concurrency-heuristic',
    location,
    evidence: [
      {
        summary:
          '[same-path filesystem check/use pattern; path and data values omitted]',
        fingerprint
      }
    ],
    remediation: {
      summary:
        kind === 'filesystem-check-then-use'
          ? 'Open once with restrictive flags and operate through the resulting handle; avoid existence/access check followed by a path reopen.'
          : kind === 'non-atomic-read-check-write'
            ? 'Move the state predicate into an atomic conditional update, compare a version/ETag, or use a transaction with isolation that prevents competing updates.'
            : 'Use a bounded worker pool and validate that concurrent writes are atomic, idempotent, or uniquely keyed.'
    },
    metadata: {
      analysisModel: kind,
      cwe:
        kind === 'filesystem-check-then-use'
          ? 'CWE-367'
          : kind === 'non-atomic-read-check-write'
            ? 'CWE-362'
            : 'CWE-400',
      limitation:
        'Static same-function heuristic; it cannot prove runtime scheduling, database isolation, lock scope, or filesystem provider behavior.'
    }
  };
}

type FunctionFacts = {
  calls: ts.CallExpression[];
  declarations: ts.VariableDeclaration[];
  conditionals: ts.IfStatement[];
};

function emptyFacts(): FunctionFacts {
  return { calls: [], declarations: [], conditionals: [] };
}

function findFilesystemCheckUse(
  sourceFile: ts.SourceFile,
  calls: readonly ts.CallExpression[],
  findings: Finding[]
): void {
  const checkedPaths = new Set<string>();
  for (const call of calls) {
    const name = methodName(call) ?? '';
    const path = pathKey(callArgument(call));
    if (!path) continue;
    if (fileCheckMethods.has(name)) checkedPaths.add(path);
    else if (fileUseMethods.has(name) && checkedPaths.has(path)) {
      findings.push(
        createFinding(sourceFile, call, 'filesystem-check-then-use')
      );
    }
  }
}

function findReadCheckWrite(
  sourceFile: ts.SourceFile,
  facts: FunctionFacts,
  findings: Finding[]
): void {
  const { declarations, conditionals, calls } = facts;
  for (const declaration of declarations) {
    if (!ts.isIdentifier(declaration.name)) continue;
    const readCall = unwrapCall(declaration.initializer);
    if (!readCall || !objectReadMethods.has(methodName(readCall) ?? ''))
      continue;
    const entityName = declaration.name.text;
    for (const conditional of conditionals) {
      if (
        conditional.getStart(sourceFile) < declaration.getStart(sourceFile) ||
        !mentionsIdentifier(conditional.expression, entityName)
      )
        continue;
      const testedState = conditional.expression
        .getText()
        .match(
          new RegExp(`${entityName}\\s*\\.\\s*([A-Za-z_$][\\w$]*)`, 'u')
        )?.[1];
      if (!testedState) continue;
      const writes = calls.filter(
        (call) =>
          conditional.thenStatement.getStart(sourceFile) <=
            call.getStart(sourceFile) &&
          conditional.thenStatement.getEnd() >= call.getEnd() &&
          objectWriteMethods.has(methodName(call) ?? '') &&
          call.arguments.some((argument) =>
            mentionsIdentifier(argument, entityName)
          )
      );
      for (const write of writes) {
        if (containsVersionPredicate(write) || hasAtomicOperation(write))
          continue;
        findings.push(
          createFinding(sourceFile, write, 'non-atomic-read-check-write')
        );
      }
    }
  }
}

/** Detects narrow, same-function filesystem and shared-state concurrency candidates. */
export function analyzeConcurrencySource(
  filePath: string,
  content: string,
  capturedSourceFile?: ts.SourceFile
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
  const findings: Finding[] = [];
  const factsByFunction = new Map<ts.Node, FunctionFacts>();
  const topLevelFacts = emptyFacts();
  const functionStack: ts.Node[] = [];
  const visit = (node: ts.Node): void => {
    const startsFunction =
      ts.isFunctionLike(node) && 'body' in node && Boolean(node.body);
    if (startsFunction) {
      functionStack.push(node);
      factsByFunction.set(node, emptyFacts());
    }
    const currentFunction = functionStack.at(-1);
    const facts =
      (currentFunction && factsByFunction.get(currentFunction)) ??
      topLevelFacts;
    if (ts.isCallExpression(node)) {
      facts.calls.push(node);
      findUnboundedPromiseAll(sourceFile, node, findings);
    }
    if (ts.isVariableDeclaration(node)) facts.declarations.push(node);
    if (ts.isIfStatement(node)) facts.conditionals.push(node);
    ts.forEachChild(node, visit);
    if (startsFunction) functionStack.pop();
  };
  visit(sourceFile);
  findFilesystemCheckUse(sourceFile, topLevelFacts.calls, findings);
  findReadCheckWrite(sourceFile, topLevelFacts, findings);
  for (const facts of factsByFunction.values()) {
    findFilesystemCheckUse(sourceFile, facts.calls, findings);
    findReadCheckWrite(sourceFile, facts, findings);
  }
  return [
    ...new Map(findings.map((finding) => [finding.id, finding])).values()
  ];
}
