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

function propertyName(name: ts.PropertyName): string | undefined {
  return ts.isIdentifier(name) || ts.isStringLiteral(name)
    ? name.text
    : undefined;
}

function isDeclarationIdentifier(node: ts.Identifier): boolean {
  const parent = node.parent;
  return (
    (ts.isVariableDeclaration(parent) && parent.name === node) ||
    (ts.isParameter(parent) && parent.name === node) ||
    (ts.isFunctionDeclaration(parent) && parent.name === node) ||
    (ts.isFunctionExpression(parent) && parent.name === node) ||
    (ts.isClassDeclaration(parent) && parent.name === node) ||
    (ts.isClassExpression(parent) && parent.name === node) ||
    (ts.isTypeParameterDeclaration(parent) && parent.name === node) ||
    (ts.isImportClause(parent) && parent.name === node) ||
    (ts.isImportSpecifier(parent) && parent.name === node) ||
    (ts.isNamespaceImport(parent) && parent.name === node) ||
    (ts.isImportEqualsDeclaration(parent) && parent.name === node) ||
    (ts.isEnumDeclaration(parent) && parent.name === node) ||
    (ts.isModuleDeclaration(parent) && parent.name === node) ||
    (ts.isCatchClause(parent) && parent.variableDeclaration?.name === node)
  );
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

function containsVersionPredicate(node: ts.Node, entityName: string): boolean {
  let found = false;
  const walk = (child: ts.Node): void => {
    if (found) return;
    if (
      ts.isPropertyAssignment(child) &&
      propertyName(child.name) === 'where'
    ) {
      const where = child.initializer;
      if (ts.isObjectLiteralExpression(where)) {
        for (const predicate of where.properties) {
          if (!ts.isPropertyAssignment(predicate)) continue;
          const key = propertyName(predicate.name);
          if (
            key &&
            /^(?:version|revision|etag|updatedAt|rowVersion)$/iu.test(key) &&
            ts.isPropertyAccessExpression(predicate.initializer) &&
            predicate.initializer.name.text === key &&
            ts.isIdentifier(predicate.initializer.expression) &&
            predicate.initializer.expression.text === entityName
          ) {
            found = true;
            return;
          }
        }
      }
    }
    if (child !== node && ts.isFunctionLike(child)) return;
    ts.forEachChild(child, walk);
  };
  walk(node);
  return found;
}

function isSerializableTransaction(write: ts.Node): boolean {
  for (
    let current: ts.Node | undefined = write;
    current;
    current = current.parent
  ) {
    if (!ts.isFunctionLike(current) || !('body' in current) || !current.body)
      continue;
    const call = current.parent;
    if (
      !ts.isCallExpression(call) ||
      !call.arguments.includes(current as ts.Expression) ||
      !['transaction', '$transaction'].includes(methodName(call) ?? '')
    )
      continue;
    const options = call.arguments[1];
    if (!options || !ts.isObjectLiteralExpression(options)) continue;
    return options.properties.some((property) => {
      if (
        !ts.isPropertyAssignment(property) ||
        propertyName(property.name) !== 'isolationLevel'
      )
        return false;
      const value = property.initializer;
      if (ts.isStringLiteral(value))
        return value.text.toLowerCase() === 'serializable';
      return (
        ts.isPropertyAccessExpression(value) &&
        value.name.text.toLowerCase() === 'serializable'
      );
    });
  }
  return false;
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
const MAX_RECOGNIZED_POOL_CONCURRENCY = 32;

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

type FunctionIndex = ReadonlyMap<string, readonly ts.FunctionLikeDeclaration[]>;
type BoundedPools = ReadonlyMap<string, ts.VariableDeclaration>;
type SideEffectMemo = Map<ts.FunctionLikeDeclaration, boolean>;

function callbackFunction(
  callback: ts.Expression,
  functions: FunctionIndex
): ts.FunctionLikeDeclaration | undefined {
  if (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback))
    return callback;
  if (ts.isIdentifier(callback)) {
    const declarations = functions.get(callback.text);
    if (declarations?.length === 1) return declarations[0];
  }
  return undefined;
}

function numericConcurrency(expression: ts.Expression | undefined): boolean {
  return Boolean(
    expression &&
    ts.isNumericLiteral(expression) &&
    Number.isSafeInteger(Number(expression.text)) &&
    Number(expression.text) > 0 &&
    Number(expression.text) <= MAX_RECOGNIZED_POOL_CONCURRENCY
  );
}

function collectBoundedPools(
  sourceFile: ts.SourceFile
): Map<string, ts.VariableDeclaration> {
  const pLimitFactories = new Set<string>();
  const trustedFactoryBindings = new Set<ts.Identifier>();
  for (const statement of sourceFile.statements) {
    if (
      !ts.isImportDeclaration(statement) ||
      !ts.isStringLiteral(statement.moduleSpecifier) ||
      !statement.importClause
    )
      continue;
    const module = statement.moduleSpecifier.text;
    if (module === 'p-limit' && statement.importClause.name) {
      pLimitFactories.add(statement.importClause.name.text);
      trustedFactoryBindings.add(statement.importClause.name);
    }
    const bindings = statement.importClause.namedBindings;
    if (!bindings || !ts.isNamedImports(bindings)) continue;
    for (const binding of bindings.elements) {
      if (binding.isTypeOnly) continue;
      const imported = binding.propertyName?.text ?? binding.name.text;
      if (module === 'p-limit' && ['default', 'pLimit'].includes(imported)) {
        pLimitFactories.add(binding.name.text);
        trustedFactoryBindings.add(binding.name);
      }
    }
  }

  const declarations = new Map<string, ts.VariableDeclaration[]>();
  const unsafeUses = new Set<string>();
  const shadowedFactories = new Set<string>();
  const collect = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
      const values = declarations.get(node.name.text) ?? [];
      values.push(node);
      declarations.set(node.name.text, values);
    }
    if (ts.isIdentifier(node)) {
      const parent = node.parent;
      const declarationName =
        ts.isVariableDeclaration(parent) && parent.name === node;
      const directCall =
        ts.isCallExpression(parent) && parent.expression === node;
      if (!declarationName && !directCall) unsafeUses.add(node.text);
      if (
        isDeclarationIdentifier(node) &&
        pLimitFactories.has(node.text) &&
        !trustedFactoryBindings.has(node)
      )
        shadowedFactories.add(node.text);
    }
    ts.forEachChild(node, collect);
  };
  collect(sourceFile);

  const limiters = new Map<string, ts.VariableDeclaration>();
  for (const [name, values] of declarations) {
    const declaration = values[0];
    const initializer = declaration?.initializer;
    const declarationList = declaration?.parent;
    if (
      values.length !== 1 ||
      !declaration ||
      !initializer ||
      !ts.isCallExpression(initializer) ||
      !ts.isIdentifier(initializer.expression) ||
      !pLimitFactories.has(initializer.expression.text) ||
      shadowedFactories.has(initializer.expression.text) ||
      !numericConcurrency(initializer.arguments[0]) ||
      !declarationList ||
      !ts.isVariableDeclarationList(declarationList) ||
      (declarationList.flags & ts.NodeFlags.Const) === 0
    )
      continue;
    if (!unsafeUses.has(name)) limiters.set(name, declaration);
  }
  return limiters;
}

function isWithinDeclarationScope(
  declaration: ts.VariableDeclaration,
  use: ts.Node
): boolean {
  let scope: ts.Node | undefined = declaration.parent;
  while (
    scope &&
    !ts.isSourceFile(scope) &&
    !ts.isBlock(scope) &&
    !ts.isFunctionLike(scope)
  )
    scope = scope.parent;
  if (!scope || declaration.getStart() >= use.getStart()) return false;
  for (
    let current: ts.Node | undefined = use;
    current;
    current = current.parent
  )
    if (current === scope) return true;
  return false;
}

function isBoundedPoolCall(
  call: ts.CallExpression,
  limiters: BoundedPools
): boolean {
  if (ts.isIdentifier(call.expression)) {
    const pool = limiters.get(call.expression.text);
    if (pool && isWithinDeclarationScope(pool, call)) return true;
  }
  return false;
}

function hasSideEffectingCallback(
  callback: ts.Expression,
  functions: FunctionIndex,
  pools: BoundedPools,
  memo: SideEffectMemo,
  visited = new Set<ts.FunctionLikeDeclaration>(),
  depth = 0
): boolean {
  const declaration = callbackFunction(callback, functions);
  if (!declaration || !('body' in declaration) || !declaration.body)
    return true;
  const cached = memo.get(declaration);
  if (cached !== undefined) return cached;
  if (visited.has(declaration) || depth >= 16) return true;
  visited.add(declaration);
  let sideEffect = false;
  const walk = (node: ts.Node): void => {
    if (sideEffect) return;
    if (node !== declaration && ts.isFunctionLike(node)) {
      if (
        ts.isCallExpression(node.parent) &&
        node.parent.arguments.includes(node as ts.Expression)
      )
        return; // The parent call examines callbacks without executing them.
      return;
    }
    if (ts.isCallExpression(node)) {
      const name = methodName(node);
      if (name && concurrentSideEffectMethods.has(name)) {
        sideEffect = true;
        return;
      }
      if (isBoundedPoolCall(node, pools)) {
        for (const argument of node.arguments)
          if (
            !ts.isArrowFunction(argument) &&
            !ts.isFunctionExpression(argument)
          )
            walk(argument);
        return;
      }
      for (const argument of node.arguments) {
        if (
          callbackFunction(argument, functions) &&
          hasSideEffectingCallback(
            argument,
            functions,
            pools,
            memo,
            visited,
            depth + 1
          )
        ) {
          sideEffect = true;
          return;
        }
      }
      if (
        ts.isIdentifier(node.expression) &&
        hasSideEffectingCallback(
          node.expression,
          functions,
          pools,
          memo,
          visited,
          depth + 1
        )
      ) {
        sideEffect = true;
        return;
      }
    }
    ts.forEachChild(node, walk);
  };
  walk(declaration.body);
  visited.delete(declaration);
  memo.set(declaration, sideEffect);
  return sideEffect;
}

function findUnboundedPromiseAll(
  sourceFile: ts.SourceFile,
  node: ts.Node,
  findings: Finding[],
  functions: FunctionIndex,
  pools: BoundedPools,
  memo: SideEffectMemo
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
  if (!callback || !hasSideEffectingCallback(callback, functions, pools, memo))
    return;
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
        if (
          containsVersionPredicate(write, entityName) ||
          hasAtomicOperation(write) ||
          isSerializableTransaction(write)
        )
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
  const functionsByName = new Map<string, ts.FunctionLikeDeclaration[]>();
  const collectFunctions = (node: ts.Node): void => {
    if (ts.isFunctionDeclaration(node) && node.name && node.body) {
      const declarations = functionsByName.get(node.name.text) ?? [];
      declarations.push(node);
      functionsByName.set(node.name.text, declarations);
    } else if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      (ts.isArrowFunction(node.initializer) ||
        ts.isFunctionExpression(node.initializer))
    ) {
      const declarations = functionsByName.get(node.name.text) ?? [];
      declarations.push(node.initializer);
      functionsByName.set(node.name.text, declarations);
    }
    ts.forEachChild(node, collectFunctions);
  };
  collectFunctions(sourceFile);
  const functions: FunctionIndex = functionsByName;
  const limiters = collectBoundedPools(sourceFile);
  const sideEffectMemo: SideEffectMemo = new Map();
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
      findUnboundedPromiseAll(
        sourceFile,
        node,
        findings,
        functions,
        limiters,
        sideEffectMemo
      );
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
