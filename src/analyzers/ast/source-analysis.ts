import ts from 'typescript';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import path from 'node:path';
import type { Finding } from '../../contracts/finding.js';
import { astSecurityRules, type AstSecurityRule } from './rules.js';
import { analyzeAuthorizationSource } from './authorization-analysis.js';
import { analyzeConcurrencySource } from './concurrency-analysis.js';

type BindingKind =
  | 'namespace'
  | 'filesystem'
  | 'exec'
  | 'execSync'
  | 'spawn'
  | 'spawnSync'
  | 'execFile'
  | 'execFileSync'
  | 'fork'
  | 'unsafeDeserializerNamespace'
  | 'unsafeDeserializer'
  | 'dynamicChildProcess'
  | 'shadow';
type ScopeKind = 'source' | 'function' | 'block' | 'loop' | 'catch';
type BindingWrite = {
  position: number;
  expression?: ts.Expression;
  uncertain: boolean;
};
type ImportBinding = {
  moduleSpecifier: string;
  importedName?: string;
  namespace: boolean;
};
type ExportBinding =
  | { kind: 'module'; moduleSpecifier: string; importedName: string }
  | { kind: 'namespace'; moduleSpecifier: string }
  | { kind: 'local'; localName: string }
  | { kind: 'variable'; declaration: ts.VariableDeclaration }
  | { kind: 'expression'; expression: ts.Expression };
type LocalBindingReference = {
  declaration: ts.VariableDeclaration;
  propertyName?: string;
  writes: BindingWrite[];
};
type ProjectModuleResolver = {
  sourceFilesByAbsolutePath: Map<string, ts.SourceFile>;
  scopes: WeakMap<ts.Node, Scope>;
  importsBySource: WeakMap<ts.SourceFile, Map<string, ImportBinding>>;
  exportsBySource: WeakMap<ts.SourceFile, Map<string, ExportBinding[]>>;
  exportStarsBySource: WeakMap<ts.SourceFile, string[]>;
  localsBySource: WeakMap<ts.SourceFile, Map<string, LocalBindingReference>>;
  commonJsModuleBySource: WeakMap<ts.SourceFile, ts.Expression>;
  exportCache: WeakMap<ts.SourceFile, Map<string, BindingKind | null>>;
  resolutionWork: number;
  exportCacheEntries: number;
  resolveModule: (
    moduleSpecifier: string,
    containingFile: string
  ) => ts.SourceFile | undefined;
};
type Scope = {
  kind: ScopeKind;
  node: ts.Node;
  parent?: Scope;
  bindings: Map<string, BindingKind>;
  writes: Map<string, BindingWrite[]>;
  dynamicWrites: Set<string>;
  projectModules?: ProjectModuleResolver;
};
type PendingBinding = {
  name: ts.BindingName;
  initializer?: ts.Expression;
  scope: Scope;
};

function isPotentialChildProcess(kind: BindingKind | undefined): boolean {
  return (
    kind === 'namespace' ||
    kind === 'exec' ||
    kind === 'execSync' ||
    kind === 'spawn' ||
    kind === 'spawnSync' ||
    kind === 'execFile' ||
    kind === 'execFileSync' ||
    kind === 'fork' ||
    kind === 'dynamicChildProcess'
  );
}

function childProcessExport(name: string): BindingKind | undefined {
  const methods: Record<string, BindingKind> = {
    exec: 'exec',
    execSync: 'execSync',
    spawn: 'spawn',
    spawnSync: 'spawnSync',
    execFile: 'execFile',
    execFileSync: 'execFileSync',
    fork: 'fork'
  };
  return methods[name];
}

function definitelySafeChildProcessValue(
  expression: ts.Expression | undefined
): boolean {
  let current = expression;
  while (
    current &&
    (ts.isParenthesizedExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isTypeAssertionExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isSatisfiesExpression(current))
  )
    current = current.expression;
  return Boolean(
    current &&
    (ts.isArrowFunction(current) ||
      ts.isFunctionExpression(current) ||
      ts.isClassExpression(current) ||
      ts.isObjectLiteralExpression(current) ||
      ts.isArrayLiteralExpression(current) ||
      ts.isNewExpression(current) ||
      ts.isStringLiteralLike(current) ||
      ts.isNumericLiteral(current) ||
      current.kind === ts.SyntaxKind.TrueKeyword ||
      current.kind === ts.SyntaxKind.FalseKeyword ||
      current.kind === ts.SyntaxKind.NullKeyword)
  );
}

function conditionallyExecutesChildren(node: ts.Node): boolean {
  if (
    ts.isIfStatement(node) ||
    ts.isSwitchStatement(node) ||
    ts.isCaseClause(node) ||
    ts.isForStatement(node) ||
    ts.isForInStatement(node) ||
    ts.isForOfStatement(node) ||
    ts.isWhileStatement(node) ||
    ts.isDoStatement(node) ||
    ts.isTryStatement(node) ||
    ts.isCatchClause(node) ||
    ts.isConditionalExpression(node)
  )
    return true;
  return (
    ts.isBinaryExpression(node) &&
    (node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
      node.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
      node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)
  );
}

function bindingPatternContains(name: ts.BindingName, target: string): boolean {
  if (ts.isIdentifier(name)) return name.text === target;
  return name.elements.some(
    (element) =>
      !ts.isOmittedExpression(element) &&
      bindingPatternContains(element.name, target)
  );
}

function declaresTopLevelName(
  sourceFile: ts.SourceFile,
  name: string
): boolean {
  return sourceFile.statements.some((statement) => {
    if (ts.isVariableStatement(statement))
      return statement.declarationList.declarations.some((declaration) =>
        bindingPatternContains(declaration.name, name)
      );
    if (
      (ts.isFunctionDeclaration(statement) ||
        ts.isClassDeclaration(statement)) &&
      statement.name?.text === name
    )
      return true;
    if (ts.isImportEqualsDeclaration(statement))
      return statement.name.text === name;
    if (
      ts.isImportDeclaration(statement) &&
      statement.importClause &&
      !statement.importClause.isTypeOnly
    ) {
      if (statement.importClause.name?.text === name) return true;
      const bindings = statement.importClause.namedBindings;
      if (!bindings) return false;
      if (ts.isNamespaceImport(bindings)) return bindings.name.text === name;
      return bindings.elements.some(
        (element) => !element.isTypeOnly && element.name.text === name
      );
    }
    return false;
  });
}

function spendProjectModuleResolution(modules: ProjectModuleResolver): void {
  modules.resolutionWork += 1;
  if (modules.resolutionWork > MAX_INTERPROCEDURAL_WORK)
    throw new Error('AST project module resolution work budget exceeded');
}

function cacheProjectModuleExport(
  sourceFile: ts.SourceFile,
  exportName: string,
  result: BindingKind | undefined,
  modules: ProjectModuleResolver
): void {
  let cache = modules.exportCache.get(sourceFile);
  if (!cache) {
    cache = new Map();
    modules.exportCache.set(sourceFile, cache);
  }
  if (!cache.has(exportName)) {
    modules.exportCacheEntries += 1;
    if (modules.exportCacheEntries > MAX_AST_TRAVERSAL_NODES)
      throw new Error('AST project module export cache budget exceeded');
  }
  cache.set(exportName, result ?? null);
}

function indexProjectModuleSources(
  parsedFiles: readonly ts.SourceFile[]
): Pick<
  ProjectModuleResolver,
  | 'importsBySource'
  | 'exportsBySource'
  | 'exportStarsBySource'
  | 'localsBySource'
  | 'commonJsModuleBySource'
  | 'exportCache'
> {
  const importsBySource = new WeakMap<
    ts.SourceFile,
    Map<string, ImportBinding>
  >();
  const exportsBySource = new WeakMap<
    ts.SourceFile,
    Map<string, ExportBinding[]>
  >();
  const exportStarsBySource = new WeakMap<ts.SourceFile, string[]>();
  const localsBySource = new WeakMap<
    ts.SourceFile,
    Map<string, LocalBindingReference>
  >();
  const commonJsModuleBySource = new WeakMap<ts.SourceFile, ts.Expression>();
  const exportCache = new WeakMap<
    ts.SourceFile,
    Map<string, BindingKind | null>
  >();

  for (const sourceFile of parsedFiles) {
    const imports = new Map<string, ImportBinding>();
    const exports = new Map<string, ExportBinding[]>();
    const exportStars: string[] = [];
    const locals = new Map<string, LocalBindingReference>();
    let commonJsModule: ts.Expression | undefined;
    const commonJsGlobalsAvailable =
      !declaresTopLevelName(sourceFile, 'module') &&
      !declaresTopLevelName(sourceFile, 'exports');
    for (const statement of sourceFile.statements) {
      if (
        ts.isImportEqualsDeclaration(statement) &&
        !statement.isTypeOnly &&
        ts.isExternalModuleReference(statement.moduleReference) &&
        statement.moduleReference.expression &&
        ts.isStringLiteral(statement.moduleReference.expression)
      ) {
        imports.set(statement.name.text, {
          moduleSpecifier: statement.moduleReference.expression.text,
          namespace: true
        });
      }

      if (
        ts.isImportDeclaration(statement) &&
        ts.isStringLiteral(statement.moduleSpecifier) &&
        statement.importClause &&
        !statement.importClause.isTypeOnly
      ) {
        if (statement.importClause.name)
          imports.set(statement.importClause.name.text, {
            moduleSpecifier: statement.moduleSpecifier.text,
            importedName: 'default',
            namespace: false
          });
        const bindings = statement.importClause.namedBindings;
        if (bindings && ts.isNamespaceImport(bindings)) {
          imports.set(bindings.name.text, {
            moduleSpecifier: statement.moduleSpecifier.text,
            namespace: true
          });
        } else if (bindings && ts.isNamedImports(bindings)) {
          for (const element of bindings.elements) {
            if (!element.isTypeOnly)
              imports.set(element.name.text, {
                moduleSpecifier: statement.moduleSpecifier.text,
                importedName: element.propertyName?.text ?? element.name.text,
                namespace: false
              });
          }
        }
      }

      if (ts.isExportDeclaration(statement)) {
        if (statement.isTypeOnly) continue;
        const moduleSpecifier =
          statement.moduleSpecifier &&
          ts.isStringLiteral(statement.moduleSpecifier)
            ? statement.moduleSpecifier.text
            : undefined;
        if (!statement.exportClause && moduleSpecifier) {
          exportStars.push(moduleSpecifier);
        } else if (
          statement.exportClause &&
          ts.isNamespaceExport(statement.exportClause) &&
          moduleSpecifier
        ) {
          const bindings = exports.get(statement.exportClause.name.text) ?? [];
          bindings.push({ kind: 'namespace', moduleSpecifier });
          exports.set(statement.exportClause.name.text, bindings);
        } else if (
          statement.exportClause &&
          ts.isNamedExports(statement.exportClause)
        ) {
          for (const element of statement.exportClause.elements) {
            if (element.isTypeOnly) continue;
            const bindings = exports.get(element.name.text) ?? [];
            const localName = element.propertyName?.text ?? element.name.text;
            bindings.push(
              moduleSpecifier
                ? {
                    kind: 'module',
                    moduleSpecifier,
                    importedName: localName
                  }
                : { kind: 'local', localName }
            );
            exports.set(element.name.text, bindings);
          }
        }
        continue;
      }

      if (ts.isExportAssignment(statement)) {
        if (statement.isExportEquals) {
          commonJsModule = statement.expression;
        } else {
          exports.set('default', [
            { kind: 'expression', expression: statement.expression }
          ]);
        }
        continue;
      }

      if (
        commonJsGlobalsAvailable &&
        ts.isExpressionStatement(statement) &&
        ts.isBinaryExpression(statement.expression) &&
        statement.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken
      ) {
        const { left, right } = statement.expression;
        const appendExpressionExport = (
          exportName: string,
          expression: ts.Expression
        ): void => {
          const bindings = exports.get(exportName) ?? [];
          bindings.push({ kind: 'expression', expression });
          exports.set(exportName, bindings);
        };
        if (ts.isPropertyAccessExpression(left)) {
          if (
            ts.isIdentifier(left.expression) &&
            left.expression.text === 'exports'
          ) {
            appendExpressionExport(left.name.text, right);
          } else if (
            ts.isPropertyAccessExpression(left.expression) &&
            ts.isIdentifier(left.expression.expression) &&
            left.expression.expression.text === 'module' &&
            left.expression.name.text === 'exports'
          ) {
            appendExpressionExport(left.name.text, right);
          } else if (
            ts.isIdentifier(left.expression) &&
            left.expression.text === 'module' &&
            left.name.text === 'exports'
          ) {
            commonJsModule = right;
            if (ts.isObjectLiteralExpression(right)) {
              for (const property of right.properties) {
                if (!ts.isPropertyAssignment(property)) continue;
                const exportName = propertyName(property.name);
                if (exportName)
                  appendExpressionExport(exportName, property.initializer);
              }
            }
          }
        }
      }

      if (!ts.isVariableStatement(statement)) continue;
      const exported = statement.modifiers?.some(
        (modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword
      );
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name)) {
          locals.set(declaration.name.text, { declaration, writes: [] });
          if (exported) {
            const bindings = exports.get(declaration.name.text) ?? [];
            bindings.push({ kind: 'variable', declaration });
            exports.set(declaration.name.text, bindings);
          }
          continue;
        }
        if (!ts.isObjectBindingPattern(declaration.name)) continue;
        for (const element of declaration.name.elements) {
          if (ts.isOmittedExpression(element) || !ts.isIdentifier(element.name))
            continue;
          const name = element.name.text;
          const reference: LocalBindingReference = {
            declaration,
            propertyName: propertyName(element.propertyName) ?? name,
            writes: []
          };
          locals.set(name, reference);
          if (exported) {
            const bindings = exports.get(name) ?? [];
            bindings.push({ kind: 'variable', declaration });
            exports.set(name, bindings);
          }
        }
      }
    }
    if (imports.size > 0) importsBySource.set(sourceFile, imports);
    if (exports.size > 0) exportsBySource.set(sourceFile, exports);
    if (exportStars.length > 0)
      exportStarsBySource.set(sourceFile, exportStars);
    if (locals.size > 0) localsBySource.set(sourceFile, locals);
    if (commonJsModule) commonJsModuleBySource.set(sourceFile, commonJsModule);
  }

  return {
    importsBySource,
    exportsBySource,
    exportStarsBySource,
    localsBySource,
    commonJsModuleBySource,
    exportCache
  };
}

/** Indexes top-level local writes after lexical bindings have been collected. */
function indexProjectModuleWrites(
  parsedFiles: readonly ts.SourceFile[],
  scopes: WeakMap<ts.Node, Scope>,
  modules: ProjectModuleResolver
): void {
  for (const sourceFile of parsedFiles) {
    const sourceScope = scopes.get(sourceFile);
    const locals = modules.localsBySource.get(sourceFile);
    if (!sourceScope || !locals) continue;
    const collectWrites = (
      node: ts.Node,
      conditional: boolean,
      inNestedFunction: boolean
    ): void => {
      const nestedConditional =
        conditional || conditionallyExecutesChildren(node);
      const nestedFunction = inNestedFunction || ts.isFunctionLike(node);
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
        node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
        ts.isIdentifier(node.left)
      ) {
        const reference = locals.get(node.left.text);
        const assignmentScope = scopes.get(node);
        // A same-named local in a nested function/block is a separate binding
        // and must not mutate the module's exported alias.
        if (
          reference &&
          assignmentScope &&
          bindingOwner(assignmentScope, node.left.text) === sourceScope
        ) {
          reference.writes.push({
            position: nestedFunction
              ? Number.NEGATIVE_INFINITY
              : node.getStart(sourceFile),
            ...(node.operatorToken.kind === ts.SyntaxKind.EqualsToken
              ? { expression: node.right }
              : {}),
            uncertain:
              node.operatorToken.kind !== ts.SyntaxKind.EqualsToken ||
              nestedFunction ||
              nestedConditional ||
              assignmentScope !== sourceScope
          });
        }
      }
      ts.forEachChild(node, (child) =>
        collectWrites(child, nestedConditional, nestedFunction)
      );
    };
    collectWrites(sourceFile, false, false);
    for (const reference of locals.values())
      reference.writes.sort((left, right) => left.position - right.position);
  }
}

function findImportBinding(
  sourceFile: ts.SourceFile,
  localName: string,
  modules?: ProjectModuleResolver
): ImportBinding | undefined {
  const indexed = modules?.importsBySource.get(sourceFile);
  if (modules) return indexed?.get(localName);
  for (const statement of sourceFile.statements) {
    if (
      ts.isImportEqualsDeclaration(statement) &&
      !statement.isTypeOnly &&
      statement.name.text === localName &&
      ts.isExternalModuleReference(statement.moduleReference) &&
      statement.moduleReference.expression &&
      ts.isStringLiteral(statement.moduleReference.expression)
    )
      return {
        moduleSpecifier: statement.moduleReference.expression.text,
        namespace: true
      };
    if (
      !ts.isImportDeclaration(statement) ||
      !ts.isStringLiteral(statement.moduleSpecifier) ||
      !statement.importClause ||
      statement.importClause.isTypeOnly
    )
      continue;
    if (statement.importClause.name?.text === localName)
      return {
        moduleSpecifier: statement.moduleSpecifier.text,
        importedName: 'default',
        namespace: false
      };
    const bindings = statement.importClause.namedBindings;
    if (bindings && ts.isNamespaceImport(bindings)) {
      if (bindings.name.text === localName)
        return {
          moduleSpecifier: statement.moduleSpecifier.text,
          namespace: true
        };
    } else if (bindings && ts.isNamedImports(bindings)) {
      for (const element of bindings.elements) {
        if (!element.isTypeOnly && element.name.text === localName)
          return {
            moduleSpecifier: statement.moduleSpecifier.text,
            importedName: element.propertyName?.text ?? element.name.text,
            namespace: false
          };
      }
    }
  }
  return undefined;
}

function resolveChildProcessImport(
  binding: ImportBinding,
  sourceFile: ts.SourceFile,
  modules: ProjectModuleResolver,
  depth: number,
  visited: Set<string>
): BindingKind | undefined {
  if (depth > MAX_BINDING_RESOLUTION_DEPTH) return 'dynamicChildProcess';
  if (isChildProcessModule(binding.moduleSpecifier)) {
    // Node exposes the CommonJS built-in export as the default ESM binding.
    // Treat it like a namespace so default imports retain method provenance.
    if (binding.namespace || binding.importedName === 'default')
      return 'namespace';
    return binding.importedName
      ? childProcessExport(binding.importedName)
      : undefined;
  }
  spendProjectModuleResolution(modules);
  const target = modules.resolveModule(
    binding.moduleSpecifier,
    sourceFile.fileName
  );
  if (!target) return undefined;
  if (binding.namespace) {
    for (const name of [
      'exec',
      'execSync',
      'spawn',
      'spawnSync',
      'execFile',
      'execFileSync',
      'fork'
    ]) {
      if (resolveChildProcessExport(target, name, modules, depth + 1, visited))
        return 'namespace';
    }
    return undefined;
  }
  return binding.importedName
    ? resolveChildProcessExport(
        target,
        binding.importedName,
        modules,
        depth + 1,
        visited
      )
    : undefined;
}

function resolveChildProcessExport(
  sourceFile: ts.SourceFile,
  exportName: string,
  modules: ProjectModuleResolver,
  depth: number,
  visited: Set<string>
): BindingKind | undefined {
  if (depth > MAX_BINDING_RESOLUTION_DEPTH) return 'dynamicChildProcess';
  const cache = modules.exportCache.get(sourceFile);
  if (cache?.has(exportName)) return cache.get(exportName) ?? undefined;
  const visitKey = `${canonicalPath(sourceFile.fileName)}#export:${exportName}`;
  if (visited.has(visitKey)) return undefined;
  spendProjectModuleResolution(modules);
  visited.add(visitKey);
  let result: BindingKind | undefined;
  const bindings =
    modules.exportsBySource.get(sourceFile)?.get(exportName) ?? [];
  for (const binding of bindings) {
    let candidate: BindingKind | undefined;
    if (binding.kind === 'module' || binding.kind === 'namespace') {
      candidate = resolveChildProcessImport(
        binding.kind === 'namespace'
          ? { moduleSpecifier: binding.moduleSpecifier, namespace: true }
          : {
              moduleSpecifier: binding.moduleSpecifier,
              importedName: binding.importedName,
              namespace: false
            },
        sourceFile,
        modules,
        depth + 1,
        visited
      );
    } else if (binding.kind === 'local') {
      candidate = resolveLocalChildProcessValue(
        sourceFile,
        binding.localName,
        modules,
        depth + 1,
        visited
      );
    } else if (binding.kind === 'expression') {
      candidate = resolveChildProcessExpression(
        binding.expression,
        sourceFile,
        modules,
        depth + 1,
        visited
      );
    } else {
      candidate = resolveLocalChildProcessValue(
        sourceFile,
        exportName,
        modules,
        depth + 1,
        visited
      );
    }
    if (!candidate) continue;
    if (result && result !== candidate) {
      result = 'dynamicChildProcess';
      break;
    }
    result = candidate;
  }

  if (!result) {
    for (const moduleSpecifier of modules.exportStarsBySource.get(sourceFile) ??
      []) {
      spendProjectModuleResolution(modules);
      const target = modules.resolveModule(
        moduleSpecifier,
        sourceFile.fileName
      );
      if (!target) continue;
      const candidate = resolveChildProcessExport(
        target,
        exportName,
        modules,
        depth + 1,
        visited
      );
      if (!candidate) continue;
      if (result && result !== candidate) {
        result = 'dynamicChildProcess';
        break;
      }
      result = candidate;
    }
  }
  if (!result) {
    const commonJsModule = modules.commonJsModuleBySource.get(sourceFile);
    const moduleKind = commonJsModule
      ? resolveChildProcessExpression(
          commonJsModule,
          sourceFile,
          modules,
          depth + 1,
          visited
        )
      : undefined;
    if (moduleKind === 'namespace') result = childProcessExport(exportName);
    else if (
      moduleKind === 'dynamicChildProcess' &&
      childProcessExport(exportName)
    )
      result = moduleKind;
  }
  visited.delete(visitKey);
  cacheProjectModuleExport(sourceFile, exportName, result, modules);
  return result;
}

function resolveLocalChildProcessValue(
  sourceFile: ts.SourceFile,
  localName: string,
  modules: ProjectModuleResolver,
  depth: number,
  visited: Set<string>
): BindingKind | undefined {
  if (depth > MAX_BINDING_RESOLUTION_DEPTH) return 'dynamicChildProcess';
  const visitKey = `${canonicalPath(sourceFile.fileName)}#local:${localName}`;
  if (visited.has(visitKey)) return undefined;
  spendProjectModuleResolution(modules);
  visited.add(visitKey);

  const imported = findImportBinding(sourceFile, localName, modules);
  if (imported) {
    const result = resolveChildProcessImport(
      imported,
      sourceFile,
      modules,
      depth + 1,
      visited
    );
    visited.delete(visitKey);
    return result;
  }

  const reference = modules.localsBySource.get(sourceFile)?.get(localName);
  if (!reference) {
    visited.delete(visitKey);
    return undefined;
  }
  const namespace = resolveChildProcessExpression(
    reference.declaration.initializer,
    sourceFile,
    modules,
    depth + 1,
    visited
  );
  let result =
    !reference.propertyName || !isPotentialChildProcess(namespace)
      ? namespace
      : namespace === 'namespace'
        ? childProcessExport(reference.propertyName)
        : namespace;
  if (
    !result &&
    definitelySafeChildProcessValue(reference.declaration.initializer)
  )
    result = 'shadow';

  for (const write of reference.writes) {
    if (write.position === Number.NEGATIVE_INFINITY) continue;
    const assigned = write.expression
      ? ts.isIdentifier(write.expression) && write.expression.text === localName
        ? result
        : (resolveChildProcessExpression(
            write.expression,
            sourceFile,
            modules,
            depth + 1,
            visited
          ) ??
          (definitelySafeChildProcessValue(write.expression)
            ? 'shadow'
            : undefined))
      : undefined;
    if (write.uncertain) {
      result =
        isPotentialChildProcess(result) || isPotentialChildProcess(assigned)
          ? 'dynamicChildProcess'
          : (assigned ?? 'shadow');
    } else if (assigned) {
      result = assigned;
    } else {
      result = isPotentialChildProcess(result)
        ? 'dynamicChildProcess'
        : 'shadow';
    }
  }

  if (
    reference.writes.some(
      (write) => write.position === Number.NEGATIVE_INFINITY
    ) &&
    reference.writes.some((write) => {
      if (write.position !== Number.NEGATIVE_INFINITY) return false;
      if (!write.expression) return isPotentialChildProcess(result);
      const assigned = resolveChildProcessExpression(
        write.expression,
        sourceFile,
        modules,
        depth + 1,
        visited
      );
      return (
        isPotentialChildProcess(result) || isPotentialChildProcess(assigned)
      );
    })
  )
    result = 'dynamicChildProcess';
  visited.delete(visitKey);
  return result;
}

function resolveChildProcessExpression(
  expression: ts.Expression | undefined,
  sourceFile: ts.SourceFile,
  modules: ProjectModuleResolver,
  depth: number,
  visited: Set<string>
): BindingKind | undefined {
  if (!expression) return undefined;
  if (depth > MAX_BINDING_RESOLUTION_DEPTH) return 'dynamicChildProcess';
  if (ts.isIdentifier(expression))
    return resolveLocalChildProcessValue(
      sourceFile,
      expression.text,
      modules,
      depth + 1,
      visited
    );
  if (
    ts.isParenthesizedExpression(expression) ||
    ts.isAsExpression(expression) ||
    ts.isTypeAssertionExpression(expression) ||
    ts.isNonNullExpression(expression) ||
    ts.isSatisfiesExpression(expression)
  )
    return resolveChildProcessExpression(
      expression.expression,
      sourceFile,
      modules,
      depth + 1,
      visited
    );
  if (
    ts.isCallExpression(expression) &&
    ts.isIdentifier(expression.expression)
  ) {
    const requireIsShadowed = declaresTopLevelName(sourceFile, 'require');
    const [argument] = expression.arguments;
    if (
      expression.expression.text === 'require' &&
      !requireIsShadowed &&
      expression.arguments.length === 1 &&
      argument &&
      ts.isStringLiteral(argument) &&
      isChildProcessModule(argument.text)
    )
      return 'namespace';
  }
  if (ts.isPropertyAccessExpression(expression)) {
    const receiver = resolveChildProcessExpression(
      expression.expression,
      sourceFile,
      modules,
      depth + 1,
      visited
    );
    return receiver === 'namespace'
      ? childProcessExport(expression.name.text)
      : undefined;
  }
  if (
    ts.isElementAccessExpression(expression) &&
    expression.argumentExpression &&
    ts.isStringLiteral(expression.argumentExpression)
  ) {
    const receiver = resolveChildProcessExpression(
      expression.expression,
      sourceFile,
      modules,
      depth + 1,
      visited
    );
    return receiver === 'namespace'
      ? childProcessExport(expression.argumentExpression.text)
      : undefined;
  }
  return undefined;
}

/** Selects the TypeScript parser mode from a source filename extension. */
function scriptKind(filePath: string): ts.ScriptKind {
  if (filePath.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (filePath.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (filePath.endsWith('.js')) return ts.ScriptKind.JS;
  if (filePath.endsWith('.mjs')) return ts.ScriptKind.JS;
  if (filePath.endsWith('.cjs')) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

/** Recognizes Node's built-in child-process module specifiers. */
function isChildProcessModule(value: string): boolean {
  return value === 'child_process' || value === 'node:child_process';
}

const fileSystemMethods = new Set([
  'access',
  'appendFile',
  'appendFileSync',
  'createReadStream',
  'createWriteStream',
  'copyFile',
  'copyFileSync',
  'lstat',
  'lstatSync',
  'mkdir',
  'mkdirSync',
  'mkdtemp',
  'open',
  'openSync',
  'readFile',
  'readFileSync',
  'readdir',
  'readdirSync',
  'realpath',
  'rm',
  'rmSync',
  'rmdir',
  'rmdirSync',
  'stat',
  'statSync',
  'unlink',
  'unlinkSync',
  'writeFile',
  'writeFileSync'
]);

function isFileSystemModule(value: string): boolean {
  return ['fs', 'node:fs', 'fs/promises', 'node:fs/promises'].includes(value);
}

function scopeKind(node: ts.Node): ScopeKind | undefined {
  if (ts.isSourceFile(node)) return 'source';
  if (ts.isFunctionLike(node)) return 'function';
  if (ts.isBlock(node) || ts.isCaseBlock(node)) return 'block';
  if (
    ts.isForStatement(node) ||
    ts.isForInStatement(node) ||
    ts.isForOfStatement(node)
  )
    return 'loop';
  if (ts.isCatchClause(node)) return 'catch';
  return undefined;
}

const MAX_AST_TRAVERSAL_DEPTH = 512;
const MAX_AST_TRAVERSAL_NODES = 1_000_000;
const MAX_BINDING_RESOLUTION_DEPTH = 256;

function createScopeTree(
  node: ts.Node,
  parent: Scope | undefined,
  scopes: WeakMap<ts.Node, Scope>,
  budget: { nodes: number } = { nodes: 0 },
  depth = 0,
  projectModules?: ProjectModuleResolver
): Scope {
  budget.nodes += 1;
  if (depth > MAX_AST_TRAVERSAL_DEPTH || budget.nodes > MAX_AST_TRAVERSAL_NODES)
    throw new Error('AST source traversal budget exceeded');
  const kind = scopeKind(node);
  const scope = kind
    ? {
        kind,
        node,
        parent,
        bindings: new Map<string, BindingKind>(),
        writes: new Map<string, BindingWrite[]>(),
        dynamicWrites: new Set<string>(),
        projectModules
      }
    : (parent ?? {
        kind: 'source' as const,
        node,
        bindings: new Map<string, BindingKind>(),
        writes: new Map<string, BindingWrite[]>(),
        dynamicWrites: new Set<string>(),
        projectModules
      });
  scopes.set(node, scope);
  ts.forEachChild(node, (child) => {
    createScopeTree(child, scope, scopes, budget, depth + 1, projectModules);
  });
  return scope;
}

function lookupBinding(
  scope: Scope,
  name: string,
  position = Number.POSITIVE_INFINITY,
  depth = 0
): BindingKind | undefined {
  if (depth > MAX_BINDING_RESOLUTION_DEPTH) return 'dynamicChildProcess';
  for (
    let current: Scope | undefined = scope;
    current;
    current = current.parent
  ) {
    const binding = current.bindings.get(name);
    if (binding) {
      if (current.dynamicWrites.has(name)) return 'dynamicChildProcess';
      const writes = current.writes.get(name);
      if (!writes?.length) return binding;
      let low = 0;
      let high = writes.length;
      while (low < high) {
        const middle = low + Math.floor((high - low) / 2);
        const write = writes[middle];
        if (write && write.position < position) low = middle + 1;
        else high = middle;
      }
      if (low === 0) return binding;
      const write = writes[low - 1];
      if (!write) return 'dynamicChildProcess';
      if (write.uncertain) {
        const prior = lookupBinding(current, name, write.position, depth + 1);
        const assigned = write.expression
          ? childProcessValue(
              write.expression,
              current,
              write.position,
              depth + 1
            )
          : undefined;
        return isPotentialChildProcess(prior) ||
          isPotentialChildProcess(assigned)
          ? 'dynamicChildProcess'
          : 'shadow';
      }
      return write.expression
        ? (childProcessValue(
            write.expression,
            current,
            write.position,
            depth + 1
          ) ?? 'shadow')
        : 'shadow';
    }
  }
  return undefined;
}

function nearestVarScope(scope: Scope): Scope {
  for (
    let current: Scope | undefined = scope;
    current;
    current = current.parent
  ) {
    if (current.kind === 'function' || current.kind === 'source')
      return current;
  }
  return scope;
}

function bindPattern(
  name: ts.BindingName,
  scope: Scope,
  binding: BindingKind
): void {
  if (ts.isIdentifier(name)) {
    scope.bindings.set(name.text, binding);
    return;
  }
  for (const element of name.elements) {
    if (ts.isOmittedExpression(element)) continue;
    bindPattern(element.name, scope, binding);
  }
}

function propertyName(name: ts.PropertyName | undefined): string | undefined {
  if (name && (ts.isIdentifier(name) || ts.isStringLiteral(name)))
    return name.text;
  return undefined;
}

function requiredChildProcess(
  expression: ts.Expression | undefined,
  scope: Scope,
  position = Number.POSITIVE_INFINITY,
  depth = 0
): boolean {
  if (
    !expression ||
    !ts.isCallExpression(expression) ||
    !ts.isIdentifier(expression.expression) ||
    expression.expression.text !== 'require' ||
    expression.arguments.length !== 1 ||
    lookupBinding(scope, 'require', position, depth + 1) !== undefined
  )
    return false;
  const [argument] = expression.arguments;
  return Boolean(
    argument &&
    ts.isStringLiteral(argument) &&
    isChildProcessModule(argument.text)
  );
}

function requiredFileSystem(
  expression: ts.Expression | undefined,
  scope: Scope,
  position = Number.POSITIVE_INFINITY,
  depth = 0
): boolean {
  if (
    !expression ||
    !ts.isCallExpression(expression) ||
    !ts.isIdentifier(expression.expression) ||
    expression.expression.text !== 'require' ||
    expression.arguments.length !== 1 ||
    lookupBinding(scope, 'require', position, depth + 1) !== undefined
  )
    return false;
  const [argument] = expression.arguments;
  return Boolean(
    argument &&
    ts.isStringLiteral(argument) &&
    isFileSystemModule(argument.text)
  );
}

function requiredUnsafeDeserializer(
  expression: ts.Expression | undefined,
  scope: Scope,
  position = Number.POSITIVE_INFINITY,
  depth = 0
): boolean {
  if (
    !expression ||
    !ts.isCallExpression(expression) ||
    !ts.isIdentifier(expression.expression) ||
    expression.expression.text !== 'require' ||
    expression.arguments.length !== 1 ||
    lookupBinding(scope, 'require', position, depth + 1) !== undefined
  )
    return false;
  const [argument] = expression.arguments;
  return Boolean(
    argument &&
    ts.isStringLiteral(argument) &&
    argument.text === 'node-serialize'
  );
}

function childProcessValue(
  expression: ts.Expression | undefined,
  scope: Scope,
  position = Number.POSITIVE_INFINITY,
  depth = 0
): BindingKind | undefined {
  if (!expression) return undefined;
  if (depth > MAX_BINDING_RESOLUTION_DEPTH) return 'dynamicChildProcess';
  if (ts.isIdentifier(expression)) {
    const binding = lookupBinding(scope, expression.text, position, depth + 1);
    if (
      !scope.projectModules ||
      (binding !== 'shadow' && binding !== undefined) ||
      bindingOwner(scope, expression.text)?.kind !== 'source'
    )
      return binding;
    const imported = findImportBinding(
      expression.getSourceFile(),
      expression.text,
      scope.projectModules
    );
    if (!imported) return binding;
    return (
      resolveChildProcessImport(
        imported,
        expression.getSourceFile(),
        scope.projectModules,
        depth + 1,
        new Set<string>()
      ) ?? binding
    );
  }
  if (requiredChildProcess(expression, scope, position, depth))
    return 'namespace';
  if (requiredFileSystem(expression, scope, position, depth))
    return 'filesystem';
  if (requiredUnsafeDeserializer(expression, scope, position, depth))
    return 'unsafeDeserializerNamespace';
  if (
    !ts.isPropertyAccessExpression(expression) &&
    !ts.isElementAccessExpression(expression)
  )
    return undefined;
  const method = ts.isPropertyAccessExpression(expression)
    ? expression.name.text
    : expression.argumentExpression &&
        ts.isStringLiteral(expression.argumentExpression)
      ? expression.argumentExpression.text
      : undefined;
  if (!method) return undefined;
  const receiver = childProcessValue(
    expression.expression,
    scope,
    position,
    depth + 1
  );
  if (receiver === 'namespace') {
    if (method === 'exec') return 'exec';
    if (method === 'execSync') return 'execSync';
    if (method === 'spawn') return 'spawn';
    if (method === 'spawnSync') return 'spawnSync';
    if (method === 'execFile') return 'execFile';
    if (method === 'execFileSync') return 'execFileSync';
    if (method === 'fork') return 'fork';
  }
  if (receiver === 'filesystem' && fileSystemMethods.has(method))
    return 'filesystem';
  if (receiver === 'unsafeDeserializerNamespace' && method === 'unserialize')
    return 'unsafeDeserializer';
  return 'shadow';
}

function shellOptionEnabled(call: ts.CallExpression): boolean {
  return call.arguments.some(
    (argument) =>
      ts.isObjectLiteralExpression(argument) &&
      argument.properties.some(
        (property) =>
          ts.isPropertyAssignment(property) &&
          propertyName(property.name) === 'shell' &&
          property.initializer.kind === ts.SyntaxKind.TrueKeyword
      )
  );
}

function invokesShell(call: ts.CallExpression, scope: Scope): boolean {
  const kind = childProcessValue(
    call.expression,
    scope,
    call.expression.getStart()
  );
  if (kind === 'exec' || kind === 'execSync' || kind === 'dynamicChildProcess')
    return true;
  return (
    ['spawn', 'spawnSync', 'execFile', 'execFileSync'].includes(kind ?? '') &&
    shellOptionEnabled(call)
  );
}

function dynamicChildProcessCall(
  call: ts.CallExpression,
  scope: Scope
): boolean {
  const target = call.expression;
  return Boolean(
    ts.isElementAccessExpression(target) &&
    target.argumentExpression &&
    !ts.isStringLiteral(target.argumentExpression) &&
    childProcessValue(target.expression, scope, target.getStart()) ===
      'namespace'
  );
}

/** Returns the identifier whose binding determines a supported alias expression. */
function aliasReference(
  expression: ts.Expression | undefined
): ts.Identifier | undefined {
  if (!expression) return undefined;
  if (ts.isIdentifier(expression)) return expression;
  if (ts.isPropertyAccessExpression(expression))
    return aliasReference(expression.expression);
  return undefined;
}

function assignmentMayBeConditional(node: ts.Node, owner: Scope): boolean {
  for (let current = node.parent; current; current = current.parent) {
    if (current === owner.node) return false;
    if (
      ts.isFunctionLike(current) ||
      ts.isIfStatement(current) ||
      ts.isSwitchStatement(current) ||
      ts.isCaseClause(current) ||
      ts.isForStatement(current) ||
      ts.isForInStatement(current) ||
      ts.isForOfStatement(current) ||
      ts.isWhileStatement(current) ||
      ts.isDoStatement(current) ||
      ts.isTryStatement(current) ||
      ts.isCatchClause(current) ||
      ts.isConditionalExpression(current)
    )
      return true;
    if (
      ts.isBinaryExpression(current) &&
      (current.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
        current.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
        current.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)
    )
      return true;
  }
  return true;
}

function assignmentInNestedFunction(node: ts.Node, owner: Scope): boolean {
  for (let current = node.parent; current; current = current.parent) {
    if (current === owner.node) return false;
    if (ts.isFunctionLike(current)) return true;
  }
  return false;
}

/** Assigns imported dangerous functions to lexical scopes, respecting shadowing. */
function collectBindings(
  sourceFile: ts.SourceFile,
  scopes: WeakMap<ts.Node, Scope>
): void {
  const pending: PendingBinding[] = [];
  const seenScopes = new Set<Scope>();
  const collect = (node: ts.Node): void => {
    const scope = scopes.get(node);
    if (!scope) return;
    seenScopes.add(scope);

    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
      ts.isIdentifier(node.left)
    ) {
      const owner = bindingOwner(scope, node.left.text);
      if (owner) {
        const writes = owner.writes.get(node.left.text) ?? [];
        const nestedFunctionWrite = assignmentInNestedFunction(node, owner);
        writes.push({
          position: nestedFunctionWrite
            ? Number.NEGATIVE_INFINITY
            : node.getStart(sourceFile),
          ...(node.operatorToken.kind === ts.SyntaxKind.EqualsToken
            ? { expression: node.right }
            : {}),
          uncertain:
            node.operatorToken.kind !== ts.SyntaxKind.EqualsToken ||
            nestedFunctionWrite ||
            assignmentMayBeConditional(node, owner)
        });
        owner.writes.set(node.left.text, writes);
      }
    }

    if (ts.isImportDeclaration(node) && node.importClause) {
      const moduleName = ts.isStringLiteral(node.moduleSpecifier)
        ? node.moduleSpecifier.text
        : undefined;
      const fromChildProcess = Boolean(
        moduleName &&
        isChildProcessModule(moduleName) &&
        !node.importClause.isTypeOnly
      );
      const fromFileSystem = Boolean(
        moduleName &&
        isFileSystemModule(moduleName) &&
        !node.importClause.isTypeOnly
      );
      const fromUnsafeDeserializer = Boolean(
        moduleName === 'node-serialize' && !node.importClause.isTypeOnly
      );
      if (node.importClause.name)
        scope.bindings.set(
          node.importClause.name.text,
          fromChildProcess
            ? 'namespace'
            : fromFileSystem
              ? 'filesystem'
              : fromUnsafeDeserializer
                ? 'unsafeDeserializerNamespace'
                : 'shadow'
        );
      const bindings = node.importClause.namedBindings;
      if (bindings && ts.isNamespaceImport(bindings)) {
        scope.bindings.set(
          bindings.name.text,
          fromChildProcess
            ? 'namespace'
            : fromFileSystem
              ? 'filesystem'
              : fromUnsafeDeserializer
                ? 'unsafeDeserializerNamespace'
                : 'shadow'
        );
      } else if (bindings && ts.isNamedImports(bindings)) {
        for (const element of bindings.elements) {
          const imported = element.propertyName?.text ?? element.name.text;
          const binding =
            fromChildProcess && !element.isTypeOnly
              ? imported === 'exec'
                ? 'exec'
                : imported === 'execSync'
                  ? 'execSync'
                  : imported === 'spawn'
                    ? 'spawn'
                    : imported === 'spawnSync'
                      ? 'spawnSync'
                      : imported === 'execFile'
                        ? 'execFile'
                        : imported === 'execFileSync'
                          ? 'execFileSync'
                          : imported === 'fork'
                            ? 'fork'
                            : 'shadow'
              : fromFileSystem &&
                  !element.isTypeOnly &&
                  fileSystemMethods.has(imported)
                ? 'filesystem'
                : fromUnsafeDeserializer &&
                    !element.isTypeOnly &&
                    imported === 'unserialize'
                  ? 'unsafeDeserializer'
                  : 'shadow';
          scope.bindings.set(element.name.text, binding);
        }
      }
    }

    if (ts.isImportEqualsDeclaration(node)) {
      const moduleReference = node.moduleReference;
      const required =
        ts.isExternalModuleReference(moduleReference) &&
        moduleReference.expression &&
        ts.isStringLiteral(moduleReference.expression) &&
        isChildProcessModule(moduleReference.expression.text);
      const requiredFs =
        ts.isExternalModuleReference(moduleReference) &&
        moduleReference.expression &&
        ts.isStringLiteral(moduleReference.expression) &&
        isFileSystemModule(moduleReference.expression.text);
      const requiredUnsafeDeserializerModule =
        ts.isExternalModuleReference(moduleReference) &&
        moduleReference.expression &&
        ts.isStringLiteral(moduleReference.expression) &&
        moduleReference.expression.text === 'node-serialize';
      scope.bindings.set(
        node.name.text,
        required
          ? 'namespace'
          : requiredFs
            ? 'filesystem'
            : requiredUnsafeDeserializerModule
              ? 'unsafeDeserializerNamespace'
              : 'shadow'
      );
    }

    if (ts.isFunctionLike(node)) {
      const functionScope = scopes.get(node);
      if (functionScope) {
        for (const parameter of node.parameters)
          bindPattern(parameter.name, functionScope, 'shadow');
      }
      if (ts.isFunctionExpression(node) && node.name && functionScope)
        functionScope.bindings.set(node.name.text, 'shadow');
    }

    if (
      (ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) &&
      node.name
    ) {
      const parentScope = scopes.get(node.parent);
      parentScope?.bindings.set(node.name.text, 'shadow');
    }

    if (ts.isCatchClause(node) && node.variableDeclaration) {
      const catchScope = scopes.get(node);
      if (catchScope)
        bindPattern(node.variableDeclaration.name, catchScope, 'shadow');
    }

    if (ts.isVariableDeclaration(node)) {
      const declarationScope = scopes.get(node);
      const list = node.parent;
      const isVar =
        ts.isVariableDeclarationList(list) &&
        (list.flags & ts.NodeFlags.BlockScoped) === 0;
      const bindingScope = declarationScope
        ? isVar
          ? nearestVarScope(declarationScope)
          : declarationScope
        : undefined;
      if (bindingScope) {
        bindPattern(node.name, bindingScope, 'shadow');
        if (node.initializer)
          pending.push({
            name: node.name,
            initializer: node.initializer,
            scope: bindingScope
          });
      }
    }

    ts.forEachChild(node, collect);
  };
  collect(sourceFile);
  for (const scope of seenScopes) {
    for (const writes of scope.writes.values())
      writes.sort((left, right) => left.position - right.position);
  }

  const dependents = new Map<Scope, Map<string, PendingBinding[]>>();
  for (const item of pending) {
    const reference = aliasReference(item.initializer);
    const owner = reference
      ? bindingOwner(scopes.get(reference) ?? item.scope, reference.text)
      : undefined;
    if (!reference || !owner) continue;
    const names = dependents.get(owner) ?? new Map<string, PendingBinding[]>();
    const bindings = names.get(reference.text) ?? [];
    bindings.push(item);
    names.set(reference.text, bindings);
    dependents.set(owner, names);
  }

  const queue = [...pending];
  const queued = new Set(queue);
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const item = queue[cursor];
    if (!item) continue;
    queued.delete(item);
    const kind = childProcessValue(
      item.initializer,
      item.scope,
      item.initializer?.getStart(sourceFile)
    );
    if (!kind || kind === 'shadow') continue;
    const changedNames: string[] = [];
    if (ts.isIdentifier(item.name)) {
      if (item.scope.bindings.get(item.name.text) !== kind) {
        item.scope.bindings.set(item.name.text, kind);
        changedNames.push(item.name.text);
      }
    } else if (
      ts.isObjectBindingPattern(item.name) &&
      (kind === 'namespace' ||
        kind === 'filesystem' ||
        kind === 'unsafeDeserializerNamespace')
    ) {
      for (const element of item.name.elements) {
        if (ts.isOmittedExpression(element) || !ts.isIdentifier(element.name))
          continue;
        const imported =
          propertyName(element.propertyName) ?? element.name.text;
        const alias =
          kind === 'filesystem' && fileSystemMethods.has(imported)
            ? 'filesystem'
            : kind === 'namespace' && imported === 'exec'
              ? 'exec'
              : kind === 'namespace' && imported === 'execSync'
                ? 'execSync'
                : kind === 'unsafeDeserializerNamespace' &&
                    imported === 'unserialize'
                  ? 'unsafeDeserializer'
                  : 'shadow';
        if (
          alias !== 'shadow' &&
          item.scope.bindings.get(element.name.text) !== alias
        ) {
          item.scope.bindings.set(element.name.text, alias);
          changedNames.push(element.name.text);
        }
      }
    }

    for (const name of changedNames) {
      for (const dependent of dependents.get(item.scope)?.get(name) ?? []) {
        if (queued.has(dependent)) continue;
        queued.add(dependent);
        queue.push(dependent);
      }
    }
  }

  for (const scope of seenScopes) {
    for (const [name, writes] of scope.writes) {
      if (
        writes.some((write) => write.position === Number.NEGATIVE_INFINITY) &&
        (isPotentialChildProcess(scope.bindings.get(name)) ||
          writes.some(
            (write) =>
              write.position === Number.NEGATIVE_INFINITY &&
              isPotentialChildProcess(
                write.expression
                  ? childProcessValue(write.expression, scope, write.position)
                  : undefined
              )
          ))
      )
        scope.dynamicWrites.add(name);
    }
  }
}

/** Maps an AST node to a one-based source location. */
function findingLocation(
  sourceFile: ts.SourceFile,
  node: ts.Node,
  filePath = sourceFile.fileName
): Finding['location'] {
  const start = sourceFile.getLineAndCharacterOfPosition(
    node.getStart(sourceFile)
  );
  const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd());

  return {
    file: filePath,
    line: start.line + 1,
    column: start.character + 1,
    endLine: end.line + 1,
    endColumn: end.character + 1
  };
}

/** Builds an AST finding without retaining the matched source expression. */
function createFinding(
  sourceFile: ts.SourceFile,
  node: ts.Node,
  rule: AstSecurityRule,
  filePath = sourceFile.fileName
): Finding {
  const location = findingLocation(sourceFile, node, filePath);
  const fingerprint =
    `${rule.id}:${filePath}:` +
    `${location?.line ?? 0}:${location?.column ?? 0}`;

  return {
    id: fingerprint,
    ruleId: rule.id,
    title: rule.title,
    category: rule.category,
    severity: rule.severity,
    confidence: rule.confidence,
    message: rule.message,
    source: 'typescript-ast',
    location,
    evidence: [
      {
        // Source excerpts can contain credentials no detector recognizes.
        summary: `[source expression redacted; ${ts.SyntaxKind[node.kind]}]`,
        fingerprint
      }
    ],
    remediation: {
      summary: rule.remediation
    },
    metadata: {
      nodeKind: ts.SyntaxKind[node.kind],
      ruleVersion: '1'
    }
  };
}

/** Resolves an imported child-process call to its matching security rule. */
function childProcessRuleForCall(
  call: ts.CallExpression,
  scope: Scope
): AstSecurityRule | undefined {
  const kind = childProcessValue(
    call.expression,
    scope,
    call.expression.getStart()
  );
  if (kind === 'exec') return astSecurityRules.childProcessExec;
  if (kind === 'execSync') return astSecurityRules.childProcessExecSync;
  if (kind === 'dynamicChildProcess')
    return astSecurityRules.dynamicCommandExecution;
  return undefined;
}

type TaintedNames = Map<Scope, Set<string>>;

type FlowBinding = { scope: Scope; name: string };
type FlowAnalysis = {
  tainted: TaintedNames;
  callReturns: WeakMap<ts.CallExpression, FlowBinding>;
};

const MAX_TAINT_FLOW_WORK = 250_000;

function spendTaintWork(
  budget: { used: number },
  maxWork = MAX_TAINT_FLOW_WORK
): void {
  budget.used += 1;
  if (budget.used > maxWork)
    throw new Error('AST taint analysis work budget exceeded');
}

function bindingOwner(
  scope: Scope | undefined,
  name: string
): Scope | undefined {
  for (let current = scope; current; current = current.parent) {
    if (current.bindings.has(name)) return current;
  }
  return undefined;
}

function flowTargets(
  name: ts.BindingName,
  scope: Scope,
  sensitiveOnly: boolean
): FlowBinding[] {
  if (ts.isIdentifier(name)) return [{ scope, name: name.text }];
  return name.elements.flatMap((element) => {
    if (ts.isOmittedExpression(element)) return [];
    const identifier = element.name;
    if (!ts.isIdentifier(identifier)) return [];
    const sourceName = propertyName(element.propertyName) ?? identifier.text;
    return !sensitiveOnly || sensitiveName.test(sourceName)
      ? [{ scope, name: identifier.text }]
      : [];
  });
}

/** Builds a linear, scope-aware alias graph and propagates taint by worklist. */
function collectFlowNames(
  sourceFiles: readonly ts.SourceFile[],
  scopes: WeakMap<ts.Node, Scope>,
  isSource: (expression: ts.Expression) => boolean,
  sensitiveDestructuring: boolean,
  checker?: ts.TypeChecker,
  maxWork = MAX_TAINT_FLOW_WORK
): FlowAnalysis {
  const budget = { used: 0 };
  const tainted: TaintedNames = new Map();
  const callReturns = new WeakMap<ts.CallExpression, FlowBinding>();
  const fallbackSourceFile =
    sourceFiles[0] ??
    ts.createSourceFile('empty.ts', '', ts.ScriptTarget.Latest);
  const sourceScope = (sourceFiles[0] && scopes.get(sourceFiles[0])) ?? {
    kind: 'source' as const,
    node: fallbackSourceFile,
    bindings: new Map<string, BindingKind>(),
    writes: new Map<string, BindingWrite[]>(),
    dynamicWrites: new Set<string>()
  };
  const reverse = new Map<Scope, Map<string, FlowBinding[]>>();
  const queue: FlowBinding[] = [];
  const queued = new Map<Scope, Set<string>>();
  const functions = new Map<Scope, Map<string, ts.FunctionLikeDeclaration>>();
  const returns = new WeakMap<ts.FunctionLikeDeclaration, FlowBinding>();

  const registerFunction = (
    owner: Scope | undefined,
    name: string,
    declaration: ts.FunctionLikeDeclaration
  ): void => {
    if (!owner || !('body' in declaration) || !declaration.body) return;
    const bindings = functions.get(owner) ?? new Map();
    bindings.set(name, declaration);
    functions.set(owner, bindings);
  };

  const collectFunctions = (node: ts.Node): void => {
    spendTaintWork(budget, maxWork);
    if (ts.isFunctionDeclaration(node) && node.name) {
      registerFunction(scopes.get(node.parent), node.name.text, node);
    } else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
      const initializer = node.initializer;
      if (
        initializer &&
        (ts.isArrowFunction(initializer) ||
          ts.isFunctionExpression(initializer))
      ) {
        registerFunction(
          bindingOwner(scopes.get(node), node.name.text),
          node.name.text,
          initializer
        );
      }
    }
    ts.forEachChild(node, collectFunctions);
  };
  for (const sourceFile of sourceFiles) collectFunctions(sourceFile);

  const declarationForCall = (
    expression: ts.Expression,
    callScope: Scope
  ): ts.FunctionLikeDeclaration | undefined => {
    if (ts.isIdentifier(expression)) {
      const owner = bindingOwner(callScope, expression.text);
      const local = owner
        ? functions.get(owner)?.get(expression.text)
        : undefined;
      if (local) return local;
    }
    if (!checker) return undefined;
    let symbol = checker.getSymbolAtLocation(expression);
    if (!symbol) return undefined;
    if ((symbol.flags & ts.SymbolFlags.Alias) !== 0) {
      try {
        symbol = checker.getAliasedSymbol(symbol);
      } catch {
        return undefined;
      }
    }
    for (const declaration of symbol.getDeclarations() ?? []) {
      if (
        (ts.isFunctionDeclaration(declaration) ||
          ts.isMethodDeclaration(declaration)) &&
        declaration.body
      )
        return declaration;
      if (ts.isVariableDeclaration(declaration)) {
        const initializer = declaration.initializer;
        if (
          initializer &&
          (ts.isArrowFunction(initializer) ||
            ts.isFunctionExpression(initializer))
        )
          return initializer;
      }
    }
    return undefined;
  };

  const resolveFunction = (
    expression: ts.Expression,
    callScope: Scope
  ): ts.FunctionLikeDeclaration | undefined => {
    return declarationForCall(expression, callScope);
  };

  const functionReturn = (
    declaration: ts.FunctionLikeDeclaration
  ): FlowBinding => {
    const known = returns.get(declaration);
    if (known) return known;
    const scope = scopes.get(declaration);
    if (!scope) return { scope: sourceScope, name: '' };
    const value = {
      scope,
      name: `\u0000return:${declaration.getStart(declaration.getSourceFile())}`
    };
    returns.set(declaration, value);
    return value;
  };

  const enqueue = (binding: FlowBinding): void => {
    const names = queued.get(binding.scope) ?? new Set<string>();
    if (names.has(binding.name)) return;
    names.add(binding.name);
    queued.set(binding.scope, names);
    queue.push(binding);
  };
  const addDependency = (from: FlowBinding, to: FlowBinding): void => {
    const names = reverse.get(from.scope) ?? new Map<string, FlowBinding[]>();
    const dependents = names.get(from.name) ?? [];
    dependents.push(to);
    names.set(from.name, dependents);
    reverse.set(from.scope, names);
  };
  const expressionFacts = (
    expression: ts.Expression,
    expressionScope: Scope
  ): { source: boolean; references: FlowBinding[] } => {
    let source = false;
    const references = new Map<Scope, Set<string>>();
    const visit = (node: ts.Node): void => {
      spendTaintWork(budget, maxWork);
      if (source && references.size === 0) return;
      if (node !== expression && ts.isFunctionLike(node)) return;
      if (ts.isExpression(node) && isMemberAccessRoot(node) && isSource(node))
        source = true;
      if (
        sensitiveDestructuring &&
        ts.isCallExpression(node) &&
        isRedactionCall(node)
      )
        return;
      if (ts.isCallExpression(node)) {
        const callerScope = scopes.get(node) ?? expressionScope;
        const declaration = resolveFunction(node.expression, callerScope);
        if (declaration) {
          const returned = functionReturn(declaration);
          callReturns.set(node, returned);
          const names = references.get(returned.scope) ?? new Set<string>();
          names.add(returned.name);
          references.set(returned.scope, names);
        }
      }
      if (ts.isIdentifier(node) && !isIdentifierPropertyName(node)) {
        const owner = bindingOwner(
          scopes.get(node) ?? expressionScope,
          node.text
        );
        if (owner) {
          const names = references.get(owner) ?? new Set<string>();
          names.add(node.text);
          references.set(owner, names);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(expression);
    return {
      source,
      references: [...references].flatMap(([scope, names]) =>
        [...names].map((name) => ({ scope, name }))
      )
    };
  };

  const addFlow = (
    expression: ts.Expression | undefined,
    expressionScope: Scope,
    targets: readonly FlowBinding[],
    specialSource = false
  ): void => {
    const facts = expression
      ? expressionFacts(expression, expressionScope)
      : { source: false, references: [] };
    for (const target of targets) {
      if (facts.source || specialSource) enqueue(target);
      for (const reference of facts.references)
        addDependency(reference, target);
    }
  };

  const collect = (node: ts.Node): void => {
    spendTaintWork(budget, maxWork);
    if (ts.isVariableDeclaration(node)) {
      const scope = scopes.get(node);
      if (scope) {
        const targets = flowTargets(node.name, scope, sensitiveDestructuring);
        addFlow(
          node.initializer,
          scope,
          targets,
          sensitiveDestructuring &&
            ts.isObjectBindingPattern(node.name) &&
            (isProcessEnvironmentObject(node.initializer) ||
              Boolean(node.initializer && isRequestSource(node.initializer)))
        );
      }
    }
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left)
    ) {
      const scope = scopes.get(node);
      const owner = bindingOwner(scope, node.left.text);
      if (scope && owner) {
        addFlow(node.right, scope, [{ scope: owner, name: node.left.text }]);
      }
    }

    if (ts.isCallExpression(node)) {
      const callScope = scopes.get(node);
      const declaration = callScope
        ? resolveFunction(node.expression, callScope)
        : undefined;
      if (declaration) {
        const returned = functionReturn(declaration);
        callReturns.set(node, returned);
        const parameters = declaration.parameters;
        const functionScope = scopes.get(declaration);
        if (functionScope) {
          for (let index = 0; index < parameters.length; index += 1) {
            const parameter = parameters[index];
            const argument = node.arguments[index];
            if (!parameter) continue;
            addFlow(
              argument,
              callScope ?? functionScope,
              flowTargets(parameter.name, functionScope, sensitiveDestructuring)
            );
          }
        }
      }

      // Promise callbacks receive the resolved value; collection callbacks
      // receive elements. Add bounded static edges without running callbacks.
      const target = node.expression;
      const method = ts.isPropertyAccessExpression(target)
        ? target.name.text
        : undefined;
      const callback = node.arguments[0];
      if (
        method &&
        callback &&
        (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback)) &&
        callback.parameters[0] &&
        ['then', 'map', 'flatMap', 'filter', 'forEach'].includes(method)
      ) {
        const callbackScope = scopes.get(callback);
        const parameter = callback.parameters[0];
        if (callbackScope && parameter && ts.isPropertyAccessExpression(target))
          addFlow(
            target.expression,
            callScope ?? callbackScope,
            flowTargets(parameter.name, callbackScope, sensitiveDestructuring)
          );
      }
    }

    if (ts.isReturnStatement(node) && node.expression) {
      let owner = node.parent;
      while (owner && !ts.isFunctionLike(owner)) owner = owner.parent;
      if (owner && 'body' in owner && owner.body) {
        addFlow(
          node.expression,
          scopes.get(owner) ?? scopes.get(node) ?? sourceScope,
          [functionReturn(owner)]
        );
      }
    }
    ts.forEachChild(node, collect);
  };
  for (const sourceFile of sourceFiles) collect(sourceFile);

  for (let cursor = 0; cursor < queue.length; cursor++) {
    spendTaintWork(budget, maxWork);
    const current = queue[cursor];
    if (!current) continue;
    const names = tainted.get(current.scope) ?? new Set<string>();
    names.add(current.name);
    tainted.set(current.scope, names);
    for (const dependent of reverse.get(current.scope)?.get(current.name) ?? [])
      enqueue(dependent);
  }
  return { tainted, callReturns };
}

function propertyPath(expression: ts.Expression): string[] | undefined {
  const parts: string[] = [];
  let current = expression;
  while (true) {
    if (ts.isParenthesizedExpression(current)) {
      current = current.expression;
      continue;
    }
    if (ts.isPropertyAccessExpression(current)) {
      parts.push(current.name.text);
      current = current.expression;
      continue;
    }
    if (
      ts.isElementAccessExpression(current) &&
      current.argumentExpression &&
      (ts.isStringLiteral(current.argumentExpression) ||
        ts.isNumericLiteral(current.argumentExpression))
    ) {
      parts.push(current.argumentExpression.text);
      current = current.expression;
      continue;
    }
    if (ts.isIdentifier(current)) {
      parts.push(current.text);
      return parts.reverse();
    }
    return undefined;
  }
}

function isMemberAccess(expression: ts.Expression): boolean {
  return (
    ts.isPropertyAccessExpression(expression) ||
    ts.isElementAccessExpression(expression)
  );
}

/** Only the outermost member chain can establish a complete source path. */
function isMemberAccessRoot(expression: ts.Expression): boolean {
  if (!isMemberAccess(expression)) return false;
  const parent = expression.parent;
  return !(
    (ts.isPropertyAccessExpression(parent) &&
      parent.expression === expression) ||
    (ts.isElementAccessExpression(parent) && parent.expression === expression)
  );
}

/** Deliberately narrow source model; this is a heuristic, not full taint proof. */
function isRequestSource(expression: ts.Expression): boolean {
  const parts: string[] = [];
  let current = expression;
  while (true) {
    if (ts.isParenthesizedExpression(current)) {
      current = current.expression;
      continue;
    }
    if (ts.isPropertyAccessExpression(current)) {
      parts.push(current.name.text);
      current = current.expression;
      continue;
    }
    if (ts.isElementAccessExpression(current)) {
      if (
        current.argumentExpression &&
        (ts.isStringLiteral(current.argumentExpression) ||
          ts.isNumericLiteral(current.argumentExpression))
      )
        parts.push(current.argumentExpression.text);
      current = current.expression;
      continue;
    }
    if (ts.isIdentifier(current)) {
      parts.push(current.text);
      break;
    }
    return false;
  }
  parts.reverse();
  const root = parts[0];
  const supportedRoot =
    root === 'req' ||
    root === 'request' ||
    root === 'ctx' ||
    root === 'context';
  if (!supportedRoot) return false;
  const contextRoot = root === 'ctx' || root === 'context';
  const requestObject =
    !contextRoot ||
    parts[1] === 'request' ||
    ['body', 'params', 'query'].includes(parts[1] ?? '');
  return (
    requestObject &&
    parts
      .slice(contextRoot && parts[1] === 'request' ? 2 : 1)
      .some((part) => ['body', 'params', 'query'].includes(part))
  );
}

function isTainted(
  expression: ts.Expression,
  scope: Scope,
  tainted: TaintedNames,
  callReturns: WeakMap<ts.CallExpression, FlowBinding>
): boolean {
  if (isMemberAccessRoot(expression) && isRequestSource(expression))
    return true;
  if (ts.isIdentifier(expression)) {
    for (
      let current: Scope | undefined = scope;
      current;
      current = current.parent
    ) {
      if (tainted.get(current)?.has(expression.text)) return true;
    }
    return false;
  }
  let found = false;
  const visit = (node: ts.Node): void => {
    if (found) return;
    if (node !== expression && ts.isFunctionLike(node)) return;
    if (ts.isCallExpression(node)) {
      const returned = callReturns.get(node);
      if (returned && tainted.get(returned.scope)?.has(returned.name)) {
        found = true;
        return;
      }
    }
    if (
      ts.isExpression(node) &&
      isMemberAccessRoot(node) &&
      isRequestSource(node)
    ) {
      found = true;
      return;
    }
    if (ts.isIdentifier(node)) {
      for (
        let current: Scope | undefined = scope;
        current;
        current = current.parent
      ) {
        if (tainted.get(current)?.has(node.text)) {
          found = true;
          return;
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(expression);
  return found;
}

function collectTaintedNames(
  sourceFiles: readonly ts.SourceFile[],
  scopes: WeakMap<ts.Node, Scope>,
  checker?: ts.TypeChecker,
  maxWork?: number
): FlowAnalysis {
  return collectFlowNames(
    sourceFiles,
    scopes,
    isRequestSource,
    false,
    checker,
    maxWork
  );
}

const sensitiveName =
  /(?:token|secret|password|passwd|private.?key|api.?key|credential|auth.?key|(?:access|refresh).?token|session.?cookie|email|phone|ssn|social.?security|birth.?date|date.?of.?birth|passport|address)/iu;
const redactionHelpers = new Set([
  'redactSecret',
  'redactSecrets',
  'redactSensitive',
  'redactSensitiveData',
  'maskSecret',
  'maskToken',
  'sanitizeSecret'
]);

function isIdentifierPropertyName(node: ts.Identifier): boolean {
  return (
    (ts.isPropertyAssignment(node.parent) && node.parent.name === node) ||
    (ts.isPropertyAccessExpression(node.parent) && node.parent.name === node) ||
    (ts.isMethodDeclaration(node.parent) && node.parent.name === node)
  );
}

function isCredentialEnvironmentSource(expression: ts.Expression): boolean {
  const parts = propertyPath(expression);
  return Boolean(
    parts &&
    parts[0] === 'process' &&
    parts[1] === 'env' &&
    parts.slice(2).some((part) => sensitiveName.test(part))
  );
}

function isSensitiveDataSource(expression: ts.Expression): boolean {
  if (isCredentialEnvironmentSource(expression)) return true;
  if (!isMemberAccessRoot(expression)) return false;
  const parent = expression.parent;
  if (ts.isCallExpression(parent) && parent.expression === expression)
    return false;
  const parts = propertyPath(expression);
  return Boolean(parts?.slice(1).some((part) => sensitiveName.test(part)));
}

function isProcessEnvironmentObject(
  expression: ts.Expression | undefined
): boolean {
  const parts = expression ? propertyPath(expression) : undefined;
  return Boolean(
    parts && parts[0] === 'process' && parts[1] === 'env' && parts.length === 2
  );
}

function isRedactionCall(expression: ts.Expression): boolean {
  if (!ts.isCallExpression(expression)) return false;
  const target = expression.expression;
  const name = ts.isPropertyAccessExpression(target)
    ? target.name.text
    : ts.isIdentifier(target)
      ? target.text
      : '';
  return redactionHelpers.has(name);
}

function collectSensitiveNames(
  sourceFiles: readonly ts.SourceFile[],
  scopes: WeakMap<ts.Node, Scope>,
  checker?: ts.TypeChecker,
  maxWork?: number
): FlowAnalysis {
  return collectFlowNames(
    sourceFiles,
    scopes,
    (expression) =>
      !isRedactionCall(expression) && isSensitiveDataSource(expression),
    true,
    checker,
    maxWork
  );
}

export type AstProjectInput = {
  filePath: string;
  absolutePath: string;
  content: string;
};

export type AstProjectAnalysis = {
  sourceFiles: Map<string, ts.SourceFile>;
  scopes: WeakMap<ts.Node, Scope>;
  resourceMiddlewareFunctions: WeakMap<
    ts.Identifier,
    ts.FunctionLikeDeclaration
  >;
  taint: FlowAnalysis;
  sensitive: FlowAnalysis;
  /** Transitive content digests for each file's resolved local import closure. */
  dependencyDigests: Map<string, string>;
};

// Match repository discovery's default file ceiling so a supported large
// snapshot is not marked partial solely because its source files are numerous.
// The byte and work budgets remain independent guards against dense inputs.
const MAX_INTERPROCEDURAL_FILES = 50_000;
const MAX_INTERPROCEDURAL_BYTES = 64 * 1024 * 1024;
const MAX_INTERPROCEDURAL_WORK = 8_000_000;

function canonicalPath(filePath: string): string {
  const resolved = path.resolve(filePath);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

/** Build TypeScript host directory entries in one pass over known directories. */
export function indexSourceDirectoryChildren(
  directories: ReadonlySet<string>
): ReadonlyMap<string, ReadonlySet<string>> {
  const childrenByDirectory = new Map<string, Set<string>>();
  for (const directory of directories) {
    const parent = path.dirname(directory);
    if (parent === directory) continue;
    let children = childrenByDirectory.get(parent);
    if (!children) {
      children = new Set<string>();
      childrenByDirectory.set(parent, children);
    }
    children.add(directory);
  }
  return childrenByDirectory;
}

function isPathWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative === '' ||
    (!path.isAbsolute(relative) &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`))
  );
}

/**
 * Creates a bounded TypeScript symbol graph from the exact source strings read
 * by the scanner. The compiler host cannot read repository files outside that
 * snapshot; TypeScript's own standard library declarations remain available.
 */
export function createAstProjectAnalysis(
  inputs: readonly AstProjectInput[]
): AstProjectAnalysis {
  const totalBytes = inputs.reduce(
    (total, input) => total + Buffer.byteLength(input.content),
    0
  );
  if (
    inputs.length > MAX_INTERPROCEDURAL_FILES ||
    totalBytes > MAX_INTERPROCEDURAL_BYTES
  )
    throw new Error('AST interprocedural project input budget exceeded');

  const inputByAbsolutePath = new Map(
    inputs.map((input) => [canonicalPath(input.absolutePath), input])
  );
  const sourceDirectories = new Set<string>();
  for (const input of inputs) {
    let directory = path.dirname(path.resolve(input.absolutePath));
    while (!sourceDirectories.has(directory)) {
      sourceDirectories.add(directory);
      const parent = path.dirname(directory);
      if (parent === directory) break;
      directory = parent;
    }
  }
  const sourceDirectoryChildren =
    indexSourceDirectoryChildren(sourceDirectories);

  const options: ts.CompilerOptions = {
    allowJs: true,
    checkJs: false,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    noEmit: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.Latest,
    types: []
  };
  const host = ts.createCompilerHost(options, true);
  const defaultGetSourceFile = host.getSourceFile.bind(host);
  const defaultFileExists = host.fileExists.bind(host);
  const defaultReadFile = host.readFile.bind(host);
  const defaultDirectoryExists = host.directoryExists?.bind(host);
  const typeScriptLib = path.resolve(
    path.dirname(ts.sys.getExecutingFilePath())
  );
  const isTypeScriptLib = (filePath: string): boolean =>
    isPathWithin(typeScriptLib, path.resolve(filePath));

  host.getCurrentDirectory = () =>
    inputs[0]
      ? path.dirname(path.resolve(inputs[0].absolutePath))
      : process.cwd();
  host.fileExists = (filePath) =>
    inputByAbsolutePath.has(canonicalPath(filePath)) ||
    (isTypeScriptLib(filePath) && defaultFileExists(filePath));
  host.readFile = (filePath) => {
    const input = inputByAbsolutePath.get(canonicalPath(filePath));
    if (input) return input.content;
    return isTypeScriptLib(filePath) ? defaultReadFile(filePath) : undefined;
  };
  host.getSourceFile = (
    filePath,
    languageVersionOrOptions,
    onError,
    shouldCreateNewSourceFile
  ) => {
    const input = inputByAbsolutePath.get(canonicalPath(filePath));
    if (input)
      return ts.createSourceFile(
        filePath,
        input.content,
        languageVersionOrOptions,
        true,
        scriptKind(filePath)
      );
    if (isTypeScriptLib(filePath))
      return defaultGetSourceFile(
        filePath,
        languageVersionOrOptions,
        onError,
        shouldCreateNewSourceFile
      );
    return undefined;
  };
  host.directoryExists = (directoryName) => {
    const absolute = path.resolve(directoryName);
    return (
      sourceDirectories.has(absolute) ||
      (isTypeScriptLib(absolute) &&
        (defaultDirectoryExists?.(directoryName) ?? false))
    );
  };
  host.getDirectories = (directoryName) => {
    const absolute = path.resolve(directoryName);
    return [...(sourceDirectoryChildren.get(absolute) ?? [])];
  };
  host.realpath = (filePath) => path.resolve(filePath);
  host.resolveModuleNames = (moduleNames, containingFile) =>
    moduleNames.map((moduleName) => {
      const resolved = ts.resolveModuleName(
        moduleName,
        containingFile,
        options,
        host
      ).resolvedModule;
      return resolved &&
        inputByAbsolutePath.has(canonicalPath(resolved.resolvedFileName))
        ? resolved
        : undefined;
    });

  const program = ts.createProgram(
    inputs.map((input) => path.resolve(input.absolutePath)),
    options,
    host
  );
  const sourceFiles = new Map<string, ts.SourceFile>();
  const parsedFiles: ts.SourceFile[] = [];
  for (const input of inputs) {
    const parsed = program.getSourceFile(path.resolve(input.absolutePath));
    if (!parsed) throw new Error('AST snapshot source could not be parsed');
    sourceFiles.set(input.filePath, parsed);
    parsedFiles.push(parsed);
  }

  const scopes = new WeakMap<ts.Node, Scope>();
  const traversalBudget = { nodes: 0 };
  const sourceFilesByAbsolutePath = new Map(
    parsedFiles.map((sourceFile) => [
      canonicalPath(sourceFile.fileName),
      sourceFile
    ])
  );
  const projectModules: ProjectModuleResolver = {
    sourceFilesByAbsolutePath,
    scopes,
    resolutionWork: 0,
    exportCacheEntries: 0,
    importsBySource: new WeakMap(),
    exportsBySource: new WeakMap(),
    exportStarsBySource: new WeakMap(),
    localsBySource: new WeakMap(),
    commonJsModuleBySource: new WeakMap(),
    exportCache: new WeakMap(),
    resolveModule: (moduleSpecifier, containingFile) => {
      const resolved = ts.resolveModuleName(
        moduleSpecifier,
        containingFile,
        options,
        host
      ).resolvedModule;
      return resolved
        ? sourceFilesByAbsolutePath.get(
            canonicalPath(resolved.resolvedFileName)
          )
        : undefined;
    }
  };
  for (const sourceFile of parsedFiles) {
    createScopeTree(
      sourceFile,
      undefined,
      scopes,
      traversalBudget,
      0,
      projectModules
    );
  }
  Object.assign(projectModules, indexProjectModuleSources(parsedFiles));
  for (const sourceFile of parsedFiles) {
    collectBindings(sourceFile, scopes);
  }
  indexProjectModuleWrites(parsedFiles, scopes, projectModules);
  const checker = program.getTypeChecker();
  const inputPathByAbsolutePath = new Map(
    inputs.map((input) => [canonicalPath(input.absolutePath), input.filePath])
  );
  const adjacency = new Map<string, Set<string>>();
  for (const input of inputs) {
    const sourceFile = sourceFiles.get(input.filePath);
    if (!sourceFile) continue;
    const dependencies = new Set<string>();
    for (const specifier of localModuleSpecifiers(sourceFile)) {
      const resolved = ts.resolveModuleName(
        specifier,
        sourceFile.fileName,
        options,
        host
      ).resolvedModule?.resolvedFileName;
      const dependency = resolved
        ? inputPathByAbsolutePath.get(canonicalPath(resolved))
        : undefined;
      if (dependency) dependencies.add(dependency);
    }
    adjacency.set(input.filePath, dependencies);
  }
  const dependencyDigests = transitiveImportDigests(inputs, adjacency);
  const resourceMiddlewareFunctions = new WeakMap<
    ts.Identifier,
    ts.FunctionLikeDeclaration
  >();
  const routeMethods = new Set([
    'get',
    'post',
    'put',
    'patch',
    'delete',
    'all'
  ]);
  const resolveFunctionDeclaration = (
    expression: ts.Identifier
  ): ts.FunctionLikeDeclaration | undefined => {
    let symbol = checker.getSymbolAtLocation(expression);
    if (symbol && (symbol.flags & ts.SymbolFlags.Alias) !== 0) {
      try {
        symbol = checker.getAliasedSymbol(symbol);
      } catch {
        return undefined;
      }
    }
    const declarations = symbol?.getDeclarations() ?? [];
    if (declarations.length !== 1) return undefined;
    const declaration = declarations[0];
    if (
      declaration &&
      ts.isFunctionLike(declaration) &&
      'body' in declaration &&
      declaration.body
    )
      return declaration;
    if (declaration && ts.isVariableDeclaration(declaration)) {
      const initializer = declaration.initializer;
      if (
        initializer &&
        (ts.isArrowFunction(initializer) ||
          ts.isFunctionExpression(initializer))
      )
        return initializer;
    }
    return undefined;
  };
  for (const sourceFile of parsedFiles) {
    const collectMiddleware = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        const method = ts.isPropertyAccessExpression(node.expression)
          ? node.expression.name.text.toLowerCase()
          : ts.isIdentifier(node.expression)
            ? node.expression.text.toLowerCase()
            : '';
        if (routeMethods.has(method)) {
          const handlerIndex = node.arguments.findIndex(
            (argument) =>
              ts.isArrowFunction(argument) || ts.isFunctionExpression(argument)
          );
          for (const argument of node.arguments.slice(
            0,
            handlerIndex < 0 ? undefined : handlerIndex
          )) {
            if (!ts.isIdentifier(argument)) continue;
            const declaration = resolveFunctionDeclaration(argument);
            if (declaration)
              resourceMiddlewareFunctions.set(argument, declaration);
          }
        }
      }
      ts.forEachChild(node, collectMiddleware);
    };
    collectMiddleware(sourceFile);
  }
  return {
    sourceFiles,
    scopes,
    resourceMiddlewareFunctions,
    taint: collectTaintedNames(
      parsedFiles,
      scopes,
      checker,
      MAX_INTERPROCEDURAL_WORK
    ),
    sensitive: collectSensitiveNames(
      parsedFiles,
      scopes,
      checker,
      MAX_INTERPROCEDURAL_WORK
    ),
    dependencyDigests
  };
}

export type AstProjectComponentPlan = {
  components: string[][];
  componentDigests: Map<string, string>;
  dependencyDigests: Map<string, string>;
  projectWide: boolean;
};

/**
 * Resolve the immutable snapshot's local import graph and stable component
 * identities without constructing TypeScript Programs. This plan lets the
 * AST cache invalidate an edited component and its importers while retaining
 * unrelated module components.
 *
 * Graph traversal is O(F + E). Directory indexing and resolution costs
 * O(FP + ER), where P is maximum ancestor-directory depth and R is candidate
 * lookup work per import. Auxiliary graph space is O(FP + E), excluding the
 * immutable source strings and TypeScript parser state.
 */
export function planAstProjectComponents(
  inputs: readonly AstProjectInput[]
): AstProjectComponentPlan {
  const totalBytes = inputs.reduce(
    (total, input) => total + Buffer.byteLength(input.content),
    0
  );
  if (
    inputs.length > MAX_INTERPROCEDURAL_FILES ||
    totalBytes > MAX_INTERPROCEDURAL_BYTES
  )
    throw new Error('AST interprocedural project input budget exceeded');
  const inputByAbsolutePath = new Map(
    inputs.map((input) => [canonicalPath(input.absolutePath), input])
  );
  const inputByPath = new Map(inputs.map((input) => [input.filePath, input]));
  const options: ts.CompilerOptions = {
    allowJs: true,
    checkJs: false,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    noEmit: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.Latest,
    types: []
  };
  const sourceDirectories = new Set<string>();
  for (const input of inputs) {
    let directory = path.dirname(path.resolve(input.absolutePath));
    while (!sourceDirectories.has(directory)) {
      sourceDirectories.add(directory);
      const parent = path.dirname(directory);
      if (parent === directory) break;
      directory = parent;
    }
  }
  const sourceDirectoryChildren =
    indexSourceDirectoryChildren(sourceDirectories);
  const host = ts.createCompilerHost(options, true);
  const defaultGetSourceFile = host.getSourceFile.bind(host);
  const defaultFileExists = host.fileExists.bind(host);
  const defaultReadFile = host.readFile.bind(host);
  const defaultDirectoryExists = host.directoryExists?.bind(host);
  const typeScriptLib = path.resolve(
    path.dirname(ts.sys.getExecutingFilePath())
  );
  const isTypeScriptLib = (filePath: string): boolean =>
    isPathWithin(typeScriptLib, path.resolve(filePath));
  host.fileExists = (filePath) =>
    inputByAbsolutePath.has(canonicalPath(filePath)) ||
    (isTypeScriptLib(filePath) && defaultFileExists(filePath));
  host.readFile = (filePath) => {
    const input = inputByAbsolutePath.get(canonicalPath(filePath));
    if (input) return input.content;
    return isTypeScriptLib(filePath) ? defaultReadFile(filePath) : undefined;
  };
  host.getSourceFile = (filePath, languageVersionOrOptions, onError, fresh) => {
    const input = inputByAbsolutePath.get(canonicalPath(filePath));
    if (input)
      return ts.createSourceFile(
        filePath,
        input.content,
        languageVersionOrOptions,
        true,
        scriptKind(filePath)
      );
    if (isTypeScriptLib(filePath))
      return defaultGetSourceFile(
        filePath,
        languageVersionOrOptions,
        onError,
        fresh
      );
    return undefined;
  };
  host.directoryExists = (directoryName) => {
    const absolute = path.resolve(directoryName);
    return (
      sourceDirectories.has(absolute) ||
      (isTypeScriptLib(absolute) &&
        (defaultDirectoryExists?.(directoryName) ?? false))
    );
  };
  host.getDirectories = (directoryName) => [
    ...(sourceDirectoryChildren.get(path.resolve(directoryName)) ?? [])
  ];
  host.realpath = (filePath) => path.resolve(filePath);
  const adjacency = new Map<string, Set<string>>();
  const reverse = new Map<string, Set<string>>();
  let requiresProjectWideProgram = false;
  for (const input of inputs) {
    const sourceFile = ts.createSourceFile(
      input.absolutePath,
      input.content,
      ts.ScriptTarget.Latest,
      true,
      scriptKind(input.absolutePath)
    );
    if (
      !ts.isExternalModule(sourceFile) ||
      input.absolutePath.endsWith('.d.ts') ||
      containsProjectWideModuleDeclaration(sourceFile)
    )
      requiresProjectWideProgram = true;
    const dependencies = new Set<string>();
    for (const specifier of localModuleSpecifiers(sourceFile)) {
      const resolved = ts.resolveModuleName(
        specifier,
        sourceFile.fileName,
        options,
        host
      ).resolvedModule?.resolvedFileName;
      const dependency = resolved
        ? inputByAbsolutePath.get(canonicalPath(resolved))?.filePath
        : undefined;
      if (dependency) dependencies.add(dependency);
    }
    adjacency.set(input.filePath, dependencies);
    for (const dependency of dependencies) {
      let parents = reverse.get(dependency);
      if (!parents) {
        parents = new Set();
        reverse.set(dependency, parents);
      }
      parents.add(input.filePath);
    }
  }

  const visited = new Set<string>();
  const components: string[][] = [];
  for (const input of inputs) {
    if (visited.has(input.filePath)) continue;
    const componentPaths: string[] = [];
    const pending = [input.filePath];
    visited.add(input.filePath);
    while (pending.length) {
      const current = pending.pop();
      if (!current) continue;
      componentPaths.push(current);
      for (const neighbor of [
        ...(adjacency.get(current) ?? []),
        ...(reverse.get(current) ?? [])
      ]) {
        if (visited.has(neighbor)) continue;
        visited.add(neighbor);
        pending.push(neighbor);
      }
    }
    components.push(
      componentPaths.sort((left, right) => left.localeCompare(right))
    );
  }

  // Script files, ambient declarations, and global augmentations can affect
  // files without import edges. Preserve project-wide cache invalidation and
  // checker semantics for those inputs.
  if (requiresProjectWideProgram)
    components.splice(0, components.length, [
      ...inputs
        .map((input) => input.filePath)
        .sort((left, right) => left.localeCompare(right))
    ]);

  const sortedComponents = components.sort((left, right) =>
    (left[0] ?? '').localeCompare(right[0] ?? '')
  );
  const componentDigests = new Map<string, string>();
  const componentDigestByIndex = sortedComponents.map((component) => {
    const digest = createHash('sha256').update('ast-component-v1\0');
    for (const filePath of component) {
      const input = inputByPath.get(filePath);
      if (!input) continue;
      digest.update(filePath).update('\0');
      digest
        .update(createHash('sha256').update(input.content).digest('hex'))
        .update('\0');
    }
    return digest.digest('hex');
  });
  sortedComponents.forEach((component, index) => {
    const digest = componentDigestByIndex[index];
    if (digest)
      for (const filePath of component) componentDigests.set(filePath, digest);
  });
  return {
    components: sortedComponents,
    componentDigests,
    dependencyDigests: transitiveImportDigests(inputs, adjacency),
    projectWide: requiresProjectWideProgram
  };
}

/**
 * Analyze an immutable source snapshot one weakly connected import component
 * at a time, preserving a whole-project Program for global declarations.
 * TypeScript AST/checker peak is bounded by the largest component, except in
 * the documented project-wide fallback.
 */
export function analyzeAstProjectByComponents(
  inputs: readonly AstProjectInput[]
): {
  findingsByPath: Map<string, Finding[]>;
  componentDigests: Map<string, string>;
  dependencyDigests: Map<string, string>;
  componentCount: number;
  largestComponentFiles: number;
} {
  const plan = planAstProjectComponents(inputs);
  const inputByPath = new Map(inputs.map((input) => [input.filePath, input]));
  const findingsByPath = new Map<string, Finding[]>();
  let largestComponentFiles = 0;
  for (const component of plan.components) {
    largestComponentFiles = Math.max(largestComponentFiles, component.length);
    const componentInputs = component
      .map((filePath) => inputByPath.get(filePath))
      .filter((input): input is AstProjectInput => input !== undefined);
    if (componentInputs.length === 1 && !plan.projectWide) {
      const only = componentInputs[0];
      if (only)
        findingsByPath.set(
          only.filePath,
          analyzeAstSource(only.filePath, only.content)
        );
      continue;
    }
    const project = createAstProjectAnalysis(componentInputs);
    for (const input of componentInputs) {
      findingsByPath.set(
        input.filePath,
        analyzeAstSource(input.filePath, input.content, project)
      );
      project.sourceFiles.delete(input.filePath);
    }
  }
  return {
    findingsByPath: new Map(
      inputs.flatMap((input) => {
        const findings = findingsByPath.get(input.filePath);
        return findings ? [[input.filePath, findings] as const] : [];
      })
    ),
    componentDigests: plan.componentDigests,
    dependencyDigests: plan.dependencyDigests,
    componentCount: plan.components.length,
    largestComponentFiles
  };
}

function containsProjectWideModuleDeclaration(
  sourceFile: ts.SourceFile
): boolean {
  const pending: ts.Node[] = [...sourceFile.statements];
  while (pending.length) {
    const node = pending.pop();
    if (!node) continue;
    if (
      ts.isModuleDeclaration(node) &&
      ((ts.isIdentifier(node.name) && node.name.text === 'global') ||
        ts.isStringLiteral(node.name))
    )
      return true;
    for (const child of node.getChildren(sourceFile)) pending.push(child);
  }
  return false;
}

function localModuleSpecifiers(sourceFile: ts.SourceFile): string[] {
  const result = new Set<string>();
  const pending: ts.Node[] = [sourceFile];
  while (pending.length > 0) {
    const node = pending.pop();
    if (!node) continue;
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier &&
      ts.isStringLiteralLike(node.moduleSpecifier)
    )
      result.add(node.moduleSpecifier.text);
    if (ts.isCallExpression(node) && node.arguments.length > 0) {
      const target = node.expression;
      const isImport = target.kind === ts.SyntaxKind.ImportKeyword;
      const isRequire = ts.isIdentifier(target) && target.text === 'require';
      const argument = node.arguments[0];
      if (
        (isImport || isRequire) &&
        argument &&
        ts.isStringLiteralLike(argument)
      )
        result.add(argument.text);
    }
    if (
      ts.isImportTypeNode(node) &&
      ts.isLiteralTypeNode(node.argument) &&
      ts.isStringLiteralLike(node.argument.literal)
    )
      result.add(node.argument.literal.text);
    ts.forEachChild(node, (child) => {
      pending.push(child);
    });
  }
  return [...result];
}

/**
 * Builds deterministic SCC digests in O(V log V + E log E) time and
 * O(V + E) space. Sorting roots, component members, and dependency digests
 * makes results independent of snapshot enumeration order.
 */
export type TransitiveImportDigestStats = {
  vertexVisits: number;
  edgeVisits: number;
  peakDfsFrames: number;
};

/**
 * Builds deterministic SCC digests without recursion. Traversal is
 * O(V + E) before stable sorting and uses O(V + E) additional graph state.
 */
export function transitiveImportDigests(
  inputs: readonly AstProjectInput[],
  adjacency: ReadonlyMap<string, ReadonlySet<string>>,
  stats?: TransitiveImportDigestStats
): Map<string, string> {
  const inputByPath = new Map(inputs.map((input) => [input.filePath, input]));
  const indexes = new Map<string, number>();
  const lowLinks = new Map<string, number>();
  const stack: string[] = [];
  const onStack = new Set<string>();
  const components: string[][] = [];
  let nextIndex = 0;

  const discover = (filePath: string): void => {
    const index = nextIndex++;
    indexes.set(filePath, index);
    lowLinks.set(filePath, index);
    stack.push(filePath);
    onStack.add(filePath);
    if (stats) stats.vertexVisits += 1;
  };

  const roots = [...inputs].sort((left, right) =>
    left.filePath.localeCompare(right.filePath)
  );
  for (const input of roots) {
    if (indexes.has(input.filePath)) continue;
    discover(input.filePath);
    const frames: Array<{
      filePath: string;
      parent?: string;
      dependencies: Iterator<string>;
    }> = [
      {
        filePath: input.filePath,
        dependencies: (adjacency.get(input.filePath) ?? [])[Symbol.iterator]()
      }
    ];
    if (stats) stats.peakDfsFrames = Math.max(stats.peakDfsFrames, 1);

    while (frames.length > 0) {
      const frame = frames[frames.length - 1];
      if (!frame) break;
      const next = frame.dependencies.next();
      if (!next.done) {
        const dependency = next.value;
        if (stats) stats.edgeVisits += 1;
        if (!indexes.has(dependency)) {
          discover(dependency);
          frames.push({
            filePath: dependency,
            parent: frame.filePath,
            dependencies: (adjacency.get(dependency) ?? [])[Symbol.iterator]()
          });
          if (stats)
            stats.peakDfsFrames = Math.max(stats.peakDfsFrames, frames.length);
        } else if (onStack.has(dependency)) {
          lowLinks.set(
            frame.filePath,
            Math.min(
              lowLinks.get(frame.filePath) ?? indexes.get(frame.filePath) ?? 0,
              indexes.get(dependency) ?? 0
            )
          );
        }
        continue;
      }

      frames.pop();
      const filePath = frame.filePath;
      if (lowLinks.get(filePath) === indexes.get(filePath)) {
        const component: string[] = [];
        while (stack.length > 0) {
          const member = stack.pop();
          if (member === undefined) break;
          onStack.delete(member);
          component.push(member);
          if (member === filePath) break;
        }
        components.push(component.sort());
      }
      if (frame.parent) {
        lowLinks.set(
          frame.parent,
          Math.min(
            lowLinks.get(frame.parent) ?? indexes.get(frame.parent) ?? 0,
            lowLinks.get(filePath) ?? indexes.get(filePath) ?? 0
          )
        );
      }
    }
  }

  const componentByPath = new Map<string, number>();
  components.forEach((component, componentIndex) => {
    for (const filePath of component)
      componentByPath.set(filePath, componentIndex);
  });
  const componentDigests = new Map<number, string>();
  const digests = new Map<string, string>();
  components.forEach((component, componentIndex) => {
    const members = component.flatMap((filePath) => {
      const input = inputByPath.get(filePath);
      return input
        ? [[filePath, createHash('sha256').update(input.content).digest('hex')]]
        : [];
    });
    const dependencies = new Set<number>();
    for (const filePath of component)
      for (const dependency of adjacency.get(filePath) ?? []) {
        const dependencyComponent = componentByPath.get(dependency);
        if (
          dependencyComponent !== undefined &&
          dependencyComponent !== componentIndex
        )
          dependencies.add(dependencyComponent);
      }
    const dependencyDigests = [...dependencies]
      .map((dependency) => componentDigests.get(dependency))
      .filter((digest): digest is string => digest !== undefined)
      .sort();
    const digest = createHash('sha256')
      .update(JSON.stringify({ members, dependencies: dependencyDigests }))
      .digest('hex');
    componentDigests.set(componentIndex, digest);
    for (const filePath of component)
      digests.set(
        filePath,
        createHash('sha256').update(`${digest}\0${filePath}`).digest('hex')
      );
  });
  return digests;
}

function isSensitiveValue(
  expression: ts.Expression,
  scope: Scope,
  sensitive: TaintedNames,
  callReturns: WeakMap<ts.CallExpression, FlowBinding>
): boolean {
  if (isRedactionCall(expression)) return false;
  if (isMemberAccessRoot(expression) && isSensitiveDataSource(expression))
    return true;
  if (ts.isIdentifier(expression)) {
    for (
      let current: Scope | undefined = scope;
      current;
      current = current.parent
    )
      if (sensitive.get(current)?.has(expression.text)) return true;
    return false;
  }
  let found = false;
  const visit = (node: ts.Node): void => {
    if (found || (node !== expression && ts.isFunctionLike(node))) return;
    if (ts.isExpression(node) && isRedactionCall(node)) return;
    if (ts.isCallExpression(node)) {
      const returned = callReturns.get(node);
      if (returned && sensitive.get(returned.scope)?.has(returned.name)) {
        found = true;
        return;
      }
    }
    if (
      ts.isExpression(node) &&
      isMemberAccessRoot(node) &&
      isSensitiveDataSource(node)
    ) {
      found = true;
      return;
    }
    if (ts.isIdentifier(node) && !isIdentifierPropertyName(node)) {
      for (
        let current: Scope | undefined = scope;
        current;
        current = current.parent
      ) {
        if (sensitive.get(current)?.has(node.text)) {
          found = true;
          return;
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(expression);
  return found;
}

function sensitiveOutputSink(
  call: ts.CallExpression,
  scope: Scope
):
  | 'log'
  | 'response'
  | 'outbound-request'
  | 'telemetry'
  | 'storage'
  | undefined {
  const target = call.expression;
  const method = ts.isPropertyAccessExpression(target)
    ? target.name.text.toLowerCase()
    : ts.isIdentifier(target)
      ? target.text.toLowerCase()
      : '';
  const receiver = ts.isPropertyAccessExpression(target)
    ? propertyPath(target.expression)?.at(-1)?.toLowerCase()
    : undefined;
  const receiverPath = ts.isPropertyAccessExpression(target)
    ? (propertyPath(target.expression) ?? []).map((part) => part.toLowerCase())
    : [];
  if (
    (['log', 'info', 'warn', 'error', 'debug', 'trace'].includes(method) &&
      (receiver === 'console' ||
        receiver === 'logger' ||
        receiver === 'log' ||
        receiver?.endsWith('logger'))) ||
    (receiver === 'console' &&
      ['table', 'dir', 'dirxml', 'assert', 'timelog'].includes(method))
  )
    return 'log';
  if (
    ['json', 'send', 'end'].includes(method) &&
    ['res', 'response', 'reply'].includes(receiver ?? '')
  )
    return 'response';
  if (
    ['fetch', 'request', 'get', 'post', 'put', 'patch', 'delete'].includes(
      method
    ) &&
    (method === 'fetch' ||
      ['axios', 'http', 'https', 'got', 'request', 'client'].includes(
        receiver ?? ''
      ))
  )
    return 'outbound-request';
  if (
    ['capture', 'captureexception', 'track', 'emit', 'record'].includes(
      method
    ) &&
    ['telemetry', 'analytics', 'sentry', 'tracer', 'metrics'].includes(
      receiver ?? ''
    )
  )
    return 'telemetry';
  if (
    method === 'setitem' &&
    ['localstorage', 'sessionstorage'].includes(receiver ?? '')
  )
    return 'storage';
  if (
    ['put', 'add'].includes(method) &&
    ['objectstore', 'idbobjectstore'].includes(receiver ?? '')
  )
    return 'storage';
  if (
    ['writefile', 'writefilesync', 'appendfile', 'appendfilesync'].includes(
      method
    ) &&
    isFileSystemSinkCall(call, scope)
  )
    return 'storage';
  if (
    [
      'create',
      'insertone',
      'insertmany',
      'updateone',
      'updatemany',
      'replaceone',
      'upsert'
    ].includes(method) &&
    ['db', 'database', 'collection', 'model', 'repository', 'repo'].some(
      (marker) => receiverPath.includes(marker)
    )
  )
    return 'storage';
  return undefined;
}

function htmlSink(node: ts.Node): boolean {
  if (
    ts.isBinaryExpression(node) &&
    node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
    ts.isPropertyAccessExpression(node.left)
  ) {
    return ['innerHTML', 'outerHTML'].includes(node.left.name.text);
  }
  return false;
}

/** Recognizes only explicit HTML-context encoders at HTML-writing sinks. */
function isHtmlEscaped(expression: ts.Expression): boolean {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isSatisfiesExpression(current)
  )
    current = current.expression;
  if (!ts.isCallExpression(current)) return false;
  const target = current.expression;
  const name = ts.isPropertyAccessExpression(target)
    ? target.name.text.toLowerCase()
    : ts.isIdentifier(target)
      ? target.text.toLowerCase()
      : '';
  if (
    [
      'escapehtml',
      'escapehtmlentities',
      'encodehtmlentities',
      'sanitizehtml'
    ].includes(name)
  )
    return true;
  return (
    name === 'sanitize' &&
    ts.isPropertyAccessExpression(target) &&
    ts.isIdentifier(target.expression) &&
    target.expression.text === 'DOMPurify'
  );
}

function isFileSystemSinkCall(call: ts.CallExpression, scope: Scope): boolean {
  const target = call.expression;
  if (ts.isIdentifier(target))
    return lookupBinding(scope, target.text) === 'filesystem';
  if (
    !ts.isPropertyAccessExpression(target) ||
    !fileSystemMethods.has(target.name.text)
  )
    return false;
  let receiver: ts.Expression = target.expression;
  while (ts.isPropertyAccessExpression(receiver))
    receiver = receiver.expression;
  return (
    ts.isIdentifier(receiver) &&
    lookupBinding(scope, receiver.text) === 'filesystem'
  );
}

function unwrapExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isSatisfiesExpression(current)
  )
    current = current.expression;
  return current;
}

function failClosed(statement: ts.Statement): boolean {
  if (ts.isThrowStatement(statement) || ts.isReturnStatement(statement))
    return true;
  if (ts.isBlock(statement)) {
    const last = statement.statements.at(-1);
    return last ? failClosed(last) : false;
  }
  if (ts.isIfStatement(statement))
    return Boolean(
      statement.elseStatement &&
      failClosed(statement.thenStatement) &&
      failClosed(statement.elseStatement)
    );
  return false;
}

function literalHostAllowlist(expression: ts.Expression): boolean {
  const value = unwrapExpression(expression);
  if (
    !ts.isArrayLiteralExpression(value) ||
    value.elements.length === 0 ||
    !value.elements.every((element) => ts.isStringLiteral(element))
  )
    return false;
  return value.elements.every((element) => {
    if (!ts.isStringLiteral(element)) return false;
    const host = element.text.trim().toLowerCase().replace(/\.$/u, '');
    return (
      host.length > 0 &&
      !host.includes('*') &&
      !isIP(host.replace(/^\[|\]$/gu, '')) &&
      host !== 'localhost' &&
      !host.endsWith('.localhost') &&
      !host.endsWith('.local') &&
      !host.endsWith('.internal')
    );
  });
}

function hostAllowlistGuard(
  statement: ts.IfStatement,
  candidate: ts.Expression
): boolean {
  const condition = unwrapExpression(statement.expression);
  if (
    !ts.isPrefixUnaryExpression(condition) ||
    condition.operator !== ts.SyntaxKind.ExclamationToken
  )
    return false;
  const denied = statement.thenStatement;
  if (!failClosed(denied)) return false;
  const check = unwrapExpression(condition.operand);
  if (!ts.isCallExpression(check) || check.arguments.length !== 1) return false;
  const member = check.expression;
  if (
    !ts.isPropertyAccessExpression(member) ||
    !['includes', 'has'].includes(member.name.text)
  )
    return false;
  if (!literalHostAllowlist(member.expression)) return false;
  const hostArgument = check.arguments[0];
  if (!hostArgument) return false;
  const host = unwrapExpression(hostArgument);
  if (!ts.isPropertyAccessExpression(host) || host.name.text !== 'hostname')
    return false;
  const candidateValue = unwrapExpression(candidate);
  const candidateHost =
    ts.isPropertyAccessExpression(candidateValue) &&
    ['href', 'url'].includes(candidateValue.name.text.toLowerCase())
      ? candidateValue.expression
      : candidateValue;
  return (
    candidateHost.getText() === unwrapExpression(host.expression).getText()
  );
}

function rootIdentifier(expression: ts.Expression): ts.Identifier | undefined {
  let current = unwrapExpression(expression);
  while (
    ts.isPropertyAccessExpression(current) ||
    ts.isElementAccessExpression(current)
  )
    current = current.expression;
  return ts.isIdentifier(current) ? current : undefined;
}

function mutatedBetween(
  ownerBody: ts.Node,
  expression: ts.Expression,
  start: number,
  end: number
): boolean {
  const root = rootIdentifier(expression);
  if (!root) return false;
  let mutated = false;
  const visit = (node: ts.Node): void => {
    if (mutated || (node !== ownerBody && ts.isFunctionLike(node))) return;
    if (node.getStart() > start && node.getEnd() < end) {
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
        node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
        rootIdentifier(node.left)?.text === root.text
      ) {
        mutated = true;
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(ownerBody);
  return mutated;
}

function redirectsBlocked(call: ts.CallExpression): boolean {
  const options = call.arguments[1];
  if (!options || !ts.isObjectLiteralExpression(options)) return false;
  return options.properties.some(
    (property) =>
      ts.isPropertyAssignment(property) &&
      propertyName(property.name) === 'redirect' &&
      ts.isStringLiteral(property.initializer) &&
      property.initializer.text === 'error'
  );
}

/** Accepts a literal host allowlist only when its rejection branch exits and
 * Fetch is configured to fail on redirects, which could otherwise leave the
 * checked host. Dynamic policies remain review candidates. */
function hasVerifiedFetchHostAllowlist(
  call: ts.CallExpression,
  candidate: ts.Expression
): boolean {
  if (!redirectsBlocked(call)) return false;
  let owner = call.parent;
  while (owner && !ts.isFunctionLike(owner)) owner = owner.parent;
  if (!owner || !('body' in owner) || !owner.body) return false;
  const ownerBody = owner.body;
  let verified = false;
  const visit = (node: ts.Node): void => {
    if (verified || (node !== owner && ts.isFunctionLike(node))) return;
    if (
      ts.isIfStatement(node) &&
      node.getEnd() < call.getStart() &&
      hostAllowlistGuard(node, candidate) &&
      !mutatedBetween(ownerBody, candidate, node.getEnd(), call.getStart())
    ) {
      verified = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(ownerBody);
  return verified;
}

function sourceSinkRule(
  node: ts.Node,
  scope: Scope,
  tainted: TaintedNames,
  callReturns: WeakMap<ts.CallExpression, FlowBinding>
): AstSecurityRule | undefined {
  if (htmlSink(node) && ts.isBinaryExpression(node)) {
    return isTainted(node.right, scope, tainted, callReturns) &&
      !isHtmlEscaped(node.right)
      ? astSecurityRules.crossSiteScripting
      : undefined;
  }
  if (
    ts.isElementAccessExpression(node) &&
    ts.isElementAccessExpression(node.parent) &&
    node.parent.expression === node
  ) {
    const parent = node.parent.parent;
    if (
      ts.isBinaryExpression(parent) &&
      parent.left === node.parent &&
      parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      isTainted(node, scope, tainted, callReturns)
    ) {
      return astSecurityRules.prototypePollution;
    }
  }
  if (!ts.isCallExpression(node)) return undefined;
  const target = node.expression;
  const method = ts.isPropertyAccessExpression(target)
    ? target.name.text
    : ts.isIdentifier(target)
      ? target.text
      : '';
  const first = node.arguments[0];
  if (
    childProcessValue(target, scope, target.getStart()) ===
      'unsafeDeserializer' &&
    first &&
    isTainted(first, scope, tainted, callReturns)
  )
    return astSecurityRules.unsafeDeserialization;
  if (
    dynamicChildProcessCall(node, scope) &&
    node.arguments.some((argument) =>
      isTainted(argument, scope, tainted, callReturns)
    )
  )
    return astSecurityRules.dynamicCommandExecution;
  if (
    invokesShell(node, scope) &&
    node.arguments
      .slice(0, 2)
      .some((argument) => isTainted(argument, scope, tainted, callReturns))
  )
    return astSecurityRules.commandInjection;
  if (first && isTainted(first, scope, tainted, callReturns)) {
    if (isFileSystemSinkCall(node, scope))
      return astSecurityRules.unsafeFilePath;
    if (
      [
        'query',
        'execute',
        'raw',
        '$queryRawUnsafe',
        '$executeRawUnsafe'
      ].includes(method)
    ) {
      return astSecurityRules.sqlInjection;
    }
    const receiver = ts.isPropertyAccessExpression(target)
      ? propertyPath(target.expression)?.at(-1)
      : undefined;
    if (
      ['fetch', 'request', 'get', 'post', 'put', 'patch', 'delete'].includes(
        method
      ) &&
      (method === 'fetch' ||
        ['axios', 'http', 'https', 'got', 'request', 'client'].includes(
          receiver ?? ''
        )) &&
      !hasVerifiedFetchHostAllowlist(node, first)
    ) {
      return astSecurityRules.serverSideRequestForgery;
    }
  }
  if (
    ts.isPropertyAccessExpression(target) &&
    ['insertAdjacentHTML', 'write', 'writeln'].includes(method)
  ) {
    const htmlArgument =
      method === 'insertAdjacentHTML' ? node.arguments[1] : first;
    if (
      htmlArgument &&
      isTainted(htmlArgument, scope, tainted, callReturns) &&
      !isHtmlEscaped(htmlArgument)
    )
      return astSecurityRules.crossSiteScripting;
  }
  if (
    ts.isPropertyAccessExpression(target) &&
    ts.isIdentifier(target.expression) &&
    target.expression.text === 'Object' &&
    method === 'assign' &&
    node.arguments
      .slice(1)
      .some((argument) => isTainted(argument, scope, tainted, callReturns))
  ) {
    return astSecurityRules.prototypePollution;
  }
  if (
    ts.isPropertyAccessExpression(target) &&
    ts.isIdentifier(target.expression) &&
    target.expression.text === 'Object' &&
    method === 'setPrototypeOf' &&
    node.arguments[1] &&
    isTainted(node.arguments[1], scope, tainted, callReturns)
  ) {
    return astSecurityRules.prototypePollution;
  }
  return undefined;
}

/** Analyzes supported source text for dangerous AST constructs. */
export function analyzeAstSource(
  filePath: string,
  content: string,
  project?: AstProjectAnalysis
): Finding[] {
  const projectSource = project?.sourceFiles.get(filePath);
  const sourceFile =
    projectSource?.text === content
      ? projectSource
      : ts.createSourceFile(
          filePath,
          content,
          ts.ScriptTarget.Latest,
          true,
          scriptKind(filePath)
        );
  let scopes = project?.scopes;
  let taintAnalysis = project?.taint;
  let sensitiveAnalysis = project?.sensitive;
  if (
    !projectSource ||
    projectSource.text !== content ||
    !scopes ||
    !taintAnalysis ||
    !sensitiveAnalysis
  ) {
    scopes = new WeakMap<ts.Node, Scope>();
    createScopeTree(sourceFile, undefined, scopes);
    collectBindings(sourceFile, scopes);
    taintAnalysis = collectTaintedNames([sourceFile], scopes);
    sensitiveAnalysis = collectSensitiveNames([sourceFile], scopes);
  }
  const tainted = taintAnalysis.tainted;
  const sensitive = sensitiveAnalysis.tainted;
  const findings: Finding[] = [];

  const visit = (node: ts.Node): void => {
    const scope = scopes?.get(node);
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'eval' &&
      scope &&
      lookupBinding(scope, 'eval') === undefined
    ) {
      findings.push(
        createFinding(sourceFile, node, astSecurityRules.eval, filePath)
      );
    }

    if (
      ts.isNewExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'Function' &&
      scope &&
      lookupBinding(scope, 'Function') === undefined
    ) {
      findings.push(
        createFinding(
          sourceFile,
          node,
          astSecurityRules.functionConstructor,
          filePath
        )
      );
    }

    if (ts.isCallExpression(node)) {
      const childProcessRule = scope
        ? childProcessRuleForCall(node, scope)
        : undefined;

      if (childProcessRule) {
        findings.push(
          createFinding(sourceFile, node, childProcessRule, filePath)
        );
      }
      const outputSink = scope ? sensitiveOutputSink(node, scope) : undefined;
      if (
        scope &&
        outputSink &&
        node.arguments.some((argument) =>
          isSensitiveValue(
            argument,
            scope,
            sensitive,
            sensitiveAnalysis.callReturns
          )
        )
      ) {
        const finding = createFinding(
          sourceFile,
          node,
          astSecurityRules.sensitiveDataExposure
        );
        if (outputSink === 'storage') {
          finding.severity = 'medium';
          finding.confidence = 'low';
        }
        finding.metadata = {
          ...finding.metadata,
          sourceClass: 'credential-like environment or sensitive-field value',
          sinkClass: outputSink,
          analysisModel: 'bounded-project-sensitive-flow-v2'
        };
        findings.push(finding);
      }
    }

    if (scope) {
      const sourceSink = sourceSinkRule(
        node,
        scope,
        tainted,
        taintAnalysis.callReturns
      );
      if (sourceSink)
        findings.push(createFinding(sourceFile, node, sourceSink, filePath));
    }

    ts.forEachChild(node, visit);
  };

  visit(sourceFile);

  return [
    ...findings,
    ...analyzeAuthorizationSource(
      filePath,
      content,
      sourceFile,
      project ? [...project.sourceFiles.values()] : [],
      project?.resourceMiddlewareFunctions
    ),
    ...analyzeConcurrencySource(filePath, content, sourceFile)
  ];
}
