import ts from 'typescript';
import type { Finding } from '../../contracts/finding.js';
import {
  astSecurityRules,
  type AstSecurityRule
} from './rules.js';

type ChildProcessBindings = {
  namespaceImports: Set<string>;
  execImports: Set<string>;
  execSyncImports: Set<string>;
};

function scriptKind(filePath: string): ts.ScriptKind {
  if (filePath.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (filePath.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (filePath.endsWith('.js')) return ts.ScriptKind.JS;
  if (filePath.endsWith('.mjs')) return ts.ScriptKind.JS;
  if (filePath.endsWith('.cjs')) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function isChildProcessModule(value: string): boolean {
  return value === 'child_process' || value === 'node:child_process';
}

function moduleNameFromImport(
  declaration: ts.ImportDeclaration
): string | undefined {
  return ts.isStringLiteral(declaration.moduleSpecifier)
    ? declaration.moduleSpecifier.text
    : undefined;
}

function requireModuleName(
  expression: ts.Expression | undefined
): string | undefined {
  if (
    !expression ||
    !ts.isCallExpression(expression) ||
    !ts.isIdentifier(expression.expression) ||
    expression.expression.text !== 'require' ||
    expression.arguments.length !== 1
  ) {
    return undefined;
  }

  const [argument] = expression.arguments;

  return argument && ts.isStringLiteral(argument)
    ? argument.text
    : undefined;
}

function collectBindings(
  sourceFile: ts.SourceFile
): ChildProcessBindings {
  const bindings: ChildProcessBindings = {
    namespaceImports: new Set(),
    execImports: new Set(),
    execSyncImports: new Set()
  };

  for (const statement of sourceFile.statements) {
    if (ts.isImportDeclaration(statement)) {
      const moduleName = moduleNameFromImport(statement);

      if (!moduleName || !isChildProcessModule(moduleName)) {
        continue;
      }

      const importClause = statement.importClause;

      if (!importClause) {
        continue;
      }

      const bindingsClause = importClause.namedBindings;

      if (bindingsClause && ts.isNamespaceImport(bindingsClause)) {
        bindings.namespaceImports.add(bindingsClause.name.text);
      }

      if (bindingsClause && ts.isNamedImports(bindingsClause)) {
        for (const element of bindingsClause.elements) {
          const importedName =
            element.propertyName?.text ?? element.name.text;
          const localName = element.name.text;

          if (importedName === 'exec') {
            bindings.execImports.add(localName);
          }

          if (importedName === 'execSync') {
            bindings.execSyncImports.add(localName);
          }
        }
      }
    }

    if (!ts.isVariableStatement(statement)) {
      continue;
    }

    for (const declaration of statement.declarationList.declarations) {
      const initializer = declaration.initializer;
      const moduleName = requireModuleName(initializer);

      if (
        moduleName &&
        isChildProcessModule(moduleName) &&
        ts.isIdentifier(declaration.name)
      ) {
        bindings.namespaceImports.add(declaration.name.text);
      }

      if (
        moduleName &&
        isChildProcessModule(moduleName) &&
        ts.isObjectBindingPattern(declaration.name)
      ) {
        for (const element of declaration.name.elements) {
          if (!ts.isIdentifier(element.name)) {
            continue;
          }

          const importedName =
            element.propertyName &&
            ts.isIdentifier(element.propertyName)
              ? element.propertyName.text
              : element.name.text;

          if (importedName === 'exec') {
            bindings.execImports.add(element.name.text);
          }

          if (importedName === 'execSync') {
            bindings.execSyncImports.add(element.name.text);
          }
        }
      }

      if (
        initializer &&
        ts.isPropertyAccessExpression(initializer) &&
        ts.isCallExpression(initializer.expression) &&
        ts.isIdentifier(initializer.expression.expression) &&
        initializer.expression.expression.text === 'require' &&
        initializer.expression.arguments.length === 1
      ) {
        const [argument] = initializer.expression.arguments;
        const requiredModule =
          argument && ts.isStringLiteral(argument)
            ? argument.text
            : undefined;

        if (
          requiredModule &&
          isChildProcessModule(requiredModule) &&
          ts.isIdentifier(declaration.name)
        ) {
          if (initializer.name.text === 'exec') {
            bindings.execImports.add(declaration.name.text);
          }

          if (initializer.name.text === 'execSync') {
            bindings.execSyncImports.add(declaration.name.text);
          }
        }
      }
    }
  }

  return bindings;
}

function findingLocation(
  sourceFile: ts.SourceFile,
  node: ts.Node
): Finding['location'] {
  const start = sourceFile.getLineAndCharacterOfPosition(
    node.getStart(sourceFile)
  );
  const end = sourceFile.getLineAndCharacterOfPosition(
    node.getEnd()
  );

  return {
    file: sourceFile.fileName,
    line: start.line + 1,
    column: start.character + 1,
    endLine: end.line + 1,
    endColumn: end.character + 1
  };
}

function evidenceExcerpt(
  sourceFile: ts.SourceFile,
  node: ts.Node
): string {
  const text = node
    .getText(sourceFile)
    .replaceAll(/\s+/g, ' ')
    .trim();

  return text.length <= 180
    ? text
    : `${text.slice(0, 177)}...`;
}

function createFinding(
  sourceFile: ts.SourceFile,
  node: ts.Node,
  rule: AstSecurityRule
): Finding {
  const location = findingLocation(sourceFile, node);
  const fingerprint =
    `${rule.id}:${sourceFile.fileName}:` +
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
        summary: evidenceExcerpt(sourceFile, node),
        fingerprint
      }
    ],
    remediation: {
      summary: rule.remediation
    },
    metadata: {
      nodeKind: ts.SyntaxKind[node.kind]
    }
  };
}

function childProcessRuleForCall(
  call: ts.CallExpression,
  bindings: ChildProcessBindings
): AstSecurityRule | undefined {
  const target = call.expression;

  if (ts.isIdentifier(target)) {
    if (bindings.execImports.has(target.text)) {
      return astSecurityRules.childProcessExec;
    }

    if (bindings.execSyncImports.has(target.text)) {
      return astSecurityRules.childProcessExecSync;
    }

    return undefined;
  }

  if (!ts.isPropertyAccessExpression(target)) {
    return undefined;
  }

  if (
    !ts.isIdentifier(target.expression) ||
    !bindings.namespaceImports.has(target.expression.text)
  ) {
    return undefined;
  }

  if (target.name.text === 'exec') {
    return astSecurityRules.childProcessExec;
  }

  if (target.name.text === 'execSync') {
    return astSecurityRules.childProcessExecSync;
  }

  return undefined;
}

export function analyzeAstSource(
  filePath: string,
  content: string
): Finding[] {
  const sourceFile = ts.createSourceFile(
    filePath,
    content,
    ts.ScriptTarget.Latest,
    true,
    scriptKind(filePath)
  );

  const bindings = collectBindings(sourceFile);
  const findings: Finding[] = [];

  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'eval'
    ) {
      findings.push(
        createFinding(
          sourceFile,
          node,
          astSecurityRules.eval
        )
      );
    }

    if (
      ts.isNewExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'Function'
    ) {
      findings.push(
        createFinding(
          sourceFile,
          node,
          astSecurityRules.functionConstructor
        )
      );
    }

    if (ts.isCallExpression(node)) {
      const childProcessRule = childProcessRuleForCall(
        node,
        bindings
      );

      if (childProcessRule) {
        findings.push(
          createFinding(
            sourceFile,
            node,
            childProcessRule
          )
        );
      }
    }

    ts.forEachChild(node, visit);
  };

  visit(sourceFile);

  return findings;
}
