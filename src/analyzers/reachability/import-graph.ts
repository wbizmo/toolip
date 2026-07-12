import ts from 'typescript';

export type ImportReference = {
  packageName: string;
  importedSymbols: string[];
  localSymbols: string[];
  kind:
    | 'default'
    | 'named'
    | 'namespace'
    | 'side-effect'
    | 'require'
    | 'dynamic-import';
  line: number;
  column: number;
};

function packageRoot(specifier: string): string | undefined {
  if (
    specifier.startsWith('.') ||
    specifier.startsWith('/') ||
    specifier.startsWith('node:')
  ) {
    return undefined;
  }

  if (specifier.startsWith('@')) {
    const [scope, name] = specifier.split('/');
    return scope && name ? `${scope}/${name}` : undefined;
  }

  return specifier.split('/')[0];
}

function location(
  sourceFile: ts.SourceFile,
  node: ts.Node
): { line: number; column: number } {
  const value = sourceFile.getLineAndCharacterOfPosition(
    node.getStart(sourceFile)
  );

  return {
    line: value.line + 1,
    column: value.character + 1
  };
}

export function extractPackageImports(
  filePath: string,
  content: string
): ImportReference[] {
  const sourceFile = ts.createSourceFile(
    filePath,
    content,
    ts.ScriptTarget.Latest,
    true,
    filePath.endsWith('.tsx')
      ? ts.ScriptKind.TSX
      : filePath.endsWith('.jsx')
        ? ts.ScriptKind.JSX
        : filePath.endsWith('.js') ||
            filePath.endsWith('.mjs') ||
            filePath.endsWith('.cjs')
          ? ts.ScriptKind.JS
          : ts.ScriptKind.TS
  );

  const references: ImportReference[] = [];

  const visit = (node: ts.Node): void => {
    if (
      ts.isImportDeclaration(node) &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      const root = packageRoot(node.moduleSpecifier.text);

      if (root) {
        const importedSymbols: string[] = [];
        const localSymbols: string[] = [];
        let kind: ImportReference['kind'] = 'side-effect';

        const clause = node.importClause;

        if (clause?.name) {
          kind = 'default';
          importedSymbols.push('default');
          localSymbols.push(clause.name.text);
        }

        if (clause?.namedBindings) {
          if (ts.isNamespaceImport(clause.namedBindings)) {
            kind = 'namespace';
            importedSymbols.push('*');
            localSymbols.push(
              clause.namedBindings.name.text
            );
          } else {
            kind = 'named';

            for (const element of clause.namedBindings.elements) {
              importedSymbols.push(
                element.propertyName?.text ??
                  element.name.text
              );
              localSymbols.push(element.name.text);
            }
          }
        }

        references.push({
          packageName: root,
          importedSymbols,
          localSymbols,
          kind,
          ...location(sourceFile, node)
        });
      }
    }

    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'require' &&
      node.arguments.length === 1
    ) {
      const [argument] = node.arguments;

      if (argument && ts.isStringLiteral(argument)) {
        const root = packageRoot(argument.text);

        if (root) {
          references.push({
            packageName: root,
            importedSymbols: ['*'],
            localSymbols: [],
            kind: 'require',
            ...location(sourceFile, node)
          });
        }
      }
    }

    if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword &&
      node.arguments.length === 1
    ) {
      const [argument] = node.arguments;

      if (argument && ts.isStringLiteral(argument)) {
        const root = packageRoot(argument.text);

        if (root) {
          references.push({
            packageName: root,
            importedSymbols: ['*'],
            localSymbols: [],
            kind: 'dynamic-import',
            ...location(sourceFile, node)
          });
        }
      }
    }

    ts.forEachChild(node, visit);
  };

  visit(sourceFile);

  return references;
}
