import * as path from "node:path";
import * as vscode from "vscode";

import {
  buildDiagnosticsDocumentModel,
  type DiagnosticsDocumentModel,
  type DiagnosticsFindingModel,
  type DiagnosticsProjection,
} from "./model";

type DocumentNode = {
  kind: "document";
  model: DiagnosticsDocumentModel;
  uri: vscode.Uri;
};

type FindingNode = {
  document: DocumentNode;
  finding: DiagnosticsFindingModel;
  kind: "finding";
};

type TreeNode = DocumentNode | FindingNode;

class PaintDiagnosticsProvider implements vscode.TreeDataProvider<TreeNode> {
  private readonly onDidChangeTreeDataEmitter = new vscode.EventEmitter<TreeNode | undefined>();
  readonly onDidChangeTreeData = this.onDidChangeTreeDataEmitter.event;

  refresh() {
    this.onDidChangeTreeDataEmitter.fire(undefined);
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    if (element.kind === "document") {
      const item = new vscode.TreeItem(
        element.model.label,
        vscode.TreeItemCollapsibleState.Expanded,
      );
      item.description = element.model.description;
      item.contextValue = "paintgunDiagnostics.document";
      item.tooltip = `${element.model.label}\n${element.model.description}`;
      return item;
    }

    const item = new vscode.TreeItem(
      element.finding.label,
      vscode.TreeItemCollapsibleState.None,
    );
    item.description = `${element.finding.severity} · ${element.finding.summary}`;
    item.contextValue = "paintgunDiagnostics.finding";
    item.tooltip = element.finding.tooltip;
    item.command = {
      command: "paintgunDiagnostics.openFinding",
      title: "Open finding",
      arguments: [element],
    };
    return item;
  }

  async getChildren(element?: TreeNode): Promise<TreeNode[]> {
    if (!element) {
      return await this.loadDocuments();
    }

    if (element.kind === "document") {
      return element.model.findings.map((finding) => ({
        document: element,
        finding,
        kind: "finding" as const,
      }));
    }

    return [];
  }

  private async loadDocuments(): Promise<DocumentNode[]> {
    const uris = await vscode.workspace.findFiles("**/diagnostics.*.json", "**/node_modules/**");
    const documents: DocumentNode[] = [];

    for (const uri of uris) {
      try {
        const bytes = await vscode.workspace.fs.readFile(uri);
        const projection = JSON.parse(Buffer.from(bytes).toString("utf8")) as DiagnosticsProjection;
        const workspaceFolder = vscode.workspace.getWorkspaceFolder(uri);
        const relativePath = workspaceFolder
          ? path.relative(workspaceFolder.uri.fsPath, uri.fsPath)
          : uri.fsPath;

        documents.push({
          kind: "document",
          model: buildDiagnosticsDocumentModel(relativePath, projection),
          uri,
        });
      } catch (error) {
        console.warn(`paintgun diagnostics: failed to load ${uri.fsPath}`, error);
      }
    }

    documents.sort((left, right) => left.model.label.localeCompare(right.model.label));
    return documents;
  }
}

async function resolveFindingTarget(
  documentUri: vscode.Uri,
  record: DiagnosticsFindingModel,
): Promise<vscode.Uri | undefined> {
  if (!record.filePath) {
    return undefined;
  }

  let currentDir = path.dirname(documentUri.fsPath);
  while (true) {
    const candidate = path.resolve(currentDir, record.filePath);
    const candidateUri = vscode.Uri.file(candidate);
    try {
      await vscode.workspace.fs.stat(candidateUri);
      return candidateUri;
    } catch {
      const parent = path.dirname(currentDir);
      if (parent === currentDir) {
        return undefined;
      }
      currentDir = parent;
    }
  }
}

async function openFinding(node: FindingNode) {
  const target = await resolveFindingTarget(node.document.uri, node.finding);
  if (!target) {
    vscode.window.showInformationMessage(
      `Paintgun could not resolve a source file for ${node.finding.id}.`,
    );
    return;
  }

  const document = await vscode.workspace.openTextDocument(target);
  await vscode.window.showTextDocument(document, {
    preview: false,
    preserveFocus: false,
    selection: new vscode.Range(0, 0, 0, 0),
  });

  if (node.finding.jsonPointer) {
    vscode.window.showInformationMessage(
      `Paintgun diagnostics pointer: ${node.finding.jsonPointer}`,
    );
  }
}

export function activate(context: vscode.ExtensionContext) {
  const provider = new PaintDiagnosticsProvider();

  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("paintgunDiagnostics.findings", provider),
    vscode.commands.registerCommand("paintgunDiagnostics.refresh", () => provider.refresh()),
    vscode.commands.registerCommand("paintgunDiagnostics.openFinding", (node: FindingNode) =>
      openFinding(node),
    ),
  );
}

export function deactivate() {}
