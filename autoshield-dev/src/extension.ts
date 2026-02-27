import * as vscode from 'vscode';
import axios from 'axios';

export function activate(context: vscode.ExtensionContext) {
    // 1. Create a collection for squiggles
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('autoshield');

    let scanCommand = vscode.commands.registerCommand('autoshield.scan', async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showErrorMessage("Open a folder first!");
            return;
        }

        const projectPath = workspaceFolders[0].uri.fsPath;
        vscode.window.showInformationMessage(`Scanning: ${projectPath}...`);

        try {
            // 2. Call your FastAPI Backend
            const response = await axios.post(`http://127.0.0.1:8000/analyze-code?path=${encodeURIComponent(projectPath)}`);
            const findings = response.data.results;

            // 3. Clear old squiggles
            diagnosticCollection.clear();

            // 4. Map findings to editor squiggles
            const diagnosticMap: Map<string, vscode.Diagnostic[]> = new Map();

            findings.forEach((finding: any) => {
                const uri = vscode.Uri.file(finding.file_path);
                const range = new vscode.Range(finding.line - 1, 0, finding.line - 1, 100);
                const diagnostic = new vscode.Diagnostic(
                    range, 
                    `[${finding.tool}] ${finding.message}`, 
                    finding.severity === 'HIGH' ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning
                );

                const diagnostics = diagnosticMap.get(uri.toString()) || [];
                diagnostics.push(diagnostic);
                diagnosticMap.set(uri.toString(), diagnostics);
            });

            diagnosticMap.forEach((diags, uriStr) => {
                diagnosticCollection.set(vscode.Uri.parse(uriStr), diags);
            });

            vscode.window.showInformationMessage(`Scan Complete! Found ${findings.length} issues.`);

        } catch (error) {
            vscode.window.showErrorMessage("Failed to connect to AutoShield Backend.");
        }
    });

    context.subscriptions.push(scanCommand, diagnosticCollection);
}