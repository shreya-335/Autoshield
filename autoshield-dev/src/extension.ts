import * as vscode from 'vscode';
import axios from 'axios';
import * as fs from 'fs';
import * as path from 'path';
import { AutoShieldSidebarProvider } from './sidebar.js';

const BACKEND = 'http://127.0.0.1:8000';

export function activate(context: vscode.ExtensionContext) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('autoshield');

    const sidebarProvider = new AutoShieldSidebarProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider('autoshield.view', sidebarProvider)
    );

    // ── Command: Full Tri-Layer Scan ──────────────────────────────
    const scanCommand = vscode.commands.registerCommand('autoshield.scan', async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showErrorMessage('AutoShield: Open a project folder first.');
            return;
        }

        const projectPath = workspaceFolders[0].uri.fsPath;

        const useLLM = await vscode.window.showQuickPick(
            [
                { label: '🧠 Full Analysis (Static + RAG + LLM)', value: true },
                { label: '⚡ Fast Scan (Static + RAG only)', value: false },
            ],
            { placeHolder: 'Choose analysis depth' }
        );

        if (!useLLM) { return; }

        // Signal sidebar that scan is starting
        sidebarProvider.postMessage({ type: 'scanStarted' });

        await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: 'AutoShield',
                cancellable: false,
            },
            async (progress) => {
                progress.report({ message: '🔍 Running static analysis…' });

                try {
                    const response = await axios.post(`${BACKEND}/analyze-full`, {
                        path: projectPath,
                        use_llm: useLLM.value,
                    });

                    const { results, summary, count } = response.data;

                    progress.report({ message: '🧠 Processing findings…' });

                    // Apply inline squiggles
                    diagnosticCollection.clear();
                    const diagnosticMap = new Map<string, vscode.Diagnostic[]>();

                    for (const finding of results) {
                        if (!finding.file_path || finding.file_path === 'unknown') { continue; }

                        // Resolve absolute path for diagnostics
                        const resolvedPath = _resolveFilePath(finding.file_path, projectPath);
                        if (!resolvedPath) { continue; }

                        const uri = vscode.Uri.file(resolvedPath);
                        const line = Math.max(0, (finding.line || 1) - 1);
                        const range = new vscode.Range(line, 0, line, 200);

                        const severity = _toDiagnosticSeverity(finding.risk_category);
                        const message = _formatDiagnosticMessage(finding);

                        const diagnostic = new vscode.Diagnostic(range, message, severity);
                        diagnostic.source = `AutoShield [${finding.tool}]`;
                        diagnostic.code = finding.cwe_id;

                        const existing = diagnosticMap.get(uri.toString()) ?? [];
                        existing.push(diagnostic);
                        diagnosticMap.set(uri.toString(), existing);
                    }

                    diagnosticMap.forEach((diags, uriStr) => {
                        diagnosticCollection.set(vscode.Uri.parse(uriStr), diags);
                    });

                    sidebarProvider.postMessage({
                        type: 'scanResults',
                        results,
                        summary,
                        count,
                        projectPath,
                        llmEnabled: useLLM.value,
                    });

                    const critHigh = (summary.critical ?? 0) + (summary.high ?? 0);
                    const msg = critHigh > 0
                        ? `⚠️ AutoShield: ${critHigh} critical/high issues in ${count} findings`
                        : `✅ AutoShield: ${count} findings, no critical issues`;

                    vscode.window.showInformationMessage(msg, 'View in Sidebar').then(sel => {
                        if (sel) { vscode.commands.executeCommand('autoshield.view.focus'); }
                    });

                } catch (error: any) {
                    sidebarProvider.postMessage({ type: 'scanError', error: error?.response?.data?.detail ?? error.message });
                    const detail = error?.response?.data?.detail ?? error.message;
                    vscode.window.showErrorMessage(
                        `AutoShield scan failed: ${detail}. Is the backend running?`
                    );
                }
            }
        );
    });

    // ── Command: Analyze selection ────────────────────────────────
    const analyzeSelectionCommand = vscode.commands.registerCommand(
        'autoshield.analyzeSelection',
        async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) { return; }

            const selection = editor.selection;
            const code = editor.document.getText(selection);

            if (!code.trim()) {
                vscode.window.showWarningMessage('AutoShield: Select some code first.');
                return;
            }

            await vscode.window.withProgress(
                { location: vscode.ProgressLocation.Notification, title: 'AutoShield: Analyzing…' },
                async () => {
                    try {
                        const response = await axios.post(`${BACKEND}/rag/analyze`, {
                            code_snippet: code,
                            cwe_id: 'CWE-Unknown',
                            severity: 'medium',
                            vuln_type: '',
                            file_path: editor.document.fileName,
                            line: selection.start.line + 1,
                            tool: 'manual-review',
                            use_llm: true,
                        });

                        sidebarProvider.postMessage({
                            type: 'singleAnalysis',
                            result: response.data,
                        });

                        vscode.commands.executeCommand('autoshield.view.focus');
                    } catch (error: any) {
                        vscode.window.showErrorMessage(
                            `Analysis failed: ${error?.response?.data?.detail ?? error.message}`
                        );
                    }
                }
            );
        }
    );

    // ── Command: Apply Fix ────────────────────────────────────────
    const applyFixCommand = vscode.commands.registerCommand(
        'autoshield.applyFix',
        async (args: { filePath: string; line: number; originalCode: string; fixCode: string }) => {
            if (!args?.filePath || !args?.fixCode) {
                vscode.window.showErrorMessage('AutoShield: Missing fix data.');
                return;
            }

            const workspaceFolders = vscode.workspace.workspaceFolders;
            const projectPath = workspaceFolders?.[0]?.uri.fsPath ?? '';
            const resolvedPath = _resolveFilePath(args.filePath, projectPath);

            if (!resolvedPath) {
                vscode.window.showErrorMessage(`AutoShield: Cannot resolve file path: ${args.filePath}`);
                return;
            }

            const confirm = await vscode.window.showWarningMessage(
                `Apply AI-generated fix to ${resolvedPath.split('/').pop()}?`,
                { modal: true },
                'Apply Fix',
                'Cancel'
            );

            if (confirm !== 'Apply Fix') { return; }

            try {
                const response = await axios.post(`${BACKEND}/apply-fix`, {
                    file_path: resolvedPath,
                    line: args.line,
                    original_code: args.originalCode,
                    fix_code: args.fixCode,
                });

                if (response.data.success) {
                    vscode.window.showInformationMessage(
                        `✅ Fix applied to ${resolvedPath.split('/').pop()}`
                    );
                    const uri = vscode.Uri.file(resolvedPath);
                    const doc = await vscode.workspace.openTextDocument(uri);
                    await vscode.window.showTextDocument(doc);
                    vscode.commands.executeCommand('autoshield.scan');
                }
            } catch (error: any) {
                vscode.window.showErrorMessage(
                    `Failed to apply fix: ${error?.response?.data?.detail ?? error.message}`
                );
            }
        }
    );

    // ── Command: Jump to file/line ────────────────────────────────
    const jumpToCommand = vscode.commands.registerCommand(
        'autoshield.jumpToLine',
        async (args: { filePath: string; line: number }) => {
            if (!args?.filePath || args.filePath === 'unknown') { return; }

            const workspaceFolders = vscode.workspace.workspaceFolders;
            const projectPath = workspaceFolders?.[0]?.uri.fsPath ?? '';

            // Resolve relative or absolute path
            const resolvedPath = _resolveFilePath(args.filePath, projectPath);

            if (!resolvedPath) {
                vscode.window.showWarningMessage(`AutoShield: Cannot find file: ${args.filePath}`);
                return;
            }

            try {
                const uri = vscode.Uri.file(resolvedPath);
                const doc = await vscode.workspace.openTextDocument(uri);
                const editor = await vscode.window.showTextDocument(doc);
                const line = Math.max(0, (args.line || 1) - 1);
                const pos = new vscode.Position(line, 0);
                editor.selection = new vscode.Selection(pos, pos);
                editor.revealRange(
                    new vscode.Range(pos, pos),
                    vscode.TextEditorRevealType.InCenter
                );
            } catch {
                vscode.window.showWarningMessage(`AutoShield: Cannot open: ${args.filePath}`);
            }
        }
    );

    // ── Command: Generate Fix (calls Gemini) ─────────────────────
    const generateFixCommand = vscode.commands.registerCommand(
        'autoshield.generateFix',
        async (args: { codeSnippet: string; vulnType: string; cweId: string; findingIndex: number }) => {
            if (!args?.codeSnippet) { return; }

            sidebarProvider.postMessage({ type: 'fixGenerating', findingIndex: args.findingIndex });

            try {
                const response = await axios.post(`${BACKEND}/rag/generate-fix`, {
                    code_snippet: args.codeSnippet,
                    vuln_type: args.vulnType,
                    cwe_id: args.cweId,
                });

                sidebarProvider.postMessage({
                    type: 'fixGenerated',
                    findingIndex: args.findingIndex,
                    fixData: response.data,
                });
            } catch (error: any) {
                sidebarProvider.postMessage({
                    type: 'fixError',
                    findingIndex: args.findingIndex,
                    error: error?.response?.data?.detail ?? error.message,
                });
            }
        }
    );

    // ── Command: Clear diagnostics ────────────────────────────────
    const clearCommand = vscode.commands.registerCommand('autoshield.clear', () => {
        diagnosticCollection.clear();
        sidebarProvider.postMessage({ type: 'clear' });
        vscode.window.showInformationMessage('AutoShield: Diagnostics cleared.');
    });

    context.subscriptions.push(
        scanCommand,
        analyzeSelectionCommand,
        applyFixCommand,
        jumpToCommand,
        generateFixCommand,
        clearCommand,
        diagnosticCollection,
    );
}

export function deactivate() {}

// ── Helpers ────────────────────────────────────────────────────────

/**
 * Resolves a file path that may be absolute or relative.
 * If relative, joins it against the workspace project path.
 * Returns null if the file cannot be found on disk.
 */
function _resolveFilePath(filePath: string, projectPath: string): string | null {
    if (!filePath || filePath === 'unknown') { return null; }

    // Already absolute and exists
    if (path.isAbsolute(filePath) && fs.existsSync(filePath)) {
        return filePath;
    }

    // Try joining with workspace root
    if (projectPath) {
        const joined = path.join(projectPath, filePath);
        if (fs.existsSync(joined)) {
            return joined;
        }
    }

    // Try stripping any leading slash and joining
    const stripped = filePath.replace(/^[/\\]+/, '');
    if (projectPath) {
        const joined2 = path.join(projectPath, stripped);
        if (fs.existsSync(joined2)) {
            return joined2;
        }
    }

    // Absolute path that doesn't exist on disk
    if (path.isAbsolute(filePath)) {
        return filePath; // Let VS Code try — it'll give a better error message
    }

    return null;
}

function _toDiagnosticSeverity(riskCategory: string): vscode.DiagnosticSeverity {
    switch ((riskCategory ?? '').toUpperCase()) {
        case 'CRITICAL':
        case 'HIGH':
            return vscode.DiagnosticSeverity.Error;
        case 'MEDIUM':
            return vscode.DiagnosticSeverity.Warning;
        default:
            return vscode.DiagnosticSeverity.Information;
    }
}

function _formatDiagnosticMessage(finding: any): string {
    const score = finding.risk_score?.toFixed(1) ?? '?';
    const cat = finding.risk_category ?? finding.final_severity ?? 'UNKNOWN';
    const owasp = finding.owasp_category ? ` | OWASP: ${finding.owasp_category}` : '';
    const fp = finding.false_positive_likelihood > 0.5 ? ' ⚠ Possible FP' : '';
    return `[${cat} | Score: ${score}/100${owasp}] ${finding.vuln_type || finding.cwe_id}${fp}`;
}