import * as vscode from 'vscode';

export class AutoShieldSidebarProvider implements vscode.WebviewViewProvider {
  private _view?: vscode.WebviewView;

  constructor(private readonly _extensionUri: vscode.Uri) {}

  resolveWebviewView(webviewView: vscode.WebviewView) {
    this._view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
    };

    webviewView.webview.html = this._getHtml();

    webviewView.webview.onDidReceiveMessage(async (msg) => {
      console.log("📨 Extension received:", msg);

      switch (msg.type) {
        case 'runScan':
          vscode.commands.executeCommand('autoshield.scan');
          break;

        case 'clearResults':
          vscode.commands.executeCommand('autoshield.clear');
          break;

        // Jump to the file + line where the issue was found
        case 'jumpToLine':
          vscode.commands.executeCommand('autoshield.jumpToLine', {
            filePath: msg.filePath,
            line: msg.line,
          });
          break;

        // Ask the LLM to generate a fix for a finding
        case 'generateFix':
          vscode.commands.executeCommand('autoshield.generateFix', {
            codeSnippet: msg.codeSnippet,
            vulnType: msg.vulnType,
            cweId: msg.cweId,
            findingIndex: msg.findingIndex,
          });
          break;

        // Apply a previously generated fix to the file
        case 'applyFix':
          vscode.commands.executeCommand('autoshield.applyFix', {
            filePath: msg.filePath,
            line: msg.line,
            originalCode: msg.originalCode,
            fixCode: msg.fixCode,
          });
          break;
      }
    });
  }

  postMessage(msg: any) {
    console.log("📩 Sending to sidebar:", msg);
    this._view?.webview.postMessage(msg);
  }

  private _getHtml(): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
    <style>
      * { box-sizing: border-box; margin: 0; padding: 0; }

      body {
        background: #0d1117;
        color: #e6edf3;
        font-family: 'Segoe UI', sans-serif;
        font-size: 12px;
        padding: 12px;
      }

      h2 {
        font-size: 14px;
        font-weight: 600;
        margin-bottom: 10px;
        color: #58a6ff;
        letter-spacing: 0.5px;
      }

      .toolbar {
        display: flex;
        gap: 6px;
        margin-bottom: 12px;
      }

      button {
        background: #21262d;
        color: #e6edf3;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 5px 10px;
        cursor: pointer;
        font-size: 11px;
        flex: 1;
        transition: background 0.15s;
      }
      button:hover { background: #30363d; }
      button:disabled { opacity: 0.4; cursor: not-allowed; }

      .btn-primary {
        background: #1f6feb;
        border-color: #1f6feb;
        color: #fff;
      }
      .btn-primary:hover { background: #388bfd; }

      .btn-fix {
        background: #238636;
        border-color: #2ea043;
        color: #fff;
        padding: 4px 8px;
        font-size: 10px;
        flex: none;
      }
      .btn-fix:hover { background: #2ea043; }

      .btn-apply {
        background: #9e6a03;
        border-color: #d29922;
        color: #fff;
        padding: 4px 8px;
        font-size: 10px;
        flex: none;
      }
      .btn-apply:hover { background: #d29922; }

      .btn-goto {
        background: transparent;
        border-color: #30363d;
        color: #58a6ff;
        padding: 4px 8px;
        font-size: 10px;
        flex: none;
        text-decoration: underline;
      }
      .btn-goto:hover { background: #161b22; }

      #status {
        margin-bottom: 10px;
        color: #8b949e;
        font-size: 11px;
        min-height: 16px;
      }

      .finding-card {
        border: 1px solid #30363d;
        margin-bottom: 10px;
        border-radius: 8px;
        background: #161b22;
        overflow: hidden;
      }

      .finding-header {
        padding: 8px 10px;
        display: flex;
        align-items: flex-start;
        gap: 8px;
        cursor: pointer;
        user-select: none;
      }
      .finding-header:hover { background: #1c2128; }

      .severity-badge {
        font-size: 9px;
        font-weight: 700;
        padding: 2px 6px;
        border-radius: 4px;
        text-transform: uppercase;
        flex-shrink: 0;
        margin-top: 1px;
      }
      .sev-CRITICAL { background: #6e1111; color: #ff7b72; border: 1px solid #ff7b72; }
      .sev-HIGH     { background: #5a2d0c; color: #ffa657; border: 1px solid #ffa657; }
      .sev-MEDIUM   { background: #3d3500; color: #e3b341; border: 1px solid #e3b341; }
      .sev-LOW      { background: #0d2416; color: #3fb950; border: 1px solid #3fb950; }
      .sev-INFO     { background: #0d1b30; color: #58a6ff; border: 1px solid #58a6ff; }

      .finding-title {
        flex: 1;
        font-weight: 600;
        color: #e6edf3;
        font-size: 11px;
        line-height: 1.4;
      }

      .finding-meta {
        padding: 0 10px 8px 10px;
        color: #8b949e;
        font-size: 10px;
        line-height: 1.6;
      }

      .finding-meta .file-link {
        color: #58a6ff;
        cursor: pointer;
        text-decoration: underline;
        word-break: break-all;
      }
      .finding-meta .file-link:hover { color: #79c0ff; }

      .finding-body {
        padding: 0 10px 10px 10px;
        border-top: 1px solid #21262d;
        display: none;
      }
      .finding-body.open { display: block; }

      .section-label {
        color: #8b949e;
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin: 8px 0 4px;
        font-weight: 600;
      }

      .reasoning-text {
        color: #c9d1d9;
        font-size: 11px;
        line-height: 1.5;
        background: #0d1117;
        border-radius: 4px;
        padding: 6px 8px;
        border: 1px solid #21262d;
      }

      .fix-actions {
        display: flex;
        gap: 6px;
        margin-top: 8px;
        align-items: center;
        flex-wrap: wrap;
      }

      .fix-block {
        margin-top: 8px;
        background: #0d1117;
        border: 1px solid #238636;
        border-radius: 6px;
        overflow: hidden;
      }

      .fix-block-header {
        background: #0f2a18;
        padding: 4px 8px;
        font-size: 10px;
        color: #3fb950;
        font-weight: 600;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }

      .fix-code {
        padding: 8px;
        font-family: 'Cascadia Code', 'Consolas', monospace;
        font-size: 10px;
        color: #c9d1d9;
        white-space: pre-wrap;
        word-break: break-all;
        max-height: 140px;
        overflow-y: auto;
      }

      .fix-explanation {
        padding: 6px 8px;
        font-size: 10px;
        color: #8b949e;
        border-top: 1px solid #21262d;
        line-height: 1.5;
      }

      .spinner {
        display: inline-block;
        width: 10px;
        height: 10px;
        border: 2px solid #30363d;
        border-top-color: #58a6ff;
        border-radius: 50%;
        animation: spin 0.7s linear infinite;
        margin-right: 5px;
        vertical-align: middle;
      }
      @keyframes spin { to { transform: rotate(360deg); } }

      .score-row {
        display: flex;
        align-items: center;
        gap: 6px;
        margin-top: 4px;
      }

      .score-bar-bg {
        flex: 1;
        height: 4px;
        background: #21262d;
        border-radius: 2px;
        overflow: hidden;
      }

      .score-bar-fill {
        height: 100%;
        border-radius: 2px;
        transition: width 0.4s ease;
      }

      .risks-list {
        list-style: none;
        margin-top: 4px;
      }
      .risks-list li {
        color: #c9d1d9;
        font-size: 10px;
        line-height: 1.5;
        padding-left: 12px;
        position: relative;
      }
      .risks-list li::before {
        content: '›';
        position: absolute;
        left: 2px;
        color: #ffa657;
      }

      .chevron {
        font-size: 10px;
        color: #8b949e;
        transition: transform 0.2s;
        flex-shrink: 0;
      }
      .chevron.open { transform: rotate(90deg); }
    </style>
    </head>
    <body>

      <h2>🛡 AutoShield</h2>

      <div class="toolbar">
        <button class="btn-primary" onclick="runScan()">⚡ Scan</button>
        <button onclick="clearUI()">🧹 Clear</button>
      </div>

      <div id="status"></div>
      <div id="out"></div>

      <script>
        const vscode = acquireVsCodeApi();

        // Stores the current results so fix buttons can reference them
        let currentResults = [];

        function runScan() {
          document.getElementById('status').innerText = "Running scan...";
          vscode.postMessage({ type: 'runScan' });
        }

        function clearUI() {
          document.getElementById('out').innerHTML = '';
          document.getElementById('status').innerText = '';
          currentResults = [];
        }

        // ── Jump to file/line ───────────────────────────────────────────
        function jumpToLine(filePath, line) {
          vscode.postMessage({ type: 'jumpToLine', filePath, line });
        }

        // ── Request LLM fix ─────────────────────────────────────────────
        function generateFix(index) {
          const r = currentResults[index];
          if (!r) return;
          vscode.postMessage({
            type: 'generateFix',
            findingIndex: index,
            codeSnippet: r.code_snippet || r.message || '',
            vulnType: r.vuln_type || '',
            cweId: r.cwe_id || 'CWE-Unknown',
          });
        }

        // ── Apply fix to file ───────────────────────────────────────────
        function applyFix(index) {
          const r = currentResults[index];
          if (!r || !r._fixCode) return;
          vscode.postMessage({
            type: 'applyFix',
            filePath: r.file_path,
            line: r.line,
            originalCode: r.code_snippet || '',
            fixCode: r._fixCode,
          });
        }

        // ── Toggle expand/collapse ──────────────────────────────────────
        function toggleCard(index) {
          const body = document.getElementById('body-' + index);
          const chev = document.getElementById('chev-' + index);
          if (!body) return;
          const isOpen = body.classList.toggle('open');
          chev.classList.toggle('open', isOpen);
        }

        // ── Severity → bar color ────────────────────────────────────────
        function scoreColor(score) {
          if (score >= 85) return '#ff7b72';
          if (score >= 65) return '#ffa657';
          if (score >= 40) return '#e3b341';
          return '#3fb950';
        }

        // ── Render all findings ─────────────────────────────────────────
        function renderResults(results) {
          const out = document.getElementById('out');
          out.innerHTML = '';

          if (!results || results.length === 0) {
            out.innerHTML = '<p style="color:#8b949e;margin-top:8px;">✅ No issues found</p>';
            return;
          }

          results.forEach((r, i) => {
            const cat = (r.risk_category || 'MEDIUM').toUpperCase();
            const score = r.risk_score || 0;
            const fileName = (r.file_path || 'unknown').split(/[\\/]/).pop();
            const hasExistingFix = !!(r.fix_code || r.recommended_fix);
            const keyRisks = r.key_risks || [];
            const reasoning = r.reasoning || '';

            const card = document.createElement('div');
            card.className = 'finding-card';
            card.id = 'card-' + i;

            card.innerHTML = \`
              <div class="finding-header" onclick="toggleCard(\${i})">
                <span class="severity-badge sev-\${cat}">\${cat}</span>
                <span class="finding-title">\${r.vuln_type || r.cwe_id || 'Unknown Issue'}</span>
                <span class="chevron" id="chev-\${i}">›</span>
              </div>

              <div class="finding-meta">
                <span class="file-link" onclick="jumpToLine('\${r.file_path}', \${r.line || 1})" title="\${r.file_path}">
                  📄 \${fileName}
                </span>
                &nbsp;·&nbsp; Line \${r.line || 0}
                &nbsp;·&nbsp; Score \${score}/100
                <div class="score-row">
                  <div class="score-bar-bg">
                    <div class="score-bar-fill" style="width:\${score}%;background:\${scoreColor(score)}"></div>
                  </div>
                </div>
              </div>

              <div class="finding-body" id="body-\${i}">
                \${reasoning ? \`
                  <div class="section-label">🧠 LLM Reasoning</div>
                  <div class="reasoning-text">\${reasoning}</div>
                \` : ''}

                \${keyRisks.length > 0 ? \`
                  <div class="section-label">⚠ Key Risks</div>
                  <ul class="risks-list">
                    \${keyRisks.map(k => \`<li>\${k}</li>\`).join('')}
                  </ul>
                \` : ''}

                <div class="fix-actions">
                  <button class="btn-goto" onclick="jumpToLine('\${r.file_path}', \${r.line || 1})">
                    📍 Go to Line \${r.line || 1}
                  </button>
                  <button class="btn-fix" id="fix-btn-\${i}" onclick="generateFix(\${i})">
                    🔧 Get Fix
                  </button>
                </div>

                \${hasExistingFix ? renderFixBlock(i, r.fix_code || '', r.recommended_fix || '') : ''}

                <div id="fix-area-\${i}"></div>
              </div>
            \`;

            out.appendChild(card);
          });
        }

        function renderFixBlock(index, fixCode, explanation) {
          if (!fixCode && !explanation) return '';
          return \`
            <div class="fix-block" id="fix-block-\${index}">
              <div class="fix-block-header">
                ✅ Suggested Fix
                \${fixCode ? \`<button class="btn-apply" onclick="applyFix(\${index})">⚡ Apply Fix</button>\` : ''}
              </div>
              \${fixCode ? \`<div class="fix-code">\${escapeHtml(fixCode)}</div>\` : ''}
              \${explanation ? \`<div class="fix-explanation">\${explanation}</div>\` : ''}
            </div>
          \`;
        }

        function escapeHtml(s) {
          return String(s)
            .replace(/&/g,'&amp;')
            .replace(/</g,'&lt;')
            .replace(/>/g,'&gt;');
        }

        // ── Message handler ─────────────────────────────────────────────
        window.addEventListener('message', event => {
          const msg = event.data;
          const out = document.getElementById('out');
          const status = document.getElementById('status');

          // Scan started
          if (msg.type === 'scanStarted') {
            status.innerText = "🔍 Scanning...";
            out.innerHTML = '';
            currentResults = [];
          }

          // Scan results
          if (msg.type === 'scanResults') {
            status.innerText = "✅ Scan complete — " + msg.count + " finding(s)";
            currentResults = msg.results || [];
            renderResults(currentResults);
          }

          // Clear
          if (msg.type === 'clear') {
            clearUI();
          }

          // Error
          if (msg.type === 'scanError') {
            status.innerHTML = '<span style="color:#ff7b72">❌ ' + msg.error + '</span>';
          }

          // Fix is being generated (spinner on button)
          if (msg.type === 'fixGenerating') {
            const btn = document.getElementById('fix-btn-' + msg.findingIndex);
            if (btn) {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span>Generating...';
            }
          }

          // Fix ready
          if (msg.type === 'fixGenerated') {
            const i = msg.findingIndex;
            const fixData = msg.fixData || {};
            const btn = document.getElementById('fix-btn-' + i);
            if (btn) {
              btn.disabled = false;
              btn.innerText = '🔄 Regenerate Fix';
            }

            // Store fix on the result so Apply Fix can use it
            if (currentResults[i]) {
              currentResults[i]._fixCode = fixData.fix_code || '';
            }

            // Render fix block in the expanded area
            const area = document.getElementById('fix-area-' + i);
            if (area) {
              area.innerHTML = renderFixBlock(i, fixData.fix_code || '', fixData.explanation || '');
            }

            // Auto-open the card body if not already open
            const body = document.getElementById('body-' + i);
            const chev = document.getElementById('chev-' + i);
            if (body && !body.classList.contains('open')) {
              body.classList.add('open');
              if (chev) chev.classList.add('open');
            }
          }

          // Fix generation error
          if (msg.type === 'fixError') {
            const i = msg.findingIndex;
            const btn = document.getElementById('fix-btn-' + i);
            if (btn) {
              btn.disabled = false;
              btn.innerText = '🔧 Retry Fix';
            }
            const area = document.getElementById('fix-area-' + i);
            if (area) {
              area.innerHTML = '<div style="color:#ff7b72;font-size:10px;margin-top:6px;">❌ ' + msg.error + '</div>';
            }
          }

        });
      </script>
    </body>
    </html>
    `;
  }
}