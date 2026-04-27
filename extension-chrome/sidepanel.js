// sidepanel.js
// AutoShield Side Panel — UI logic, backend communication, rendering

const BACKEND = 'http://127.0.0.1:8000';

// ─── State ──────────────────────────────────────────────────────────
let currentTab = 'security';
let securityResults = [];
let complianceResults = null;
let currentUrl = '';
let port = null;
let isScanning = false;

// ─── Init ────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById("btnScan")?.addEventListener("click", runScan);
  document.getElementById("btnDeep")?.addEventListener("click", runDeepScan);
  connectToBackground();
  getCurrentTabUrl();
});

function logStep(message) {
  const logDiv = document.getElementById("log");
  if (!logDiv) return;
  const entry = document.createElement("div");
  entry.textContent = "• " + message;
  entry.style.fontSize = "10px";
  entry.style.color = "#aaa";
  logDiv.appendChild(entry);
  logDiv.scrollTop = logDiv.scrollHeight;
}

function connectToBackground() {
  port = chrome.runtime.connect({ name: 'autoshield-sidepanel' });
  port.onMessage.addListener(handleBackgroundMessage);
  port.onDisconnect.addListener(() => {
    port = null;
    setTimeout(connectToBackground, 1000);
  });
}

function getCurrentTabUrl() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      currentUrl = tabs[0].url || '';
      const badge = document.getElementById('urlBadge');
      if (badge) {
        const display = currentUrl.replace(/^https?:\/\//, '').slice(0, 35);
        badge.textContent = display || 'No page';
        badge.title = currentUrl;
      }
    }
  });
}

// ─── Tab Switching ────────────────────────────────────────────────────
function switchTab(name) {
  currentTab = name;
  document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));
  document.getElementById('tab-' + name)?.classList.add('active');
  document.getElementById('panel-' + name)?.classList.add('active');
}

// ─── Scan Triggers ────────────────────────────────────────────────────
async function runScan() {
  if (isScanning) { return; }
  getCurrentTabUrl();
  setStatus('Extracting page data...', 'scanning', true);
  logStep('🚀 Scan initiated');
  setBtnsDisabled(true);
  isScanning = true;

  if (port) {
    port.postMessage({ type: 'triggerExtraction', useLLM: false });
  } else {
    setStatus('Extension connection lost — refresh the panel', 'error');
    setBtnsDisabled(false);
    isScanning = false;
  }
}

async function runDeepScan() {
  if (isScanning) { return; }
  getCurrentTabUrl();

  if (!currentUrl || currentUrl.startsWith('chrome://')) {
    setStatus('Cannot scan browser internal pages', 'error');
    return;
  }

  setStatus('Running deep scan (LLM enabled)...', 'scanning', true);
  logStep('🧠 Deep scan with LLM reasoning');
  setBtnsDisabled(true);
  isScanning = true;

  try {
    fetch(`${BACKEND}/analyze-runtime?url=${encodeURIComponent(currentUrl)}`, {
      method: 'POST'
    }).catch(() => {});

    if (port) {
      port.postMessage({ type: 'triggerExtraction', useLLM: true });
    }
  } catch (e) {
    setStatus(`Deep scan failed: ${e.message}`, 'error');
    setBtnsDisabled(false);
    isScanning = false;
  }
}

function clearAll() {
  securityResults = [];
  complianceResults = null;
  document.getElementById('security-out').innerHTML = '<div class="empty"><span class="empty-icon">🔒</span>Click <strong>[Scan]</strong> to analyze<br/>the current page for<br/>security vulnerabilities</div>';
  document.getElementById('compliance-out').innerHTML = '<div class="empty"><span class="empty-icon">©</span>Click <strong>[Scan]</strong> to check<br/>media assets for<br/>copyright &amp; compliance</div>';
  document.getElementById('summary').classList.remove('visible');
  const logDiv = document.getElementById('log');
  if (logDiv) logDiv.innerHTML = '';
  setStatus('Cleared', '');
}

// ─── Message Handler ──────────────────────────────────────────────────
function handleBackgroundMessage(msg) {
  if (msg.type === 'progress') {
    logStep(msg.step);
  }
  if (msg.type === 'pageDataExtracted') {
    logStep('📦 Data received from page');
    setStatus('Analyzing with RAG + AI...', 'scanning', true);
    analyzePageData(msg.data, msg.useLLM || false);
  }
  if (msg.type === 'extractionError') {
    setStatus('Extraction failed: ' + msg.error, 'error');
    setBtnsDisabled(false);
    isScanning = false;
  }
}

// ─── Main Analysis ────────────────────────────────────────────────────
async function analyzePageData(pageData, useLLM = false) {
  logStep('🧠 Running AI analysis...');
  try {
    const [secResult, compResult] = await Promise.allSettled([
      analyzeSecurityData(pageData, useLLM),
      analyzeComplianceData(pageData),
    ]);

    if (secResult.status === 'fulfilled') {
      securityResults = secResult.value;
      renderSecurityResults(securityResults);
    }

    if (compResult.status === 'fulfilled') {
      complianceResults = compResult.value;
      renderComplianceResults(complianceResults);
    }

    const totalSec = securityResults.length;
    const totalComp = complianceResults?.issues?.length || 0;
    logStep('✅ Scan complete');
    setStatus(`Done — ${totalSec} security + ${totalComp} compliance findings`, 'done');
    updateSummary(securityResults);
    setBtnsDisabled(false);
    isScanning = false;

  } catch (e) {
    logStep('❌ Analysis failed: ' + e.message);
    setStatus('Analysis error: ' + e.message, 'error');
    setBtnsDisabled(false);
    isScanning = false;
  }
}

// ─── Security Analysis ────────────────────────────────────────────────
async function analyzeSecurityData(pageData, useLLM = false) {
  const findings = buildSecurityFindings(pageData);
  const results = [];

  setStatus(`Analyzing ${findings.length} finding(s)...`, 'scanning', true);

  for (const finding of findings.slice(0, 15)) {
    try {
      const res = await fetch(`${BACKEND}/rag/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code_snippet: finding.snippet,
          cwe_id: finding.cwe_id,
          severity: finding.severity,
          vuln_type: finding.vuln_type,
          file_path: currentUrl,
          line: 0,
          tool: 'autoshield-chrome',
          use_llm: useLLM,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        results.push({ ...data, _original: finding });
      } else {
        results.push(buildFallbackResult(finding));
      }
    } catch (_) {
      results.push(buildFallbackResult(finding));
    }
  }

  return results;
}

// ─── Fallback Result (backend unreachable) ────────────────────────────
// NOTE: This is only used when the HTTP request to the backend fails entirely.
// The backend now always returns static fixes via risk_engine.py's CWE dictionary,
// so this fallback should rarely be seen in practice.
function buildFallbackResult(finding) {
  // Minimal static fixes for the most common CWEs — mirrors the backend dict
  const QUICK_FIXES = {
    'CWE-693': { fix: 'Add a Content-Security-Policy meta tag to your <head>.', code: "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\">" },
    'CWE-922': { fix: "Don't store auth tokens or sensitive data in localStorage. Use HttpOnly cookies set by the server instead.", code: "// Use server-set HttpOnly cookies for auth tokens\n// Avoid: localStorage.setItem('token', jwt)" },
    'CWE-79':  { fix: 'Replace innerHTML with textContent, or sanitize with DOMPurify before DOM insertion.', code: "element.textContent = userInput; // safe\n// or: element.innerHTML = DOMPurify.sanitize(userInput);" },
    'CWE-829': { fix: 'Add integrity= and crossorigin= attributes to external script tags (SRI).', code: '<script src="https://cdn.example.com/lib.js"\n  integrity="sha384-..."\n  crossorigin="anonymous"></script>' },
    'CWE-319': { fix: 'Change form action to https:// and enable HSTS on your server.', code: '<form action="https://yourdomain.com/login" method="POST">' },
    'CWE-352': { fix: 'Add a CSRF token hidden field to all state-changing forms.', code: '<input type="hidden" name="csrf_token" value="{{ csrf_token }}">' },
    'CWE-1021': { fix: 'Add sandbox attribute to external iframes.', code: '<iframe src="https://external.com" sandbox="allow-scripts allow-same-origin"></iframe>' },
  };

  const q = QUICK_FIXES[finding.cwe_id] || { fix: 'Review this finding and apply secure coding best practices.', code: '' };

  return {
    vuln_type: finding.vuln_type || 'Unknown Issue',
    cwe_id: finding.cwe_id || '',
    risk_category: finding.severity ? finding.severity.toUpperCase() : 'MEDIUM',
    risk_score: finding.severity === 'critical' ? 90 : finding.severity === 'high' ? 70 : finding.severity === 'medium' ? 45 : 20,
    owasp_category: '',
    reasoning: 'Backend is offline — showing local static analysis only.',
    recommended_fix: q.fix,
    fix_code: q.code,
    key_risks: [],
    llm_available: false,
    _original: finding,
    _fallback: true,
  };
}

// ─── Build Security Findings from extracted page data ─────────────────
function buildSecurityFindings(pageData) {
  const findings = [];
  const sec = pageData.security || {};

  sec.inlineScripts?.forEach((script) => {
    if (script.hasEval)
      findings.push({ vuln_type: 'eval() usage detected', cwe_id: 'CWE-95', severity: 'high', snippet: script.snippet, location: `inline script #${script.index}` });
    if (script.hasDocumentWrite)
      findings.push({ vuln_type: 'document.write() usage', cwe_id: 'CWE-79', severity: 'medium', snippet: script.snippet, location: `inline script #${script.index}` });
    if (script.hasInnerHTML)
      findings.push({ vuln_type: 'innerHTML assignment (potential XSS)', cwe_id: 'CWE-79', severity: 'medium', snippet: script.snippet, location: `inline script #${script.index}` });
  });

  const externalNoSRI = sec.externalScripts?.filter((s) => s.isExternal && !s.hasSRI) || [];
  if (externalNoSRI.length > 0)
    findings.push({ vuln_type: 'External scripts without Subresource Integrity (SRI)', cwe_id: 'CWE-829', severity: externalNoSRI.length > 3 ? 'high' : 'medium', snippet: externalNoSRI.map((s) => s.src).join('\n'), location: `${externalNoSRI.length} external script(s)` });

  if (sec.mixedContent?.length > 0)
    findings.push({ vuln_type: 'Mixed content (HTTP resources on HTTPS page)', cwe_id: 'CWE-311', severity: 'high', snippet: sec.mixedContent.map((m) => `${m.tag}[${m.attr}]=${m.url}`).join('\n'), location: `${sec.mixedContent.length} mixed content resource(s)` });

  sec.forms?.forEach((form) => {
    if (form.hasPasswordField && form.isHttpAction)
      findings.push({ vuln_type: 'Password field submits over HTTP', cwe_id: 'CWE-319', severity: 'critical', snippet: `Form action: ${form.action}`, location: `form #${form.index}` });
    if (form.hasPasswordField && !form.hasCSRFToken)
      findings.push({ vuln_type: 'Password form missing CSRF protection', cwe_id: 'CWE-352', severity: 'medium', snippet: `Form action: ${form.action}, method: ${form.method}`, location: `form #${form.index}` });
  });

  if (!sec.metaTags?.csp)
    findings.push({ vuln_type: 'Content Security Policy (CSP) not set', cwe_id: 'CWE-693', severity: 'medium', snippet: 'No Content-Security-Policy meta tag detected.', location: 'page headers/meta' });

  const unsandboxedIframes = sec.iframes?.filter((f) => f.isExternal && !f.sandbox) || [];
  if (unsandboxedIframes.length > 0)
    findings.push({ vuln_type: 'External iframes without sandbox attribute', cwe_id: 'CWE-1021', severity: 'medium', snippet: unsandboxedIframes.map((f) => f.src).join('\n'), location: `${unsandboxedIframes.length} unsandboxed iframe(s)` });

  const storageIssues = [...(sec.storageUsage?.localStorage || []), ...(sec.storageUsage?.sessionStorage || [])];
  if (storageIssues.length > 0)
    findings.push({ vuln_type: 'Sensitive data keys found in browser storage', cwe_id: 'CWE-922', severity: 'high', snippet: storageIssues.map((s) => s.key).join(', '), location: 'localStorage / sessionStorage' });

  return findings;
}

// ─── Compliance Analysis ──────────────────────────────────────────────
async function analyzeComplianceData(pageData) {
  const comp = pageData.compliance || {};
  const issues = [];
  const clean = [];

  const FREE_DOMAINS = new Set(['images.unsplash.com','source.unsplash.com','cdn.pixabay.com','pixabay.com','images.pexels.com','www.pexels.com','fonts.googleapis.com','fonts.gstatic.com','cdnjs.cloudflare.com','cdn.jsdelivr.net','unpkg.com','ajax.googleapis.com']);
  const PAID_DOMAINS = new Set(['shutterstock.com','gettyimages.com','istockphoto.com','adobestock.com','stock.adobe.com','dreamstime.com','alamy.com','depositphotos.com']);

  comp.images?.forEach((img) => {
    if (!img.src || img.src.startsWith('data:')) return;
    const domain = img.domain || '';
    if ([...PAID_DOMAINS].some((d) => domain === d || domain.endsWith('.' + d)))
      issues.push({ type: 'image', src: img.src, domain, severity: 'HIGH', issue: 'Image may be hotlinked from paid stock site', recommendation: `Verify you have a license for images from ${domain}.` });
    else if (FREE_DOMAINS.has(domain))
      clean.push({ type: 'image', src: img.src, status: 'free-source', note: `Free source: ${domain}` });
    else if (img.isExternal)
      issues.push({ type: 'image', src: img.src, domain, severity: 'REVIEW', issue: 'External image — license unknown', recommendation: 'Verify you have rights to use this image or host it locally.' });
  });

  comp.videos?.forEach((v) => {
    if (!v.src || !v.isExternal) return;
    issues.push({ type: 'video', src: v.src, domain: v.domain, severity: 'REVIEW', issue: 'External video resource — license unknown', recommendation: 'Verify licensing or use an official embed player.' });
  });

  comp.iframeEmbeds?.forEach((frame) => {
    if (frame.isYouTube || frame.isVimeo)
      clean.push({ type: 'embed', src: frame.src, status: 'ok', note: 'Official platform embed — generally OK' });
  });

  const li = comp.licenseIndicators || {};
  const summary = {
    copyrightText: li.copyrightText || '',
    stockImageWarnings: (li.shutterstockImages || 0) + (li.gettyImages || 0) + (li.adobeStockImages || 0),
    freeImages: (li.unsplashImages || 0) + (li.pixabayImages || 0) + (li.pexelsImages || 0),
  };

  return { issues, clean, summary };
}

// ════════════════════════════════════════════════════════════════════
// RENDER SECURITY RESULTS
//
// Changes vs previous version:
//  • ALL cards now auto-expand (not just CRITICAL/HIGH)
//  • "✦ Fix" pill shown when fix_code present
//  • "⚡ LLM" badge shown when AI reasoning was used (llm_available=true)
//  • Inner tabs: Analysis | Fix Code when both exist
//  • Copy button on fix code block
//  • Offline note shows quick fix anyway (from client-side fallback dict)
// ════════════════════════════════════════════════════════════════════
function renderSecurityResults(results) {
  const out = document.getElementById('security-out');
  if (!results || results.length === 0) {
    out.innerHTML = '<div class="empty"><span class="empty-icon">✅</span>No security issues detected<br/>on this page</div>';
    return;
  }

  out.innerHTML = '';

  const header = document.createElement('div');
  header.className = 'section-header';
  header.innerHTML = `Vulnerabilities <span class="section-count">${results.length}</span>`;
  out.appendChild(header);

  results.forEach((r, i) => {
    const cat = (r.risk_category || 'MEDIUM').toUpperCase();
    const score = r.risk_score || 0;
    const hasFix = !!(r.fix_code && r.fix_code.trim());
    const hasAnalysis = !!(r.reasoning || r.recommended_fix || (r.key_risks && r.key_risks.length));
    const hasBody = hasFix || hasAnalysis;
    const usedLLM = r.llm_available === true;

    const card = document.createElement('div');
    card.className = 'card';

    // ── Header ───────────────────────────────────────────────────────
    const headDiv = document.createElement('div');
    headDiv.className = 'card-head';
    if (hasBody) headDiv.setAttribute('onclick', `toggleCard('s-${i}','s-chev-${i}')`);
    headDiv.style.cursor = hasBody ? 'pointer' : 'default';

    headDiv.innerHTML = `
      <span class="sev-tag sev-${cat}">${cat}</span>
      <div style="min-width:0;flex:1">
        <div class="card-title-row">
          <span class="card-title">${esc(r.vuln_type || r.cwe_id || 'Unknown')}</span>
          ${hasFix ? `<span class="fix-pill">✦ Fix</span>` : ''}
          ${usedLLM ? `<span class="llm-pill">⚡ LLM</span>` : ''}
        </div>
        <div class="card-meta">
          ${esc(r.cwe_id || '')}${r._original?.location ? ' · ' + esc(r._original.location) : ''}
          ${r.owasp_category && r.owasp_category !== 'Unknown' ? ' · ' + esc(r.owasp_category) : ''}
        </div>
        <div class="score-row">
          <div class="score-track"><div class="score-fill" style="width:${score}%;background:${scoreColor(score)}"></div></div>
          <span class="score-num">${score}/100</span>
        </div>
      </div>
      ${hasBody ? `<span class="chevron open" id="s-chev-${i}">&gt;</span>` : '<span style="width:12px;display:inline-block"></span>'}
    `;
    card.appendChild(headDiv);

    // ── Body — ALL CARDS START EXPANDED ──────────────────────────────
    if (hasBody) {
      const bodyDiv = document.createElement('div');
      bodyDiv.id = `s-${i}`;
      bodyDiv.className = 'card-body open'; // always open

      if (r._fallback && !r.recommended_fix) {
        bodyDiv.innerHTML = `
          <div class="body-sec offline-note">
            <span style="color:var(--amber-dim)">⚠ Backend offline</span> — start your FastAPI server to get full AI analysis.
          </div>`;
      } else if (hasFix && hasAnalysis) {
        bodyDiv.innerHTML = `
          <div class="inner-tabs">
            <button class="inner-tab active" onclick="switchInnerTab(${i},'analysis',this)">Analysis</button>
            <button class="inner-tab" onclick="switchInnerTab(${i},'fix',this)">Fix Code</button>
          </div>
          <div id="s-${i}-analysis">${buildAnalysisHTML(r)}</div>
          <div id="s-${i}-fix" style="display:none">${buildFixHTML(r)}</div>
        `;
      } else if (hasFix) {
        bodyDiv.innerHTML = buildFixHTML(r);
      } else {
        bodyDiv.innerHTML = buildAnalysisHTML(r);
      }

      card.appendChild(bodyDiv);
    }

    out.appendChild(card);
  });
}

// ── Analysis HTML ─────────────────────────────────────────────────────
function buildAnalysisHTML(r) {
  let html = '';

  if (r.reasoning) {
    html += `<div class="body-sec">
      <div class="sec-label">Analysis</div>
      <div class="body-text">${esc(r.reasoning)}</div>
    </div>`;
  }

  if (r.key_risks && r.key_risks.length) {
    html += `<div class="body-sec">
      <div class="sec-label">Key Risks</div>
      <ul class="asset-list">
        ${r.key_risks.map(k => `<li class="asset-item"><span class="asset-status st-issue">risk</span><span>${esc(k)}</span></li>`).join('')}
      </ul>
    </div>`;
  }

  if (r.recommended_fix) {
    html += `<div class="body-sec">
      <div class="sec-label">How to Fix</div>
      <div class="body-text fix-hint">${esc(r.recommended_fix)}</div>
    </div>`;
  }

  return html || `<div class="body-sec"><div class="body-text" style="color:var(--text-lo)">No analysis data</div></div>`;
}

// ── Fix Code HTML ─────────────────────────────────────────────────────
function buildFixHTML(r) {
  let html = '';

  if (r.recommended_fix) {
    html += `<div class="body-sec">
      <div class="sec-label">What to do</div>
      <div class="body-text fix-hint">${esc(r.recommended_fix)}</div>
    </div>`;
  }

  if (r.fix_code) {
    const encoded = encodeURIComponent(r.fix_code);
    html += `<div class="fix-wrap">
      <div class="fix-head">
        <span>Suggested Fix</span>
        <button class="copy-btn" onclick="copyFix(this,'${encoded}')">Copy</button>
      </div>
      <div class="fix-code">${esc(r.fix_code)}</div>
    </div>`;
  }

  return html;
}

// ── Inner tab switcher ────────────────────────────────────────────────
function switchInnerTab(cardIdx, tab, clickedBtn) {
  const aPanel = document.getElementById(`s-${cardIdx}-analysis`);
  const fPanel = document.getElementById(`s-${cardIdx}-fix`);
  if (!aPanel || !fPanel) return;

  const bodyDiv = document.getElementById(`s-${cardIdx}`);
  bodyDiv?.querySelectorAll('.inner-tab').forEach(t => t.classList.remove('active'));
  clickedBtn?.classList.add('active');

  if (tab === 'analysis') {
    aPanel.style.display = '';
    fPanel.style.display = 'none';
  } else {
    aPanel.style.display = 'none';
    fPanel.style.display = '';
  }
}

// ── Copy to clipboard ─────────────────────────────────────────────────
function copyFix(btn, encodedCode) {
  const code = decodeURIComponent(encodedCode);
  navigator.clipboard.writeText(code).then(() => {
    btn.textContent = 'Copied!';
    btn.style.color = 'var(--green)';
    setTimeout(() => { btn.textContent = 'Copy'; btn.style.color = ''; }, 1500);
  }).catch(() => {
    btn.textContent = 'Failed';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  });
}

// ─── Render Compliance Results ────────────────────────────────────────
function renderComplianceResults(data) {
  const out = document.getElementById('compliance-out');
  if (!data) {
    out.innerHTML = '<div class="empty"><span class="empty-icon">©</span>No compliance data available</div>';
    return;
  }

  out.innerHTML = '';

  if (data.summary) {
    const s = data.summary;
    if (s.copyrightText || s.stockImageWarnings > 0 || s.freeImages > 0) {
      const bannerDiv = document.createElement('div');
      bannerDiv.style.cssText = 'padding:8px 12px;border-bottom:1px solid var(--border);background:var(--bg2);font-size:9px;color:var(--text-lo);line-height:1.8';
      bannerDiv.innerHTML = `
        ${s.copyrightText ? `<div style="color:var(--text-dim)">📄 ${esc(s.copyrightText)}</div>` : ''}
        ${s.stockImageWarnings > 0 ? `<div style="color:#cc7700">⚠ ${s.stockImageWarnings} potential paid stock image source(s)</div>` : ''}
        ${s.freeImages > 0 ? `<div style="color:var(--green)">✓ ${s.freeImages} image(s) from known free sources</div>` : ''}
      `;
      out.appendChild(bannerDiv);
    }
  }

  if (data.issues?.length > 0) {
    const issHeader = document.createElement('div');
    issHeader.className = 'section-header';
    issHeader.innerHTML = `Issues Requiring Review <span class="section-count">${data.issues.length}</span>`;
    out.appendChild(issHeader);

    data.issues.forEach((issue, i) => {
      const card = document.createElement('div');
      card.className = 'card';
      const sevClass = issue.severity === 'HIGH' ? 'sev-HIGH' : 'sev-REVIEW';
      card.innerHTML = `
        <div class="card-head" onclick="toggleCard('c-${i}','c-chev-${i}')">
          <span class="sev-tag ${sevClass}">${issue.severity}</span>
          <div>
            <div class="card-title">${esc(issue.issue || 'Compliance Issue')}</div>
            <div class="card-meta asset-url" title="${esc(issue.src || '')}">${esc(issue.domain || issue.src || '')}</div>
          </div>
          <span class="chevron open" id="c-chev-${i}">&gt;</span>
        </div>
        <div class="card-body open" id="c-${i}">
          <div class="body-sec">
            <div class="sec-label">Resource</div>
            <div class="body-text" style="word-break:break-all;font-size:9px">${esc(issue.src || '')}</div>
          </div>
          ${issue.recommendation ? `<div class="body-sec"><div class="sec-label">Recommendation</div><div class="body-text fix-hint">${esc(issue.recommendation)}</div></div>` : ''}
        </div>
      `;
      out.appendChild(card);
    });
  }

  if (data.clean?.length > 0) {
    const cleanHeader = document.createElement('div');
    cleanHeader.className = 'section-header';
    cleanHeader.style.cursor = 'pointer';
    cleanHeader.innerHTML = `Licensed / Free Assets <span class="section-count">${data.clean.length}</span> <span style="font-size:8px;color:var(--text-lo)">(click to expand)</span>`;
    cleanHeader.onclick = () => {
      const cl = document.getElementById('clean-list');
      if (cl) cl.style.display = cl.style.display === 'none' ? 'block' : 'none';
    };
    out.appendChild(cleanHeader);

    const cleanList = document.createElement('div');
    cleanList.id = 'clean-list';
    cleanList.style.display = 'none';

    data.clean.forEach((item) => {
      const row = document.createElement('div');
      row.style.cssText = 'padding:5px 12px;border-bottom:1px solid var(--border);display:flex;gap:6px;align-items:center;';
      const stClass = (item.status === 'free-source' || item.status === 'ok') ? 'st-free' : 'st-review';
      row.innerHTML = `
        <span class="asset-status ${stClass}">${item.status}</span>
        <span style="font-size:9px;color:var(--text-lo);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(item.src)}">${esc(item.note || item.src)}</span>
      `;
      cleanList.appendChild(row);
    });

    out.appendChild(cleanList);
  }

  if (!data.issues?.length && !data.clean?.length) {
    out.innerHTML = '<div class="empty"><span class="empty-icon">©</span>No media assets found<br/>on this page to check</div>';
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────
function toggleCard(bodyId, chevId) {
  const body = document.getElementById(bodyId);
  const chev = document.getElementById(chevId);
  if (!body) return;
  const open = body.classList.toggle('open');
  if (chev) chev.classList.toggle('open', open);
}

function updateSummary(results) {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  results.forEach((r) => {
    const k = (r.risk_category || 'MEDIUM').toUpperCase();
    if (c[k] !== undefined) c[k]++;
  });
  document.getElementById('s-crit').textContent = c.CRITICAL;
  document.getElementById('s-high').textContent = c.HIGH;
  document.getElementById('s-med').textContent = c.MEDIUM;
  document.getElementById('s-low').textContent = c.LOW;
  if (results.length > 0) document.getElementById('summary').classList.add('visible');
}

function setStatus(text, cls, pulse) {
  const el = document.getElementById('statusbar');
  el.className = 'statusbar' + (cls ? ' ' + cls : '');
  el.innerHTML = (pulse ? '<span class="dot"></span>' : '') + text;
}

function setBtnsDisabled(disabled) {
  document.getElementById('btnScan').disabled = disabled;
  document.getElementById('btnDeep').disabled = disabled;
}

function scoreColor(s) {
  if (s >= 85) return '#cc3333';
  if (s >= 65) return '#ffe8c9';
  if (s >= 40) return '#ffbb02';
  return '#4a8a3a';
}

function esc(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}