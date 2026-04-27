# rag/services/risk_engine.py
# Deterministic Risk Scoring Engine
#
# Final formula (weighted):
#   Risk = 0.50 × Static Score
#        + 0.20 × LLM Adjustment
#        + 0.20 × RAG Context Score
#        + 0.10 × Exploitability Bonus
#
# Output: 0–100 risk score, category, and full audit trail.

from typing import Dict, List

# Base severity scores (0–100)
SEVERITY_BASE_SCORES = {
    "critical": 95,
    "high": 75,
    "medium": 50,
    "low": 20,
    "info": 5,
}

# LLM adjustment factors
LLM_ADJUSTMENT_SCORES = {
    2: 15,
    1: 8,
    0: 0,
    -1: -8,
    -2: -15,
}

# Exploitability bonus
EXPLOITABILITY_BONUS = {
    "high": 10,
    "medium": 5,
    "low": 0,
}

# Attack vector bonus
ATTACK_VECTOR_BONUS = {
    "network": 8,
    "adjacent": 4,
    "local": 2,
    "physical": 0,
}


# ── Static fix knowledge base (used when LLM is disabled) ────────────────────
# Keyed by CWE ID. Gives developers actionable guidance even on quick scan.
CWE_STATIC_FIXES: Dict[str, Dict] = {
    "CWE-79": {
        "recommended_fix": "Sanitize all user-supplied data before inserting it into the DOM. Use textContent instead of innerHTML, or a trusted sanitization library like DOMPurify.",
        "fix_code": "// Instead of:\nelement.innerHTML = userInput;\n\n// Use:\nelement.textContent = userInput;\n// Or with DOMPurify:\nelement.innerHTML = DOMPurify.sanitize(userInput);",
        "key_risks": ["Cross-site scripting (XSS)", "Session hijacking via cookie theft", "Malicious script injection"],
        "reasoning": "innerHTML assignments with unsanitized input are the leading cause of XSS vulnerabilities. Attackers can inject <script> tags or event handlers to execute arbitrary JavaScript in the victim's browser.",
    },
    "CWE-89": {
        "recommended_fix": "Use parameterized queries or prepared statements instead of string concatenation to build SQL queries.",
        "fix_code": "# Instead of:\nquery = f\"SELECT * FROM users WHERE id = {user_id}\"\n\n# Use parameterized query:\ncursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "key_risks": ["SQL injection leading to data theft", "Authentication bypass", "Database destruction"],
        "reasoning": "SQL injection allows attackers to manipulate database queries by injecting malicious SQL through user-controlled input.",
    },
    "CWE-95": {
        "recommended_fix": "Never use eval() or Function() with user-controlled data. Parse JSON with JSON.parse(), execute logic with explicit conditionals.",
        "fix_code": "// Instead of:\neval(userInput);\n\n// For JSON:\nconst data = JSON.parse(userInput);\n\n// For dynamic keys:\nconst allowedActions = { 'run': runFn, 'stop': stopFn };\nif (allowedActions[userInput]) allowedActions[userInput]();",
        "key_risks": ["Arbitrary code execution", "Remote code execution if input reaches server", "Complete application compromise"],
        "reasoning": "eval() executes arbitrary strings as code. Any user-controlled data passed to eval() gives attackers direct code execution capability.",
    },
    "CWE-319": {
        "recommended_fix": "Force HTTPS for all form submissions. Redirect HTTP to HTTPS at the server level and set the Strict-Transport-Security header.",
        "fix_code": "<!-- Change form action from http:// to https:// -->\n<form action=\"https://yourdomain.com/login\" method=\"POST\">\n\n<!-- In your server config (nginx): -->\n<!-- add_header Strict-Transport-Security \"max-age=31536000\"; -->",
        "key_risks": ["Credentials intercepted in transit", "Man-in-the-middle attacks", "Password theft on public networks"],
        "reasoning": "Submitting passwords over HTTP sends them in plaintext. Anyone on the same network (coffee shop WiFi, ISP) can read the credentials.",
    },
    "CWE-352": {
        "recommended_fix": "Add a CSRF token to all state-changing forms. Generate a unique per-session token server-side and verify it on submission.",
        "fix_code": "<!-- Add hidden CSRF token to form -->\n<form method=\"POST\" action=\"/submit\">\n  <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\">\n  ...\n</form>\n\n# Server-side verification (Python/Flask example):\nif request.form['csrf_token'] != session['csrf_token']:\n    abort(403)",
        "key_risks": ["Cross-site request forgery", "Unauthorized state changes on behalf of authenticated users"],
        "reasoning": "Without CSRF tokens, attackers can trick authenticated users into submitting forms to your site from a malicious third-party page.",
    },
    "CWE-311": {
        "recommended_fix": "Serve all resources (images, scripts, stylesheets) over HTTPS. Update all src and href attributes to use https:// or protocol-relative URLs.",
        "fix_code": "<!-- Instead of: -->\n<script src=\"http://cdn.example.com/lib.js\"></script>\n<img src=\"http://example.com/image.png\">\n\n<!-- Use: -->\n<script src=\"https://cdn.example.com/lib.js\"></script>\n<img src=\"https://example.com/image.png\">\n<!-- Or protocol-relative: -->\n<script src=\"//cdn.example.com/lib.js\"></script>",
        "key_risks": ["Mixed content blocks resource loading in modern browsers", "HTTP resources can be intercepted and replaced"],
        "reasoning": "Browsers block or warn about HTTP resources loaded on HTTPS pages. Attackers can inject malicious code by intercepting the unencrypted HTTP request.",
    },
    "CWE-829": {
        "recommended_fix": "Add integrity and crossorigin attributes to all external script and stylesheet tags (Subresource Integrity).",
        "fix_code": "<!-- Generate SRI hash: https://www.srihash.org/ -->\n<script\n  src=\"https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js\"\n  integrity=\"sha384-wBPduPAZNkQmG4WLqbPYFqNBQovUPaGPwQZHIxpCAE2BXLN9lqQr9rcBhW0CQDM\"\n  crossorigin=\"anonymous\">\n</script>",
        "key_risks": ["Supply chain attack via CDN compromise", "Malicious script injection if CDN is hacked"],
        "reasoning": "Without SRI, if a CDN is compromised, attackers can replace the hosted file with malicious code that runs on your site.",
    },
    "CWE-693": {
        "recommended_fix": "Add a Content Security Policy header or meta tag that whitelists trusted sources for scripts, styles, and other resources.",
        "fix_code": "<!-- Add to <head>: -->\n<meta http-equiv=\"Content-Security-Policy\"\n  content=\"default-src 'self'; script-src 'self' https://trusted-cdn.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;\">\n\n<!-- Or set server header (nginx): -->\n<!-- add_header Content-Security-Policy \"default-src 'self'\"; -->",
        "key_risks": ["No browser-enforced protection against XSS", "Malicious scripts from any origin can execute"],
        "reasoning": "CSP is a browser security mechanism that restricts which resources can be loaded. Without it, successful XSS attacks have no additional mitigation layer.",
    },
    "CWE-1021": {
        "recommended_fix": "Add the sandbox attribute to all iframes embedding third-party content to restrict their capabilities.",
        "fix_code": "<!-- Restrictive sandbox (recommended): -->\n<iframe src=\"https://external.com\"\n  sandbox=\"allow-scripts allow-same-origin\"\n  referrerpolicy=\"no-referrer\">\n</iframe>\n\n<!-- For display-only content (most restrictive): -->\n<iframe src=\"https://external.com\" sandbox></iframe>",
        "key_risks": ["Clickjacking attacks via iframe overlay", "Third-party content accessing parent page context"],
        "reasoning": "Unsandboxed iframes can navigate the top-level page, access cookies, or overlay deceptive UI on top of your content.",
    },
    "CWE-922": {
        "recommended_fix": "Never store sensitive data (tokens, passwords, PII) in localStorage or sessionStorage. Use HttpOnly cookies for auth tokens or keep them in memory only.",
        "fix_code": "// Instead of storing JWT in localStorage:\nlocalStorage.setItem('token', jwt);\n\n// Store auth state in memory only:\nlet authToken = null; // lives only for this page session\nauthToken = jwt;\n\n// For persistent auth, use HttpOnly cookies set by the server:\n// Set-Cookie: token=xxx; HttpOnly; Secure; SameSite=Strict",
        "key_risks": ["XSS can steal all localStorage data", "Tokens persist after logout if not explicitly cleared", "Accessible to any JavaScript on the page"],
        "reasoning": "localStorage is accessible to all JavaScript on the page. A single XSS vulnerability allows complete theft of all stored data including auth tokens.",
    },
    "CWE-200": {
        "recommended_fix": "Remove sensitive data from HTTP responses, error messages, and client-side code. Never expose internal paths, stack traces, or API keys in responses.",
        "fix_code": "// Remove sensitive info from error responses:\n// Instead of:\nres.json({ error: err.stack, dbQuery: query });\n\n// Use:\nres.json({ error: 'An internal error occurred', code: 'ERR_500' });\n// Log details server-side only:\nconsole.error('[Internal]', err.stack);",
        "key_risks": ["Information disclosure aids attacker reconnaissance", "Exposed stack traces reveal tech stack and file paths"],
        "reasoning": "Detailed error messages and exposed internals give attackers a map of your application's structure and potential attack surfaces.",
    },
}

# Fallback for unknown CWEs
CWE_DEFAULT_FIX = {
    "recommended_fix": "Review this finding manually. Apply the principle of least privilege, validate all inputs, and ensure output encoding is in place.",
    "fix_code": "",
    "key_risks": ["Security misconfiguration", "Potential data exposure"],
    "reasoning": "This pattern was flagged by static analysis. Review the code in context to determine exploitability and apply appropriate mitigations.",
}


def get_static_fix(cwe_id: str, vuln_type: str = "") -> Dict:
    """
    Returns a static fix dict for a given CWE when LLM is unavailable.
    Falls back to a generic recommendation if CWE not in the dictionary.
    """
    fix = CWE_STATIC_FIXES.get(cwe_id)
    if fix:
        return fix

    # Try partial match (e.g. "CWE-79" matches "CWE-79: XSS")
    for key, val in CWE_STATIC_FIXES.items():
        if cwe_id.startswith(key) or key in cwe_id:
            return val

    return CWE_DEFAULT_FIX.copy()


def compute_risk_score(
    final_severity: str,
    llm_result: Dict,
    rag_confidence: float,
    conflict_resolution: Dict,
) -> Dict:
    sev = final_severity.lower().strip()

    # ── Component A: Static Score (50% weight) ────────────────────────
    static_base = SEVERITY_BASE_SCORES.get(sev, 50)
    component_a = static_base * 0.50

    # ── Component B: LLM Adjustment (20% weight) ─────────────────────
    llm_adjustment = int(llm_result.get("severity_adjustment", 0))
    llm_confidence = float(llm_result.get("confidence", 0.5))
    llm_available = llm_result.get("llm_available", False)

    if llm_available:
        adjustment_pts = LLM_ADJUSTMENT_SCORES.get(llm_adjustment, 0)
        component_b = adjustment_pts * llm_confidence * 0.20
    else:
        component_b = 0.0

    # ── Component C: RAG Context Score (20% weight) ───────────────────
    rag_score = rag_confidence * 100
    component_c = rag_score * 0.20

    # ── Component D: Exploitability + Attack Vector (10% weight) ──────
    exploitability = llm_result.get("exploitability", "medium")
    attack_vector = llm_result.get("attack_vector", "network")

    exp_bonus = EXPLOITABILITY_BONUS.get(exploitability, 5)
    av_bonus = ATTACK_VECTOR_BONUS.get(attack_vector, 4)
    component_d = (exp_bonus + av_bonus) * 0.10

    raw_score = component_a + component_b + component_c + component_d
    final_score = round(max(0, min(100, raw_score)), 1)

    return {
        "risk_score": final_score,
        "risk_category": _score_to_category(final_score),
        "components": {
            "static_contribution": round(component_a, 2),
            "llm_contribution": round(component_b, 2),
            "rag_contribution": round(component_c, 2),
            "exploitability_contribution": round(component_d, 2),
        },
        "inputs": {
            "final_severity": sev,
            "llm_adjustment": llm_adjustment,
            "llm_confidence": llm_confidence,
            "rag_confidence": round(rag_confidence, 4),
            "exploitability": exploitability,
            "attack_vector": attack_vector,
        },
    }


def _score_to_category(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    elif score >= 65:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 15:
        return "LOW"
    else:
        return "INFORMATIONAL"


def build_final_verdict(
    code_snippet: str,
    cwe_id: str,
    static_severity: str,
    vuln_type: str,
    file_path: str,
    line: int,
    tool: str,
    rag_result: Dict,
    llm_result: Dict,
    conflict_resolution: Dict,
) -> Dict:
    """
    Assembles the complete final verdict combining all three paths.

    KEY CHANGE: When LLM is unavailable (use_llm=False or Groq down),
    we fall back to the static CWE fix dictionary so the extension always
    shows actionable fix guidance — never blank cards.
    """
    rag_confidence = float(rag_result.get("confidence", 0.5))
    final_severity = conflict_resolution.get("final_severity", static_severity)

    risk = compute_risk_score(
        final_severity=final_severity,
        llm_result=llm_result,
        rag_confidence=rag_confidence,
        conflict_resolution=conflict_resolution,
    )

    priority = _risk_to_priority(risk["risk_score"])

    # ── Populate fix fields ───────────────────────────────────────────
    # Use LLM output if available; fall back to static CWE dictionary.
    # This ensures every card shows a fix — even on quick scan without LLM.
    llm_available = llm_result.get("llm_available", False)

    if llm_available and llm_result.get("recommended_fix"):
        # LLM gave us real content — use it
        recommended_fix = llm_result.get("recommended_fix", "")
        fix_code        = llm_result.get("fix_code", "")
        key_risks       = llm_result.get("key_risks", [])
        reasoning       = llm_result.get("reasoning", "")
    else:
        # LLM unavailable or returned empty — use static dictionary
        static_fix  = get_static_fix(cwe_id, vuln_type)
        recommended_fix = static_fix.get("recommended_fix", "")
        fix_code        = static_fix.get("fix_code", "")
        key_risks       = static_fix.get("key_risks", [])
        # For reasoning, combine RAG context summary if available
        ctx = rag_result.get("context_chunks", [])
        if ctx:
            first_chunk = ctx[0].get("text", "")[:200]
            reasoning = static_fix.get("reasoning", "") + (
                f"\n\nRAG context ({ctx[0].get('source','')}):\n{first_chunk}..." if first_chunk else ""
            )
        else:
            reasoning = static_fix.get("reasoning", "")

    return {
        # ── Core identification ──────────────────────────────────────
        "vulnerability_id": f"{tool}::{cwe_id}::{file_path}:{line}",
        "cwe_id": cwe_id,
        "vuln_type": vuln_type,
        "file_path": file_path,
        "line": line,
        "tool": tool,
        # ── Verdict ─────────────────────────────────────────────────
        "final_severity": final_severity,
        "risk_score": risk["risk_score"],
        "risk_category": risk["risk_category"],
        "priority": priority,
        "is_valid_vulnerability": llm_result.get("is_valid_vulnerability", True),
        "false_positive_likelihood": llm_result.get("false_positive_likelihood", 0.2),
        # ── Conflict resolution trace ────────────────────────────────
        "conflict_detected": conflict_resolution.get("conflict_detected", False),
        "resolution_path": conflict_resolution.get("resolution_path", ""),
        "static_severity": conflict_resolution.get("static_severity", static_severity),
        "llm_severity": conflict_resolution.get("llm_severity", "unavailable"),
        # ── Security intelligence ─────────────────────────────────────
        "owasp_category": rag_result.get("owasp_category", "Unknown"),
        "related_cves": rag_result.get("related_cves", []),
        "exploitability": conflict_resolution.get("rag_exploitability", "medium"),
        # ── Fix & insights (LLM or static fallback) ───────────────────
        "key_risks": key_risks,
        "recommended_fix": recommended_fix,
        "fix_code": fix_code,
        "reasoning": reasoning,
        "llm_confidence": llm_result.get("confidence", 0.5),
        "llm_available": llm_available,
        # ── Score breakdown ───────────────────────────────────────────
        "score_components": risk["components"],
        # ── Context snippets for debugging ────────────────────────────
        "context_chunks": rag_result.get("context_chunks", []),
        "code_snippet": code_snippet,
    }


def _risk_to_priority(score: float) -> str:
    if score >= 85:
        return "P0 — Fix Immediately"
    elif score >= 65:
        return "P1 — Fix This Sprint"
    elif score >= 40:
        return "P2 — Fix This Quarter"
    elif score >= 15:
        return "P3 — Track & Monitor"
    else:
        return "P4 — Informational"