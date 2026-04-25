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
    2: 15,    # +2 → big increase
    1: 8,     # +1 → small increase
    0: 0,     # no change
    -1: -8,   # -1 → small reduction
    -2: -15,  # -2 → big reduction
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


def compute_risk_score(
    final_severity: str,
    llm_result: Dict,
    rag_confidence: float,
    conflict_resolution: Dict,
) -> Dict:
    """
    Computes the final unified risk score.

    Args:
        final_severity: Resolved severity from conflict engine
        llm_result: Full LLM analysis dict
        rag_confidence: Average similarity score from RAG (0–1)
        conflict_resolution: Output from conflict_resolver.resolve()

    Returns:
        Dict with risk_score (0–100), risk_category, and component breakdown.
    """
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
        # Scale by LLM confidence — low confidence = smaller adjustment
        component_b = adjustment_pts * llm_confidence * 0.20
    else:
        component_b = 0.0  # No LLM → neutral

    # ── Component C: RAG Context Score (20% weight) ───────────────────
    # Higher RAG confidence = more reliable context
    rag_score = rag_confidence * 100  # 0–100
    component_c = rag_score * 0.20

    # ── Component D: Exploitability + Attack Vector (10% weight) ──────
    exploitability = llm_result.get("exploitability", "medium")
    attack_vector = llm_result.get("attack_vector", "network")

    exp_bonus = EXPLOITABILITY_BONUS.get(exploitability, 5)
    av_bonus = ATTACK_VECTOR_BONUS.get(attack_vector, 4)
    component_d = (exp_bonus + av_bonus) * 0.10

    # ── Final Score ───────────────────────────────────────────────────
    raw_score = component_a + component_b + component_c + component_d

    # Clamp to 0–100
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
    """Maps numeric risk score to human-readable category."""
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
    # Static inputs
    code_snippet: str,
    cwe_id: str,
    static_severity: str,
    vuln_type: str,
    file_path: str,
    line: int,
    tool: str,
    # Processed inputs
    rag_result: Dict,
    llm_result: Dict,
    conflict_resolution: Dict,
) -> Dict:
    """
    Assembles the complete final verdict combining all three paths.
    This is the object returned to the VS Code extension / dashboard.
    """
    rag_confidence = float(rag_result.get("confidence", 0.5))
    final_severity = conflict_resolution.get("final_severity", static_severity)

    risk = compute_risk_score(
        final_severity=final_severity,
        llm_result=llm_result,
        rag_confidence=rag_confidence,
        conflict_resolution=conflict_resolution,
    )

    # Priority label for the extension sidebar
    priority = _risk_to_priority(risk["risk_score"])

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
        # ── LLM insights ─────────────────────────────────────────────
        "key_risks": llm_result.get("key_risks", []),
        "recommended_fix": llm_result.get("recommended_fix", ""),
        "fix_code": llm_result.get("fix_code", ""),  
        "reasoning": llm_result.get("reasoning", ""),
        "llm_confidence": llm_result.get("confidence", 0.5),
        "llm_available": llm_result.get("llm_available", False),
        # ── Score breakdown ───────────────────────────────────────────
        "score_components": risk["components"],
        # ── Context snippets for debugging ────────────────────────────
        "context_chunks": rag_result.get("context_chunks", []),
        "code_snippet": code_snippet,
    }


def _risk_to_priority(score: float) -> str:
    """Maps risk score to display priority for VS Code extension."""
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