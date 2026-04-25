# rag/services/llm_service.py
# Path C: LLM Reasoning Layer — Groq (Stable + Fast + Free Tier)

import json
import os
import re
import time
from typing import Dict, List, Optional
from dotenv import load_dotenv
from groq import Groq

# -----------------------------
# Load ENV
# -----------------------------
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

print("GROQ KEY LOADED:", bool(GROQ_API_KEY))

# -----------------------------
# Init Client
# -----------------------------
client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None


# -----------------------------
# Safe JSON Extractor
# -----------------------------
def _extract_json(text: str) -> Dict:
    try:
        return json.loads(text)
    except:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group())
        raise ValueError("No valid JSON found in response")


# -----------------------------
# LLM CALL (Groq)
# -----------------------------
def _call_llm(prompt: str, system: str = "") -> str:
    if not client:
        raise EnvironmentError("GROQ_API_KEY not set")

    messages = []

    if system:
        messages.append({"role": "system", "content": system})

    messages.append({"role": "user", "content": prompt})

    # Retry logic (handles rate limits + network)
    for attempt in range(3):
        try:
            response = client.chat.completions.create(
                model=os.getenv("GROQ_MODEL"),  # 🔥 best balance
                messages=messages,
                temperature=0.0,
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            print(f"[LLM RETRY {attempt+1}] {e}")

            # exponential backoff
            time.sleep(2 ** attempt)

    raise RuntimeError("Groq API failed after retries")


# -----------------------------
# Prompt Builder
# -----------------------------
def build_reasoning_prompt(
    code_snippet: str,
    cwe_id: str,
    severity: str,
    vuln_type: str,
    rag_context: List[Dict],
    static_findings: Optional[List[Dict]] = None,
) -> str:

    context_text = ""
    for i, chunk in enumerate(rag_context[:2], 1):  # reduced for efficiency
        src = chunk.get("source", chunk.get("metadata", {}).get("source", "Unknown"))
        sim = chunk.get("similarity", 0)
        text = chunk.get("text", "")[:300]
        context_text += f"\n[Context {i} | {src} | Score: {sim:.2f}]\n{text}\n"

    static_text = ""
    if static_findings:
        for f in static_findings[:2]:
            static_text += (
                f"- {f.get('tool')} | {f.get('file_path')}:{f.get('line')} | "
                f"{f.get('message')} | {f.get('severity')}\n"
            )
    else:
        static_text = "No static findings."

    return f"""
You are a senior application security engineer.

Analyze the vulnerability and return STRICT JSON.

CWE: {cwe_id}
Type: {vuln_type}
Severity: {severity}

Code:
{code_snippet[:400]}

Static Findings:
{static_text}

Context:
{context_text}

Return ONLY JSON:
{{
  "is_valid_vulnerability": true,
  "severity_assessment": "high",
  "severity_adjustment": 0,
  "confidence": 0.8,
  "exploitability": "high",
  "attack_vector": "network",
  "false_positive_likelihood": 0.1,
  "key_risks": ["..."],
  "recommended_fix": "...",
  "fix_code": "...",
  "reasoning": "..."
}}
"""


# -----------------------------
# Main Analysis
# -----------------------------
def analyze_with_llm(
    code_snippet: str,
    cwe_id: str,
    severity: str,
    vuln_type: str,
    rag_context: List[Dict],
    static_findings: Optional[List[Dict]] = None,
) -> Dict:

    try:
        prompt = build_reasoning_prompt(
            code_snippet, cwe_id, severity, vuln_type,
            rag_context, static_findings
        )

        system = "You are a cybersecurity expert. Return ONLY valid JSON. No markdown."

        raw = _call_llm(prompt, system)

        # Clean markdown fences
        raw = re.sub(r"```json|```", "", raw).strip()

        result = _extract_json(raw)
        result["llm_available"] = True

        return _validate_llm_output(result)

    except Exception as e:
        print(f"[LLM ERROR]: {e}")
        return _fallback_response(severity, str(e))


# -----------------------------
# Fix Generator
# -----------------------------
def generate_fix_for_snippet(
    code_snippet: str,
    vuln_type: str,
    cwe_id: str
) -> Dict:

    prompt = f"""
Fix this vulnerability.

Type: {vuln_type}
CWE: {cwe_id}

Code:
{code_snippet[:600]}

Return ONLY JSON:
{{
  "fix_code": "...",
  "explanation": "...",
  "steps": ["..."]
}}
"""

    try:
        raw = _call_llm(prompt)
        raw = re.sub(r"```json|```", "", raw).strip()
        return _extract_json(raw)

    except Exception as e:
        return {
            "fix_code": "",
            "explanation": f"Failed: {e}",
            "steps": []
        }


# -----------------------------
# Validation
# -----------------------------
def _validate_llm_output(result: Dict) -> Dict:
    defaults = {
        "is_valid_vulnerability": True,
        "severity_assessment": "medium",
        "severity_adjustment": 0,
        "confidence": 0.5,
        "exploitability": "medium",
        "attack_vector": "network",
        "false_positive_likelihood": 0.2,
        "key_risks": [],
        "recommended_fix": "",
        "fix_code": "",
        "reasoning": "",
        "llm_available": True,
    }

    for k, v in defaults.items():
        result.setdefault(k, v)

    # Clamp values safely
    result["confidence"] = max(0.0, min(1.0, float(result["confidence"])))
    result["false_positive_likelihood"] = max(0.0, min(1.0, float(result["false_positive_likelihood"])))
    result["severity_adjustment"] = max(-2, min(2, int(result["severity_adjustment"])))

    return result


# -----------------------------
# Fallback (NEVER FAIL)
# -----------------------------
def _fallback_response(severity: str, reason: str) -> Dict:
    return {
        "is_valid_vulnerability": True,
        "severity_assessment": severity.lower(),
        "severity_adjustment": 0,
        "confidence": 0.5,
        "exploitability": "medium",
        "attack_vector": "network",
        "false_positive_likelihood": 0.2,
        "key_risks": [],
        "recommended_fix": "Manual review required based on static analysis.",
        "fix_code": "",
        "reasoning": f"LLM unavailable: {reason}",
        "llm_available": False,
    }