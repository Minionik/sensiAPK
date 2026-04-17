import os
import json
import requests

API_KEY = os.getenv("ANTHROPIC_API_KEY")
MODEL = "claude-3-5-sonnet-20241022"


# ===============================
# INTERNAL HELPERS
# ===============================

def _call_api(prompt, max_tokens=1024):
    """Core API call with JSON response parsing."""
    if not API_KEY:
        return None

    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            },
            json={
                "model": MODEL,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0
            },
            timeout=45
        )
        r.raise_for_status()
        content = r.json()["content"][0]["text"]
        return _parse_json(content)
    except Exception as e:
        return {"error": str(e)}


def _parse_json(content):
    """Extract JSON from possibly markdown-wrapped content."""
    if "```json" in content:
        content = content.split("```json")[1].split("```")[0].strip()
    elif "```" in content:
        content = content.split("```")[1].split("```")[0].strip()
    try:
        return json.loads(content)
    except Exception:
        return {"raw": content}


# ===============================
# PASS 1 — INDIVIDUAL SAST ANALYSIS
# ===============================

def analyze_finding(f):
    """
    Pass 1: Analyze each finding individually.
    - Determines if it is a true positive or false positive
    - Maps to OWASP Mobile Top 10 and CWE
    - Flags findings that need recursive deeper analysis
    """
    if not API_KEY:
        return f

    prompt = f"""You are a senior mobile application security researcher performing SAST (Static Application Security Testing) analysis on an Android application.

Analyze the following finding and determine if it represents a TRUE POSITIVE security vulnerability.

Finding:
{json.dumps(f, indent=2)}

Your analysis must answer:
1. Is this a genuine vulnerability or a false positive?
2. Does the value look like a real secret (not a placeholder, test value, or framework default like "example_key", "your_token_here", "null", "true/false")?
3. Is it realistically exploitable on a physical/emulated Android device?
4. What OWASP Mobile Top 10 (2024) category applies?
5. What CWE ID is most relevant?
6. Does this finding need a deeper recursive SAST investigation? (e.g., an exported component was found — does it handle sensitive data from storage?)

Return ONLY valid JSON — no extra text:
{{
  "valid": true,
  "confidence": 85,
  "risk": "high",
  "is_false_positive": false,
  "false_positive_reason": null,
  "owasp_category": "M9",
  "owasp_name": "Insecure Data Storage",
  "cwe_id": "CWE-312",
  "cwe_name": "Cleartext Storage of Sensitive Information",
  "reason": "detailed technical reasoning for the classification",
  "needs_deeper_analysis": false,
  "deeper_analysis_hint": null,
  "next_actions": [
    "adb pull /data/data/com.example.app/shared_prefs/auth.xml",
    "Check if the token is reused across sessions"
  ]
}}"""

    result = _call_api(prompt, max_tokens=1024)

    if result and "error" not in result:
        f["ai_struct"] = result
    else:
        f["ai_struct"] = {
            "valid": False,
            "reason": f"AI error: {result.get('error', 'unknown') if result else 'no response'}"
        }

    return f


# ===============================
# PASS 2 — BATCH CROSS-CORRELATION
# ===============================

def batch_analyze(findings):
    """
    Pass 2: Send all findings together to identify:
    - Multi-finding attack chains
    - False positives that only become clear in context
    - SAST-level severity verdicts per finding
    - Overall application risk posture
    """
    if not API_KEY or not findings:
        return findings

    # Build concise summaries to stay within token limits
    summaries = []
    for i, f in enumerate(findings):
        summaries.append({
            "id": i,
            "type": f.get("type"),
            "source": f.get("source"),
            "classification": f.get("classification"),
            "value_preview": (f.get("value") or "")[:60],
            "entropy": f.get("entropy"),
            "exploit_level": f.get("exploit_level"),
            "exploit_score": f.get("exploit_score"),
            "correlation": f.get("correlation", []),
            "owasp_category": f.get("ai_struct", {}).get("owasp_category"),
            "cwe_id": f.get("ai_struct", {}).get("cwe_id"),
            "issue": f.get("issue"),
            "component": f.get("component"),
            "file_tags": f.get("file_tags", [])
        })

    prompt = f"""You are a senior mobile application security researcher performing a comprehensive SAST review of an Android application.

Below are ALL findings from the scan. Analyze them as a whole to:
1. Identify multi-step attack chains (e.g., exported Activity + hardcoded API key = full account takeover)
2. Confirm or reject individual findings as true positives based on the full context
3. Assign a SAST severity verdict to each confirmed finding (critical/high/medium/low)
4. Provide an overall risk assessment of the application

All Findings:
{json.dumps(summaries, indent=2)}

Return ONLY valid JSON:
{{
  "attack_chains": [
    {{
      "finding_ids": [0, 2],
      "chain_description": "Exported Activity (finding 0) can be launched by any app, and it reads the hardcoded API key (finding 2) from shared prefs, enabling full API access without authentication.",
      "combined_risk": "critical",
      "owasp_categories": ["M3", "M9"],
      "cwe_ids": ["CWE-926", "CWE-312"]
    }}
  ],
  "false_positives": [
    {{
      "finding_id": 1,
      "reason": "Value 'example_api_key_here' is a placeholder string, not a real credential."
    }}
  ],
  "confirmed_vulnerabilities": [
    {{
      "finding_id": 0,
      "sast_verdict": "confirmed",
      "severity": "high",
      "cwe": "CWE-312",
      "owasp": "M9",
      "summary": "Auth token stored in plaintext SharedPreferences, accessible to any app with READ_EXTERNAL_STORAGE or via ADB backup."
    }}
  ],
  "overall_risk": "critical",
  "key_findings_summary": "Application stores authentication tokens in plaintext and exposes internal components without permission checks, enabling unauthenticated access."
}}"""

    result = _call_api(prompt, max_tokens=2048)

    if not result or "error" in result:
        return findings

    # --- Apply batch results back to individual findings ---

    fp_ids = {fp["finding_id"] for fp in result.get("false_positives", [])}
    confirmed_map = {c["finding_id"]: c for c in result.get("confirmed_vulnerabilities", [])}
    fp_reasons = {fp["finding_id"]: fp.get("reason") for fp in result.get("false_positives", [])}

    for chain in result.get("attack_chains", []):
        for fid in chain.get("finding_ids", []):
            if 0 <= fid < len(findings):
                findings[fid].setdefault("attack_chains", []).append({
                    "chain_description": chain.get("chain_description"),
                    "combined_risk": chain.get("combined_risk"),
                    "owasp_categories": chain.get("owasp_categories", []),
                    "cwe_ids": chain.get("cwe_ids", [])
                })

    for i, f in enumerate(findings):
        if i in fp_ids:
            f["batch_false_positive"] = True
            f["batch_fp_reason"] = fp_reasons.get(i)

        if i in confirmed_map:
            f["sast_verdict"] = confirmed_map[i]

    # Store the summary on the first finding
    if findings:
        findings[0]["batch_analysis_summary"] = {
            "overall_risk": result.get("overall_risk"),
            "key_findings_summary": result.get("key_findings_summary"),
            "attack_chains_count": len(result.get("attack_chains", []))
        }

    return findings


# ===============================
# PASS 3 — RECURSIVE DEEP-DIVE
# ===============================

def recursive_validate(f, all_findings, depth=0):
    """
    Pass 3: Recursive deep-dive for findings flagged by Pass 1.
    Provides precise attack scenario, chaining opportunity, and remediation.
    Max recursion depth: 2
    """
    if not API_KEY or depth >= 2:
        return f

    ai = f.get("ai_struct", {})
    if not ai.get("needs_deeper_analysis"):
        return f

    # Gather related findings as context (limit to 5)
    related = [
        other for other in all_findings
        if other is not f and (
            other.get("source") == f.get("source") or
            other.get("type") == f.get("type") or
            (f.get("value") and f["value"] in str(other.get("value", "")))
        )
    ][:5]

    related_summaries = [
        {
            "type": r.get("type"),
            "source": r.get("source"),
            "value_preview": (r.get("value") or "")[:50],
            "classification": r.get("classification"),
            "exploit_level": r.get("exploit_level"),
            "owasp": r.get("ai_struct", {}).get("owasp_category")
        }
        for r in related
    ]

    prompt = f"""You are performing a RECURSIVE SAST deep-dive on a specific Android security finding.

Previous analysis flagged this finding for deeper investigation.
Reason: {ai.get('deeper_analysis_hint', 'Suspicious finding — needs context-aware validation')}
Recursion depth: {depth + 1}/2

Primary Finding:
{json.dumps(f, indent=2)}

Related Findings (for context):
{json.dumps(related_summaries, indent=2)}

Perform a thorough recursive SAST analysis:
1. Is this a CONFIRMED real vulnerability given all the context?
2. Can an attacker chain this with related findings for a higher-impact attack?
3. What is the precise, realistic attack scenario?
4. Provide concrete evidence from the finding data that supports your conclusion.

Return ONLY valid JSON:
{{
  "confirmed": true,
  "final_risk": "high",
  "attack_scenario": "An attacker with physical access can run 'adb backup -noapk com.example.app' to extract the unencrypted SharedPreferences containing the session token, then replay it to authenticate as the victim.",
  "evidence": [
    "Token has entropy 4.8 indicating it is a real credential, not a placeholder",
    "Token found in shared_prefs source which is accessible via ADB backup",
    "allowBackup=true confirmed in manifest"
  ],
  "cwe_id": "CWE-312",
  "owasp": "M9",
  "needs_further_recursion": false,
  "remediation": "Disable ADB backup (android:allowBackup=false), store tokens in Android Keystore, and use EncryptedSharedPreferences."
}}"""

    result = _call_api(prompt, max_tokens=1500)

    if result and "error" not in result:
        f["recursive_analysis"] = result
        f["recursive_depth"] = depth + 1

        # Recurse further if flagged (depth-limited)
        if result.get("needs_further_recursion") and depth < 1:
            f["ai_struct"]["needs_deeper_analysis"] = True
            f["ai_struct"]["deeper_analysis_hint"] = result.get("attack_scenario", "")
            f = recursive_validate(f, all_findings, depth + 1)

    return f


# ===============================
# POC GENERATION (AI-POWERED)
# ===============================

# ===============================
# PHASE 2 — CODE SAST BATCH AI
# ===============================

def batch_analyze_code(code_findings):
    """
    AI batch analysis of static code findings.
    - Confirms / dismisses each finding as true positive
    - Identifies compound code-level attack chains
      (e.g., JS enabled + addJavascriptInterface + unvalidated URL = RCE)
    - Removes pure pattern-match noise (e.g., Random() in test utils)
    """
    if not API_KEY or not code_findings:
        return code_findings

    summaries = []
    for i, f in enumerate(code_findings):
        summaries.append({
            "id":            i,
            "rule_id":       f.get("rule_id"),
            "title":         f.get("title"),
            "severity":      f.get("severity"),
            "description":   f.get("description"),
            "owasp":         f.get("owasp"),
            "cwe":           f.get("cwe"),
            "relative_path": f.get("relative_path"),
            "line_number":   f.get("line_number"),
            "line_snippet":  f.get("line", "")[:120],
        })

    prompt = f"""You are a senior Android security researcher performing AI-assisted SAST review of decompiled APK source code.

Below are all pattern-matched findings from static analysis. Your job is to:
1. Confirm findings that are genuinely exploitable in a real Android app context
2. Dismiss findings that are false positives (test utilities, commented code, non-security imports, known safe usage)
3. Identify compound attack chains where multiple findings together create a higher-impact vulnerability
   (e.g., setJavaScriptEnabled(true) + addJavascriptInterface + unvalidated WebView URL = RCE)
4. Assign final SAST severity taking code context into account

All Code Findings:
{json.dumps(summaries, indent=2)}

Return ONLY valid JSON:
{{
  "confirmed": [
    {{
      "id": 0,
      "confirmed_severity": "high",
      "sast_summary": "AES cipher uses ECB mode in PaymentProcessor.java — payment data patterns are visible in ciphertext"
    }}
  ],
  "false_positives": [
    {{
      "id": 2,
      "reason": "new Random() is in a test helper class, not used for cryptographic purposes"
    }}
  ],
  "compound_chains": [
    {{
      "finding_ids": [3, 5, 7],
      "chain_description": "setJavaScriptEnabled(true) + addJavascriptInterface('Android') + WebView loads user-controlled URL → attacker-controlled page can call Android.* methods → RCE",
      "combined_severity": "critical",
      "owasp": "M1",
      "cwe": "CWE-749"
    }}
  ]
}}"""

    result = _call_api(prompt, max_tokens=2048)

    if not result or "error" in result:
        return code_findings

    confirmed_ids   = {c["id"]: c for c in result.get("confirmed", [])}
    fp_ids          = {fp["id"]: fp.get("reason") for fp in result.get("false_positives", [])}

    for chain in result.get("compound_chains", []):
        for fid in chain.get("finding_ids", []):
            if 0 <= fid < len(code_findings):
                code_findings[fid].setdefault("code_chains", []).append({
                    "chain_description":  chain.get("chain_description"),
                    "combined_severity":  chain.get("combined_severity"),
                    "owasp":             chain.get("owasp"),
                    "cwe":               chain.get("cwe"),
                })

    for i, f in enumerate(code_findings):
        if i in fp_ids:
            f["code_false_positive"]  = True
            f["code_fp_reason"]       = fp_ids[i]

        if i in confirmed_ids:
            c = confirmed_ids[i]
            f["code_sast_confirmed"]  = True
            f["code_sast_severity"]   = c.get("confirmed_severity", f.get("severity"))
            f["code_sast_summary"]    = c.get("sast_summary")

    return code_findings


# ===============================
# POC GENERATION (AI-POWERED)
# ===============================

def generate_poc(f):
    """
    Generate a precise, context-aware Proof of Concept.
    Uses SAST verdicts from Pass 1/2/3 to produce a targeted PoC.
    """
    if not API_KEY:
        return f

    # Build SAST context from whichever pass produced the best verdict
    sast_context = (
        f.get("recursive_analysis") or
        f.get("sast_verdict") or
        f.get("ai_struct") or
        {}
    )

    prompt = f"""You are a mobile application security expert generating a Proof of Concept for a confirmed vulnerability.

Vulnerability Finding:
{json.dumps(f, indent=2)}

SAST Verdict:
{json.dumps(sast_context, indent=2)}

Generate a practical, precise PoC that a security researcher can run immediately.

Return ONLY valid JSON:
{{
  "poc": "adb shell 'run-as com.example.app cat /data/data/com.example.app/shared_prefs/auth.xml'",
  "steps": [
    "Connect device via ADB with USB debugging enabled",
    "Run the PoC command above",
    "Extract the token value from the XML output",
    "Use the token in an API request: curl -H 'Authorization: Bearer <token>' https://api.example.com/user"
  ],
  "impact": "Full account takeover — attacker obtains a valid session token and can perform all actions as the victim user.",
  "attack_vector": "Local (ADB access) or physical device access",
  "cvss_estimate": "6.8"
}}"""

    result = _call_api(prompt, max_tokens=1024)

    if result and "error" not in result:
        f["poc"] = result
    else:
        f["poc"] = {
            "error": f"AI PoC failed: {result.get('error', 'unknown') if result else 'no response'}"
        }

    return f
