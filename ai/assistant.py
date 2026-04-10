import os
import requests
import json

API_KEY = os.getenv("OPENAI_API_KEY")


# ===============================
# AI ANALYSIS (CORE REASONING)
# ===============================
def analyze_finding(f):

    if not API_KEY:
        return f

    prompt = f"""
You are a senior mobile security expert.

STRICT:
- Return ONLY JSON
- No extra text

Analyze this finding:
{json.dumps(f)}

Return:
{{
 "valid": true/false,
 "risk": "low|medium|high|critical",
 "reason": "...",
 "next_actions": []
}}
"""

    try:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0
            }
        )

        content = r.json()["choices"][0]["message"]["content"]

        f["ai_struct"] = json.loads(content)

    except Exception as e:
        f["ai_struct"] = {
            "valid": False,
            "reason": f"AI error: {str(e)}"
        }

    return f


# ===============================
# AI POC GENERATION
# ===============================
def generate_poc(f):

    if not API_KEY:
        return f

    prompt = f"""
You are a mobile security expert.

Vulnerability:
{json.dumps(f)}

Generate:
1. Practical exploitation steps
2. ADB command PoC
3. Expected result

Return ONLY JSON:
{{
 "poc": "...",
 "steps": ["..."],
 "impact": "..."
}}
"""

    try:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0
            }
        )

        content = r.json()["choices"][0]["message"]["content"]

        f["poc"] = json.loads(content)

    except Exception as e:
        f["poc"] = {
            "error": f"AI PoC failed: {str(e)}"
        }

    return f