"""
output/report.py
Generates a self-contained HTML security report for sensiAPK scan results.
No external dependencies — all CSS/JS is inline.
"""

import html
import json
import os
from datetime import datetime


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _esc(val):
    """HTML-escape a value safely."""
    return html.escape(str(val or ""), quote=True)


def _sev_class(severity):
    s = (severity or "").lower()
    if s == "critical": return "sev-critical"
    if s == "high":     return "sev-high"
    if s == "medium":   return "sev-medium"
    return "sev-low"


def _exploit_class(level):
    if level == "highly_exploitable":    return "sev-high"
    if level == "potentially_exploitable": return "sev-medium"
    return "sev-low"


def _json_block(data):
    if not data:
        return ""
    try:
        return _esc(json.dumps(data, indent=2))
    except Exception:
        return _esc(str(data))


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    font-size: 14px;
    line-height: 1.6;
}

a { color: #58a6ff; text-decoration: none; }

/* ── HEADER ── */
.header {
    background: linear-gradient(135deg, #161b22 0%, #1a2233 100%);
    border-bottom: 1px solid #30363d;
    padding: 28px 40px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.header h1 { font-size: 24px; color: #58a6ff; font-weight: 700; }
.header .meta { font-size: 12px; color: #8b949e; text-align: right; line-height: 1.8; }
.header .pkg  { font-size: 16px; color: #e6edf3; font-weight: 600; margin-top: 4px; }

/* ── LAYOUT ── */
.container { max-width: 1300px; margin: 0 auto; padding: 32px 40px; }

/* ── SECTIONS ── */
.section-title {
    font-size: 18px;
    font-weight: 700;
    color: #e6edf3;
    border-left: 4px solid #58a6ff;
    padding-left: 12px;
    margin: 40px 0 20px;
}
.section-title.danger  { border-color: #f85149; }
.section-title.warning { border-color: #d29922; }
.section-title.code    { border-color: #3fb950; }

/* ── SUMMARY CARDS ── */
.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
}
.stat-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 20px 16px;
    text-align: center;
}
.stat-card .num  { font-size: 36px; font-weight: 800; display: block; line-height: 1; margin-bottom: 6px; }
.stat-card .lbl  { font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.6px; }
.stat-card.red   { border-color: #f85149; }
.stat-card.red .num { color: #f85149; }
.stat-card.orange{ border-color: #d29922; }
.stat-card.orange .num { color: #d29922; }
.stat-card.green { border-color: #3fb950; }
.stat-card.green .num { color: #3fb950; }
.stat-card.blue  { border-color: #58a6ff; }
.stat-card.blue  .num { color: #58a6ff; }
.stat-card.purple{ border-color: #bc8cff; }
.stat-card.purple .num { color: #bc8cff; }

/* ── RISK BANNER ── */
.risk-banner {
    border-radius: 10px;
    padding: 20px 24px;
    margin-bottom: 32px;
    font-weight: 700;
    font-size: 16px;
    display: flex;
    align-items: center;
    gap: 14px;
    border: 1px solid;
}
.risk-banner.critical { background: rgba(248,81,73,0.12); border-color: #f85149; color: #f85149; }
.risk-banner.high     { background: rgba(248,81,73,0.08); border-color: #da3633; color: #f85149; }
.risk-banner.medium   { background: rgba(210,153,34,0.1); border-color: #d29922; color: #d29922; }
.risk-banner.low      { background: rgba(63,185,80,0.08); border-color: #3fb950; color: #3fb950; }
.risk-banner .icon    { font-size: 28px; }
.risk-banner .text p  { font-size: 13px; font-weight: 400; color: #8b949e; margin-top: 2px; }

/* ── FINDING CARDS ── */
.finding-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    margin-bottom: 20px;
    overflow: hidden;
}
.finding-header {
    padding: 14px 20px;
    display: flex;
    align-items: center;
    gap: 12px;
    cursor: pointer;
    user-select: none;
    background: #1c2128;
    border-bottom: 1px solid #30363d;
}
.finding-header:hover { background: #21262d; }
.finding-header .idx  { color: #8b949e; font-size: 12px; min-width: 36px; }
.finding-header .title{ font-weight: 600; color: #e6edf3; flex: 1; }
.finding-header .tags { display: flex; gap: 6px; flex-wrap: wrap; }
.finding-body  { padding: 20px; display: none; }
.finding-card.open .finding-body { display: block; }
.finding-card.open .finding-header { background: #21262d; }

/* Severity badges */
.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.4px;
}
.sev-critical { background: rgba(248,81,73,0.2);  color: #f85149; border: 1px solid #f85149; }
.sev-high     { background: rgba(218,54,51,0.15);  color: #ff7b72; border: 1px solid #da3633; }
.sev-medium   { background: rgba(210,153,34,0.15); color: #d29922; border: 1px solid #d29922; }
.sev-low      { background: rgba(88,166,255,0.12); color: #58a6ff; border: 1px solid #388bfd; }
.badge-type   { background: rgba(188,140,255,0.15); color: #bc8cff; border: 1px solid #8957e5; font-size: 11px; padding: 2px 8px; border-radius: 4px; }
.badge-owasp  { background: rgba(63,185,80,0.12);  color: #3fb950; border: 1px solid #2ea043; font-size: 11px; padding: 2px 8px; border-radius: 4px; }
.badge-cwe    { background: rgba(88,166,255,0.1);  color: #79c0ff; border: 1px solid #388bfd; font-size: 11px; padding: 2px 8px; border-radius: 4px; }

/* ── DETAIL GRID ── */
.detail-grid {
    display: grid;
    grid-template-columns: 140px 1fr;
    gap: 8px 12px;
    margin-bottom: 16px;
}
.detail-grid .lbl { color: #8b949e; font-size: 12px; padding-top: 2px; }
.detail-grid .val { color: #e6edf3; word-break: break-all; }

/* ── CODE BLOCKS ── */
.code-block {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 14px 16px;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 13px;
    color: #79c0ff;
    overflow-x: auto;
    white-space: pre;
    margin: 8px 0 14px;
    line-height: 1.5;
}

/* ── SUB-SECTIONS ── */
.sub-section {
    margin: 16px 0 8px;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: #8b949e;
    border-bottom: 1px solid #21262d;
    padding-bottom: 4px;
}

/* ── ATTACK CHAIN ── */
.chain-card {
    background: rgba(248,81,73,0.07);
    border: 1px solid #da3633;
    border-radius: 8px;
    padding: 14px 16px;
    margin: 10px 0;
}
.chain-card .chain-title { color: #f85149; font-weight: 700; margin-bottom: 6px; }
.chain-card .chain-desc  { color: #c9d1d9; font-size: 13px; }

/* ── POC BLOCK ── */
.poc-block {
    background: rgba(210,153,34,0.07);
    border: 1px solid #d29922;
    border-radius: 6px;
    padding: 12px 16px;
    font-family: monospace;
    font-size: 13px;
    color: #d29922;
    margin: 8px 0;
    white-space: pre-wrap;
    word-break: break-all;
}

/* ── REMEDIATION ── */
.remediation {
    background: rgba(63,185,80,0.07);
    border: 1px solid #2ea043;
    border-radius: 6px;
    padding: 12px 16px;
    color: #3fb950;
    font-size: 13px;
    margin: 8px 0;
}

/* ── AI BLOCK ── */
.ai-block {
    background: rgba(188,140,255,0.07);
    border: 1px solid #8957e5;
    border-radius: 6px;
    padding: 12px 16px;
    font-size: 13px;
    color: #c9d1d9;
    margin: 8px 0;
}
.ai-block .ai-label { color: #bc8cff; font-weight: 700; margin-bottom: 4px; }

/* ── STEPS LIST ── */
.steps-list { padding-left: 18px; margin: 6px 0; }
.steps-list li { margin-bottom: 4px; color: #c9d1d9; }

/* ── OWASP TABLE ── */
.ref-table { width: 100%; border-collapse: collapse; margin-top: 12px; }
.ref-table th { background: #21262d; color: #8b949e; text-align: left; padding: 8px 12px; font-size: 12px; border: 1px solid #30363d; }
.ref-table td { padding: 8px 12px; border: 1px solid #30363d; font-size: 13px; vertical-align: top; }
.ref-table tr:hover td { background: #161b22; }

/* ── FOOTER ── */
.footer {
    text-align: center;
    padding: 32px;
    color: #484f58;
    font-size: 12px;
    border-top: 1px solid #21262d;
    margin-top: 60px;
}

/* ── TOGGLE CHEVRON ── */
.chevron { transition: transform 0.2s; display: inline-block; }
.finding-card.open .chevron { transform: rotate(90deg); }

/* ── NO FINDINGS ── */
.empty-state {
    text-align: center;
    padding: 40px;
    color: #484f58;
    font-size: 15px;
    border: 1px dashed #30363d;
    border-radius: 10px;
}
"""

# ---------------------------------------------------------------------------
# JAVASCRIPT
# ---------------------------------------------------------------------------

JS = """
function toggle(id) {
    const card = document.getElementById(id);
    card.classList.toggle('open');
}
function expandAll(prefix) {
    document.querySelectorAll('.finding-card').forEach(c => {
        if (c.id.startsWith(prefix)) c.classList.add('open');
    });
}
function collapseAll(prefix) {
    document.querySelectorAll('.finding-card').forEach(c => {
        if (c.id.startsWith(prefix)) c.classList.remove('open');
    });
}
"""

# ---------------------------------------------------------------------------
# COMPONENT BUILDERS
# ---------------------------------------------------------------------------

def _badge(text, cls):
    return f'<span class="badge {cls}">{_esc(text)}</span>'


def _detail_row(label, value, monospace=False):
    if not value:
        return ""
    v = f'<code>{_esc(value)}</code>' if monospace else f'<span class="val">{_esc(str(value))}</span>'
    return f'<div class="lbl">{_esc(label)}</div><div>{v}</div>'


def _code_block(content):
    return f'<div class="code-block">{_esc(str(content))}</div>'


def _subsection(title):
    return f'<div class="sub-section">{_esc(title)}</div>'


def _poc_block(content):
    return f'<div class="poc-block">{_esc(str(content))}</div>'


def _remediation_block(content):
    return f'<div class="remediation">🛡️ {_esc(str(content))}</div>'


def _ai_block(label, content):
    return f'<div class="ai-block"><div class="ai-label">🤖 {_esc(label)}</div>{_esc(str(content))}</div>'


def _steps_list(steps):
    if not steps:
        return ""
    items = "".join(f"<li>{_esc(s)}</li>" for s in steps)
    return f'<ol class="steps-list">{items}</ol>'


# ---------------------------------------------------------------------------
# PHASE 1 FINDING CARD
# ---------------------------------------------------------------------------

def _render_p1_card(idx, f):
    ftype    = f.get("type", "finding")
    source   = f.get("source", "")
    level    = f.get("exploit_level", "low_value")
    score    = f.get("exploit_score", 0)
    ai       = f.get("ai_struct", {}) or {}
    sast     = f.get("sast_verdict", {}) or {}
    rec      = f.get("recursive_analysis", {}) or {}
    poc      = f.get("poc", {}) or {}
    chains   = f.get("attack_chains", []) or []

    # Determine display severity
    sev = (
        sast.get("severity") or
        ai.get("risk") or
        ("high" if level == "highly_exploitable" else "medium")
    )

    owasp = sast.get("owasp") or ai.get("owasp_category") or rec.get("owasp") or f.get("owasp", "")
    cwe   = sast.get("cwe") or ai.get("cwe_id") or rec.get("cwe_id") or f.get("cwe", "")

    # Header tags
    tags = (
        _badge(sev.upper(), _sev_class(sev)) +
        f' <span class="badge-type">{_esc(ftype)}</span>'
    )
    if owasp:
        tags += f' <span class="badge-owasp">{_esc(owasp)}</span>'
    if cwe:
        tags += f' <span class="badge-cwe">{_esc(cwe)}</span>'

    # Title
    title = (
        f.get("issue") or
        f.get("title") or
        f.get("label") or
        ftype
    )

    card_id = f"p1-{idx}"

    # Body
    body = '<div class="detail-grid">'
    body += _detail_row("Source",     source)
    body += _detail_row("File / Path", f.get("path") or f.get("file"))
    val = f.get("value", "")
    if val:
        body += _detail_row("Value", val[:200], monospace=True)
    if f.get("line"):
        body += _detail_row("Context line", str(f.get("line"))[:300])
    body += _detail_row("Exploit Score", str(score))
    body += _detail_row("Exploit Level", level)
    body += _detail_row("Entropy",       str(f.get("entropy", "")))
    body += _detail_row("Classification", f.get("classification"))
    body += "</div>"

    # Manifest specifics
    if ftype == "manifest_vuln":
        body += _subsection("Manifest Detail")
        body += "<div class='detail-grid'>"
        body += _detail_row("Issue",     f.get("issue"))
        body += _detail_row("Detail",    f.get("detail"))
        body += _detail_row("Component", f.get("component"))
        body += _detail_row("Name",      f.get("name"))
        body += _detail_row("Deep Link", f.get("deep_link"))
        body += "</div>"

    # Permission specifics
    if ftype in ("permission_vuln", "permission_combo"):
        body += _subsection("Permission Detail")
        body += "<div class='detail-grid'>"
        perms = f.get("permissions") or [f.get("permission", "")]
        body += _detail_row("Permission(s)", ", ".join(perms))
        body += _detail_row("Description",   f.get("description"))
        body += "</div>"

    # JWT payload
    if f.get("payload"):
        body += _subsection("JWT Payload")
        body += _code_block(json.dumps(f["payload"], indent=2))

    if f.get("decoded"):
        body += _subsection("Decoded Value")
        body += _code_block(f["decoded"][:400])

    # Validation signals
    if f.get("validation"):
        body += _subsection("Validation Signals")
        body += "<ul class='steps-list'>"
        for v in f["validation"]:
            body += f"<li>{_esc(v)}</li>"
        body += "</ul>"

    # Exploit reasons
    if f.get("exploit_reasons"):
        body += _subsection("Why Exploitable")
        body += "<ul class='steps-list'>"
        for r in f["exploit_reasons"]:
            body += f"<li>{_esc(r)}</li>"
        body += "</ul>"

    # AI SAST verdict
    if sast:
        body += _subsection("SAST Verdict (AI Pass 2)")
        body += "<div class='detail-grid'>"
        body += _detail_row("Severity", sast.get("severity", "").upper())
        body += _detail_row("Summary",  sast.get("summary"))
        body += _detail_row("CWE",      sast.get("cwe"))
        body += _detail_row("OWASP",    sast.get("owasp"))
        body += "</div>"
    elif ai and ai.get("reason"):
        body += _subsection("AI Analysis (Pass 1)")
        body += "<div class='detail-grid'>"
        body += _detail_row("Risk",       ai.get("risk", "").upper())
        body += _detail_row("Confidence", str(ai.get("confidence", "N/A")) + "%")
        body += _detail_row("Valid",      str(ai.get("valid")))
        body += _detail_row("OWASP",      f"{ai.get('owasp_category','')} — {ai.get('owasp_name','')}")
        body += _detail_row("CWE",        f"{ai.get('cwe_id','')} — {ai.get('cwe_name','')}")
        body += "</div>"
        body += _ai_block("Reasoning", ai.get("reason", ""))
        if ai.get("false_positive_reason"):
            body += _ai_block("False Positive Note", ai["false_positive_reason"])
        if ai.get("next_actions"):
            body += _subsection("Recommended Next Actions")
            body += _steps_list(ai["next_actions"])

    # Recursive deep-dive
    if rec:
        body += _subsection(f"Recursive Deep-Dive Analysis (depth {f.get('recursive_depth', 1)})")
        conf_badge = _badge("CONFIRMED", "sev-high") if rec.get("confirmed") else _badge("UNCONFIRMED", "sev-low")
        body += f"<p style='margin-bottom:8px'>{conf_badge} &nbsp; Final Risk: {_badge((rec.get('final_risk') or 'N/A').upper(), _sev_class(rec.get('final_risk', 'low')))}</p>"
        if rec.get("attack_scenario"):
            body += _ai_block("Attack Scenario", rec["attack_scenario"])
        if rec.get("evidence"):
            body += _subsection("Evidence")
            body += "<ul class='steps-list'>"
            for e in rec["evidence"]:
                body += f"<li>{_esc(e)}</li>"
            body += "</ul>"
        if rec.get("remediation"):
            body += _remediation_block(rec["remediation"])

    # Attack chains
    if chains:
        body += _subsection("Attack Chains")
        for ch in chains:
            cr = ch.get("combined_risk", "high")
            body += f'<div class="chain-card"><div class="chain-title">{_badge(cr.upper(), _sev_class(cr))} Attack Chain</div>'
            body += f'<div class="chain-desc">{_esc(ch.get("chain_description", ""))}</div>'
            owasps = ", ".join(ch.get("owasp_categories", []))
            cwes   = ", ".join(ch.get("cwe_ids", []))
            if owasps:
                body += f'<div style="margin-top:6px;font-size:12px;color:#8b949e">OWASP: {_esc(owasps)} &nbsp;|&nbsp; CWE: {_esc(cwes)}</div>'
            body += "</div>"

    # Manual PoC
    if f.get("manual_poc"):
        body += _subsection("Manual Verification")
        body += _poc_block(f["manual_poc"])

    # AI PoC
    if poc and not poc.get("error"):
        body += _subsection("AI-Generated PoC")
        if poc.get("poc"):
            body += _poc_block(poc["poc"])
        if poc.get("steps"):
            body += _steps_list(poc["steps"])
        body += "<div class='detail-grid' style='margin-top:8px'>"
        body += _detail_row("Impact",        poc.get("impact"))
        body += _detail_row("Attack Vector", poc.get("attack_vector"))
        body += _detail_row("CVSS Estimate", poc.get("cvss_estimate"))
        body += "</div>"

    return f"""
<div class="finding-card" id="{card_id}">
  <div class="finding-header" onclick="toggle('{card_id}')">
    <span class="idx">P1-{idx}</span>
    <span class="title">{_esc(str(title))}</span>
    <span class="tags">{tags}</span>
    <span class="chevron">▶</span>
  </div>
  <div class="finding-body">{body}</div>
</div>
"""


# ---------------------------------------------------------------------------
# PHASE 2 CODE FINDING CARD
# ---------------------------------------------------------------------------

def _render_p2_card(idx, f):
    rule_id  = f.get("rule_id", "")
    title    = f.get("title", "Code Finding")
    sev      = f.get("code_sast_severity") or f.get("severity", "low")
    owasp    = f.get("owasp", "")
    cwe      = f.get("cwe", "")
    chains   = f.get("code_chains", []) or []
    rel_path = f.get("relative_path") or f.get("file", "")
    ln       = f.get("line_number", "?")

    tags = (
        _badge(sev.upper(), _sev_class(sev)) +
        f' <span class="badge-type">{_esc(rule_id)}</span>'
    )
    if owasp:
        tags += f' <span class="badge-owasp">{_esc(owasp)}</span>'
    if cwe:
        tags += f' <span class="badge-cwe">{_esc(cwe)}</span>'

    card_id = f"p2-{idx}"

    body = "<div class='detail-grid'>"
    body += _detail_row("File",        f"{rel_path}:{ln}")
    body += _detail_row("Description", f.get("description"))
    body += _detail_row("OWASP",       owasp)
    body += _detail_row("CWE",         cwe)
    body += "</div>"

    if f.get("code_sast_summary"):
        body += _ai_block("AI SAST Summary", f["code_sast_summary"])

    if f.get("line"):
        body += _subsection("Matched Line")
        body += _code_block(f["line"][:300])

    if f.get("snippet"):
        body += _subsection("Code Context")
        body += _code_block(f["snippet"])

    if chains:
        body += _subsection("Compound Attack Chain")
        for ch in chains:
            cs = ch.get("combined_severity", "high")
            body += f'<div class="chain-card"><div class="chain-title">{_badge(cs.upper(), _sev_class(cs))} Compound Chain</div>'
            body += f'<div class="chain-desc">{_esc(ch.get("chain_description", ""))}</div>'
            if ch.get("owasp"):
                body += f'<div style="margin-top:6px;font-size:12px;color:#8b949e">OWASP: {_esc(ch["owasp"])} &nbsp;|&nbsp; CWE: {_esc(ch.get("cwe","N/A"))}</div>'
            body += "</div>"

    if f.get("manual_poc"):
        body += _subsection("PoC")
        body += _poc_block(f["manual_poc"])

    return f"""
<div class="finding-card" id="{card_id}">
  <div class="finding-header" onclick="toggle('{card_id}')">
    <span class="idx">P2-{idx}</span>
    <span class="title">{_esc(title)}</span>
    <span class="tags">{tags}</span>
    <span class="chevron">▶</span>
  </div>
  <div class="finding-body">{body}</div>
</div>
"""


# ---------------------------------------------------------------------------
# OWASP REFERENCE TABLE
# ---------------------------------------------------------------------------

OWASP_REF = [
    ("M1",  "Improper Credential Usage",            "Hardcoded/insecure credential handling"),
    ("M2",  "Inadequate Supply Chain Security",      "Vulnerable third-party components"),
    ("M3",  "Insecure Authentication/Authorization", "Missing or weak authentication controls"),
    ("M4",  "Insufficient Input/Output Validation",  "SQL injection, path traversal, command injection"),
    ("M5",  "Insecure Communication",                "Cleartext traffic, SSL bypass, MITM vulnerabilities"),
    ("M6",  "Inadequate Privacy Controls",           "Sensitive data collection without consent/protection"),
    ("M7",  "Insufficient Binary Protections",       "Reverse engineering, dynamic code loading, obfuscation"),
    ("M8",  "Security Misconfiguration",             "Debuggable builds, insecure defaults, misconfig"),
    ("M9",  "Insecure Data Storage",                 "Plaintext storage of sensitive data"),
    ("M10", "Insufficient Cryptography",             "Weak algorithms, hardcoded keys, ECB mode"),
]


def _render_owasp_table():
    rows = ""
    for cat, name, desc in OWASP_REF:
        rows += f"<tr><td><b>{_esc(cat)}</b></td><td>{_esc(name)}</td><td>{_esc(desc)}</td></tr>"
    return f"""
<table class="ref-table">
  <thead><tr><th>Category</th><th>Name</th><th>Description</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
"""


# ---------------------------------------------------------------------------
# MAIN GENERATOR
# ---------------------------------------------------------------------------

def generate(ctx, output_path):
    """
    Generate a self-contained HTML report.
    ctx.phase1_findings and ctx.code_findings must be populated by the engine.
    """
    phase1  = ctx.phase1_findings or []
    code_f  = ctx.code_findings   or []
    pkg     = getattr(ctx, "package", "Unknown")
    scan_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ---- Stats ----
    p1_total  = len(phase1)
    p1_high   = sum(1 for f in phase1 if f.get("exploit_level") == "highly_exploitable")
    p1_med    = sum(1 for f in phase1 if f.get("exploit_level") == "potentially_exploitable")
    p2_total  = len(code_f)
    p2_crit   = sum(1 for f in code_f if f.get("severity") == "critical")
    p2_high   = sum(1 for f in code_f if f.get("severity") == "high")
    p2_med    = sum(1 for f in code_f if f.get("severity") == "medium")
    chains    = sum(len(f.get("attack_chains", [])) for f in phase1)
    chains   += sum(len(f.get("code_chains", [])) for f in code_f)

    # ---- Overall risk ----
    if p2_crit > 0 or p1_high > 0:
        overall_risk   = "critical"
        risk_icon      = "🔴"
        risk_text      = "Critical vulnerabilities identified — immediate remediation required"
    elif p2_high > 0:
        overall_risk   = "high"
        risk_icon      = "🟠"
        risk_text      = "High severity findings — address before production release"
    elif p1_med > 0 or p2_med > 0:
        overall_risk   = "medium"
        risk_icon      = "🟡"
        risk_text      = "Medium severity findings — verify and remediate"
    else:
        overall_risk   = "low"
        risk_icon      = "🟢"
        risk_text      = "No critical vulnerabilities identified — review low severity findings"

    # ---- Batch AI summary ----
    batch_summary = phase1[0].get("batch_analysis_summary", {}) if phase1 else {}
    batch_html = ""
    if batch_summary:
        ai_risk = batch_summary.get("overall_risk", "")
        ai_sum  = batch_summary.get("key_findings_summary", "")
        ai_ch   = batch_summary.get("attack_chains_count", 0)
        batch_html = f"""
<div class="ai-block" style="margin-bottom:24px;">
  <div class="ai-label">🤖 AI Overall Assessment</div>
  <div class="detail-grid" style="margin-top:8px">
    <div class="lbl">Risk Level</div><div>{_badge(ai_risk.upper(), _sev_class(ai_risk))}</div>
    <div class="lbl">Attack Chains</div><div>{_esc(str(ai_ch))}</div>
    <div class="lbl">Summary</div><div>{_esc(ai_sum)}</div>
  </div>
</div>"""

    # ---- Summary cards ----
    summary_cards = f"""
<div class="summary-grid">
  <div class="stat-card red">
    <span class="num">{p1_high}</span>
    <div class="lbl">Highly<br>Exploitable</div>
  </div>
  <div class="stat-card orange">
    <span class="num">{p1_med}</span>
    <div class="lbl">Potentially<br>Exploitable</div>
  </div>
  <div class="stat-card red">
    <span class="num">{p2_crit + p2_high}</span>
    <div class="lbl">Code<br>Critical/High</div>
  </div>
  <div class="stat-card orange">
    <span class="num">{p2_med}</span>
    <div class="lbl">Code<br>Medium</div>
  </div>
  <div class="stat-card purple">
    <span class="num">{chains}</span>
    <div class="lbl">Attack<br>Chains</div>
  </div>
  <div class="stat-card blue">
    <span class="num">{p1_total + p2_total}</span>
    <div class="lbl">Total<br>Findings</div>
  </div>
</div>"""

    # ---- Risk banner ----
    risk_banner = f"""
<div class="risk-banner {overall_risk}">
  <span class="icon">{risk_icon}</span>
  <div class="text">
    <div>Overall Risk: {overall_risk.upper()}</div>
    <p>{_esc(risk_text)}</p>
  </div>
</div>"""

    # ---- Phase 1 cards ----
    if phase1:
        p1_cards = "".join(_render_p1_card(i + 1, f) for i, f in enumerate(phase1))
        expand_p1 = """
<div style="margin-bottom:12px;font-size:12px;color:#8b949e;">
  <a href="#" onclick="expandAll('p1-');return false;">Expand All</a> &nbsp;|&nbsp;
  <a href="#" onclick="collapseAll('p1-');return false;">Collapse All</a>
</div>"""
        p1_section = f"""
<div class="section-title danger">Phase 1 — Runtime Findings ({p1_total})</div>
{expand_p1}
{p1_cards}"""
    else:
        p1_section = """
<div class="section-title">Phase 1 — Runtime Findings</div>
<div class="empty-state">No exploitable runtime findings identified.</div>"""

    # ---- Phase 2 cards ----
    if code_f:
        p2_cards = "".join(_render_p2_card(i + 1, f) for i, f in enumerate(code_f))
        expand_p2 = """
<div style="margin-bottom:12px;font-size:12px;color:#8b949e;">
  <a href="#" onclick="expandAll('p2-');return false;">Expand All</a> &nbsp;|&nbsp;
  <a href="#" onclick="collapseAll('p2-');return false;">Collapse All</a>
</div>"""
        p2_section = f"""
<div class="section-title code">Phase 2 — Static Code Analysis ({p2_total})</div>
{expand_p2}
{p2_cards}"""
    else:
        p2_section = ""

    # ---- OWASP reference ----
    owasp_section = f"""
<div class="section-title">OWASP Mobile Top 10 Reference</div>
{_render_owasp_table()}"""

    # ---- Full HTML ----
    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>sensiAPK Report — {_esc(pkg)}</title>
  <style>{CSS}</style>
</head>
<body>

<div class="header">
  <div>
    <h1>sensiAPK v3.0</h1>
    <div class="pkg">📦 {_esc(pkg)}</div>
  </div>
  <div class="meta">
    <div>Scan Date: {_esc(scan_dt)}</div>
    <div>Tool: sensiAPK Recursive AI SAST</div>
    <div>Report: {_esc(os.path.basename(output_path))}</div>
  </div>
</div>

<div class="container">

  <div class="section-title">Executive Summary</div>
  {risk_banner}
  {summary_cards}
  {batch_html}

  {p1_section}
  {p2_section}
  {owasp_section}

</div>

<div class="footer">
  Generated by sensiAPK v3.0 — Recursive AI SAST | {_esc(scan_dt)}
  <br>For authorized security testing only.
</div>

<script>{JS}</script>
</body>
</html>"""

    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html_doc)
        return True
    except Exception as e:
        print(f"[ERROR] Failed to write report: {e}")
        return False
