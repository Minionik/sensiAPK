from core.enricher import enrich
from core.graph import build_graph
from core.validator import validate
from core.poc import generate_manual_poc
from core.classifier import classify_file
from core.exploitability import evaluate_exploitability

from ai.assistant import analyze_finding, generate_poc


def run_engine(ctx):

    raw = []

    # -----------------------
    # COLLECT
    # -----------------------
    for c in ctx.collectors:
        data = c.collect(ctx.base_path)
        if data:
            raw.extend(data)

    # -----------------------
    # ANALYZE
    # -----------------------
    findings = []

    for item in raw:
        for a in ctx.analyzers:
            res = a.analyze(item)

            if res:
                if isinstance(res, list):
                    findings.extend(res)
                else:
                    findings.append(res)

    # -----------------------
    # ENRICH
    # -----------------------
    findings = [enrich(f) for f in findings]

    # -----------------------
    # FILE INTELLIGENCE
    # -----------------------
    findings = [classify_file(f) for f in findings]

    # GRAPH CORRELATION
    findings = build_graph(findings)

# ADVANCED CORRELATION (CRITICAL)
    if ctx.correlator:
        findings = ctx.correlator(findings)

    # -----------------------
    # VALIDATION
    # -----------------------
    findings = [validate(f) for f in findings]

    # -----------------------
    # EXPLOITABILITY
    # -----------------------
    findings = [evaluate_exploitability(f) for f in findings]

    # -----------------------
    # FINAL PROCESSING
    # -----------------------
    enhanced = []

    for f in findings:

        # Always generate manual PoC
        f["manual_poc"] = generate_manual_poc(f)

        # AI reasoning
        if ctx.use_ai and f.get("exploit_score", 0) > 40:
            f = analyze_finding(f)

        # AI PoC (only for manifest issues)
        if ctx.use_ai and f.get("type") == "manifest_vuln":
            f = generate_poc(f)

        enhanced.append(f)

    # -----------------------
    # FILTER FINAL RESULTS
    # -----------------------
    final = [
        f for f in enhanced
        if f.get("exploit_level") in ["highly_exploitable", "potentially_exploitable"]
    ]

    # -----------------------
    # OUTPUT
    # -----------------------
    ctx.output.render(final)
