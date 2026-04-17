from core.enricher import enrich
from core.graph import build_graph
from core.validator import validate
from core.poc import generate_manual_poc
from core.classifier import classify_file
from core.exploitability import evaluate_exploitability

from ai.assistant import (
    analyze_finding,
    generate_poc,
    batch_analyze,
    recursive_validate,
    batch_analyze_code,
)

from collectors import apk_code as apk_code_collector
from analyzers import code as code_analyzer
from analyzers.permissions import analyze_combos


def run_engine(ctx):

    # ==================================================================
    # PHASE 1 — RUNTIME DATA ANALYSIS
    # ==================================================================

    raw = []

    # --------------------------
    # COLLECT from device
    # --------------------------
    for c in ctx.collectors:
        data = c.collect(ctx.base_path)
        if data:
            raw.extend(data)

    # Capture all permissions for combo analysis
    all_perms = [
        item.get("permission", "").split(".")[-1]
        for item in raw
        if item.get("type") == "manifest_permission"
    ]

    # --------------------------
    # ANALYZE
    # --------------------------
    findings = []

    for item in raw:
        for a in ctx.analyzers:
            res = a.analyze(item)
            if res:
                if isinstance(res, list):
                    findings.extend(res)
                else:
                    findings.append(res)

    # Inject dangerous permission combo findings
    combo_findings = analyze_combos(all_perms)
    findings.extend(combo_findings)

    # --------------------------
    # ENRICH
    # --------------------------
    findings = [enrich(f) for f in findings]

    # --------------------------
    # FILE INTELLIGENCE
    # --------------------------
    findings = [classify_file(f) for f in findings]

    # GRAPH CORRELATION
    findings = build_graph(findings)

    # ADVANCED CORRELATION
    if ctx.correlator:
        findings = ctx.correlator(findings)

    # --------------------------
    # VALIDATION
    # --------------------------
    findings = [validate(f) for f in findings]

    # --------------------------
    # EXPLOITABILITY
    # --------------------------
    findings = [evaluate_exploitability(f) for f in findings]

    # --------------------------
    # MANUAL PoC (ALWAYS)
    # --------------------------
    for f in findings:
        f["manual_poc"] = generate_manual_poc(f)

    # ==================================================================
    # AI PIPELINE — 3-PASS RECURSIVE SAST (Phase 1 findings)
    # ==================================================================

    if ctx.use_ai:

        if ctx.verbose:
            print("[AI] Pass 1: Individual SAST analysis...")
        for i, f in enumerate(findings):
            if f.get("exploit_score", 0) > 20:
                findings[i] = analyze_finding(f)

        if ctx.verbose:
            print("[AI] Pass 2: Batch cross-correlation...")
        findings = batch_analyze(findings)

        if ctx.verbose:
            print("[AI] Pass 3: Recursive deep-dive validation...")
        for i, f in enumerate(findings):
            if f.get("ai_struct", {}).get("needs_deeper_analysis"):
                findings[i] = recursive_validate(f, findings, depth=0)

        if ctx.verbose:
            print("[AI] Generating PoCs for confirmed vulnerabilities...")
        for i, f in enumerate(findings):
            sast_sev          = f.get("sast_verdict", {}).get("severity", "")
            recursive_ok      = f.get("recursive_analysis", {}).get("confirmed", False)
            is_manifest       = f.get("type") == "manifest_vuln"
            if sast_sev in ("critical", "high") or recursive_ok or is_manifest:
                findings[i] = generate_poc(f)

    def is_valid_finding(f):
        if f.get("exploit_level") == "highly_exploitable":
            return True
        if f.get("type") in ("secret", "jwt") and f.get("classification") != "low_value":
            return True
        rule_id = f.get("rule_id", "")
        if rule_id.startswith("CODE-00") or rule_id.startswith("CODE-01") or rule_id in ("CODE-025", "CODE-026", "CODE-060"):
            return True
        return False

    # --------------------------
    # FILTER Phase 1 results
    # --------------------------
    if ctx.use_ai:
        phase1_final = [
            f for f in findings
            if not f.get("batch_false_positive")
            and is_valid_finding(f)
        ]
    else:
        phase1_final = [
            f for f in findings
            if is_valid_finding(f)
        ]

    # ==================================================================
    # PHASE 2 — STATIC CODE ANALYSIS (decompiled APK)
    # ==================================================================

    code_findings = []

    if ctx.apk_dir:

        if ctx.verbose:
            print(f"[CODE] Scanning decompiled APK: {ctx.apk_dir}")

        # Collect source files
        code_items = apk_code_collector.collect(ctx.apk_dir)

        if ctx.verbose:
            print(f"[CODE] Files collected: {len(code_items)}")

        # Apply SAST rules
        raw_code_findings = []
        for item in code_items:
            res = code_analyzer.analyze(item)
            if res:
                if isinstance(res, list):
                    raw_code_findings.extend(res)
                else:
                    raw_code_findings.append(res)

        if ctx.verbose:
            print(f"[CODE] Raw SAST findings: {len(raw_code_findings)}")

        # Exploitability scoring for code findings
        raw_code_findings = [evaluate_exploitability(f) for f in raw_code_findings]

        # Manual PoC
        for f in raw_code_findings:
            f["manual_poc"] = generate_manual_poc(f)

        # AI batch analysis for code findings
        if ctx.use_ai and raw_code_findings:
            if ctx.verbose:
                print("[AI] Code analysis: batch SAST validation...")
            raw_code_findings = batch_analyze_code(raw_code_findings)

        # Filter: strictly show valid exploitable issues or info leakage
        code_findings = [
            f for f in raw_code_findings
            if is_valid_finding(f)
            and not f.get("code_false_positive")
        ]

    # ==================================================================
    # STORE findings on context (used by HTML report after engine returns)
    # ==================================================================
    ctx.phase1_findings = phase1_final
    ctx.code_findings   = code_findings

    # ==================================================================
    # OUTPUT — both phases
    # ==================================================================
    ctx.output.render(phase1_final, code_findings=code_findings)
