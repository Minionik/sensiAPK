RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
NC      = "\033[0m"

SEV_COLOR = {
    "critical": RED,
    "high":     RED,
    "medium":   YELLOW,
    "low":      BLUE,
}


def section(title):
    print(f"\n{MAGENTA}{BOLD}=== {title} ==={NC}\n")


def _sev_badge(severity):
    c = SEV_COLOR.get((severity or "").lower(), BLUE)
    return f"{c}{BOLD}[{severity.upper()}]{NC}"


def render(findings, code_findings=None):
    code_findings = code_findings or []

    # ===============================
    # 1. SCAN COVERAGE
    # ===============================
    section("SCAN COVERAGE")

    print(f"{BLUE}[*] Phase 1 — Runtime Data Sources:{NC}")
    print("  - Shared Preferences")
    print("  - Databases (SQLite)")
    print("  - Application Files (.json .xml .log .properties .env .yaml ...)")
    print("  - WebView Storage (cookies)")
    print("  - AndroidManifest.xml (components, permissions, flags)")

    print(f"\n{BLUE}[*] Phase 1 — Analysis:{NC}")
    print("  - Secret detection (AWS, Firebase, GitHub, Stripe, Twilio, generic)")
    print("  - JWT extraction and decoding")
    print("  - Manifest: debuggable, backup, cleartext, network security config")
    print("  - Manifest: exported components, missing permission guard, deep links")
    print("  - Manifest: minSdkVersion / targetSdkVersion checks")
    print("  - Dangerous permissions + combo detection")
    print("  - Base64 decoding + entropy analysis")
    print("  - Token reuse & cross-source correlation")
    print("  - Exploitability scoring")

    if code_findings:
        print(f"\n{BLUE}[*] Phase 2 — Static Code Analysis:{NC}")
        print("  - 30+ SAST rules (crypto, SSL, WebView, SQLi, secrets, intent security ...)")
        print("  - AI compound chain detection")
        print("  - False positive filtering")

    print(f"\n{BLUE}[*] AI Pipeline (if --ai):{NC}")
    print("  - Pass 1: Individual SAST + OWASP/CWE mapping + confidence score")
    print("  - Pass 2: Batch cross-finding attack chains + FP removal")
    print("  - Pass 3: Recursive deep-dive (max depth 2)")
    print("  - AI PoC with CVSS estimate")

    # ===============================
    # 2. NO FINDINGS
    # ===============================
    if not findings and not code_findings:
        section("RESULT")
        print(f"{GREEN}[✓] No exploitable sensitive data identified{NC}")
        print(f"\n{YELLOW}[*] Limitations:{NC}")
        print("  - Encrypted or runtime-only data is not visible")
        print("  - Dynamic protections not evaluated")
        print(f"\n{GREEN}[✓] Scan Completed{NC}")
        return

    # ===============================
    # 3. SUMMARY
    # ===============================
    section("SUMMARY")

    p1_high   = sum(1 for f in findings      if f.get("exploit_level") == "highly_exploitable")
    p1_med    = sum(1 for f in findings      if f.get("exploit_level") == "potentially_exploitable")
    p2_crit   = sum(1 for f in code_findings if f.get("severity") in ("critical",))
    p2_high   = sum(1 for f in code_findings if f.get("severity") == "high")
    p2_med    = sum(1 for f in code_findings if f.get("severity") == "medium")

    print(f"{BLUE}Phase 1 — Runtime Findings:{NC}      {len(findings)}")
    print(f"  {RED}Highly Exploitable:{NC}            {p1_high}")
    print(f"  {YELLOW}Potentially Exploitable:{NC}       {p1_med}")

    if code_findings:
        print(f"\n{BLUE}Phase 2 — Code SAST Findings:{NC}    {len(code_findings)}")
        print(f"  {RED}Critical:{NC}                      {p2_crit}")
        print(f"  {RED}High:{NC}                          {p2_high}")
        print(f"  {YELLOW}Medium:{NC}                        {p2_med}")

    # Batch AI summary
    batch_summary = findings[0].get("batch_analysis_summary", {}) if findings else {}
    if batch_summary:
        risk   = batch_summary.get("overall_risk", "unknown").upper()
        rc     = SEV_COLOR.get(risk.lower(), YELLOW)
        chains = batch_summary.get("attack_chains_count", 0)
        print(f"\n{rc}[AI] Overall Runtime Risk: {risk}{NC}")
        if chains:
            print(f"{RED}[AI] Attack Chains Identified: {chains}{NC}")
        sumtext = batch_summary.get("key_findings_summary")
        if sumtext:
            print(f"{CYAN}[AI] Summary: {sumtext}{NC}")

    # ===============================
    # 4. PHASE 1 — DETAILED FINDINGS
    # ===============================
    if findings:
        section("PHASE 1 — RUNTIME FINDINGS")

        for i, f in enumerate(findings, 1):
            print(f"{MAGENTA}{BOLD}[P1-{i}] {f.get('type', 'finding')}{NC}")

            print(f"{BLUE}Source:{NC} {f.get('source')}")

            if f.get("path"):
                print(f"{BLUE}Path:{NC}   {f.get('path')}")
            elif f.get("file"):
                print(f"{BLUE}File:{NC}   {f.get('file')}")

            val = f.get("value", "")
            if val:
                print(f"{BLUE}Value:{NC}  {val[:100]}{'...' if len(val) > 100 else ''}")

            if f.get("line"):
                print(f"{BLUE}Context:{NC} {str(f.get('line'))[:150]}")

            # --- SAST verdict (AI Pass 1+2) ---
            ai   = f.get("ai_struct", {})
            sast = f.get("sast_verdict", {})

            if sast or ai:
                print(f"\n{CYAN}{BOLD}--- SAST Analysis ---{NC}")

                if sast:
                    sev = sast.get("severity", "")
                    print(f"{_sev_badge(sev)} {sast.get('summary', '')}")
                    if sast.get("cwe"):
                        print(f"CWE: {sast['cwe']}  OWASP: {sast.get('owasp', 'N/A')}")
                elif ai:
                    risk = ai.get("risk", "")
                    print(f"{_sev_badge(risk)} Confidence: {ai.get('confidence', 'N/A')}%  Valid: {ai.get('valid')}")
                    if ai.get("owasp_category"):
                        print(f"OWASP: {ai['owasp_category']} — {ai.get('owasp_name', '')}  |  CWE: {ai.get('cwe_id', 'N/A')}")
                    if ai.get("reason"):
                        print(f"Reason: {ai['reason']}")
                    if ai.get("false_positive_reason"):
                        print(f"{YELLOW}[FP Note] {ai['false_positive_reason']}{NC}")
                    if ai.get("next_actions"):
                        print("Next Actions:")
                        for n in ai["next_actions"]:
                            print(f"  → {n}")

            # --- Recursive Deep-Dive (Pass 3) ---
            rec = f.get("recursive_analysis", {})
            if rec:
                depth = f.get("recursive_depth", 1)
                cc    = RED if rec.get("confirmed") else YELLOW
                print(f"\n{CYAN}{BOLD}--- Recursive Analysis (depth {depth}) ---{NC}")
                print(f"{cc}Confirmed: {rec.get('confirmed')}  |  Final Risk: {(rec.get('final_risk') or 'N/A').upper()}{NC}")
                if rec.get("attack_scenario"):
                    print(f"Scenario: {rec['attack_scenario']}")
                if rec.get("evidence"):
                    print("Evidence:")
                    for e in rec["evidence"]:
                        print(f"  ✓ {e}")
                if rec.get("cwe_id"):
                    print(f"CWE: {rec['cwe_id']}  OWASP: {rec.get('owasp', 'N/A')}")
                if rec.get("remediation"):
                    print(f"{GREEN}Remediation: {rec['remediation']}{NC}")

            # --- Attack chains (Pass 2) ---
            chains = f.get("attack_chains", [])
            if chains:
                print(f"\n{RED}{BOLD}--- Attack Chains ---{NC}")
                for chain in chains:
                    cr = chain.get("combined_risk", "").upper()
                    print(f"  {_sev_badge(cr.lower())} {chain.get('chain_description')}")
                    owasps = ", ".join(chain.get("owasp_categories", []))
                    cwes   = ", ".join(chain.get("cwe_ids", []))
                    if owasps:
                        print(f"         OWASP: {owasps}  CWE: {cwes}")

            # --- Exploitability ---
            print(f"\n{CYAN}--- Exploitability ---{NC}")
            print(f"Score: {f.get('exploit_score')}  |  Level: {f.get('exploit_level')}")
            if f.get("exploit_reasons"):
                for r in f["exploit_reasons"]:
                    print(f"  - {r}")

            # --- Technical details ---
            print(f"\n{CYAN}--- Technical Details ---{NC}")
            print(f"Entropy: {f.get('entropy', 0)}  |  Length: {f.get('length', 0)}")
            if f.get("classification"):
                print(f"Classification: {f.get('classification')}")
            if f.get("validation"):
                for v in f["validation"]:
                    print(f"  - {v}")
            if f.get("decoded"):
                print(f"Decoded:\n  {f['decoded'][:150]}")
            if f.get("payload"):
                print(f"JWT Payload:\n  {f['payload']}")

            # --- Manifest specifics ---
            if f.get("type") == "manifest_vuln":
                print(f"\n{RED}[MANIFEST]{NC} {f.get('issue')}")
                if f.get("detail"):
                    print(f"  Detail:    {f['detail']}")
                if f.get("component"):
                    print(f"  Component: {f.get('component')} → {f.get('name')}")
                if f.get("deep_link"):
                    print(f"  Deep Link: {f.get('deep_link')}")
                if f.get("owasp"):
                    print(f"  OWASP: {f['owasp']}  CWE: {f.get('cwe', 'N/A')}")

            # --- Permission specifics ---
            if f.get("type") == "permission_vuln":
                print(f"\n{YELLOW}[PERMISSION]{NC} {f.get('permission')}")
                print(f"  {f.get('description')}")
                print(f"  OWASP: {f.get('owasp')}  CWE: {f.get('cwe', 'N/A')}")

            if f.get("type") == "permission_combo":
                print(f"\n{RED}[PERMISSION COMBO]{NC} {' + '.join(f.get('permissions', []))}")
                print(f"  {f.get('description')}")
                print(f"  OWASP: {f.get('owasp')}  CWE: {f.get('cwe', 'N/A')}")

            # --- Manual PoC ---
            if f.get("manual_poc"):
                print(f"\n{CYAN}[MANUAL PoC]{NC}")
                print(f"{YELLOW}{f['manual_poc']}{NC}")

            # --- AI PoC ---
            poc = f.get("poc", {})
            if poc and not poc.get("error"):
                print(f"\n{YELLOW}{BOLD}[AI PoC]{NC}")
                if poc.get("poc"):
                    print(f"  {poc['poc']}")
                if poc.get("steps"):
                    print("Steps:")
                    for s in poc["steps"]:
                        print(f"  {s}")
                if poc.get("impact"):
                    print(f"Impact: {poc['impact']}")
                if poc.get("cvss_estimate"):
                    print(f"CVSS:   {poc['cvss_estimate']}")

            print("\n" + "-" * 70)

    # ===============================
    # 5. PHASE 2 — CODE ANALYSIS
    # ===============================
    if code_findings:
        section("PHASE 2 — STATIC CODE ANALYSIS")

        for i, f in enumerate(code_findings, 1):
            sev = f.get("code_sast_severity") or f.get("severity", "low")
            print(f"{_sev_badge(sev)} {MAGENTA}{BOLD}[P2-{i}] {f.get('rule_id')} — {f.get('title')}{NC}")

            rel  = f.get("relative_path") or f.get("file", "unknown")
            ln   = f.get("line_number", "?")
            print(f"{BLUE}File:{NC}  {rel}:{ln}")
            print(f"{BLUE}Desc:{NC}  {f.get('description')}")

            if f.get("code_sast_summary"):
                print(f"{CYAN}AI:    {f['code_sast_summary']}{NC}")

            owasp = f.get("owasp", "N/A")
            cwe   = f.get("cwe", "N/A")
            print(f"OWASP: {owasp}  |  CWE: {cwe}")

            if f.get("line"):
                print(f"\nMatched line:")
                print(f"  {YELLOW}{f['line'][:200]}{NC}")

            if f.get("snippet"):
                print(f"\nContext:")
                print(f.get("snippet"))

            # Compound chains
            chains = f.get("code_chains", [])
            if chains:
                print(f"\n{RED}{BOLD}--- Compound Attack Chain ---{NC}")
                for ch in chains:
                    print(f"  {_sev_badge(ch.get('combined_severity', 'high'))} {ch.get('chain_description')}")
                    if ch.get("owasp"):
                        print(f"  OWASP: {ch['owasp']}  CWE: {ch.get('cwe', 'N/A')}")

            if f.get("manual_poc"):
                print(f"\n{CYAN}[PoC]{NC} {YELLOW}{f['manual_poc']}{NC}")

            if f.get("code_false_positive"):
                print(f"{YELLOW}[Dismissed by AI] {f.get('code_fp_reason')}{NC}")

            print("\n" + "-" * 70)

    # ===============================
    # 6. FINAL VERDICT
    # ===============================
    section("FINAL VERDICT")

    p1_high = sum(1 for f in findings      if f.get("exploit_level") == "highly_exploitable")
    p2_crit = sum(1 for f in code_findings if f.get("severity") in ("critical",))
    p2_high = sum(1 for f in code_findings if f.get("severity") == "high")

    if p1_high > 0 or p2_crit > 0:
        print(f"{RED}[!] Critical/highly exploitable vulnerabilities found — immediate action required{NC}")
    elif p2_high > 0:
        print(f"{RED}[!] High severity code vulnerabilities found — review before release{NC}")
    elif findings or code_findings:
        print(f"{YELLOW}[!] Potential findings — manual verification recommended{NC}")
    else:
        print(f"{GREEN}[✓] No critical exploitation paths identified{NC}")

    print(f"\n{GREEN}[✓] Scan Completed{NC}")
