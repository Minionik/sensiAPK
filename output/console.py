RED="\033[91m";GREEN="\033[92m";YELLOW="\033[93m"
BLUE="\033[94m";CYAN="\033[96m";MAGENTA="\033[95m";NC="\033[0m"


def section(title):
    print(f"\n{MAGENTA}=== {title} ==={NC}\n")


def render(findings):

    # ===============================
    # 1. SCAN COVERAGE
    # ===============================
    section("SCAN COVERAGE")

    print(f"{BLUE}[*] Data Sources Tested:{NC}")
    print("  - Shared Preferences")
    print("  - Databases (SQLite)")
    print("  - Application Files")
    print("  - WebView Storage")
    print("  - AndroidManifest.xml")

    print(f"\n{BLUE}[*] Analysis Performed:{NC}")
    print("  - Secret detection (tokens, API keys, passwords)")
    print("  - JWT extraction and decoding")
    print("  - Base64 decoding")
    print("  - Entropy analysis")
    print("  - Token reuse detection")
    print("  - File sensitivity classification")
    print("  - Exploitability scoring")
    print("  - Manifest vulnerability checks")
    print("  - Manual PoC generation")
    print("  - AI-assisted reasoning (optional)")

    # ===============================
    # 2. NO FINDINGS
    # ===============================
    if not findings:
        section("RESULT")

        print(f"{GREEN}[✓] No exploitable sensitive data identified{NC}")

        print(f"\n{YELLOW}[*] Interpretation:{NC}")
        print("  - No high-value secrets detected")
        print("  - No exploitable tokens found")
        print("  - No insecure manifest exposure detected")

        print(f"\n{YELLOW}[*] Limitations:{NC}")
        print("  - Encrypted or runtime-only data is not visible")
        print("  - Dynamic protections not evaluated")

        print(f"\n{GREEN}[✓] Scan Completed{NC}")
        return

    # ===============================
    # 3. SUMMARY
    # ===============================
    section("SUMMARY")

    total = len(findings)
    high = sum(1 for f in findings if f.get("exploit_level") == "highly_exploitable")
    medium = sum(1 for f in findings if f.get("exploit_level") == "potentially_exploitable")

    print(f"{BLUE}[*] Total Findings:{NC} {total}")
    print(f"{RED}[*] Highly Exploitable:{NC} {high}")
    print(f"{YELLOW}[*] Potentially Exploitable:{NC} {medium}")

    # ===============================
    # 4. DETAILED FINDINGS
    # ===============================
    section("DETAILED FINDINGS")

    for i, f in enumerate(findings, 1):

        print(f"{MAGENTA}[{i}] Finding{NC}")

        # ---------------------------
        # BASIC INFO
        # ---------------------------
        print(f"{BLUE}Type:{NC} {f.get('type')}")
        print(f"{BLUE}Source:{NC} {f.get('source')}")

        if f.get("path"):
            print(f"{BLUE}Path:{NC} {f.get('path')}")
        elif f.get("file"):
            print(f"{BLUE}File:{NC} {f.get('file')}")
        else:
            print(f"{RED}File: Unknown{NC}")

        val = f.get("value", "")
        if val:
            print(f"{BLUE}Value:{NC} {val[:100]}{'...' if len(val)>100 else ''}")

        if f.get("line"):
            print(f"{BLUE}Context:{NC} {f.get('line')[:150]}")

        # ---------------------------
        # INTELLIGENCE (CORE)
        # ---------------------------
        print(f"\n{CYAN}--- Intelligence ---{NC}")

        print(f"Exploit Score: {f.get('exploit_score')}")
        print(f"Exploit Level: {f.get('exploit_level')}")

        if f.get("file_tags"):
            print(f"File Tags: {', '.join(f['file_tags'])}")

        if f.get("exploit_reasons"):
            print("Why exploitable:")
            for r in f["exploit_reasons"]:
                print(f"  - {r}")

        # ---------------------------
        # TECHNICAL DETAILS
        # ---------------------------
        print(f"\n{CYAN}--- Technical Details ---{NC}")

        print(f"Entropy: {f.get('entropy',0)}")
        print(f"Length: {f.get('length',0)}")

        if f.get("classification"):
            print(f"Classification: {f.get('classification')}")

        if f.get("related"):
            print(f"Reuse Count: {f.get('related')}")

        if f.get("validation"):
            print("\nValidation Signals:")
            for v in f["validation"]:
                print(f"  - {v}")

        if f.get("decoded"):
            print("\nDecoded Value:")
            print(f"  {f['decoded'][:150]}")

        if f.get("payload"):
            print("\nJWT Payload:")
            print(f"  {f['payload']}")

        # ---------------------------
        # MANIFEST ISSUES
        # ---------------------------
        if f.get("type") == "manifest_vuln":
            print(f"\n{RED}[MANIFEST ISSUE]{NC}")
            print(f"Issue: {f.get('issue')}")
            print(f"Component: {f.get('component')}")
            print(f"Name: {f.get('name')}")

        # ---------------------------
        # MANUAL PoC (CRITICAL)
        # ---------------------------
        if f.get("manual_poc"):
            print(f"\n{CYAN}[MANUAL VERIFICATION]{NC}")
            print("Run this command:")
            print(f"{YELLOW}{f['manual_poc']}{NC}")

        # ---------------------------
        # AI ANALYSIS (OPTIONAL)
        # ---------------------------
        ai = f.get("ai_struct")

        if ai:
            print(f"\n{MAGENTA}[AI ANALYSIS]{NC}")
            print(f"Risk: {ai.get('risk')}")
            print(f"Valid: {ai.get('valid')}")
            print(f"Reason: {ai.get('reason')}")

            if ai.get("next_actions"):
                print("Next Steps:")
                for n in ai["next_actions"]:
                    print(f"  - {n}")

        # ---------------------------
        # AI PoC
        # ---------------------------
        if f.get("poc"):
            print(f"\n{YELLOW}[AI GENERATED POC]{NC}")
            print(f"Command: {f['poc'].get('poc')}")

            print("Steps:")
            for s in f["poc"].get("steps", []):
                print(f"  - {s}")

            print(f"Impact: {f['poc'].get('impact')}")

        print("\n" + "-"*70)

    # ===============================
    # 5. FINAL VERDICT
    # ===============================
    section("FINAL VERDICT")

    if high > 0:
        print(f"{RED}[!] Highly exploitable vulnerabilities found{NC}")
        print("Immediate action required")
    elif medium > 0:
        print(f"{YELLOW}[!] Potentially exploitable findings found{NC}")
        print("Manual verification recommended")
    else:
        print(f"{GREEN}[✓] No critical exploitation paths identified{NC}")

    print(f"\n{GREEN}[✓] Scan Completed{NC}")