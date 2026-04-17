import argparse
import os
import subprocess
import sys
from datetime import datetime

from core.context import Context
from core.engine import run_engine

from collectors import shared_prefs, database, files, webview
from analyzers import secrets, jwt
from correlators import linker
from output import console
from output import report as html_report

from collectors import manifest
from analyzers import manifest as manifest_analyzer
from analyzers import permissions as permissions_analyzer


def root():
    subprocess.run("adb root", shell=True)
    subprocess.run("adb wait-for-device", shell=True)

    if "uid=0" not in subprocess.getoutput("adb shell id"):
        print("[ERROR] ADB root required")
        sys.exit(1)


def banner():
    print("\n=== sensiAPK v3.0 (Recursive AI SAST) ===\n")


def detailed_help():
    print("""
================= sensiAPK - Advanced Help =================

DESCRIPTION:
  sensiAPK extracts and analyzes sensitive data from Android apps
  using a multi-stage SAST pipeline with optional AI-powered
  recursive vulnerability validation.

USAGE:
  python main.py -p <package_name> [options]

OPTIONS:
  -p, --package     Target package name (required if not prompted)
  --apk-dir         Path to decompiled APK folder (Jadx/Apktool output)
                    Enables Phase 2: Static code analysis (SAST)
  --ai              Enable 3-pass AI recursive SAST analysis
  --no-root         Skip adb root check (not recommended)
  --verbose         Show debug-level output including AI pass progress
  --help            Show this detailed help

EXAMPLES:
  python main.py -p com.example.app
  python main.py -p com.example.app --ai --verbose
  python main.py -p com.example.app --apk-dir /path/to/jadx-output --ai
  python main.py --ai   (will prompt for package)

WORKFLOW:

  PHASE 1 — Runtime Data Analysis (requires rooted device):
  ──────────────────────────────────────────────────────────
  1. Collect from device:
     - Shared Preferences
     - Databases (SQLite)
     - Application Files (.json, .xml, .log, .properties, .env ...)
     - WebView storage (cookies, localStorage)
     - AndroidManifest.xml (permissions, components, flags)

  2. Analyze:
     - Secrets: AWS/Firebase/GitHub/Stripe/Twilio/generic tokens
     - JWT tokens (decode + expiry check)
     - Manifest vulnerabilities:
       · debuggable, allowBackup, testOnly
       · usesCleartextTraffic, missing networkSecurityConfig
       · Exported components without permission guard
       · Deep link hijacking risks
       · Low minSdkVersion / targetSdkVersion
     - Dangerous permissions (READ_SMS, CAMERA, SYSTEM_ALERT_WINDOW ...)
     - Dangerous permission combos (READ_SMS + INTERNET = OTP exfil)

  3. Enrich & Correlate:
     - Base64 decoding + entropy scoring
     - Token reuse detection across sources
     - File sensitivity classification
     - Exploitability scoring

  4. AI Recursive SAST (--ai):
     Pass 1 — Individual: OWASP/CWE mapping, FP detection, confidence score
     Pass 2 — Batch: attack chains, contextual FP removal, severity verdict
     Pass 3 — Recursive: deep-dive on flagged findings (max depth 2)
     PoC   — AI-generated exploit steps with CVSS estimate

  PHASE 2 — Static Code Analysis (--apk-dir):
  ─────────────────────────────────────────────
  Runs 30+ SAST rules across Java/Kotlin/Smali/XML source files:
  - Hardcoded secrets (AWS, Firebase, GitHub, Stripe, Twilio, generic)
  - Weak/broken crypto (MD5, SHA-1, DES, ECB mode, insecure Random)
  - SSL/TLS bypass (custom TrustManager, disabled HostnameVerifier)
  - WebView XSS surface (JS enabled, file access, addJavascriptInterface)
  - SQL injection (raw query string concatenation)
  - Sensitive data logging (Log.d/v/i with tokens/passwords)
  - Insecure file permissions (MODE_WORLD_READABLE/WRITABLE)
  - Intent security (PendingIntent, implicit broadcast, sticky broadcast)
  - Dynamic code loading (DexClassLoader, PathClassLoader)
  - Object deserialization, path traversal, ZipSlip
  - AI batch analysis of all code findings for chaining and FP removal

REQUIREMENTS:
  - Rooted device/emulator with ADB access (for Phase 1)
  - Decompiled APK folder via Jadx or Apktool (for --apk-dir)
  - sqlite3 installed
  - ANTHROPIC_API_KEY environment variable set (for --ai)

COMMON ISSUES:
  - "ADB root required"  → device not rooted
  - No findings          → app may use encryption or runtime-only storage
  - AI not working       → ANTHROPIC_API_KEY not set in environment
  - Code phase empty     → check --apk-dir points to decompiled sources

============================================================
""")


def parse_args():
    parser = argparse.ArgumentParser(
        description="sensiAPK - Sensitive Data Extractor & SAST Analyzer",
        add_help=True
    )

    parser.add_argument("-p", "--package",  help="Target package name")
    parser.add_argument("--apk-dir",        help="Path to decompiled APK folder (Jadx/Apktool)")
    parser.add_argument("--ai",             action="store_true", help="Enable AI analysis")
    parser.add_argument("--no-root",        action="store_true", help="Skip root check")
    parser.add_argument("--verbose",        action="store_true", help="Verbose output")
    parser.add_argument("--help-all",       action="store_true", help="Show detailed help")

    args = parser.parse_args()

    if args.help_all:
        detailed_help()
        sys.exit(0)

    return args


def main():
    banner()

    args = parse_args()

    if not args.no_root:
        root()

    pkg = args.package or input("Package: ").strip()

    if not pkg:
        print("[ERROR] Package name required")
        sys.exit(1)

    # ------------------------------------------------------------------
    # APK directory (Phase 2 — code analysis)
    # ------------------------------------------------------------------
    apk_dir = args.apk_dir

    if not apk_dir:
        apk_dir_input = input(
            "Decompiled APK folder (Jadx/Apktool output) [Enter to skip]: "
        ).strip()
        apk_dir = apk_dir_input if apk_dir_input else None

    if apk_dir and not os.path.isdir(apk_dir):
        print(f"[WARN] --apk-dir '{apk_dir}' is not a valid directory — skipping code analysis")
        apk_dir = None

    # ------------------------------------------------------------------
    # Build context
    # ------------------------------------------------------------------
    base = f"/data/data/{pkg}"

    ctx         = Context(base)
    ctx.package = pkg          # stored for the HTML report
    ctx.use_ai  = args.ai
    ctx.verbose = args.verbose
    ctx.apk_dir = apk_dir

    ctx.collectors = [
        shared_prefs,
        database,
        files,
        webview,
        manifest,
    ]

    ctx.analyzers = [
        secrets,
        jwt,
        manifest_analyzer,
        permissions_analyzer,
    ]

    ctx.correlator = linker.correlate
    ctx.output     = console

    run_engine(ctx)

    # ------------------------------------------------------------------
    # HTML REPORT (prompt after scan)
    # ------------------------------------------------------------------
    try:
        gen = input("\nGenerate HTML report? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        gen = "n"

    if gen in ("", "y", "yes"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default   = f"sensiapk_{pkg}_{timestamp}.html"

        try:
            path_input = input(f"Report path [{default}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            path_input = ""

        report_path = path_input if path_input else default

        print(f"\n[*] Generating report → {report_path}")
        ok = html_report.generate(ctx, report_path)
        if ok:
            abs_path = os.path.abspath(report_path)
            print(f"[✓] Report saved: {abs_path}")
        else:
            print("[ERROR] Report generation failed.")


if __name__ == "__main__":
    main()
