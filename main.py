import argparse
import subprocess
import sys

from core.context import Context
from core.engine import run_engine

from collectors import shared_prefs, database, files, webview
from analyzers import secrets, jwt
from correlators import linker
from output import console

from collectors import manifest
from analyzers import manifest as manifest_analyzer


def root():
    subprocess.run("adb root", shell=True)
    subprocess.run("adb wait-for-device", shell=True)

    if "uid=0" not in subprocess.getoutput("adb shell id"):
        print("[ERROR] ADB root required")
        sys.exit(1)


def banner():
    print("\n=== sensiAPK v2.0 (AI-Enhanced) ===\n")


def detailed_help():
    print("""
================= sensiAPK - Advanced Help =================

DESCRIPTION:
  sensiAPK extracts and analyzes sensitive data from Android apps.

USAGE:
  python main.py -p <package_name> [options]

OPTIONS:
  -p, --package     Target package name (required if not prompted)
  --ai              Enable AI-powered analysis (recommended)
  --no-root         Skip adb root check (not recommended)
  --verbose         Show debug-level output
  --help            Show this detailed help

EXAMPLES:
  python main.py -p com.example.app
  python main.py -p com.example.app --ai
  python main.py --ai (will prompt for package)

WORKFLOW:
  1. Collect data from:
     - Shared Preferences
     - Databases
     - Files
     - WebView storage

  2. Analyze:
     - Secrets (tokens, keys, passwords)
     - JWT tokens

  3. Enrich:
     - Decode Base64
     - Calculate entropy
     - Classify token types

  4. Correlate:
     - Detect reused tokens
     - Link across sources

  5. Validate:
     - Expiry checks
     - Entropy scoring
     - Confidence scoring

  6. AI (optional):
     - Risk analysis
     - False positive reduction
     - Suggested next steps

REQUIREMENTS:
  - Rooted device/emulator
  - adb working
  - sqlite3 installed
  - OPENAI_API_KEY set (for AI)

COMMON ISSUES:
  - "ADB root required" → device not rooted
  - No findings → app may not store plaintext data
  - AI not working → API key not set

============================================================
""")


def parse_args():
    parser = argparse.ArgumentParser(
        description="sensiAPK - Sensitive Data Extractor",
        add_help=True  # keeps -h basic help
    )

    parser.add_argument("-p", "--package", help="Target package name")
    parser.add_argument("--ai", action="store_true", help="Enable AI analysis")
    parser.add_argument("--no-root", action="store_true", help="Skip root check")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--help-all", action="store_true", help="Show detailed help")

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

    base = f"/data/data/{pkg}"

    ctx = Context(base)
    ctx.use_ai = args.ai
    ctx.verbose = args.verbose

    # Modules
    ctx.collectors = [
    shared_prefs,
    database,
    files,
    webview,
    manifest   # ← ADD
    ]

    ctx.analyzers = [
    secrets,
    jwt,
    manifest_analyzer   # ← ADD
    ]

    ctx.correlator = linker.correlate
    ctx.output = console

    run_engine(ctx)


if __name__ == "__main__":
    main()