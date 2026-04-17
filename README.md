<h1 align="center">
  <br>
  🕵️‍♂️ sensiAPK
  <br>
</h1>

<h4 align="center">Advanced Runtime & Static AI-Powered Android Security Analyzer</h4>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#disclaimer">Disclaimer</a>
</p>

---

## ⚡ Overview

**sensiAPK** is a sophisticated, dual-phase Android application security tool. It combines **runtime data extraction** (via ADB) with **static source code analysis** (SAST), layered underneath a brutal strict-filtering engine designed to permanently destroy false-positives.

Unlike standard noisy SAST scanners, sensiAPK utilizes a dedicated logic filter mapped to **OWASP Mobile Top 10** to guarantee that it only outputs:
1. **Highly Exploitable Issues:** (RCE, Universal File Access, SSL Bypasses)
2. **Definitive Information Leaks:** (Hardcoded AWS/Stripe Keys, JWT exposures, and explicit Tokens)

By integrating an optional **3-Pass AI Recursive Engine** powered by Anthropic's Claude, `sensiAPK` can dynamically perform deep-dive validation of potential exploitation chains and provide precise, context-aware Proof of Concepts (PoCs).

---

## 🔥 Features

* **Zero-Noise Filtering:** Aggressively drops unexploitable `MODE_WORLD_READABLE` or random `allowBackup=true` spam in favor of strict, exploit-level reporting.
* **Smart Secret Detection:** Uses high-entropy classification to parse Android SharedPreferences, SQLite databases, Application Files, and raw `.smali`/`.java`/`.kt` files for active credentials.
* **Manifest & Permission Correlation:** Detects dangerous permission combinations (e.g., `READ_SMS` + `INTERNET` = OTP exfiltration).
* **AI False-Positive Purging (--ai):**
  * *Pass 1:* Classifies finding true-positives via context heuristics.
  * *Pass 2:* Batch cross-correlation to find multi-step UI/Intent attack chains.
  * *Pass 3:* Generates a CVSS estimate and exact ADB Proof of Concept.
* **HTML Report Generation:** Produces clean, actionable HTML files containing the final filtered payload of vulnerabilities.

---

## 🛠️ How It Works

### Phase 1: Runtime Context Analysis 
Connect a rooted Android device or emulator. sensiAPK will actively pull data via ADB directly from `/data/data/<package_name>`, analyzing live `SharedPreferences`, WebView storage databases, and active cached `.xml`/`.env` files for runtime leaks that static tools traditionally miss.

### Phase 2: Static Source Analysis
Point sensiAPK to a decompiled application folder (via standard tools like `jadx` or `apktool`). The tool will evaluate the raw static properties, dynamically limiting logic on `.smali` files exclusively to information-leak checks to bypass decompilation instruction spam.

---

## ⚙️ Installation

**Requirements:**
- Python 3.10+
- Rooted Android device/emulator (with ADB enabled and authorized)
- SQLite3
- *Optional:* `jadx` or `apktool` for Phase 2 code analysis
- *Optional:* `ANTHROPIC_API_KEY` for AI features

1. Clone the repository:
```bash
git clone https://github.com/Minionik/sensiAPK.git
cd sensiAPK
```

2. Install the necessary dependencies (if required):
```bash
pip install -r requirements.txt
```

3. Configure your AI Key (Optional but recommended):
```powershell
# On Windows
$env:ANTHROPIC_API_KEY="your-api-key-here"

# On Linux/macOS
export ANTHROPIC_API_KEY="your-api-key-here"
```

---

## 🚀 Usage

Ensure your device is connected (`adb devices`) and run:

### Basic Runtime Analysis
Pull and scan active memory/disk data from a running application package:
```bash
python main.py -p com.example.vulnerableapp
```

### Full SAST + Runtime Pipeline with AI
Combine live ADB disk scraping with static code analysis, augmented by Claude AI to eliminate false positives:
```bash
python main.py -p com.example.vulnerableapp --apk-dir /path/to/jadx_output --ai
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-p`, `--package` | The target Android package name (e.g., `com.whatsapp`) |
| `--apk-dir` | Path to the decompiled APK folder (enables Phase 2 SAST) |
| `--ai` | Enables the 3-pass AI recursive vulnerability validation |
| `--no-root` | Skips the ADB root check (not recommended, misses data) |
| `--verbose` | Shows debug-level output and AI pass progress |
| `--help-all` | Shows detailed tool and pipeline architecture help |

---

## 🛡️ Disclaimer

**sensiAPK** is designed explicitly for authorized security researchers, penetration testers, and developers to analyze applications they own or have explicit, documented permission to audit. The authors and contributors are not responsible for the misuse of this tool in unauthorized environments. Do not engage in illegal software exploitation.
