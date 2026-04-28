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
  <a href="#ai-providers">AI Providers</a> •
  <a href="#usage">Usage</a> •
  <a href="#disclaimer">Disclaimer</a>
</p>

---

## ⚡ Overview

**sensiAPK** is a sophisticated, dual-phase Android application security tool. It combines **runtime data extraction** (via ADB) with **static source code analysis** (SAST), layered underneath a brutal strict-filtering engine designed to permanently destroy false-positives.

Unlike standard noisy SAST scanners, sensiAPK utilizes a dedicated logic filter mapped to **OWASP Mobile Top 10** to guarantee that it only outputs:
1. **Highly Exploitable Issues:** (RCE, Universal File Access, SSL Bypasses)
2. **Definitive Information Leaks:** (Hardcoded AWS/Stripe Keys, JWT exposures, and explicit Tokens)

By integrating an optional **3-Pass AI Recursive Engine**, `sensiAPK` can dynamically perform deep-dive validation of potential exploitation chains and provide precise, context-aware Proof of Concepts (PoCs). Supports **Anthropic Claude, OpenAI GPT, xAI Grok, and local Ollama** models.

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
- *Optional:* An API key for your chosen AI provider (see [AI Providers](#ai-providers))

1. Clone the repository:
```bash
git clone https://github.com/Minionik/sensiAPK.git
cd sensiAPK
```

2. Create and activate a Python virtual environment to avoid conflicts (Recommended):
```powershell
# On Windows
python -m venv venv
.\venv\Scripts\activate

# On Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

3. Install the necessary dependencies:
```bash
pip install -r requirements.txt
```

4. Configure your AI provider key (see [AI Providers](#ai-providers) for all options):
```powershell
# Anthropic — Windows
$env:ANTHROPIC_API_KEY="your-key-here"

# Anthropic — Linux/macOS
export ANTHROPIC_API_KEY="your-key-here"
```

---

## 🤖 AI Providers

sensiAPK supports four AI backends for the `--ai` pipeline. The provider is **auto-detected** from whichever API key is set in your environment, or you can force one with `--provider`.

**Priority order (auto-detect):** Anthropic → OpenAI → Grok → Ollama

---

### 1. Anthropic Claude (default)

Best accuracy for security reasoning. Requires an [Anthropic API key](https://console.anthropic.com/).

```powershell
# Windows
$env:ANTHROPIC_API_KEY="sk-ant-..."

# Linux/macOS
export ANTHROPIC_API_KEY="sk-ant-..."
```

```bash
python main.py -p com.example.app --ai
python main.py -p com.example.app --ai --provider anthropic --model claude-3-5-sonnet-20241022
```

| Default Model | Alternatives |
|---|---|
| `claude-3-5-sonnet-20241022` | `claude-3-opus-20240229`, `claude-3-haiku-20240307` |

---

### 2. OpenAI GPT

Requires an [OpenAI API key](https://platform.openai.com/api-keys).

```powershell
# Windows
$env:OPENAI_API_KEY="sk-..."

# Linux/macOS
export OPENAI_API_KEY="sk-..."
```

```bash
python main.py -p com.example.app --ai --provider openai
python main.py -p com.example.app --ai --provider openai --model gpt-4-turbo
```

| Default Model | Alternatives |
|---|---|
| `gpt-4o` | `gpt-4-turbo`, `gpt-4`, `gpt-3.5-turbo` |

---

### 3. xAI Grok

Requires an [xAI API key](https://console.x.ai/). Uses an OpenAI-compatible endpoint.

```powershell
# Windows
$env:XAI_API_KEY="xai-..."

# Linux/macOS
export XAI_API_KEY="xai-..."
```

```bash
python main.py -p com.example.app --ai --provider grok
python main.py -p com.example.app --ai --provider grok --model grok-2-latest
```

| Default Model | Alternatives |
|---|---|
| `grok-2-latest` | `grok-beta`, `grok-2` |

---

### 4. Ollama (Local — No API Key Required)

Run AI analysis entirely offline using a local [Ollama](https://ollama.com/) server. No API key needed.

**Setup:**
```bash
# 1. Install Ollama from https://ollama.com/
# 2. Pull a model
ollama pull llama3
ollama pull mistral
ollama pull qwen2.5

# 3. Start the server (runs on http://localhost:11434 by default)
ollama serve
```

```bash
# Use default host (localhost:11434)
python main.py -p com.example.app --ai --provider ollama --model llama3

# Use a remote Ollama server
python main.py -p com.example.app --ai --provider ollama --model mistral --ollama-host http://192.168.1.5:11434
```

| Default Model | Recommended Security Models |
|---|---|
| `llama3` | `mistral`, `qwen2.5`, `deepseek-r1`, `llama3.1` |

> **Note:** Larger models (7B+) produce significantly better security analysis. Results may vary compared to cloud providers.

---

### Provider Quick Reference

| Provider | Env Variable | Default Model | Requires Key |
|----------|-------------|---------------|-------------|
| `anthropic` | `ANTHROPIC_API_KEY` | `claude-3-5-sonnet-20241022` | Yes |
| `openai` | `OPENAI_API_KEY` | `gpt-4o` | Yes |
| `grok` | `XAI_API_KEY` | `grok-2-latest` | Yes |
| `ollama` | *(none)* | `llama3` | No |

---

## 🚀 Usage

Ensure your device is connected (`adb devices`) and run:

### Basic Runtime Analysis
Pull and scan active memory/disk data from a running application package:
```bash
python main.py -p com.example.vulnerableapp
```

### Full SAST + Runtime Pipeline with AI
Combine live ADB disk scraping with static code analysis, augmented by AI to eliminate false positives:
```bash
# Auto-detect provider from environment keys
python main.py -p com.example.vulnerableapp --apk-dir /path/to/jadx_output --ai

# Force a specific provider and model
python main.py -p com.example.vulnerableapp --apk-dir /path/to/jadx_output --ai --provider openai --model gpt-4o

# Run fully offline with Ollama
python main.py -p com.example.vulnerableapp --ai --provider ollama --model mistral
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-p`, `--package` | The target Android package name (e.g., `com.whatsapp`) |
| `--apk-dir` | Path to the decompiled APK folder (enables Phase 2 SAST) |
| `--ai` | Enables the 3-pass AI recursive vulnerability validation |
| `--provider` | AI backend: `anthropic`, `openai`, `ollama`, `grok` (auto-detected if omitted) |
| `--model` | Override the default model (e.g. `gpt-4-turbo`, `llama3`, `grok-2-latest`) |
| `--ollama-host` | Custom Ollama server URL (default: `http://localhost:11434`) |
| `--no-root` | Skips the ADB root check (not recommended, misses data) |
| `--verbose` | Shows debug-level output and AI pass progress |
| `--help-all` | Shows detailed tool and pipeline architecture help |

---

## 🛡️ Disclaimer

**sensiAPK** is designed explicitly for authorized security researchers, penetration testers, and developers to analyze applications they own or have explicit, documented permission to audit. The authors and contributors are not responsible for the misuse of this tool in unauthorized environments. Do not engage in illegal software exploitation.
