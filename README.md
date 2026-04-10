# 🥷 sensiAPK

<p align="center">
  <b>Advanced Android Security Analysis & Sensitive Data Discovery Tool</b>
</p>

---

<p align="center">
      ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⠀⠀⠀⣀⣤⣶⣶⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⣾⣿⣿⡿⠟⠛⠛⠻⢿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⣿⣿⡏⠀⠀⠀⠀⠀⠀⢹⣿⣿⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⣿⣿⡇⠀⠘⠿⠿⠇⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⢿⣿⣧⠀⠀⠀⠀⠀⠀⣼⣿⡿⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⠀⠻⢿⣷⣶⣤⣤⣶⡾⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀
      ⠀⠀⠀⠀⠀⠀⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
</p>

<p align="center">
  <b>sensiAPK</b>
</p>

---

## 🔍 Overview

**sensiAPK** is a powerful tool designed for **Android APK security analysis**, focusing on identifying:

- Sensitive data exposure  
- Hardcoded secrets  
- Misconfigurations  
- Security weaknesses in decompiled code  

Built for **penetration testers, security researchers, and red teamers**, it automates tedious manual analysis and enhances efficiency.

---

## ⚡ Features

### 🔎 Deep Static Analysis
- Scans **smali & source code**
- Detects **sensitive strings, keys, tokens**

### 🧠 AI-Assisted Detection
- Identifies:
  - Security checks  
  - Detection logic  
  - Weak implementations  

### 🔐 Sensitive Data Discovery
- API keys  
- Tokens  
- Credentials  
- Firebase configs  

### 🧩 Modular Design
- Easily extendable  
- Plug-and-play modules  

---

## 🛠️ Installation

```bash
git clone https://github.com/yourusername/sensiAPK.git
cd sensiAPK
pip install -r requirements.txt

# 🚀 Usage

## 🔹 Basic Scan
Run a standard scan on a target application:

```bash
python main.py -p com.target.app

### AI Enhanced
```bash
python main.py -p com.target.app --ai

### Interactive Mode
```bash
Interactive Mode

### Help
```bash
python main.py -h

### Detailed Help
```bash
python main.py --help-all

## Setup
```bash
pip install -r requirements.txt

### Linux/Mac
```bash
export OPENAI_API_KEY=your_api_key

### Windows
```bash
setx OPENAI_API_KEY your_api_key


### Connect Device
```bash
adb devices
adb root






