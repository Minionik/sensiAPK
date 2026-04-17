import re

# ---------------------------------------------------------------------------
# SAST RULE FORMAT:
#   (rule_id, title, pattern, severity, description, owasp, cwe)
#
# severity: critical | high | medium | low
# owasp:    OWASP Mobile Top 10 2024 category (M1–M10)
# cwe:      CWE ID string
# ---------------------------------------------------------------------------

RULES = [

    # -----------------------------------------------------------------------
    # HARDCODED SECRETS & CREDENTIALS
    # -----------------------------------------------------------------------
    ("CODE-001", "Hardcoded Password",
     r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']',
     "high", "Password hardcoded in source — will be visible in decompiled APK", "M9", "CWE-259"),

    ("CODE-002", "Hardcoded API Key",
     r'(?i)(api_key|apikey|api[-_]secret|access_key|auth_key|client_secret)\s*[=:]\s*["\'][A-Za-z0-9+/\-_]{16,}["\']',
     "high", "API key hardcoded in source code", "M9", "CWE-798"),

    ("CODE-003", "AWS Access Key ID",
     r'AKIA[0-9A-Z]{16}',
     "critical", "AWS Access Key ID found in source — immediate credential revocation needed", "M9", "CWE-798"),

    ("CODE-004", "AWS Secret Access Key",
     r'(?i)aws.{0,30}["\'][A-Za-z0-9/+]{40}["\']',
     "critical", "Possible AWS Secret Access Key found", "M9", "CWE-798"),

    ("CODE-005", "Firebase / Google API Key",
     r'AIza[0-9A-Za-z\-_]{35}',
     "high", "Firebase/Google API key hardcoded", "M9", "CWE-798"),

    ("CODE-006", "Google OAuth Client Secret",
     r'GOCSPX-[A-Za-z0-9_\-]{28}',
     "critical", "Google OAuth client secret found — account takeover risk", "M9", "CWE-798"),

    ("CODE-007", "GitHub Personal Access Token",
     r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}',
     "critical", "GitHub Personal Access Token found in source", "M9", "CWE-798"),

    ("CODE-008", "Stripe Secret Key",
     r'sk_live_[0-9a-zA-Z]{24,}',
     "critical", "Stripe live secret key found — financial fraud risk", "M9", "CWE-798"),

    ("CODE-009", "Stripe Publishable Key",
     r'pk_live_[0-9a-zA-Z]{24,}',
     "medium", "Stripe live publishable key found", "M9", "CWE-798"),

    ("CODE-010", "Twilio Account SID / Auth Token",
     r'AC[0-9a-f]{32}|SK[0-9a-f]{32}',
     "high", "Twilio credential found — SMS abuse risk", "M9", "CWE-798"),

    ("CODE-011", "Hardcoded RSA/EC Private Key",
     r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
     "critical", "Private key hardcoded in source — full encryption/auth bypass", "M9", "CWE-321"),

    ("CODE-012", "Hardcoded Certificate",
     r'-----BEGIN CERTIFICATE-----',
     "medium", "Certificate hardcoded in source — review if it contains private data", "M9", "CWE-321"),

    ("CODE-013", "Slack Bot/App Token",
     r'xox[baprs]-[0-9A-Za-z\-]{10,}',
     "high", "Slack token found — workspace data exposure risk", "M9", "CWE-798"),

    ("CODE-014", "Hardcoded Bearer Token",
     r'(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}',
     "high", "Bearer token hardcoded in source", "M9", "CWE-798"),

    # -----------------------------------------------------------------------
    # WEAK / BROKEN CRYPTOGRAPHY
    # -----------------------------------------------------------------------
    ("CODE-020", "Weak Hash: MD5",
     r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']\s*\)',
     "medium", "MD5 is cryptographically broken — use SHA-256 or higher", "M10", "CWE-327"),

    ("CODE-021", "Weak Hash: SHA-1",
     r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']\s*\)',
     "medium", "SHA-1 is deprecated for security — use SHA-256", "M10", "CWE-327"),

    ("CODE-022", "Weak Cipher: DES / 3DES",
     r'Cipher\.getInstance\s*\(\s*["\']DES["\']|["\']DESede["\']',
     "high", "DES/3DES is insecure — use AES-256", "M10", "CWE-327"),

    ("CODE-023", "Insecure Cipher Mode: ECB",
     r'Cipher\.getInstance\s*\(\s*["\'][^"\']*\/ECB\/[^"\']*["\']\)',
     "high", "ECB mode leaks plaintext patterns — use AES/GCM/NoPadding", "M10", "CWE-327"),

    ("CODE-024", "Insecure Random (java.util.Random)",
     r'\bnew\s+Random\s*\(',
     "medium", "java.util.Random is not cryptographically secure — use SecureRandom", "M10", "CWE-338"),

    ("CODE-025", "Hardcoded IV / Salt",
     r'(?i)(static|final).*\b(iv|salt|nonce)\b.*=.*new\s+byte\s*\[',
     "high", "Static IV/salt defeats the purpose of encryption — derive dynamically", "M10", "CWE-329"),

    ("CODE-026", "Hardcoded Encryption Key",
     r'(?i)(static|final).*\b(key|aeskey|secretkey)\b.*=.*["\'][A-Za-z0-9+/=]{8,}["\']',
     "high", "Hardcoded encryption key found", "M10", "CWE-321"),

    # -----------------------------------------------------------------------
    # SSL / TLS SECURITY
    # -----------------------------------------------------------------------
    ("CODE-030", "TrustManager Trusts All Certificates",
     r'checkServerTrusted|checkClientTrusted|getAcceptedIssuers',
     "critical", "Custom TrustManager — may accept all certs including invalid ones (MITM)", "M5", "CWE-295"),

    ("CODE-031", "HostnameVerifier Disabled",
     r'ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|\.verify\s*\(.*\)\s*\{\s*return\s+true',
     "critical", "Hostname verification disabled — MITM attack possible", "M5", "CWE-297"),

    ("CODE-032", "SSL Error Ignored in WebView",
     r'onReceivedSslError.*handler\.proceed\(\)',
     "critical", "SSL errors ignored in WebView — any invalid cert accepted", "M5", "CWE-295"),

    ("CODE-033", "Cleartext HTTP URL",
     r'http://(?!localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.|0\.0\.0\.0)',
     "medium", "Cleartext HTTP URL — traffic unencrypted and interceptable", "M5", "CWE-319"),

    ("CODE-034", "Certificate Pinning Disabled",
     r'setHostnameVerifier|trustAllCerts|TrustAllCerts|NullTrustManager|EmptyTrustManager',
     "high", "Certificate pinning appears to be bypassed or disabled", "M5", "CWE-295"),

    # -----------------------------------------------------------------------
    # WEBVIEW SECURITY
    # -----------------------------------------------------------------------
    ("CODE-040", "WebView JavaScript Enabled",
     r'setJavaScriptEnabled\s*\(\s*true\s*\)',
     "high", "JavaScript enabled in WebView — XSS attack surface expanded", "M4", "CWE-79"),

    ("CODE-041", "WebView File Access Enabled",
     r'setAllowFileAccess\s*\(\s*true\s*\)|setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)',
     "high", "WebView file access enabled — cross-origin file read via XSS possible", "M1", "CWE-200"),

    ("CODE-042", "WebView Universal File Access",
     r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',
     "critical", "Universal file access from URLs enabled — full filesystem readable via WebView XSS", "M1", "CWE-200"),

    ("CODE-043", "WebView addJavascriptInterface",
     r'addJavascriptInterface\s*\(',
     "high", "JavaScript bridge exposed — RCE possible on Android < 4.2 or with improper validation", "M1", "CWE-749"),

    ("CODE-044", "WebView Content Provider Access",
     r'setAllowContentAccess\s*\(\s*true\s*\)',
     "medium", "WebView can access content:// URIs — data leakage via ContentProvider", "M1", "CWE-200"),

    # -----------------------------------------------------------------------
    # SQL INJECTION
    # -----------------------------------------------------------------------
    ("CODE-050", "Raw SQL Query with Concatenation",
     r'rawQuery\s*\([^)]*\+|execSQL\s*\([^)]*\+',
     "high", "SQL query built with string concatenation — SQL injection risk", "M4", "CWE-89"),

    ("CODE-051", "Raw SQL SELECT with Variable",
     r'rawQuery\s*\(\s*["\']SELECT.*\+',
     "high", "Dynamic SELECT statement — SQL injection if user input is used", "M4", "CWE-89"),

    # -----------------------------------------------------------------------
    # SENSITIVE DATA LOGGING
    # -----------------------------------------------------------------------
    ("CODE-060", "Logging Sensitive Data",
     r'Log\.[divwe]\s*\([^,]+,\s*[^)]*(?:password|token|key|secret|auth|credential|pin|otp)[^)]*\)',
     "medium", "Sensitive data written to logcat — readable by any app with READ_LOGS permission", "M9", "CWE-532"),

    ("CODE-061", "printStackTrace in Production",
     r'\.printStackTrace\s*\(\s*\)',
     "low", "Stack traces logged — reveals internal implementation details", "M9", "CWE-209"),

    # -----------------------------------------------------------------------
    # FILE & STORAGE SECURITY
    # -----------------------------------------------------------------------
    ("CODE-070", "World-Readable File",
     r'MODE_WORLD_READABLE',
     "high", "File created with MODE_WORLD_READABLE — any app can read it", "M1", "CWE-732"),

    ("CODE-071", "World-Writable File",
     r'MODE_WORLD_WRITEABLE|MODE_WORLD_WRITABLE',
     "high", "File created with MODE_WORLD_WRITEABLE — any app can modify it", "M1", "CWE-732"),

    ("CODE-072", "External Storage Write",
     r'getExternalStorageDirectory\s*\(\)|getExternalFilesDir\s*\(',
     "medium", "Data written to external storage — accessible by all apps on Android < 10", "M1", "CWE-312"),

    ("CODE-073", "Sensitive Data in Clipboard",
     r'setPrimaryClip\s*\(|ClipData\.newPlainText\s*\(',
     "low", "Data copied to clipboard — accessible by any background app reading clipboard", "M6", "CWE-200"),

    # -----------------------------------------------------------------------
    # INTENT & IPC SECURITY
    # -----------------------------------------------------------------------
    ("CODE-080", "Implicit Intent for Sensitive Action",
     r'new\s+Intent\s*\(\s*["\'](?!android\.intent\.action\.VIEW)[^"\']+["\']\s*\)',
     "low", "Implicit intent — any app with matching intent-filter can receive it", "M1", "CWE-927"),

    ("CODE-081", "Broadcast Without Permission",
     r'sendBroadcast\s*\(\s*\w+\s*\)\s*;',
     "medium", "Broadcast sent without permission restriction — any app can receive", "M1", "CWE-927"),

    ("CODE-082", "Sticky Broadcast",
     r'sendStickyBroadcast\s*\(',
     "medium", "Sticky broadcasts deprecated and expose data to late receivers", "M1", "CWE-927"),

    ("CODE-083", "PendingIntent Without FLAG_IMMUTABLE",
     r'PendingIntent\.(getActivity|getService|getBroadcast)\s*\(',
     "medium", "PendingIntent without FLAG_IMMUTABLE — intent redirection on API 31+", "M3", "CWE-926"),

    ("CODE-084", "Unvalidated Intent Extra Used Directly",
     r'getIntent\s*\(\s*\)\.getStringExtra|getStringExtra\s*\([^)]+\)',
     "medium", "Intent extra data used without validation — potential injection if used in SQL/file ops", "M4", "CWE-20"),

    # -----------------------------------------------------------------------
    # DYNAMIC CODE & REFLECTION
    # -----------------------------------------------------------------------
    ("CODE-090", "Dynamic Code Loading (DexClassLoader)",
     r'DexClassLoader|PathClassLoader|InMemoryDexClassLoader',
     "high", "Dynamic DEX loading — can load untrusted code at runtime", "M7", "CWE-829"),

    ("CODE-091", "Runtime Command Execution",
     r'Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(',
     "high", "Runtime.exec() call — command injection if input not sanitized", "M4", "CWE-78"),

    ("CODE-092", "Reflection: Class.forName",
     r'Class\.forName\s*\(\s*[^"\']*\)',
     "low", "Dynamic class loading via reflection — verify class source is trusted", "M7", "CWE-470"),

    # -----------------------------------------------------------------------
    # NETWORK SECURITY
    # -----------------------------------------------------------------------
    ("CODE-100", "Hardcoded IP Address",
     r'(?<!\d)(\d{1,3}\.){3}\d{1,3}(?!\d)',
     "low", "Hardcoded IP address found — may point to internal infrastructure", "M5", "CWE-798"),

    ("CODE-101", "Insecure HTTP Client Configuration",
     r'SSLSocketFactory|X509TrustManager|HttpsURLConnection',
     "medium", "Custom HTTPS configuration — verify it enforces proper certificate validation", "M5", "CWE-295"),

    # -----------------------------------------------------------------------
    # ROOT / DEBUGGABILITY
    # -----------------------------------------------------------------------
    ("CODE-110", "Root Detection Bypass Pattern",
     r'su\s|/system/bin/su|/system/xbin/su|RootBeer|isRooted\s*\(\)',
     "low", "Root detection code found — verify it is not easily bypassed with Frida/Magisk", "M7", "CWE-693"),

    ("CODE-111", "Debug Flag Enabled in Code",
     r'BuildConfig\.DEBUG\s*==\s*true|if\s*\(\s*BuildConfig\.DEBUG\s*\)',
     "low", "Debug code paths present — confirm they are excluded from release builds", "M8", "CWE-489"),

    # -----------------------------------------------------------------------
    # MISCELLANEOUS
    # -----------------------------------------------------------------------
    ("CODE-120", "Object Deserialization",
     r'ObjectInputStream|readObject\s*\(\s*\)',
     "high", "Java deserialization used — can lead to RCE with gadget chains", "M4", "CWE-502"),

    ("CODE-121", "Path Traversal Risk",
     r'new\s+File\s*\([^)]*\+[^)]*\)',
     "medium", "File path built with string concatenation — path traversal if input is user-controlled", "M4", "CWE-22"),

    ("CODE-122", "Zip Slip Vulnerability",
     r'ZipEntry|ZipInputStream',
     "medium", "ZIP extraction found — verify entry names are sanitized to prevent ZipSlip", "M4", "CWE-22"),

    ("CODE-123", "Insecure SharedPreferences (no EncryptedSharedPreferences)",
     r'getSharedPreferences\s*\(|getDefaultSharedPreferences\s*\(',
     "low", "Plain SharedPreferences used — consider EncryptedSharedPreferences for sensitive data", "M9", "CWE-312"),

    ("CODE-124", "Content Provider Without Read Permission",
     r'android:readPermission\s*=\s*""',
     "high", "ContentProvider exported with empty readPermission — any app can read its data", "M1", "CWE-284"),
]


def _get_snippet(lines, lineno, context=3):
    """Return ±context lines around lineno (1-indexed)."""
    start = max(0, lineno - 1 - context)
    end = min(len(lines), lineno + context)
    return "\n".join(f"  {i + 1}: {lines[i]}" for i in range(start, end))


def analyze(item):
    """Run all SAST rules against a code file item from apk_code collector."""
    if item.get("source") != "apk_code":
        return None

    content = item.get("content", "")
    if not content:
        return None

    filepath      = item.get("path", "")
    relative_path = item.get("relative_path", filepath)
    ext           = item.get("ext", "")
    lines         = content.splitlines()
    findings      = []
    seen_rules    = set()  # One finding per rule per file to avoid flooding

    for rule_id, title, pattern, severity, description, owasp, cwe in RULES:
        if rule_id in seen_rules:
            continue

        if ext == ".smali":
            # Only check for sensitive info/token/key leaks in smali files, skip misconfigurations.
            is_leak_rule = (
                rule_id.startswith("CODE-00") or 
                rule_id.startswith("CODE-01") or 
                rule_id in ("CODE-025", "CODE-026", "CODE-060")
            )
            if not is_leak_rule:
                continue

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            continue

        for lineno, line in enumerate(lines, 1):
            if regex.search(line):
                findings.append({
                    "type":          "code_vuln",
                    "source":        "apk_code",
                    "rule_id":       rule_id,
                    "title":         title,
                    "severity":      severity,
                    "description":   description,
                    "owasp":         owasp,
                    "cwe":           cwe,
                    "file":          item.get("file"),
                    "path":          filepath,
                    "relative_path": relative_path,
                    "ext":           ext,
                    "line_number":   lineno,
                    "line":          line.strip(),
                    "snippet":       _get_snippet(lines, lineno),
                    # Keep value field for enricher compatibility
                    "value":         line.strip()[:200],
                })
                seen_rules.add(rule_id)
                break  # One finding per rule per file

    return findings if findings else None
