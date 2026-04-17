import re

# ---------------------------------------------------------------------------
# SECRET PATTERNS
# Each entry: (label, regex, min_length)
# Ordered from most specific to least to reduce false positives.
# ---------------------------------------------------------------------------
SECRET_PATTERNS = [
    # Cloud / infrastructure
    ("AWS Access Key ID",          r'AKIA[0-9A-Z]{16}',                              20),
    ("AWS Secret Access Key",      r'(?i)aws.{0,30}["\'][A-Za-z0-9/+]{40}["\']',    40),
    ("Firebase / Google API Key",  r'AIza[0-9A-Za-z\-_]{35}',                       39),
    ("Google OAuth Client Secret", r'GOCSPX-[A-Za-z0-9_\-]{28}',                   35),

    # Source control
    ("GitHub PAT (classic)",       r'ghp_[A-Za-z0-9]{36}',                          40),
    ("GitHub PAT (fine-grained)",  r'github_pat_[A-Za-z0-9_]{82}',                  93),
    ("GitLab Token",               r'glpat-[A-Za-z0-9\-_]{20}',                     26),

    # Payment
    ("Stripe Secret Key",          r'sk_live_[0-9a-zA-Z]{24,}',                     32),
    ("Stripe Publishable Key",     r'pk_live_[0-9a-zA-Z]{24,}',                     32),
    ("Stripe Test Secret",         r'sk_test_[0-9a-zA-Z]{24,}',                     32),

    # Messaging / comms
    ("Twilio Account SID",         r'AC[0-9a-f]{32}',                               34),
    ("Twilio Auth Token",          r'SK[0-9a-f]{32}',                               34),
    ("Slack Token",                r'xox[baprs]-[0-9A-Za-z\-]{10,48}',              15),
    ("SendGrid API Key",           r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',  69),
    ("Mailgun API Key",            r'key-[0-9a-z]{32}',                             36),

    # Generic high-confidence patterns
    ("Bearer Token",               r'(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}',           26),
    ("Private Key Block",          r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY', 10),

    # Generic key/secret/token/password in assignment
    ("Hardcoded Secret (generic)",
     r'(?i)(token|api_?key|secret|password|passwd|pwd|auth|credential|access_key)\s*[=:]\s*["\'][^"\']{8,}["\']',
     12),
]

# Values that look like real secrets but are actually placeholders
PLACEHOLDER_PATTERNS = re.compile(
    r'(?i)(your[_\-]?\w+|example|placeholder|changeme|xxxx|todo|test|sample|'
    r'<[^>]+>|\$\{[^}]+\}|%[^%]+%|none|null|true|false|undefined|empty|dummy|'
    r'insert|replace|put_your|add_your|enter_your)',
    re.IGNORECASE
)


def _is_real(val):
    if not val or len(val) < 8:
        return False
    if val.lower() in ("true", "false", "null", "none", "undefined"):
        return False
    if PLACEHOLDER_PATTERNS.search(val):
        return False
    return True


def analyze(item):
    line = item.get("line") or item.get("value", "")
    if not line:
        return None

    for label, pattern, min_len in SECRET_PATTERNS:
        try:
            m = re.search(pattern, line)
        except re.error:
            continue

        if not m:
            continue

        val = m.group(0)

        if len(val) < min_len:
            continue

        if not _is_real(val):
            continue

        return {
            "type":       "secret",
            "label":      label,
            "value":      val,
            "source":     item.get("source", "unknown"),
            "file":       item.get("file"),
            "path":       item.get("path"),
            "line":       line,
        }

    return None
