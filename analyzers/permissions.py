# ---------------------------------------------------------------------------
# DANGEROUS PERMISSIONS
# Format: short_name → (severity, description, owasp, cwe)
# ---------------------------------------------------------------------------
DANGEROUS_PERMISSIONS = {
    "READ_SMS":                 ("high",     "Can read SMS messages — OTP and private message stealing",            "M6", "CWE-200"),
    "SEND_SMS":                 ("high",     "Can send SMS — potential financial fraud via premium SMS",            "M6", "CWE-284"),
    "RECEIVE_SMS":              ("high",     "Can intercept incoming SMS — OTP bypass",                            "M6", "CWE-200"),
    "PROCESS_OUTGOING_CALLS":   ("high",     "Can intercept and redirect outgoing calls",                          "M6", "CWE-200"),
    "READ_CALL_LOG":            ("medium",   "Can read full call history",                                         "M6", "CWE-200"),
    "WRITE_CALL_LOG":           ("medium",   "Can modify call log",                                                "M6", "CWE-284"),
    "RECORD_AUDIO":             ("medium",   "Can record microphone — surveillance risk",                          "M6", "CWE-200"),
    "CAMERA":                   ("medium",   "Can capture photos/video — surveillance risk",                       "M6", "CWE-200"),
    "ACCESS_FINE_LOCATION":     ("medium",   "Precise GPS location access — user tracking",                        "M6", "CWE-200"),
    "ACCESS_COARSE_LOCATION":   ("low",      "Approximate location access",                                        "M6", "CWE-200"),
    "ACCESS_BACKGROUND_LOCATION": ("high",  "Background location tracking — always-on user surveillance",         "M6", "CWE-200"),
    "READ_CONTACTS":            ("medium",   "Can read entire contact list — data exfiltration risk",              "M6", "CWE-200"),
    "WRITE_CONTACTS":           ("medium",   "Can modify contacts — potential phishing/impersonation",             "M6", "CWE-284"),
    "READ_EXTERNAL_STORAGE":    ("medium",   "Can read all files on shared storage",                               "M1", "CWE-200"),
    "WRITE_EXTERNAL_STORAGE":   ("medium",   "Can write/overwrite files on shared storage",                        "M1", "CWE-732"),
    "MANAGE_EXTERNAL_STORAGE":  ("high",     "Unrestricted access to all files — scoped storage bypass",           "M1", "CWE-732"),
    "BIND_DEVICE_ADMIN":        ("critical", "Device administrator — can wipe device, enforce policies",            "M3", "CWE-284"),
    "SYSTEM_ALERT_WINDOW":      ("high",     "Can draw overlay on any app — tapjacking and phishing",              "M8", "CWE-1021"),
    "REQUEST_INSTALL_PACKAGES": ("high",     "Can silently install APKs — malware dropper capability",             "M7", "CWE-829"),
    "PACKAGE_USAGE_STATS":      ("medium",   "Can monitor which apps are used and when",                           "M6", "CWE-200"),
    "USE_BIOMETRIC":            ("low",      "Accesses biometric authentication API",                              "M3", "CWE-284"),
    "USE_FINGERPRINT":          ("low",      "Accesses legacy fingerprint API",                                    "M3", "CWE-284"),
    "NFC":                      ("low",      "NFC access — potential relay attack vector",                         "M5", "CWE-319"),
    "BLUETOOTH_ADMIN":          ("low",      "Full Bluetooth control — can discover and pair devices",             "M5", "CWE-284"),
    "BLUETOOTH_CONNECT":        ("low",      "Can connect to paired Bluetooth devices",                            "M5", "CWE-284"),
    "RECEIVE_BOOT_COMPLETED":   ("medium",   "Runs code on device boot — persistence mechanism",                   "M8", "CWE-284"),
    "FOREGROUND_SERVICE":       ("low",      "Runs persistent foreground service",                                 "M8", "CWE-284"),
    "CHANGE_NETWORK_STATE":     ("low",      "Can enable/disable Wi-Fi and mobile data",                           "M5", "CWE-284"),
    "INTERNET":                 ("low",      "Network access — required for data exfiltration but not dangerous alone", "M5", "CWE-284"),
    "READ_PHONE_STATE":         ("medium",   "Can read IMEI, phone number, SIM info — device fingerprinting",      "M6", "CWE-200"),
    "CALL_PHONE":               ("high",     "Can place phone calls without user interaction",                     "M6", "CWE-284"),
    "ANSWER_PHONE_CALLS":       ("medium",   "Can answer incoming calls silently",                                 "M6", "CWE-284"),
    "DISABLE_KEYGUARD":         ("high",     "Can disable the lock screen",                                        "M3", "CWE-284"),
    "WAKE_LOCK":                ("low",      "Can prevent device from sleeping — battery drain",                   "M8", "CWE-400"),
    "VIBRATE":                  ("low",      "Can make device vibrate",                                            "M8", "CWE-284"),
    "FLASHLIGHT":               ("low",      "Can control flashlight/camera LED",                                  "M8", "CWE-284"),
    "BODY_SENSORS":             ("medium",   "Access to health/fitness sensors",                                   "M6", "CWE-200"),
    "ACTIVITY_RECOGNITION":     ("low",      "Can detect physical activities (walking, running)",                  "M6", "CWE-200"),
    "GET_ACCOUNTS":             ("medium",   "Can enumerate all accounts on device — Google, Facebook, etc.",      "M6", "CWE-200"),
    "AUTHENTICATE_ACCOUNTS":    ("high",     "Can act as account authenticator — credential theft risk",           "M3", "CWE-284"),
    "MANAGE_ACCOUNTS":          ("high",     "Can add/remove/modify accounts on device",                           "M3", "CWE-284"),
    "READ_CALENDAR":            ("low",      "Can read calendar events and attendees",                             "M6", "CWE-200"),
    "WRITE_CALENDAR":           ("low",      "Can create/modify calendar events",                                  "M6", "CWE-284"),
    "ACCESS_WIFI_STATE":        ("low",      "Can read Wi-Fi SSIDs and connection state",                          "M6", "CWE-200"),
    "CHANGE_WIFI_STATE":        ("low",      "Can connect/disconnect Wi-Fi networks",                              "M5", "CWE-284"),
}

# ---------------------------------------------------------------------------
# DANGEROUS PERMISSION COMBINATIONS (attack chain detection)
# Format: ([perm_short_names], combined_severity, attack_description)
# ---------------------------------------------------------------------------
DANGEROUS_COMBOS = [
    (["READ_SMS",          "INTERNET"],
     "critical", "SMS OTP exfiltration: app can steal 2FA codes and send them to a remote server"),

    (["RECEIVE_SMS",       "INTERNET"],
     "critical", "SMS interception + exfiltration: can silently capture and relay OTP messages"),

    (["RECORD_AUDIO",      "INTERNET"],
     "critical", "Audio surveillance: microphone recordings can be streamed/uploaded remotely"),

    (["CAMERA",            "INTERNET"],
     "critical", "Camera surveillance: photos/video can be captured and exfiltrated"),

    (["ACCESS_FINE_LOCATION", "INTERNET"],
     "high",     "Real-time location tracking: precise GPS sent to remote server"),

    (["ACCESS_BACKGROUND_LOCATION", "INTERNET"],
     "critical", "Always-on location surveillance: tracks user 24/7 without interaction"),

    (["READ_CONTACTS",     "INTERNET"],
     "high",     "Contact list exfiltration: all contacts can be sent to remote server"),

    (["READ_CALL_LOG",     "INTERNET"],
     "high",     "Call log exfiltration: full call history uploaded remotely"),

    (["GET_ACCOUNTS",      "INTERNET"],
     "high",     "Account enumeration: Google/social accounts listed and potentially targeted"),

    (["REQUEST_INSTALL_PACKAGES", "INTERNET"],
     "critical", "Malware dropper: can download and silently install arbitrary APKs"),

    (["SYSTEM_ALERT_WINDOW", "INTERNET"],
     "high",     "Phishing overlay: can display fake login screens over any app"),

    (["SYSTEM_ALERT_WINDOW", "READ_SMS"],
     "critical", "Tapjacking + OTP: fake overlay captures credentials while reading 2FA SMS"),

    (["BIND_DEVICE_ADMIN", "INTERNET"],
     "critical", "Remote device management: full remote control — wipe, lock, enforce policies"),

    (["READ_PHONE_STATE",  "INTERNET"],
     "high",     "Device fingerprinting: IMEI and phone number uploaded for tracking"),

    (["DISABLE_KEYGUARD",  "CAMERA"],
     "high",     "Surveillance bypass: can disable lock screen and access camera silently"),

    (["MANAGE_EXTERNAL_STORAGE", "INTERNET"],
     "high",     "Full file system exfiltration: reads all files and uploads remotely"),
]


def analyze(item):
    """
    Analyze a manifest_permission item and produce findings for dangerous permissions
    and dangerous combinations. Called once per permission item from manifest collector.
    For combo analysis, call analyze_all() after all permissions are collected.
    """
    if item.get("type") != "manifest_permission":
        return None

    perm_full = item.get("permission", "")
    short = perm_full.split(".")[-1]

    if short not in DANGEROUS_PERMISSIONS:
        return None

    severity, description, owasp, cwe = DANGEROUS_PERMISSIONS[short]

    return {
        "type":        "permission_vuln",
        "source":      "manifest",
        "permission":  perm_full,
        "short_name":  short,
        "severity":    severity,
        "description": description,
        "owasp":       owasp,
        "cwe":         cwe,
        "value":       perm_full,
        "issue":       f"Dangerous permission: {short}",
    }


def analyze_combos(all_permissions):
    """
    Check collected permission list for dangerous combinations.
    all_permissions: list of short permission names (e.g. ["READ_SMS", "INTERNET"])
    Returns a list of combo finding dicts.
    """
    findings = []
    perm_set = set(all_permissions)

    for combo_perms, severity, description in DANGEROUS_COMBOS:
        if all(p in perm_set for p in combo_perms):
            findings.append({
                "type":        "permission_combo",
                "source":      "manifest",
                "permissions": combo_perms,
                "severity":    severity,
                "description": description,
                "owasp":       "M6",
                "cwe":         "CWE-284",
                "value":       " + ".join(combo_perms),
                "issue":       f"Dangerous permission combo: {' + '.join(combo_perms)}",
            })

    return findings
