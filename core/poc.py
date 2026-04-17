def generate_manual_poc(f):

    ftype  = f.get("type")
    source = f.get("source", "")
    path   = f.get("path", "")
    val    = (f.get("value") or "")[:10]

    # ------------------------------------------------------------------
    # CODE VULNERABILITY
    # ------------------------------------------------------------------
    if ftype == "code_vuln":
        rule = f.get("rule_id", "")
        rel  = f.get("relative_path", f.get("file", ""))
        ln   = f.get("line_number", "?")

        if rule.startswith("CODE-03"):   # SSL/TLS issues
            return f'# Verify with: frida -U -n <app_process> --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida'
        if rule.startswith("CODE-04"):   # WebView
            return f'adb shell am start -n <package>/<activity> --es url "javascript:alert(document.cookie)"'
        if rule.startswith("CODE-05"):   # SQL injection
            return f'adb shell am start -n <package>/<activity> --es input "1 OR 1=1--"'
        if rule.startswith("CODE-00"):   # Hardcoded secret
            return f'grep -r "{val}" {rel}  # Found at line {ln}'
        return f'# Review: {rel}:{ln}  Rule: {rule}'

    # ------------------------------------------------------------------
    # PERMISSION FINDINGS
    # ------------------------------------------------------------------
    if ftype in ("permission_vuln", "permission_combo"):
        perms = f.get("permissions") or [f.get("short_name", "")]
        return f'adb shell pm list permissions -g | grep -i "{", ".join(perms)}"'

    # ------------------------------------------------------------------
    # MANIFEST VULNERABILITY
    # ------------------------------------------------------------------
    if ftype == "manifest_vuln":
        issue = f.get("issue", "")
        name  = f.get("name", "<component>")
        pkg   = "<package>"

        if "debuggable" in issue:
            return f'adb shell am start -n {pkg}/{name}  # Debug via JDWP: adb forward tcp:8700 jdwp:<pid>'
        if "backup" in issue.lower():
            return f'adb backup -noapk {pkg} && adb shell tar xvf backup.ab'
        if "Exported" in issue and f.get("component") == "activity":
            return f'adb shell am start -n {pkg}/{name}'
        if "Exported" in issue and f.get("component") == "service":
            return f'adb shell am startservice -n {pkg}/{name}'
        if "Exported" in issue and f.get("component") == "receiver":
            return f'adb shell am broadcast -n {pkg}/{name}'
        if "Exported" in issue and f.get("component") == "provider":
            return f'adb shell content query --uri content://{pkg}.provider/'
        if f.get("deep_link"):
            return f'adb shell am start -a android.intent.action.VIEW -d "{f["deep_link"]}?param=test"'
        if "cleartext" in issue.lower():
            return '# Intercept with: mitmproxy --mode transparent'
        return None

    # ------------------------------------------------------------------
    # JWT
    # ------------------------------------------------------------------
    if ftype == "jwt":
        return f'adb shell "cat {path} | grep -i \\"{val}\\""'

    # ------------------------------------------------------------------
    # SECRET
    # ------------------------------------------------------------------
    if ftype == "secret":
        return f'adb shell "grep -Ri \\"{val}\\" {path}"'

    # ------------------------------------------------------------------
    # DATABASE
    # ------------------------------------------------------------------
    if source == "database":
        return f'adb shell "sqlite3 {path} \\".dump\\""'

    # ------------------------------------------------------------------
    # SHARED PREFS
    # ------------------------------------------------------------------
    if source == "shared_prefs":
        return f'adb shell "cat {path}"'

    return None
