def generate_manual_poc(f):

    path = f.get("path")
    val = f.get("value", "")[:10]

    if not path:
        return None

    # JWT
    if f.get("type") == "jwt":
        return f'adb shell "cat {path} | grep -i \\"{val}\\""'

    # Secret
    if f.get("type") == "secret":
        return f'adb shell "grep -Ri \\"{val}\\" {path}"'

    # Database
    if f.get("source") == "database":
        return f'adb shell "sqlite3 {path} \\".dump\\""'

    # Shared prefs
    if f.get("source") == "shared_prefs":
        return f'adb shell "cat {path}"'

    return None