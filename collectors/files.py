from core.utils import run

# File extensions worth reading for secret/config analysis
INTERESTING_EXTENSIONS = (
    ".json", ".xml", ".txt", ".log",
    ".properties", ".gradle", ".conf",
    ".yaml", ".yml", ".env", ".cfg",
    ".ini", ".pem", ".crt", ".key",
)


def collect(base):
    results = []

    files = run(f'adb shell "find {base} -type f 2>/dev/null"').splitlines()

    for f in files:
        f = f.strip()
        if not f:
            continue

        if not any(f.endswith(ext) for ext in INTERESTING_EXTENSIONS):
            continue

        data = run(f'adb shell "head -n 100 {f} 2>/dev/null"')

        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue

            results.append({
                "source": "file",
                "file":   f.split("/")[-1],
                "path":   f,
                "line":   line,
            })

    return results
