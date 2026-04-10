from core.utils import run

def collect(base):

    results = []

    files = run(f'adb shell "find {base} -type f 2>/dev/null"').splitlines()

    for f in files:
        if not f.endswith((".json",".xml",".txt",".log")):
            continue

        data = run(f'adb shell "head -n 50 {f}"')

        for line in data.splitlines():
            results.append({
                "source": "file",
                "file": f,
                "path": f,
                "line": line.strip()
            })

    return results