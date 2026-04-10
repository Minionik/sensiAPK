from core.utils import run
import tempfile, os

def collect(base):

    results = []

    dbs = run(f'adb shell "ls {base}/databases 2>/dev/null"').split()

    for d in dbs:
        local = os.path.join(tempfile.gettempdir(), d)

        run(f"adb pull {base}/databases/{d} {local}")

        if not os.path.exists(local):
            continue

        dump = run(f"sqlite3 {local} .dump")

        for line in dump.splitlines():
            results.append({
                "source": "database",
                "file": d,
                "path": f"{base}/databases/{d}",
                "line": line.strip()
            })

    return results