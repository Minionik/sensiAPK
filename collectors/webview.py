from core.utils import run
import tempfile, os

def collect(base):

    results = []

    local = os.path.join(tempfile.gettempdir(),"cookies.db")

    run(f"adb pull {base}/app_webview/Cookies {local}")

    if not os.path.exists(local):
        return results

    dump = run(f"sqlite3 {local} .dump")

    for line in dump.splitlines():
        results.append({
            "source": "webview",
            "file": "cookies",
            "path": f"{base}/app_webview/Cookies",
            "line": line.strip()
        })

    return results