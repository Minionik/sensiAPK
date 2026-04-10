import xml.etree.ElementTree as ET
from core.utils import run

def collect(base):

    results = []

    files = run(f'adb shell "ls {base}/shared_prefs 2>/dev/null"').split()

    for f in files:
        raw = run(f'adb shell "cat {base}/shared_prefs/{f} 2>/dev/null"')

        try:
            root = ET.fromstring(raw)
        except:
            continue

        for child in root:
            name = child.attrib.get("name","")
            value = child.attrib.get("value") or child.text

            if value:
                results.append({
                    "source": "shared_prefs",
                    "file": f,
                    "path": f"{base}/shared_prefs/{f}",
                    "key": name,
                    "value": value
                })

    return results