import xml.etree.ElementTree as ET
from core.utils import run
import tempfile, os

def collect(base):

    results = []

    local = os.path.join(tempfile.gettempdir(), "AndroidManifest.xml")

    # Try pulling manifest (may fail on some devices)
    run(f"adb pull {base}/../AndroidManifest.xml {local}")

    if not os.path.exists(local):
        return results

    try:
        tree = ET.parse(local)
        root = tree.getroot()
    except:
        return results

    app = root.find("application")

    if app is not None:
        results.append({
            "type": "manifest_app",
            "debuggable": app.attrib.get("{http://schemas.android.com/apk/res/android}debuggable"),
            "allowBackup": app.attrib.get("{http://schemas.android.com/apk/res/android}allowBackup")
        })

    for comp in root.iter():
        if comp.tag.endswith(("activity","service","receiver","provider")):

            exported = comp.attrib.get("{http://schemas.android.com/apk/res/android}exported")
            name = comp.attrib.get("{http://schemas.android.com/apk/res/android}name")

            results.append({
                "type": "manifest_component",
                "component": comp.tag,
                "name": name,
                "exported": exported
            })

    return results