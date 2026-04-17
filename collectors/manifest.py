import xml.etree.ElementTree as ET
from core.utils import run
import tempfile
import os

NS = "http://schemas.android.com/apk/res/android"


def _a(attrib, name):
    """Shorthand to get android: namespace attribute."""
    return attrib.get(f"{{{NS}}}{name}")


def collect(base):
    results = []

    local = os.path.join(tempfile.gettempdir(), "AndroidManifest.xml")

    run(f"adb pull {base}/../AndroidManifest.xml {local}")

    if not os.path.exists(local):
        return results

    try:
        tree = ET.parse(local)
        root = tree.getroot()
    except Exception:
        return results

    # ------------------------------------------------------------------
    # 1. PACKAGE METADATA
    # ------------------------------------------------------------------
    package = root.attrib.get("package", "unknown")

    uses_sdk = root.find("uses-sdk")
    min_sdk    = int(_a(uses_sdk.attrib, "minSdkVersion") or 0)    if uses_sdk is not None else 0
    target_sdk = int(_a(uses_sdk.attrib, "targetSdkVersion") or 0) if uses_sdk is not None else 0

    results.append({
        "type":       "manifest_meta",
        "package":    package,
        "min_sdk":    min_sdk,
        "target_sdk": target_sdk,
    })

    # ------------------------------------------------------------------
    # 2. APPLICATION FLAGS
    # ------------------------------------------------------------------
    app = root.find("application")
    if app is not None:
        results.append({
            "type":                  "manifest_app",
            "package":               package,
            "debuggable":            _a(app.attrib, "debuggable"),
            "allowBackup":           _a(app.attrib, "allowBackup"),
            "usesCleartextTraffic":  _a(app.attrib, "usesCleartextTraffic"),
            "networkSecurityConfig": _a(app.attrib, "networkSecurityConfig"),
            "testOnly":              _a(app.attrib, "testOnly"),
        })

    # ------------------------------------------------------------------
    # 3. PERMISSIONS
    # ------------------------------------------------------------------
    for perm in root.findall("uses-permission"):
        name = _a(perm.attrib, "name") or perm.attrib.get("name", "")
        if name:
            results.append({
                "type":       "manifest_permission",
                "permission": name,
            })

    # Also capture custom permissions defined by the app
    for perm in root.findall("permission"):
        name  = _a(perm.attrib, "name") or ""
        level = _a(perm.attrib, "protectionLevel") or "normal"
        results.append({
            "type":             "manifest_custom_permission",
            "permission":       name,
            "protection_level": level,
        })

    # ------------------------------------------------------------------
    # 4. COMPONENTS (Activity, Service, Receiver, Provider)
    # ------------------------------------------------------------------
    component_tags = ("activity", "service", "receiver", "provider",
                      "activity-alias")

    if app is not None:
        for comp in app.iter():
            tag = comp.tag.split("}")[-1] if "}" in comp.tag else comp.tag
            if tag not in component_tags:
                continue

            name       = _a(comp.attrib, "name") or ""
            exported   = _a(comp.attrib, "exported")
            permission = _a(comp.attrib, "permission")  # Missing = no access control

            # Collect intent-filter schemes (deep links)
            deep_links = []
            for intent_filter in comp.findall("intent-filter"):
                for data in intent_filter.findall("data"):
                    scheme = _a(data.attrib, "scheme")
                    host   = _a(data.attrib, "host")
                    if scheme:
                        deep_links.append(f"{scheme}://{host or '*'}")

            # If intent-filter present and exported not explicitly false → effectively exported
            has_intent_filter = comp.find("intent-filter") is not None
            effective_exported = exported == "true" or (has_intent_filter and exported != "false")

            results.append({
                "type":              "manifest_component",
                "component":         tag,
                "name":              name,
                "exported":          exported,
                "effective_exported": str(effective_exported).lower(),
                "permission":        permission,   # None = no access control on the component
                "deep_links":        deep_links,
                "has_intent_filter": str(has_intent_filter).lower(),
            })

    return results
