def analyze(item):

    findings = []

    if item.get("type") == "manifest_app":

        if item.get("debuggable") == "true":
            findings.append({
                "type": "manifest_vuln",
                "issue": "App is debuggable",
                "risk": "high",
                "detail": item
            })

        if item.get("allowBackup") == "true":
            findings.append({
                "type": "manifest_vuln",
                "issue": "ADB backup enabled",
                "risk": "medium",
                "detail": item
            })

    if item.get("type") == "manifest_component":

        if item.get("exported") == "true":
            findings.append({
                "type": "manifest_vuln",
                "issue": "Exported component",
                "risk": "high",
                "component": item.get("component"),
                "name": item.get("name")
            })

    return findings if findings else None