def analyze(item):
    findings = []

    # ------------------------------------------------------------------
    # APPLICATION-LEVEL FLAGS
    # ------------------------------------------------------------------
    if item.get("type") == "manifest_app":

        if item.get("debuggable") == "true":
            findings.append({
                "type":    "manifest_vuln",
                "source":  "manifest",
                "issue":   "App is debuggable",
                "risk":    "high",
                "detail":  "android:debuggable=true — ADB debugging allowed on any device. Attacker can attach debugger, extract memory, bypass checks.",
                "owasp":   "M8",
                "cwe":     "CWE-489",
                "value":   "android:debuggable=true",
            })

        if item.get("allowBackup") == "true":
            findings.append({
                "type":    "manifest_vuln",
                "source":  "manifest",
                "issue":   "ADB backup enabled",
                "risk":    "medium",
                "detail":  "android:allowBackup=true — adb backup extracts all app data without root.",
                "owasp":   "M9",
                "cwe":     "CWE-530",
                "value":   "android:allowBackup=true",
            })

        if item.get("usesCleartextTraffic") == "true":
            findings.append({
                "type":    "manifest_vuln",
                "source":  "manifest",
                "issue":   "Cleartext HTTP traffic permitted",
                "risk":    "high",
                "detail":  "android:usesCleartextTraffic=true — app explicitly allows unencrypted HTTP. Traffic interceptable by MITM.",
                "owasp":   "M5",
                "cwe":     "CWE-319",
                "value":   "android:usesCleartextTraffic=true",
            })

        if item.get("testOnly") == "true":
            findings.append({
                "type":    "manifest_vuln",
                "source":  "manifest",
                "issue":   "Test-only build in production",
                "risk":    "medium",
                "detail":  "android:testOnly=true — app is marked as test build. Should never reach production.",
                "owasp":   "M8",
                "cwe":     "CWE-489",
                "value":   "android:testOnly=true",
            })

        if not item.get("networkSecurityConfig"):
            findings.append({
                "type":    "manifest_vuln",
                "source":  "manifest",
                "issue":   "No Network Security Config defined",
                "risk":    "medium",
                "detail":  "No android:networkSecurityConfig — app uses platform defaults which may allow cleartext on older APIs.",
                "owasp":   "M5",
                "cwe":     "CWE-295",
                "value":   "networkSecurityConfig=missing",
            })

    # ------------------------------------------------------------------
    # SDK VERSION CHECKS
    # ------------------------------------------------------------------
    if item.get("type") == "manifest_meta":
        min_sdk = item.get("min_sdk", 0)
        target  = item.get("target_sdk", 0)

        if 0 < min_sdk < 21:
            findings.append({
                "type":    "manifest_vuln",
                "source":  "manifest",
                "issue":   f"Low minSdkVersion: {min_sdk}",
                "risk":    "medium",
                "detail":  f"minSdkVersion={min_sdk} (<21). Devices on Android <5.0 lack TLS 1.2 enforcement, SELinux hardening, and many security APIs.",
                "owasp":   "M8",
                "cwe":     "CWE-1104",
                "value":   f"minSdkVersion={min_sdk}",
            })

        if 0 < target < 31:
            findings.append({
                "type":    "manifest_vuln",
                "source":  "manifest",
                "issue":   f"Low targetSdkVersion: {target}",
                "risk":    "low",
                "detail":  f"targetSdkVersion={target} (<31). App misses modern security defaults: FLAG_IMMUTABLE PendingIntents, exported component defaults, etc.",
                "owasp":   "M8",
                "cwe":     "CWE-1104",
                "value":   f"targetSdkVersion={target}",
            })

    # ------------------------------------------------------------------
    # COMPONENT CHECKS
    # ------------------------------------------------------------------
    if item.get("type") == "manifest_component":
        component  = item.get("component", "")
        name       = item.get("name", "unknown")
        exported   = item.get("effective_exported", "false")
        permission = item.get("permission")
        deep_links = item.get("deep_links", [])

        if exported == "true":

            # Open exported component (no permission guard)
            if not permission:
                findings.append({
                    "type":      "manifest_vuln",
                    "source":    "manifest",
                    "issue":     f"Exported {component} without permission",
                    "risk":      "high",
                    "detail":    f"{name} is exported with no android:permission — any installed app can invoke it directly.",
                    "owasp":     "M1",
                    "cwe":       "CWE-926",
                    "component": component,
                    "name":      name,
                    "value":     f"exported={component}:{name}",
                })
            else:
                findings.append({
                    "type":      "manifest_vuln",
                    "source":    "manifest",
                    "issue":     f"Exported {component} (permission-guarded)",
                    "risk":      "medium",
                    "detail":    f"{name} is exported and guarded by {permission}. Verify the permission protectionLevel is 'signature'.",
                    "owasp":     "M1",
                    "cwe":       "CWE-926",
                    "component": component,
                    "name":      name,
                    "value":     f"exported={component}:{name}",
                })

            # Deep link without explicit validation warning
            for link in deep_links:
                findings.append({
                    "type":      "manifest_vuln",
                    "source":    "manifest",
                    "issue":     f"Deep link on exported {component}",
                    "risk":      "medium",
                    "detail":    f"Deep link '{link}' registered on exported {component} {name}. Unvalidated parameters can lead to open redirect or injection.",
                    "owasp":     "M1",
                    "cwe":       "CWE-939",
                    "component": component,
                    "name":      name,
                    "deep_link": link,
                    "value":     link,
                })

    return findings if findings else None
