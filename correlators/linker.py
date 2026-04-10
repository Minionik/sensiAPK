def correlate(findings):
    value_map = {}
    jwt_map = {}
    enriched = []

    # -------------------------------
    # 1. BUILD VALUE MAP
    # -------------------------------
    for f in findings:
        val = f.get("value")
        if not val:
            continue

        value_map.setdefault(val, []).append(f)

        # Track JWT payload relationships
        if f.get("type") == "jwt":
            payload = f.get("payload", {})
            uid = str(payload.get("user") or payload.get("sub") or "")
            if uid:
                jwt_map.setdefault(uid, []).append(f)

    # -------------------------------
    # 2. APPLY CORRELATION
    # -------------------------------
    for f in findings:
        val = f.get("value")

        # ---------------------------
        # TOKEN REUSE (STRONG SIGNAL)
        # ---------------------------
        if val in value_map:
            related = value_map[val]
            f["related"] = len(related)

            if len(related) > 2:
                f.setdefault("correlation", []).append("multi_source_reuse")

                sources = list(set([r.get("source") for r in related]))
                f["reuse_sources"] = sources

        # ---------------------------
        # JWT USER CLUSTERING
        # ---------------------------
        if f.get("type") == "jwt":
            payload = f.get("payload", {})
            uid = str(payload.get("user") or payload.get("sub") or "")

            if uid and uid in jwt_map:
                f["user_related_tokens"] = len(jwt_map[uid])

                if len(jwt_map[uid]) > 1:
                    f.setdefault("correlation", []).append("same_user_multiple_tokens")

        # ---------------------------
        # SECRET ↔ JWT LINKING
        # ---------------------------
        if f.get("type") == "secret":
            for j in findings:
                if j.get("type") == "jwt":
                    payload_str = str(j.get("payload", {})).lower()
                    if val and val.lower() in payload_str:
                        f.setdefault("correlation", []).append("secret_in_jwt_payload")
                        f["linked_jwt"] = j.get("value")

        # ---------------------------
        # SOURCE RISK AMPLIFICATION
        # ---------------------------
        path = (f.get("path") or "").lower()

        if "webview" in path and f.get("type") in ["jwt", "secret"]:
            f.setdefault("correlation", []).append("webview_high_risk")

        if "shared_prefs" in path and f.get("related", 0) > 1:
            f.setdefault("correlation", []).append("persistent_token_storage")

        # ---------------------------
        # DUPLICATE CLEANUP
        # ---------------------------
        fingerprint = (
            f.get("type"),
            f.get("value"),
            f.get("path")
        )

        if fingerprint not in [(
            x.get("type"),
            x.get("value"),
            x.get("path")
        ) for x in enriched]:
            enriched.append(f)

    return enriched