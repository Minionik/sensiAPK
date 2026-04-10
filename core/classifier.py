def classify_file(f):

    path = (f.get("path") or "").lower()

    score = 0
    tags = []

    # High-value locations
    if "shared_prefs" in path:
        score += 30
        tags.append("app_storage")

    if "databases" in path:
        score += 30
        tags.append("database")

    if "webview" in path:
        score += 40
        tags.append("webview")

    # Sensitive keywords
    sensitive_keywords = ["auth", "token", "session", "user", "config", "login"]

    for k in sensitive_keywords:
        if k in path:
            score += 20
            tags.append(f"keyword:{k}")

    # File type
    if path.endswith(".xml") or path.endswith(".json"):
        score += 10

    f["file_score"] = score
    f["file_tags"] = list(set(tags))

    return f