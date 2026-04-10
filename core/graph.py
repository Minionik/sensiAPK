def build_graph(findings):

    value_map = {}

    for f in findings:
        v = f.get("value")
        if not v:
            continue
        value_map.setdefault(v, []).append(f)

    # attach relationships
    for f in findings:
        v = f.get("value")
        if v in value_map:
            f["related"] = len(value_map[v])

    return findings