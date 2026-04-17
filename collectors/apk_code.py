import os

# File types relevant for SAST analysis
RELEVANT_EXTENSIONS = {'.java', '.kt', '.smali', '.xml', '.gradle', '.properties', '.json', '.yaml', '.yml', '.env'}

# Skip large auto-generated or vendor directories
SKIP_DIRS = {'build', 'test', '.git', 'androidTest', '__MACOSX', 'node_modules'}

# Skip very large files (>300KB) — usually auto-generated
MAX_FILE_SIZE = 300 * 1024


def collect(apk_dir):
    """
    Walk a decompiled APK directory and collect source files for SAST analysis.
    Compatible with Jadx output (sources/), Apktool output (smali/), and raw folders.
    """
    if not apk_dir or not os.path.isdir(apk_dir):
        return []

    results = []

    for root, dirs, files in os.walk(apk_dir):
        # Prune skipped directories in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext not in RELEVANT_EXTENSIONS:
                continue

            filepath = os.path.join(root, filename)

            try:
                if os.path.getsize(filepath) > MAX_FILE_SIZE:
                    continue

                with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                    content = fh.read()

                if not content.strip():
                    continue

                results.append({
                    "source": "apk_code",
                    "file": filename,
                    "path": filepath,
                    "relative_path": os.path.relpath(filepath, apk_dir),
                    "ext": ext,
                    "content": content
                })

            except Exception:
                continue

    return results
