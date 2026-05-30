import os
from core.finding import Finding
from core.entropy import is_high_entropy_string
from detectors.patterns import scan_line_for_patterns

IGNORED_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.pdf', '.zip', '.tar', '.gz', '.exe', '.bin',
    '.lock', '.pyc'
}

IGNORED_LINES = {
    "BASE64_CHARS",
    "HEX_CHARS",
}

IGNORED_DIRS = {
    'venv', '.git', '__pycache__', 'node_modules',
    '.pytest_cache', 'dist', 'build'
}

def should_skip_file(file_path: str) -> bool:
    _, ext = os.path.splitext(file_path)
    if ext.lower() in IGNORED_EXTENSIONS:
        return True
    parts = file_path.replace("\\", "/").split("/")
    for part in parts:
        if part in IGNORED_DIRS:
            return True
    return False

def scan_file(file_path: str) -> list[Finding]:
    findings = []

    if should_skip_file(file_path):
        return findings

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_number, line in enumerate(lines, start=1):
        line = line.rstrip()

        pattern_findings = scan_line_for_patterns(
            line=line,
            line_number=line_number,
            file_path=file_path
        )
        findings.extend(pattern_findings)

        words = line.split()
        for word in words:
            if any(ignore in line for ignore in IGNORED_LINES):
                  continue
            word = word.strip("'\"`,;:()")
            if is_high_entropy_string(word):
                already_found = any(
                    f.line_number == line_number and
                    f.file_path == file_path and
                    f.detection_method == "Pattern Match"
                    for f in findings
                )
                if not already_found:
                    findings.append(Finding(
                        file_path=file_path,
                        line_number=line_number,
                        secret_type="High Entropy String",
                        matched_value=word[:50],
                        detection_method="Entropy Analysis",
                        severity="MEDIUM",
                        remediation=(
                            "This string has high randomness and may be a "
                            "secret. Review this line manually. If it is a "
                            "secret, move it to an environment variable or "
                            "AWS Secrets Manager."
                        )
                    ))

    return findings

def scan_directory(path: str) -> list[Finding]:
    all_findings = []

    if os.path.isfile(path):
        return scan_file(path)

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for filename in files:
            file_path = os.path.join(root, filename)
            file_findings = scan_file(file_path)
            all_findings.extend(file_findings)

    return all_findings
