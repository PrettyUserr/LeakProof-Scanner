from core.finding import Finding

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢"
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def print_report(findings: list[Finding], path: str):
    print(f"\n🔍 LeakProof Scanner — scanning: {path}\n")

    if not findings:
        print("✅  No secrets detected. Your code looks clean.\n")
        return

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    print(f"{'─' * 60}")
    for f in findings:
        icon = SEVERITY_ICONS.get(f.severity, "⚪")
        print(f"\n{icon}  [{f.severity}] {f.secret_type}")
        print(f"   Method    : {f.detection_method}")
        print(f"   File      : {f.file_path}")
        print(f"   Line      : {f.line_number}")
        print(f"   Found     : {f.matched_value[:60]}")
        print(f"   Fix       : {f.remediation}")
        print(f"{'─' * 60}")

    criticals = sum(1 for f in findings if f.severity == "CRITICAL")
    highs = sum(1 for f in findings if f.severity == "HIGH")
    mediums = sum(1 for f in findings if f.severity == "MEDIUM")

    print(f"\nScan complete — {len(findings)} finding(s) found.")
    print(f"🔴 {criticals} critical  🟠 {highs} high  🟡 {mediums} medium\n")

def get_exit_code(findings: list[Finding]) -> int:
    for f in findings:
        if f.severity in ("CRITICAL", "HIGH"):
            return 1
    return 0