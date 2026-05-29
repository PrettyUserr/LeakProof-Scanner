import re
from core.finding import Finding

SECRET_PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": r'AKIA[A-Z0-9]{16}',
        "severity": "CRITICAL",
        "remediation": (
            "Immediately revoke this key in AWS Console → IAM → "
            "Users → Security credentials → Delete access key. "
            "Then rotate any systems that used it."
        )
    },
    {
        "name": "AWS Secret Key",
        "pattern": r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]',
        "severity": "CRITICAL",
        "remediation": (
            "Immediately revoke in AWS Console → IAM → "
            "Users → Security credentials → Delete access key."
        )
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": r'ghp_[a-zA-Z0-9]{36}',
        "severity": "CRITICAL",
        "remediation": (
            "Revoke immediately at github.com → Settings → "
            "Developer settings → Personal access tokens → Delete."
        )
    },
    {
        "name": "GitHub OAuth Token",
        "pattern": r'gho_[a-zA-Z0-9]{36}',
        "severity": "CRITICAL",
        "remediation": (
            "Revoke immediately at github.com → Settings → "
            "Developer settings → Personal access tokens → Delete."
        )
    },
    {
        "name": "Slack Token",
        "pattern": r'xox[baprs]-[0-9a-zA-Z\-]{10,72}',
        "severity": "HIGH",
        "remediation": (
            "Revoke at api.slack.com → Your Apps → "
            "OAuth & Permissions → Revoke token."
        )
    },
    {
        "name": "Generic API Key",
        "pattern": r'(?i)(api_key|apikey|api-key)\s*[=:]\s*[\'"][a-zA-Z0-9]{16,64}[\'"]',
        "severity": "HIGH",
        "remediation": (
            "Identify which service this key belongs to and "
            "revoke it immediately from that service's dashboard."
        )
    },
    {
        "name": "Generic Password",
        "pattern": r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]',
        "severity": "HIGH",
        "remediation": (
            "Change this password immediately in the relevant "
            "service. Never hardcode passwords — use environment "
            "variables or a secrets manager like AWS Secrets Manager."
        )
    },
    {
        "name": "Database Connection String",
        "pattern": r'(?i)(mysql|postgresql|mongodb|redis):\/\/[^\s\'"]+:[^\s\'"]+@',
        "severity": "CRITICAL",
        "remediation": (
            "Rotate the database password immediately. Move the "
            "connection string to an environment variable or "
            "AWS Secrets Manager."
        )
    },
    {
        "name": "Private Key Header",
        "pattern": r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "severity": "CRITICAL",
        "remediation": (
            "This private key is now compromised. Generate a new "
            "key pair immediately and revoke the old one from all "
            "services that trusted it."
        )
    },
    {
        "name": "Google API Key",
        "pattern": r'AIza[0-9A-Za-z\-_]{35}',
        "severity": "HIGH",
        "remediation": (
            "Revoke at console.cloud.google.com → APIs & Services "
            "→ Credentials → Delete key."
        )
    },
]

def scan_line_for_patterns(
    line: str,
    line_number: int,
    file_path: str
) -> list[Finding]:

    findings = []

    for secret in SECRET_PATTERNS:
        match = re.search(secret["pattern"], line)
        if match:
            findings.append(Finding(
                file_path=file_path,
                line_number=line_number,
                secret_type=secret["name"],
                matched_value=match.group(),
                detection_method="Pattern Match",
                severity=secret["severity"],
                remediation=secret["remediation"]
            ))

    return findings