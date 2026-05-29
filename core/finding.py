from dataclasses import dataclass

@dataclass
class Finding:
    file_path: str
    line_number: int
    secret_type: str
    matched_value: str
    detection_method: str
    severity: str
    remediation: str