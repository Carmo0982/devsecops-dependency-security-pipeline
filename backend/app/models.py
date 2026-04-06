from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Vulnerability:
    package_name: str
    version: str
    vulnerability_id: str
    severity: str
    description: str
    fixed_version: Optional[str] = None

    def to_dict(self):
        return {
            "package_name": self.package_name,
            "version": self.version,
            "vulnerability_id": self.vulnerability_id,
            "severity": self.severity,
            "description": self.description,
            "fixed_version": self.fixed_version
        }

@dataclass
class ScanResult:
    status: str
    vulnerabilities: List[Vulnerability]
    total_count: int

    def to_dict(self):
        return {
            "status": self.status,
            "total_count": self.total_count,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities]
        }