import subprocess
import json
import os
from .models import Vulnerability, ScanResult

def scan_requirements(file_path: str) -> ScanResult:
    """
    Escanea un archivo requirements.txt usando safety
    """
    vulnerabilities = []
    
    try:
        result = subprocess.run(
            ["safety", "check", "-r", file_path, "--json"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            try:
                safety_output = json.loads(result.stdout)
                items = safety_output if isinstance(safety_output, list) else safety_output.get("vulnerabilities", [])

                for vuln in items:
                    vulnerability = Vulnerability(
                        package_name=vuln.get("package_name", "unknown"),
                        version=vuln.get("installed_version", "unknown"),
                        vulnerability_id=vuln.get("vulnerability_id", "unknown"),
                        severity=_map_severity(vuln.get("severity", "unknown")),
                        description=vuln.get("description", "No description available")[:200],
                        fixed_version=vuln.get("fixed_versions", [None])[0] if vuln.get("fixed_versions") else None
                    )
                    vulnerabilities.append(vulnerability)
            except json.JSONDecodeError:
                return ScanResult(
                    status="error",
                    vulnerabilities=[],
                    total_count=0
                )

        if result.returncode not in (0, 1, 64):
            return ScanResult(
                status="error",
                vulnerabilities=[],
                total_count=0
            )
        
        status = "failed" if vulnerabilities else "passed"
        
        return ScanResult(
            status=status,
            vulnerabilities=vulnerabilities,
            total_count=len(vulnerabilities)
        )
        
    except Exception as e:
        return ScanResult(
            status="error",
            vulnerabilities=[],
            total_count=0
        )

def _map_severity(severity_str: str) -> str:
    """Mapea severidades de safety a niveles estándar"""
    severity_map = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW"
    }
    return severity_map.get(severity_str.lower(), "MEDIUM")