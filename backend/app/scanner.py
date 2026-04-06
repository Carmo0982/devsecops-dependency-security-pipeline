import subprocess
import json
import tempfile
import os
from typing import List
from .models import Vulnerability, ScanResult

def scan_requirements(file_path: str) -> ScanResult:
    """
    Escanea un archivo requirements.txt usando safety
    """
    vulnerabilities = []
    
    try:
        # Usar safety para escanear
        result = subprocess.run(
            ["safety", "check", "-r", file_path, "--json"],
            capture_output=True,
            text=True
        )
        

        if result.stdout:
            safety_output = json.loads(result.stdout)
            
            # Procesar vulnerabilidades
            for vuln in safety_output.get("vulnerabilities", []):
                vulnerability = Vulnerability(
                    package_name=vuln.get("package_name", "unknown"),
                    version=vuln.get("installed_version", "unknown"),
                    vulnerability_id=vuln.get("vulnerability_id", "unknown"),
                    severity=_map_severity(vuln.get("severity", "unknown")),
                    description=vuln.get("description", "No description available")[:200],
                    fixed_version=vuln.get("fixed_versions", [None])[0]
                )
                vulnerabilities.append(vulnerability)
        
        status = "failed" if vulnerabilities else "passed"
        
        return ScanResult(
            status=status,
            vulnerabilities=vulnerabilities,
            total_count=len(vulnerabilities)
        )
        
    except subprocess.CalledProcessError as e:
        # Safety puede fallar pero igual tener output
        if e.stdout:
            try:
                safety_output = json.loads(e.stdout)
                for vuln in safety_output.get("vulnerabilities", []):
                    vulnerability = Vulnerability(
                        package_name=vuln.get("package_name", "unknown"),
                        version=vuln.get("installed_version", "unknown"),
                        vulnerability_id=vuln.get("vulnerability_id", "unknown"),
                        severity=_map_severity(vuln.get("severity", "unknown")),
                        description=vuln.get("description", "No description available")[:200],
                        fixed_version=vuln.get("fixed_versions", [None])[0]
                    )
                    vulnerabilities.append(vulnerability)
                
                return ScanResult(
                    status="failed",
                    vulnerabilities=vulnerabilities,
                    total_count=len(vulnerabilities)
                )
            except:
                pass
        
        return ScanResult(
            status="error",
            vulnerabilities=[],
            total_count=0
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