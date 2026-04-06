import subprocess
import json
import sys
import os
import argparse
from datetime import datetime

def scan_requirements(file_path):
    if not os.path.exists(file_path):
        print(f"Error: El archivo {file_path} no existe")
        return None
    
    print(f"Escaneando: {file_path}")
    print("-" * 50)
    
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'safety', 'check', '-r', file_path, '--json'],
            capture_output=True, text=True
        )
        
        vulnerabilities = []
        
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                
                if isinstance(data, list):
                    for vuln in data:
                        vulnerabilities.append({
                            'package': vuln.get('package_name', 'unknown'),
                            'version': vuln.get('installed_version', 'unknown'),
                            'cve': vuln.get('vulnerability_id', 'unknown'),
                            'severity': vuln.get('severity', 'unknown'),
                            'description': vuln.get('description', '')[:100]
                        })
                else:
                    for vuln in data.get('vulnerabilities', []):
                        vulnerabilities.append({
                            'package': vuln.get('package_name', 'unknown'),
                            'version': vuln.get('installed_version', 'unknown'),
                            'cve': vuln.get('vulnerability_id', 'unknown'),
                            'severity': vuln.get('severity', 'unknown'),
                            'description': vuln.get('description', '')[:100]
                        })
            except json.JSONDecodeError:
                pass
        
        return vulnerabilities
        
    except Exception as e:
        print(f"Error durante el escaneo: {e}")
        return None

def print_report(vulnerabilities, file_path):
    print("\n" + "=" * 60)
    print("REPORTE DE SEGURIDAD DE DEPENDENCIAS")
    print("=" * 60)
    print(f"Archivo escaneado: {file_path}")
    print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    
    if not vulnerabilities:
        print("No se encontraron vulnerabilidades")
        print("Estado: PASSED - El pipeline puede continuar")
    else:
        print(f"Se encontraron {len(vulnerabilities)} vulnerabilidades:\n")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{i}. Paquete: {vuln['package']}")
            print(f"   Version: {vuln['version']}")
            print(f"   CVE: {vuln['cve']}")
            print(f"   Severidad: {vuln['severity'] if vuln['severity'] else 'No especificada'}")
            if vuln['description']:
                print(f"   Descripcion: {vuln['description']}...")
            print()
        
        print("-" * 60)
        print("Estado: FAILED - El pipeline debe BLOQUEARSE")
        print("Recomendacion: Actualizar las dependencias vulnerables")
    
    print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description='Escáner de seguridad de dependencias')
    parser.add_argument('file', help='Ruta al archivo requirements.txt')
    parser.add_argument('--json', action='store_true', help='Salida en formato JSON')
    parser.add_argument('--fail-on-vuln', action='store_true', help='Retornar codigo de error si hay vulnerabilidades')
    
    args = parser.parse_args()
    
    vulnerabilities = scan_requirements(args.file)
    
    if vulnerabilities is None:
        sys.exit(1)
    
    if args.json:
        print(json.dumps({
            'vulnerabilities': vulnerabilities,
            'total_count': len(vulnerabilities),
            'status': 'failed' if vulnerabilities else 'passed'
        }, indent=2))
    else:
        print_report(vulnerabilities, args.file)
    
    if args.fail_on_vuln and vulnerabilities:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()