import subprocess
import json
import sys
import os
import argparse
from datetime import datetime

def scan_requirements(file_path):
    if not os.path.exists(file_path):
        print(f"Error: El archivo {file_path} no existe")
        return None, "missing_file"
    
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
                
                if 'vulnerabilities' in data:
                    items = data['vulnerabilities']
                else:
                    items = data if isinstance(data, list) else data.get('vulnerabilities', [])
                
                for vuln in items:
                    vulnerabilities.append({
                        'package': vuln.get('package_name', 'unknown'),
                        'version': vuln.get('analyzed_version', 'unknown'),
                        'cve': vuln.get('CVE', vuln.get('vulnerability_id', 'unknown')),
                        'severity': vuln.get('severity', 'unknown'),
                        'description': vuln.get('advisory', '')[:100]
                    })
            except json.JSONDecodeError:
                return None, "invalid_output"

        if result.returncode not in (0, 1, 64) and not vulnerabilities:
            return None, result.stderr.strip() or 'safety_failed'
        
        return vulnerabilities, None
        
    except Exception as e:
        print(f"Error durante el escaneo: {e}")
        return None, "exception"

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
    parser = argparse.ArgumentParser(description='Escaner de seguridad de dependencias')
    parser.add_argument('file', help='Ruta al archivo requirements.txt')
    parser.add_argument('--json', action='store_true', help='Salida en formato JSON')
    parser.add_argument('--fail-on-vuln', action='store_true', help='Retornar codigo de error si hay vulnerabilidades')
    
    args = parser.parse_args()
    
    vulnerabilities, error = scan_requirements(args.file)
    
    if error == "missing_file":
        sys.exit(1)

    if vulnerabilities is None:
        if error and error != "missing_file":
            print(f"Error: {error}")
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
    elif error:
        sys.exit(2)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()