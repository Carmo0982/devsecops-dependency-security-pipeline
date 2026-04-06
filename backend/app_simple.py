from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import json
import os
import sys

app = Flask(__name__)
CORS(app)

os.makedirs('uploads', exist_ok=True)

python_executable = sys.executable
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'message': 'Backend funcionando'})

@app.route('/scan-example', methods=['GET'])
def scan_example():
    example_path = os.path.join(BACKEND_DIR, 'uploads', 'example.txt')
    with open(example_path, 'w') as f:
        f.write('flask==1.0.2\nrequests==2.20.0')
    
    result = subprocess.run(
        [python_executable, '-m', 'safety', 'check', '-r', example_path, '--json'],
        capture_output=True, text=True
    )
    
    os.remove(example_path)
    
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
                        'severity': vuln.get('severity', 'unknown')
                    })
            else:
                for vuln in data.get('vulnerabilities', []):
                    vulnerabilities.append({
                        'package': vuln.get('package_name', 'unknown'),
                        'version': vuln.get('installed_version', 'unknown'),
                        'cve': vuln.get('vulnerability_id', 'unknown'),
                        'severity': vuln.get('severity', 'unknown')
                    })
        except json.JSONDecodeError:
            pass
    
    return jsonify({
        'status': 'failed' if vulnerabilities else 'passed',
        'total_count': len(vulnerabilities),
        'vulnerabilities': vulnerabilities
    })

@app.route('/scan-local', methods=['GET'])
def scan_local():
    test_file_path = os.path.join(BACKEND_DIR, 'test.txt')
    
    if not os.path.exists(test_file_path):
        return jsonify({
            'error': f'El archivo test.txt no existe en {BACKEND_DIR}',
            'expected_path': test_file_path
        }), 404
    
    try:
        result = subprocess.run(
            [python_executable, '-m', 'safety', 'check', '-r', test_file_path, '--json'],
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
                            'fixed_version': vuln.get('fixed_versions', [None])[0] if vuln.get('fixed_versions') else None
                        })
                else:
                    for vuln in data.get('vulnerabilities', []):
                        vulnerabilities.append({
                            'package': vuln.get('package_name', 'unknown'),
                            'version': vuln.get('installed_version', 'unknown'),
                            'cve': vuln.get('vulnerability_id', 'unknown'),
                            'severity': vuln.get('severity', 'unknown'),
                            'fixed_version': vuln.get('fixed_versions', [None])[0] if vuln.get('fixed_versions') else None
                        })
            except json.JSONDecodeError:
                pass
        
        return jsonify({
            'status': 'failed' if vulnerabilities else 'passed',
            'total_count': len(vulnerabilities),
            'scanned_file': test_file_path,
            'vulnerabilities': vulnerabilities
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/scan', methods=['POST'])
def scan():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No se envió ningún archivo'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Nombre de archivo vacío'}), 400
        
        filepath = os.path.join('uploads', file.filename)
        file.save(filepath)
        
        result = subprocess.run(
            [python_executable, '-m', 'safety', 'check', '-r', filepath, '--json'],
            capture_output=True, text=True
        )
        
        os.remove(filepath)
        
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
                            'fixed_version': vuln.get('fixed_versions', [None])[0] if vuln.get('fixed_versions') else None
                        })
                else:
                    for vuln in data.get('vulnerabilities', []):
                        vulnerabilities.append({
                            'package': vuln.get('package_name', 'unknown'),
                            'version': vuln.get('installed_version', 'unknown'),
                            'cve': vuln.get('vulnerability_id', 'unknown'),
                            'severity': vuln.get('severity', 'unknown'),
                            'fixed_version': vuln.get('fixed_versions', [None])[0] if vuln.get('fixed_versions') else None
                        })
            except json.JSONDecodeError:
                pass
        
        return jsonify({
            'status': 'failed' if vulnerabilities else 'passed',
            'total_count': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print('=' * 50)
    print('Servidor iniciando en http://localhost:5000')
    print(f'Usando Python: {python_executable}')
    print(f'Directorio backend: {BACKEND_DIR}')
    print('=' * 50)
    print('Endpoints disponibles:')
    print('  GET  /health       - Verificar estado')
    print('  GET  /scan-example - Escanear ejemplo vulnerable')
    print('  GET  /scan-local   - Escanear test.txt de la carpeta backend')
    print('  POST /scan         - Subir y escanear archivo')
    print('=' * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)