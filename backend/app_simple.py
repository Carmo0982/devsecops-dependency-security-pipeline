from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import json
import os
import sys

app = Flask(__name__)
CORS(app)

python_executable = sys.executable
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
os.makedirs(os.path.join(BACKEND_DIR, 'uploads'), exist_ok=True)


def _run_safety_scan(file_path):
    """Ejecuta safety y devuelve vulnerabilidades o una señal de error."""
    result = subprocess.run(
        [python_executable, '-m', 'safety', 'check', '-r', file_path, '--json'],
        capture_output=True, text=True
    )

    vulnerabilities = []
    if result.stdout:
        try:
            data = json.loads(result.stdout)
            items = data if isinstance(data, list) else data.get('vulnerabilities', [])

            for vuln in items:
                vulnerabilities.append({
                    'package': vuln.get('package_name', 'unknown'),
                    'version': vuln.get('installed_version', 'unknown'),
                    'cve': vuln.get('vulnerability_id', 'unknown'),
                    'severity': vuln.get('severity', 'unknown'),
                    'fixed_version': vuln.get('fixed_versions', [None])[0] if vuln.get('fixed_versions') else None
                })
        except json.JSONDecodeError:
            return None, 'No se pudo interpretar la salida de safety'

    # safety puede devolver 64 cuando encuentra vulnerabilidades.
    if result.returncode not in (0, 1, 64):
        return None, result.stderr.strip() or 'Safety falló durante el análisis'

    return vulnerabilities, None

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'message': 'Backend funcionando'})

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'name': 'Dependency Security Backend API',
        'status': 'running',
        'docs': {
            'health': '/health',
            'scan_example': '/scan-example',
            'scan_local': '/scan-local',
            'scan_upload': '/scan'
        },
        'frontend_hint': 'El frontend se sirve por separado (por ejemplo http://localhost:5500).'
    }), 200

@app.route('/scan-example', methods=['GET'])
def scan_example():
    example_path = os.path.join(BACKEND_DIR, 'uploads', 'example.txt')
    with open(example_path, 'w') as f:
        f.write('flask==1.0.2\nrequests==2.20.0')
    
    try:
        vulnerabilities, error = _run_safety_scan(example_path)
        if error:
            return jsonify({'status': 'error', 'error': error}), 500

        return jsonify({
            'status': 'failed' if vulnerabilities else 'passed',
            'total_count': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }), 422 if vulnerabilities else 200
    finally:
        if os.path.exists(example_path):
            os.remove(example_path)

@app.route('/scan-local', methods=['GET'])
def scan_local():
    test_file_path = os.path.join(BACKEND_DIR, 'test.txt')
    
    if not os.path.exists(test_file_path):
        return jsonify({
            'error': f'El archivo test.txt no existe en {BACKEND_DIR}',
            'expected_path': test_file_path
        }), 404
    
    try:
        vulnerabilities, error = _run_safety_scan(test_file_path)
        if error:
            return jsonify({'status': 'error', 'error': error}), 500

        return jsonify({
            'status': 'failed' if vulnerabilities else 'passed',
            'total_count': len(vulnerabilities),
            'scanned_file': test_file_path,
            'vulnerabilities': vulnerabilities
        }), 422 if vulnerabilities else 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/scan', methods=['POST'])
def scan():
    filepath = None
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No se envió ningún archivo'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Nombre de archivo vacío'}), 400
        
        filepath = os.path.join(BACKEND_DIR, 'uploads', file.filename)
        file.save(filepath)
        vulnerabilities, error = _run_safety_scan(filepath)
        if error:
            return jsonify({'status': 'error', 'error': error}), 500

        return jsonify({
            'status': 'failed' if vulnerabilities else 'passed',
            'total_count': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }), 422 if vulnerabilities else 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if filepath and os.path.exists(filepath):
            os.remove(filepath)

if __name__ == '__main__':
    port = int(os.getenv('PORT', '5001'))
    print('=' * 50)
    print(f'Servidor iniciando en http://localhost:{port}')
    print(f'Usando Python: {python_executable}')
    print(f'Directorio backend: {BACKEND_DIR}')
    print('=' * 50)
    print('Endpoints disponibles:')
    print('  GET  /health       - Verificar estado')
    print('  GET  /scan-example - Escanear ejemplo vulnerable')
    print('  GET  /scan-local   - Escanear test.txt de la carpeta backend')
    print('  POST /scan         - Subir y escanear archivo')
    print('=' * 50)
    app.run(debug=True, host='0.0.0.0', port=port)