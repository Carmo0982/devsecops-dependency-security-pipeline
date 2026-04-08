import os
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
from .scanner import scan_requirements

main_bp = Blueprint('main', __name__)

@main_bp.route('/health', methods=['GET'])
def health():
    """Endpoint para verificar que el backend está vivo"""
    return jsonify({"status": "ok", "message": "Backend funcionando"})

@main_bp.route('/', methods=['GET'])
def index():
    """Endpoint raiz para orientar al usuario cuando abre la API en el navegador."""
    return jsonify({
        "name": "Dependency Security Backend API",
        "status": "running",
        "docs": {
            "health": "/health",
            "scan_example": "/scan-example",
            "scan_upload": "/scan"
        },
        "frontend_hint": "El frontend se sirve por separado (por ejemplo http://localhost:5500)."
    }), 200

@main_bp.route('/scan', methods=['POST'])
def scan():
    """
    Endpoint para escanear un archivo requirements.txt
    Uso: POST con archivo en campo 'file'
    """
    filepath = None
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No se envió ningún archivo"}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({"error": "Nombre de archivo vacío"}), 400
        
        if not file.filename.endswith('.txt'):
            return jsonify({"error": "Solo se aceptan archivos .txt"}), 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        result = scan_requirements(filepath)

        if result.status == "error":
            return jsonify(result.to_dict()), 500

        return jsonify(result.to_dict()), 422 if result.status == "failed" else 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if filepath and os.path.exists(filepath):
            os.remove(filepath)

@main_bp.route('/scan-example', methods=['GET'])
def scan_example():
    """
    Endpoint de ejemplo que escanea un requirements.txt vulnerable
    Útil para probar sin subir archivos
    """
    
    example_content = """flask==1.0.2
requests==2.20.0
numpy==1.16.0"""
    
    example_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'example_requirements.txt')
    with open(example_path, 'w') as f:
        f.write(example_content)

    try:
        result = scan_requirements(example_path)
        if result.status == "error":
            return jsonify(result.to_dict()), 500

        return jsonify(result.to_dict()), 422 if result.status == "failed" else 200
    finally:
        if os.path.exists(example_path):
            os.remove(example_path)