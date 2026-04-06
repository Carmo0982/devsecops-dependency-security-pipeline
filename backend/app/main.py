import os
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from .scanner import scan_requirements

main_bp = Blueprint('main', __name__)

os.makedirs('uploads', exist_ok=True)

@main_bp.route('/health', methods=['GET'])
def health():
    """Endpoint para verificar que el backend está vivo"""
    return jsonify({"status": "ok", "message": "Backend funcionando"})

@main_bp.route('/scan', methods=['POST'])
def scan():
    """
    Endpoint para escanear un archivo requirements.txt
    Uso: POST con archivo en campo 'file'
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No se envió ningún archivo"}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({"error": "Nombre de archivo vacío"}), 400
        
        if not file.filename.endswith('.txt'):
            return jsonify({"error": "Solo se aceptan archivos .txt"}), 400
        
  
        filename = secure_filename(file.filename)
        filepath = os.path.join('uploads', filename)
        file.save(filepath)
        
        result = scan_requirements(filepath)

        os.remove(filepath)
        
        return jsonify(result.to_dict()), 200 if result.status == "passed" else 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route('/scan-example', methods=['GET'])
def scan_example():
    """
    Endpoint de ejemplo que escanea un requirements.txt vulnerable
    Útil para probar sin subir archivos
    """
    
    example_content = """flask==1.0.2
requests==2.20.0
numpy==1.16.0"""
    
    example_path = 'uploads/example_requirements.txt'
    with open(example_path, 'w') as f:
        f.write(example_content)
    
    result = scan_requirements(example_path)
    os.remove(example_path)
    
    return jsonify(result.to_dict()), 200