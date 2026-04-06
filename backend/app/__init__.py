from flask import Flask
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    CORS(app)  
    
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file
    app.config['UPLOAD_FOLDER'] = 'uploads'

    from .main import main_bp
    app.register_blueprint(main_bp)
    
    return app