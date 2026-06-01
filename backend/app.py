"""Aplicação Flask principal"""

from flask import Flask, jsonify
from flask_cors import CORS
from backend.config import config
from backend.database import init_database, get_db_connection
from backend.routes import alerts_bp, stats_bp, logs_bp
from logs_collector.auth_monitor import AuthMonitor
import os

def create_app(config_name='development'):
    """Factory para criar a aplicação Flask"""
    app = Flask(__name__)
    
    # Carregar configuração
    app.config.from_object(config[config_name])
    
    # CORS
    CORS(app)
    
    # Inicializar banco de dados
    init_database()
    
    # Registrar blueprints (rotas)
    app.register_blueprint(alerts_bp, url_prefix='/api/alerts')
    app.register_blueprint(stats_bp, url_prefix='/api/stats')
    app.register_blueprint(logs_bp, url_prefix='/api/logs')
    
    # Rotas base
    @app.route('/', methods=['GET'])
    def index():
        return jsonify({
            'name': 'Linux IDS Platform API',
            'version': '1.0.0',
            'status': 'running'
        })
    
    @app.route('/health', methods=['GET'])
    def health():
        try:
            conn = get_db_connection()
            conn.close()
            return jsonify({'status': 'healthy', 'database': 'connected'})
        except Exception as e:
            return jsonify({'status': 'unhealthy', 'error': str(e)}), 500
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint não encontrado'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Erro interno do servidor'}), 500
    
    return app

if __name__ == '__main__':
    app = create_app()
    
    # Iniciar monitor de logs
    monitor = AuthMonitor()
    monitor.start()
    
    try:
        print("🚀 Iniciando IDS Platform na porta 5000...")
        app.run(host='0.0.0.0', port=5000, debug=True)
    finally:
        monitor.stop()
