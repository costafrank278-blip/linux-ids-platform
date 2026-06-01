"""Aplicação Flask principal"""

import os
import sys

try:
    from backend.config import config
    from backend.database import init_database, get_db_connection
    from backend.routes import alerts_bp, stats_bp, logs_bp
    from logs_collector.auth_monitor import AuthMonitor
except ModuleNotFoundError:
    if __name__ == '__main__':
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        from backend.config import config
        from backend.database import init_database, get_db_connection
        from backend.routes import alerts_bp, stats_bp, logs_bp
        from logs_collector.auth_monitor import AuthMonitor
    else:
        raise

from flask import Flask, jsonify
from flask_cors import CORS


def create_app(config_name='development'):
    """Factory para criar a aplicação Flask"""
    app = Flask(
        __name__,
        static_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend')),
        static_url_path=''
    )

    app.config.from_object(config[config_name])
    if config_name == 'production' and not app.config.get('SECRET_KEY'):
        raise ValueError('SECRET_KEY must be set in production')

    CORS(app)
    init_database()

    app.register_blueprint(alerts_bp, url_prefix='/api/alerts')
    app.register_blueprint(stats_bp, url_prefix='/api/stats')
    app.register_blueprint(logs_bp, url_prefix='/api/logs')

    @app.route('/', methods=['GET'])
    def index():
        return app.send_static_file('index.html')

    @app.route('/api', methods=['GET'])
    def api_index():
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
        except Exception:
            return jsonify({'status': 'unhealthy', 'error': 'database connection failed'}), 500

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint não encontrado'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Erro interno do servidor'}), 500

    return app


if __name__ == '__main__':
    env_name = os.environ.get('FLASK_ENV', 'development')
    app = create_app(env_name)

    monitor = AuthMonitor(log_file=app.config.get('AUTH_LOG_FILE', '/var/log/auth.log'))
    monitor.start()

    try:
        print("🚀 Iniciando IDS Platform na porta 5000...")
        app.run(
            host=app.config.get('HOST', '0.0.0.0'),
            port=app.config.get('PORT', 5000),
            debug=app.config.get('DEBUG', False),
            use_reloader=False
        )
    finally:
        monitor.stop()
