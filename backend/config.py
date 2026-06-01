"""Configuração da aplicação Flask"""

import os


class Config:
    """Configurações base"""
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, '..'))

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    FLASK_ENV = os.environ.get('FLASK_ENV') or 'development'
    DEBUG = FLASK_ENV == 'development'

    # Network
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))

    # Database
    DATABASE_PATH = os.environ.get('DATABASE_PATH') or os.path.join(BASE_DIR, 'ids_platform.db')
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DATABASE_PATH}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Logging
    LOG_FILE = os.environ.get('IDS_LOG_FILE') or os.path.join(ROOT_DIR, 'logs', 'app.log')
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

    # IDS Configuration
    AUTH_LOG_FILE = os.environ.get('AUTH_LOG_FILE', '/var/log/auth.log')
    MONITOR_POLL_INTERVAL = float(os.environ.get('MONITOR_POLL_INTERVAL', 1.0))

    BRUTE_FORCE_THRESHOLD = int(os.environ.get('BRUTE_FORCE_THRESHOLD', 5))
    BRUTE_FORCE_WINDOW = int(os.environ.get('BRUTE_FORCE_WINDOW', 300))
    PORT_SCAN_THRESHOLD = int(os.environ.get('PORT_SCAN_THRESHOLD', 10))
    PORT_SCAN_WINDOW = int(os.environ.get('PORT_SCAN_WINDOW', 60))

    # API
    MAX_RESULTS = int(os.environ.get('MAX_RESULTS', 1000))
    RESULTS_PER_PAGE = int(os.environ.get('RESULTS_PER_PAGE', 50))


class DevelopmentConfig(Config):
    """Configurações para desenvolvimento"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Configurações para produção"""
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY must be set in production")


class TestingConfig(Config):
    """Configurações para testes"""
    TESTING = True
    DEBUG = False
    DATABASE_PATH = ':memory:'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


# Selecionar configuração baseada no ambiente
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
