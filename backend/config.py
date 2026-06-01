"""Configuração da aplicação Flask"""

import os

class Config:
    """Configurações base"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    FLASK_ENV = os.environ.get('FLASK_ENV') or 'development'
    DEBUG = FLASK_ENV == 'development'
    
    # Database
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ids_platform.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Logging
    LOG_FILE = 'logs/app.log'
    LOG_LEVEL = 'INFO'
    
    # IDS Configuration
    BRUTE_FORCE_THRESHOLD = 5  # Tentativas falhadas
    BRUTE_FORCE_WINDOW = 300  # Segundos (5 minutos)
    PORT_SCAN_THRESHOLD = 10  # Portas
    PORT_SCAN_WINDOW = 60  # Segundos
    
    # API
    MAX_RESULTS = 1000
    RESULTS_PER_PAGE = 50

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
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

# Selecionar configuração baseada no ambiente
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
