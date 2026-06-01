"""Configurações globais da Linux IDS Platform."""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
BACKEND_DIR = os.path.join(BASE_DIR, 'backend')

SETTINGS = {
    'HOST': os.environ.get('HOST', '0.0.0.0'),
    'PORT': int(os.environ.get('PORT', 5000)),
    'FLASK_ENV': os.environ.get('FLASK_ENV', 'development'),
    'SECRET_KEY': os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production'),
    'DATABASE_PATH': os.environ.get('DATABASE_PATH', os.path.join(BACKEND_DIR, 'ids_platform.db')),
    'AUTH_LOG_FILE': os.environ.get('AUTH_LOG_FILE', '/var/log/auth.log'),
    'LOG_LEVEL': os.environ.get('LOG_LEVEL', 'INFO'),
    'MONITOR_POLL_INTERVAL': float(os.environ.get('MONITOR_POLL_INTERVAL', 1.0)),
    'BRUTE_FORCE_THRESHOLD': int(os.environ.get('BRUTE_FORCE_THRESHOLD', 5)),
    'BRUTE_FORCE_WINDOW': int(os.environ.get('BRUTE_FORCE_WINDOW', 300)),
    'PORT_SCAN_THRESHOLD': int(os.environ.get('PORT_SCAN_THRESHOLD', 10)),
    'PORT_SCAN_WINDOW': int(os.environ.get('PORT_SCAN_WINDOW', 60)),
    'MAX_RESULTS': int(os.environ.get('MAX_RESULTS', 1000)),
    'RESULTS_PER_PAGE': int(os.environ.get('RESULTS_PER_PAGE', 50)),
}
