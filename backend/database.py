# Database Configuration
import os
import sqlite3
from contextlib import contextmanager
from backend.config import config


def _resolve_database_path():
    env_name = os.environ.get('FLASK_ENV', 'development')
    cfg = config.get(env_name, config['default'])
    return cfg.DATABASE_PATH


DATABASE_PATH = _resolve_database_path()


def init_database():
    """Inicializa o banco de dados com as tabelas necessárias"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Tabela de Logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_file TEXT,
            log_message TEXT,
            severity TEXT
        )
    ''')

    # Tabela de Alertas
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            threat_type TEXT,
            severity TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            port INTEGER,
            description TEXT,
            status TEXT DEFAULT 'new'
        )
    ''')

    # Tabela de Eventos de Segurança
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT,
            user TEXT,
            ip_address TEXT,
            action TEXT,
            result TEXT
        )
    ''')

    # Tabela de Estatísticas
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS statistics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_alerts INTEGER DEFAULT 0,
            total_events INTEGER DEFAULT 0,
            brute_force_attempts INTEGER DEFAULT 0,
            port_scans INTEGER DEFAULT 0,
            anomalies INTEGER DEFAULT 0
        )
    ''')

    # Criar índices
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_threat_type ON alerts(threat_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity)')

    conn.commit()
    conn.close()
    print(f"✅ Database initialized at {DATABASE_PATH}")


def get_db_connection():
    """Retorna uma conexão com o banco de dados"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_connection():
    """Gerencia conexão com banco de dados automaticamente"""
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()


if __name__ == '__main__':
    init_database()
