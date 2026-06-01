"""Monitor de eventos de autenticação"""

from datetime import datetime
import os
import threading
import time

from analysis_engine.threat_analyzer import threat_analyzer
from backend.config import config
from backend.database import get_db_connection
from .log_reader import LogReader


class AuthMonitor:
    """Monitora eventos de autenticação e gera alertas"""

    def __init__(self, log_file='/var/log/auth.log'):
        self.log_reader = LogReader(log_file)
        self.running = False
        self.thread = None
        env_name = os.environ.get('FLASK_ENV', 'development')
        cfg = config.get(env_name, config['default'])
        self.poll_interval = cfg.MONITOR_POLL_INTERVAL

    def start(self):
        """Inicia o monitoramento em thread separada"""
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print("✅ Auth Monitor iniciado")

    def stop(self):
        """Para o monitoramento"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("✅ Auth Monitor parado")

    def _monitor_loop(self):
        """Loop principal de monitoramento"""
        while self.running:
            try:
                logs = self.log_reader.read_new_logs()

                for log in logs:
                    ssh_info = self.log_reader.parse_ssh_log(log)
                    if ssh_info:
                        self._process_ssh_log(ssh_info, log)

                    sudo_info = self.log_reader.parse_sudo_log(log)
                    if sudo_info:
                        self._process_sudo_log(sudo_info, log)

                time.sleep(self.poll_interval)

            except Exception as e:
                print(f"Erro no monitor: {e}")
                time.sleep(5)

    def _process_ssh_log(self, ssh_info, log_entry):
        """Processa log SSH e detecta ameaças"""
        alerts = []

        if ssh_info['status'] == 'failed':
            alerts.extend(threat_analyzer.analyze_failed_login({
                'source_ip': ssh_info['source_ip'],
                'source_port': ssh_info.get('source_port'),
                'user': ssh_info['user'],
                'timestamp': log_entry['timestamp']
            }))
        elif ssh_info['status'] == 'success':
            alerts.extend(threat_analyzer.analyze_successful_login({
                'source_ip': ssh_info['source_ip'],
                'source_port': ssh_info.get('source_port'),
                'user': ssh_info['user'],
                'timestamp': log_entry['timestamp']
            }))

        for alert in alerts:
            self._save_alert(alert)

    def _process_sudo_log(self, sudo_info, log_entry):
        """Processa log SUDO e detecta ameaças"""
        alerts = []

        if sudo_info['command']:
            escalation = threat_analyzer.detect_privilege_escalation(
                sudo_info['user'] or 'unknown',
                f"sudo {sudo_info['command']}"
            )
            if escalation:
                alerts.append(escalation)

        for alert in alerts:
            self._save_alert(alert)

    def _save_alert(self, alert):
        """Salva um alerta no banco de dados"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO alerts
                (timestamp, threat_type, severity, source_ip, description, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now(),
                alert.get('type'),
                alert.get('severity', 'medium'),
                alert.get('source_ip', 'unknown'),
                alert.get('description'),
                'new'
            ))

            conn.commit()
            conn.close()

            print(f"🚨 Alerta criado: {alert['description']}")
        except Exception as e:
            print(f"Erro ao salvar alerta: {e}")
