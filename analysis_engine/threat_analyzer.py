"""Módulo de análise de ameaças"""

from datetime import datetime
from collections import defaultdict
import re


class ThreatAnalyzer:
    """Analisador de ameaças para detectar padrões de ataque"""

    def __init__(
        self,
        brute_force_threshold=5,
        brute_force_window=300,
        port_scan_threshold=10,
        port_scan_window=60,
    ):
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window = brute_force_window
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.failed_attempts = defaultdict(list)  # IP -> [timestamps]
        self.port_scans = defaultdict(list)  # IP -> [(porta, timestamp)]

    def detect_brute_force(self, ip, failed=True):
        """Detecta tentativas de força bruta"""
        if not failed:
            if ip in self.failed_attempts:
                del self.failed_attempts[ip]
            return None

        now = datetime.now()
        self.failed_attempts[ip].append(now)

        self.failed_attempts[ip] = [
            ts for ts in self.failed_attempts[ip]
            if (now - ts).total_seconds() < self.brute_force_window
        ]

        if len(self.failed_attempts[ip]) >= self.brute_force_threshold:
            return {
                'type': 'brute_force',
                'severity': 'high',
                'source_ip': ip,
                'attempts': len(self.failed_attempts[ip]),
                'window_seconds': self.brute_force_window,
                'description': f'Detectadas {len(self.failed_attempts[ip])} tentativas de login falhadas de {ip} em {self.brute_force_window}s'
            }

        return None

    def detect_privilege_escalation(self, user, command):
        """Detecta tentativas de escalação de privilégio"""
        sudo_pattern = r'^sudo\s+|su\s+-'
        suspicious_commands = ['passwd', 'visudo', 'chmod', 'chown', 'usermod']

        if re.search(sudo_pattern, command):
            for suspicious_cmd in suspicious_commands:
                if suspicious_cmd in command:
                    return {
                        'type': 'privilege_escalation',
                        'severity': 'critical',
                        'user': user,
                        'command': command,
                        'description': f'Possível escalação de privilégio: usuário {user} executou {command}'
                    }

        return None

    def detect_port_scan(self, ip, port):
        """Detecta varredura de portas (port scanning)"""
        if not ip or port is None:
            return None

        now = datetime.now()
        self.port_scans[ip].append((int(port), now))

        self.port_scans[ip] = [
            (p, ts) for p, ts in self.port_scans[ip]
            if (now - ts).total_seconds() < self.port_scan_window
        ]

        unique_ports = set(p for p, _ in self.port_scans[ip])

        if len(unique_ports) >= self.port_scan_threshold:
            return {
                'type': 'port_scan',
                'severity': 'high',
                'source_ip': ip,
                'unique_ports': len(unique_ports),
                'ports': sorted(list(unique_ports)),
                'description': f'Detectada varredura de portas de {ip}: {len(unique_ports)} portas diferentes em {self.port_scan_window}s'
            }

        return None

    def detect_unusual_access_time(self, user, current_time):
        """Detecta acessos em horários incomuns"""
        hour = current_time.hour

        if hour < 6:
            return {
                'type': 'unusual_access_time',
                'severity': 'medium',
                'user': user,
                'time': current_time.isoformat(),
                'description': f'Acesso incomum do usuário {user} às {hour}:00'
            }

        return None

    def analyze_failed_login(self, log_entry):
        """Analisa entrada de log de login falhado"""
        alerts = []

        ip = log_entry.get('source_ip')
        source_port = log_entry.get('source_port')

        if ip:
            brute_force = self.detect_brute_force(ip, failed=True)
            if brute_force:
                alerts.append(brute_force)

            port_scan = self.detect_port_scan(ip, source_port)
            if port_scan:
                alerts.append(port_scan)

        return alerts

    def analyze_successful_login(self, log_entry):
        """Analisa entrada de log de login bem-sucedido"""
        alerts = []

        ip = log_entry.get('source_ip')
        user = log_entry.get('user', 'unknown')
        source_port = log_entry.get('source_port')
        access_time = log_entry.get('timestamp', datetime.now())

        if ip:
            self.detect_brute_force(ip, failed=False)

            port_scan = self.detect_port_scan(ip, source_port)
            if port_scan:
                alerts.append(port_scan)

        unusual_time = self.detect_unusual_access_time(user, access_time)
        if unusual_time:
            alerts.append(unusual_time)

        return alerts


# Instância global
threat_analyzer = ThreatAnalyzer()
