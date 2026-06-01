"""Módulo de análise de ameaças"""

from datetime import datetime, timedelta
from collections import defaultdict
import re

class ThreatAnalyzer:
    """Analisador de ameaças para detectar padrões de ataque"""
    
    def __init__(self, brute_force_threshold=5, brute_force_window=300):
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window = brute_force_window
        self.failed_attempts = defaultdict(list)  # IP -> [timestamps]
        self.port_scans = defaultdict(list)  # IP -> [portas]
        
    def detect_brute_force(self, ip, failed=True):
        """
        Detecta tentativas de força bruta
        
        Args:
            ip: Endereço IP da origem
            failed: Se a tentativa falhou (True) ou sucedeu (False)
            
        Returns:
            dict: Informações sobre o ataque detectado ou None
        """
        if not failed:
            # Limpar tentativas se login bem-sucedido
            if ip in self.failed_attempts:
                del self.failed_attempts[ip]
            return None
        
        now = datetime.now()
        self.failed_attempts[ip].append(now)
        
        # Remover tentativas antigas
        self.failed_attempts[ip] = [
            ts for ts in self.failed_attempts[ip]
            if (now - ts).total_seconds() < self.brute_force_window
        ]
        
        # Verificar se ultrapassou o limite
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
        """
        Detecta tentativas de escalação de privilégio
        
        Args:
            user: Nome do usuário
            command: Comando executado
            
        Returns:
            dict: Informações sobre o ataque ou None
        """
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
        """
        Detecta varredura de portas (port scanning)
        
        Args:
            ip: Endereço IP da origem
            port: Porta acessada
            
        Returns:
            dict: Informações sobre o ataque ou None
        """
        now = datetime.now()
        self.port_scans[ip].append((port, now))
        
        # Remover acessos antigos (últimos 60 segundos)
        self.port_scans[ip] = [
            (p, ts) for p, ts in self.port_scans[ip]
            if (now - ts).total_seconds() < 60
        ]
        
        # Detectar múltiplos acessos a portas diferentes
        unique_ports = set(p for p, _ in self.port_scans[ip])
        
        if len(unique_ports) >= 10:
            return {
                'type': 'port_scan',
                'severity': 'high',
                'source_ip': ip,
                'unique_ports': len(unique_ports),
                'ports': sorted(list(unique_ports)),
                'description': f'Detectada varredura de portas de {ip}: {len(unique_ports)} portas diferentes em 60s'
            }
        
        return None
    
    def detect_unusual_access_time(self, user, current_time):
        """
        Detecta acessos em horários incomuns
        
        Args:
            user: Nome do usuário
            current_time: Hora do acesso
            
        Returns:
            dict: Informações sobre o ataque ou None
        """
        hour = current_time.hour
        
        # Considerar 00:00-06:00 como horários incomuns
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
        """
        Analisa entrada de log de login falhado
        
        Args:
            log_entry: dict com dados do log
            
        Returns:
            list: Lista de alertas detectados
        """
        alerts = []
        
        # Extrair informações
        ip = log_entry.get('source_ip')
        user = log_entry.get('user', 'unknown')
        
        if ip:
            # Verificar força bruta
            brute_force = self.detect_brute_force(ip, failed=True)
            if brute_force:
                alerts.append(brute_force)
        
        return alerts
    
    def analyze_successful_login(self, log_entry):
        """
        Analisa entrada de log de login bem-sucedido
        
        Args:
            log_entry: dict com dados do log
            
        Returns:
            list: Lista de alertas detectados
        """
        alerts = []
        
        ip = log_entry.get('source_ip')
        user = log_entry.get('user', 'unknown')
        access_time = log_entry.get('timestamp', datetime.now())
        
        # Limpar tentativas de força bruta
        if ip:
            self.detect_brute_force(ip, failed=False)
        
        # Verificar horário incomum
        unusual_time = self.detect_unusual_access_time(user, access_time)
        if unusual_time:
            alerts.append(unusual_time)
        
        return alerts

# Instância global
threat_analyzer = ThreatAnalyzer()
