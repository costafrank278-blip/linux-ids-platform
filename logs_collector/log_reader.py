"""Leitor de logs do sistema"""

import os
import re
from datetime import datetime
from pathlib import Path

class LogReader:
    """Lê e processa logs de segurança do Linux"""
    
    def __init__(self, log_file='/var/log/auth.log'):
        self.log_file = log_file
        self.last_position = 0
        self.file_size = 0
        
    def read_new_logs(self):
        """Lê apenas os novos logs desde a última leitura"""
        if not os.path.exists(self.log_file):
            return []
        
        try:
            current_size = os.path.getsize(self.log_file)
            new_logs = []
            
            with open(self.log_file, 'r', errors='ignore') as f:
                # Se o arquivo foi rotacionado, começar do início
                if current_size < self.last_position:
                    self.last_position = 0
                
                f.seek(self.last_position)
                lines = f.readlines()
                
                for line in lines:
                    parsed = self.parse_log_line(line)
                    if parsed:
                        new_logs.append(parsed)
                
                self.last_position = f.tell()
                self.file_size = current_size
            
            return new_logs
        except Exception as e:
            print(f"Erro ao ler logs: {e}")
            return []
    
    def parse_log_line(self, line):
        """Analisa uma linha de log"""
        if not line.strip():
            return None
        
        # Padrão geral de logs syslog
        pattern = r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([\w\-]+)\[?(\d+)?\]?:\s+(.*)$'
        match = re.match(pattern, line)
        
        if not match:
            return None
        
        timestamp_str, hostname, process, pid, message = match.groups()
        
        return {
            'timestamp': datetime.now(),
            'hostname': hostname,
            'process': process,
            'pid': pid,
            'message': message,
            'raw': line.strip()
        }
    
    def parse_ssh_log(self, log_entry):
        """Extrai informações de SSH logs"""
        message = log_entry.get('message', '')
        result = {
            'type': None,
            'user': None,
            'source_ip': None,
            'status': None
        }
        
        # Falha de autenticação
        if 'Failed password' in message or 'Invalid user' in message:
            result['type'] = 'failed_login'
            result['status'] = 'failed'
            
            # Extrair IP
            ip_pattern = r'from\s+(\d+\.\d+\.\d+\.\d+)'
            ip_match = re.search(ip_pattern, message)
            if ip_match:
                result['source_ip'] = ip_match.group(1)
            
            # Extrair usuário
            user_pattern = r'for\s+(?:invalid user\s+)?(\w+)'
            user_match = re.search(user_pattern, message)
            if user_match:
                result['user'] = user_match.group(1)
        
        # Sucesso de autenticação
        elif 'Accepted' in message:
            result['type'] = 'successful_login'
            result['status'] = 'success'
            
            # Extrair IP
            ip_pattern = r'from\s+(\d+\.\d+\.\d+\.\d+)'
            ip_match = re.search(ip_pattern, message)
            if ip_match:
                result['source_ip'] = ip_match.group(1)
            
            # Extrair usuário
            user_pattern = r'for\s+(\w+)'
            user_match = re.search(user_pattern, message)
            if user_match:
                result['user'] = user_match.group(1)
        
        return result if result['type'] else None
    
    def parse_sudo_log(self, log_entry):
        """Extrai informações de SUDO logs"""
        message = log_entry.get('message', '')
        
        if 'sudo' not in message:
            return None
        
        result = {
            'type': 'sudo_command',
            'user': None,
            'command': None,
            'status': 'unknown'
        }
        
        # Extrair usuário
        user_pattern = r'(\w+)\s+:\s+command'
        user_match = re.search(user_pattern, message)
        if user_match:
            result['user'] = user_match.group(1)
        
        # Extrair comando
        cmd_pattern = r'COMMAND=(.*)$'
        cmd_match = re.search(cmd_pattern, message)
        if cmd_match:
            result['command'] = cmd_match.group(1)
        
        if 'allowed' in message:
            result['status'] = 'allowed'
        elif 'denied' in message:
            result['status'] = 'denied'
        
        return result
