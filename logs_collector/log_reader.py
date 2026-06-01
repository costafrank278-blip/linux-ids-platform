"""Leitor de logs do sistema"""

import os
import re
from datetime import datetime


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
            'raw': line.strip(),
            'timestamp_raw': timestamp_str,
        }

    def parse_ssh_log(self, log_entry):
        """Extrai informações de SSH logs"""
        message = log_entry.get('message', '')
        result = {
            'type': None,
            'user': None,
            'source_ip': None,
            'source_port': None,
            'status': None
        }

        if 'Failed password' in message or 'Invalid user' in message:
            result['type'] = 'failed_login'
            result['status'] = 'failed'

            ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', message)
            if ip_match:
                result['source_ip'] = ip_match.group(1)

            user_match = re.search(r'for\s+(?:invalid user\s+)?(\w+)', message)
            if user_match:
                result['user'] = user_match.group(1)

        elif 'Accepted' in message:
            result['type'] = 'successful_login'
            result['status'] = 'success'

            ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', message)
            if ip_match:
                result['source_ip'] = ip_match.group(1)

            user_match = re.search(r'for\s+(\w+)', message)
            if user_match:
                result['user'] = user_match.group(1)

        port_match = re.search(r'port\s+(\d+)', message)
        if port_match:
            result['source_port'] = int(port_match.group(1))

        return result if result['type'] else None

    def parse_sudo_log(self, log_entry):
        """Extrai informações de SUDO logs"""
        message = log_entry.get('message', '')
        process = (log_entry.get('process') or '').lower()

        if process != 'sudo' and 'COMMAND=' not in message:
            return None

        result = {
            'type': 'sudo_command',
            'user': None,
            'command': None,
            'status': 'unknown'
        }

        user_match = re.search(r'^(\w+)\s*:\s*', message)
        if user_match:
            result['user'] = user_match.group(1)

        cmd_match = re.search(r'COMMAND=(.*)$', message)
        if cmd_match:
            result['command'] = cmd_match.group(1).strip()

        if 'denied' in message.lower():
            result['status'] = 'denied'
        elif result['command']:
            result['status'] = 'allowed'

        return result
