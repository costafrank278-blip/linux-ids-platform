"""Endpoints para gerenciar logs"""

from flask import Blueprint, jsonify, request
from backend.database import get_db_connection

logs_bp = Blueprint('logs', __name__)


@logs_bp.route('/', methods=['GET'])
def get_logs():
    """Retorna logs com filtros opcionais"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        limit = int(request.args.get('limit', 100))
        severity = request.args.get('severity')
        source_file = request.args.get('source_file')

        query = 'SELECT * FROM logs WHERE 1=1'
        params = []

        if severity:
            query += ' AND severity = ?'
            params.append(severity)

        if source_file:
            query += ' AND source_file = ?'
            params.append(source_file)

        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        logs = [dict(row) for row in rows]
        return jsonify({'total': len(logs), 'logs': logs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@logs_bp.route('/<int:log_id>', methods=['GET'])
def get_log(log_id):
    """Retorna um log específico"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM logs WHERE id = ?', (log_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return jsonify({'error': 'Log não encontrado'}), 404

        return jsonify(dict(row))
    except Exception as e:
        return jsonify({'error': str(e)}), 500
