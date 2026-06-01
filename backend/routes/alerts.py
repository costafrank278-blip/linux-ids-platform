"""Endpoints para gerenciar alertas"""

from flask import Blueprint, jsonify, request, current_app
from backend.database import get_db_connection

alerts_bp = Blueprint('alerts', __name__)


@alerts_bp.route('/', methods=['GET'])
def get_alerts():
    """Retorna todos os alertas com filtros opcionais"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        threat_type = request.args.get('threat_type')
        severity = request.args.get('severity')
        status = request.args.get('status')

        max_limit = current_app.config.get('MAX_RESULTS', 1000)
        limit = int(request.args.get('limit', 100))
        if limit < 1:
            limit = 1
        limit = min(limit, max_limit)

        query = 'SELECT * FROM alerts WHERE 1=1'
        params = []

        if threat_type:
            query += ' AND threat_type = ?'
            params.append(threat_type)

        if severity:
            query += ' AND severity = ?'
            params.append(severity)

        if status:
            query += ' AND status = ?'
            params.append(status)

        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()

        alerts = [dict(row) for row in rows]
        conn.close()

        return jsonify({
            'total': len(alerts),
            'alerts': alerts
        })
    except ValueError:
        return jsonify({'error': 'Parâmetro limit inválido'}), 400
    except Exception:
        return jsonify({'error': 'Erro interno do servidor'}), 500


@alerts_bp.route('/<int:alert_id>', methods=['GET'])
def get_alert(alert_id):
    """Retorna um alerta específico"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return jsonify({'error': 'Alerta não encontrado'}), 404

        return jsonify(dict(row))
    except Exception:
        return jsonify({'error': 'Erro interno do servidor'}), 500


@alerts_bp.route('/<int:alert_id>/status', methods=['PUT'])
def update_alert_status(alert_id):
    """Atualiza o status de um alerta"""
    try:
        data = request.get_json()
        if not isinstance(data, dict):
            return jsonify({'error': 'JSON inválido'}), 400

        new_status = data.get('status')
        if not new_status:
            return jsonify({'error': 'Status é obrigatório'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE alerts SET status = ? WHERE id = ?', (new_status, alert_id))
        conn.commit()

        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Alerta não encontrado'}), 404

        conn.close()
        return jsonify({'message': 'Status atualizado com sucesso'})
    except Exception:
        return jsonify({'error': 'Erro interno do servidor'}), 500


@alerts_bp.route('/count', methods=['GET'])
def count_alerts():
    """Retorna contagem de alertas por tipo"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT threat_type, COUNT(*) as count, severity
            FROM alerts
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY threat_type, severity
        ''')
        rows = cursor.fetchall()
        conn.close()

        counts = {}
        for row in rows:
            threat_type = row[0]
            count = row[1]
            severity = row[2]
            if threat_type not in counts:
                counts[threat_type] = {}
            counts[threat_type][severity] = count

        return jsonify(counts)
    except Exception:
        return jsonify({'error': 'Erro interno do servidor'}), 500
