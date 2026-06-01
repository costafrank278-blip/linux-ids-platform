"""Endpoints para gerenciar alertas"""

from flask import Blueprint, jsonify, request
from backend.database import get_db_connection
from datetime import datetime, timedelta

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/', methods=['GET'])
def get_alerts():
    """Retorna todos os alertas com filtros opcionais"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Filtros
        threat_type = request.args.get('threat_type')
        severity = request.args.get('severity')
        status = request.args.get('status', 'new')
        limit = int(request.args.get('limit', 100))
        
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
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@alerts_bp.route('/<int:alert_id>/status', methods=['PUT'])
def update_alert_status(alert_id):
    """Atualiza o status de um alerta"""
    try:
        data = request.json
        new_status = data.get('status')
        
        if not new_status:
            return jsonify({'error': 'Status é obrigatório'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE alerts SET status = ? WHERE id = ?', (new_status, alert_id))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Status atualizado com sucesso'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
    except Exception as e:
        return jsonify({'error': str(e)}), 500
