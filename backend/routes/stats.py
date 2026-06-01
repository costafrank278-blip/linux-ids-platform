"""Endpoints para estatísticas"""

from flask import Blueprint, jsonify
from backend.database import get_db_connection
from datetime import datetime, timedelta

stats_bp = Blueprint('stats', __name__)

@stats_bp.route('/overview', methods=['GET'])
def overview():
    """Retorna visão geral das estatísticas"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total de alertas
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total_alerts = cursor.fetchone()[0]
        
        # Alertas nos últimos 24h
        cursor.execute('''
            SELECT COUNT(*) FROM alerts 
            WHERE timestamp > datetime('now', '-24 hours')
        ''')
        alerts_24h = cursor.fetchone()[0]
        
        # Alertas críticos
        cursor.execute("""
            SELECT COUNT(*) FROM alerts WHERE severity = 'critical'
        """)
        critical_alerts = cursor.fetchone()[0]
        
        # IPs únicos
        cursor.execute('SELECT COUNT(DISTINCT source_ip) FROM alerts')
        unique_ips = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_alerts': total_alerts,
            'alerts_24h': alerts_24h,
            'critical_alerts': critical_alerts,
            'unique_source_ips': unique_ips
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@stats_bp.route('/by-type', methods=['GET'])
def by_type():
    """Retorna alertas agrupados por tipo"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT threat_type, COUNT(*) as count
            FROM alerts
            GROUP BY threat_type
            ORDER BY count DESC
        ''')
        rows = cursor.fetchall()
        conn.close()
        
        stats = [{'type': row[0], 'count': row[1]} for row in rows]
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@stats_bp.route('/by-severity', methods=['GET'])
def by_severity():
    """Retorna alertas agrupados por severidade"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM alerts
            GROUP BY severity
            ORDER BY CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END
        ''')
        rows = cursor.fetchall()
        conn.close()
        
        stats = {row[0]: row[1] for row in rows}
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@stats_bp.route('/top-ips', methods=['GET'])
def top_ips():
    """Retorna os IPs com mais alertas"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count
            FROM alerts
            WHERE source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
        ''')
        rows = cursor.fetchall()
        conn.close()
        
        stats = [{'ip': row[0], 'alert_count': row[1]} for row in rows]
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
