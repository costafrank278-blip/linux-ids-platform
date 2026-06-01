"""Rotas da API"""

from .alerts import alerts_bp
from .stats import stats_bp
from .logs import logs_bp

__all__ = ['alerts_bp', 'stats_bp', 'logs_bp']
