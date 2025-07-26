# Configurações do Sistema No-Phishing
# Sistema Avançado de Proteção contra Golpes e Phishing

import os
from datetime import datetime


class Config:
    """Configurações centralizadas do sistema"""

    # Configurações básicas
    APP_NAME = "No-Phishing"
    APP_VERSION = "2.0.0"
    APP_DESCRIPTION = "Sistema Avançado de Proteção contra Golpes e Phishing"

    # Configurações do servidor
    HOST = "127.0.0.1"
    PORT = 5000
    DEBUG = True

    # Configurações de segurança
    SECRET_KEY = os.environ.get(
        'SECRET_KEY', 'sua-chave-secreta-aqui-mude-em-producao')

    # Configurações de análise
    MAX_MESSAGE_LENGTH = 5000
    ANALYSIS_TIMEOUT = 30  # segundos

    # Configurações de logging
    LOG_LEVEL = "INFO"
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

    # Configurações de cache
    CACHE_ENABLED = True
    CACHE_TIMEOUT = 3600  # 1 hora

    # Configurações de detecção
    MIN_RISK_SCORE = 0
    MAX_RISK_SCORE = 100
    CRITICAL_RISK_THRESHOLD = 80
    HIGH_RISK_THRESHOLD = 60
    MEDIUM_RISK_THRESHOLD = 40
    LOW_RISK_THRESHOLD = 20

    # Configurações de domínios
    MAX_DOMAIN_LENGTH = 253
    MAX_SUBDOMAIN_LENGTH = 63

    # Configurações de URLs
    MAX_URL_LENGTH = 2048
    ALLOWED_URL_SCHEMES = ['http', 'https']

    # Configurações de análise de texto
    MAX_WORDS_ANALYSIS = 10000
    MIN_WORD_LENGTH = 2

    # Configurações de performance
    MAX_CONCURRENT_ANALYSES = 10
    ANALYSIS_TIMEOUT_SECONDS = 30

    # Configurações de interface
    THEME_DEFAULT = "light"
    THEME_OPTIONS = ["light", "dark", "auto"]

    # Configurações de relatórios
    REPORT_ENABLED = True
    REPORT_FORMAT = "json"
    REPORT_RETENTION_DAYS = 30

    # Configurações de atualização
    AUTO_UPDATE_ENABLED = False
    UPDATE_CHECK_INTERVAL = 86400  # 24 horas

    # Configurações de backup
    BACKUP_ENABLED = True
    BACKUP_INTERVAL = 604800  # 7 dias

    @classmethod
    def get_risk_level(cls, score):
        """Determina o nível de risco baseado no score"""
        if score >= cls.CRITICAL_RISK_THRESHOLD:
            return "danger", "CRÍTICO"
        elif score >= cls.HIGH_RISK_THRESHOLD:
            return "danger", "ALTO"
        elif score >= cls.MEDIUM_RISK_THRESHOLD:
            return "warning", "MÉDIO"
        elif score >= cls.LOW_RISK_THRESHOLD:
            return "warning", "BAIXO"
        else:
            return "safe", "SEGURO"

    @classmethod
    def get_app_info(cls):
        """Retorna informações da aplicação"""
        return {
            "name": cls.APP_NAME,
            "version": cls.APP_VERSION,
            "description": cls.APP_DESCRIPTION,
            "timestamp": datetime.now().isoformat(),
            "config": {
                "max_message_length": cls.MAX_MESSAGE_LENGTH,
                "analysis_timeout": cls.ANALYSIS_TIMEOUT,
                "cache_enabled": cls.CACHE_ENABLED,
                "report_enabled": cls.REPORT_ENABLED
            }
        }
