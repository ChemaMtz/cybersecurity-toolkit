"""
Módulo de Integración Empresarial y SIEM
========================================
Conectores para exportación de eventos de seguridad a Elasticsearch, Splunk y Webhooks.
"""

from .siem_integration import SIEMIntegration

__all__ = ["SIEMIntegration"]
