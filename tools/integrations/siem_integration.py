"""
SIEM Integration Module
=======================
Módulo para transmitir alertas y hallazgos a plataformas SIEM como Elasticsearch, Splunk y Syslog.
"""

import os
import sys
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime

# Safe stdout reconfigure
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger(__name__)


class SIEMIntegration:
    """
    Integrador de eventos con plataformas SIEM (Security Information and Event Management).
    """

    def __init__(
        self,
        es_host: Optional[str] = None,
        splunk_url: Optional[str] = None,
        splunk_token: Optional[str] = None,
        webhook_url: Optional[str] = None
    ):
        self.es_host = es_host or os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")
        self.splunk_url = splunk_url or os.getenv("SPLUNK_HEC_URL")
        self.splunk_token = splunk_token or os.getenv("SPLUNK_HEC_TOKEN")
        self.webhook_url = webhook_url or os.getenv("SIEM_WEBHOOK_URL")

    def format_event(self, event_type: str, severity: str, source_tool: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Formatea un evento al estándar JSON estructurado para SIEM."""
        return {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event": {
                "kind": "alert",
                "category": "security_audit",
                "type": event_type,
                "severity": severity.upper(),
                "module": source_tool
            },
            "cybersecurity_toolkit": {
                "version": "2.0.0",
                "details": details
            }
        }

    def send_to_elasticsearch(self, document: Dict[str, Any], index_name: str = "security-events") -> Dict[str, Any]:
        """Envía un documento o alerta al cluster de Elasticsearch."""
        if not HAS_REQUESTS:
            return {"status": "error", "message": "requests library is required"}

        url = f"{self.es_host.rstrip('/')}/{index_name}/_doc"
        try:
            resp = requests.post(url, json=document, headers={"Content-Type": "application/json"}, timeout=5.0)
            return {"status": "success", "status_code": resp.status_code, "response": resp.json()}
        except Exception as e:
            logger.debug(f"Elasticsearch connection failed: {e}")
            return {"status": "error", "message": str(e)}

    def send_to_splunk(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Envía un evento a Splunk mediante HTTP Event Collector (HEC)."""
        if not HAS_REQUESTS or not self.splunk_url or not self.splunk_token:
            return {"status": "skipped", "message": "Splunk credentials or requests missing"}

        headers = {
            "Authorization": f"Splunk {self.splunk_token}",
            "Content-Type": "application/json"
        }
        payload = {"event": event_data}
        try:
            resp = requests.post(self.splunk_url, json=payload, headers=headers, timeout=5.0)
            return {"status": "success", "status_code": resp.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def export_to_file(self, event_data: Dict[str, Any], file_path: str = "siem_events.jsonl") -> str:
        """Guarda eventos de seguridad en formato JSONL para ingestión masiva."""
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_data) + "\n")
        return os.path.abspath(file_path)
