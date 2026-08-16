#!/usr/bin/env python3
"""
Cybersecurity Toolkit - Web Dashboard Server
===========================================
Servidor Flask para visualización en tiempo real de escaneos, análisis de malware y eventos forenses.
"""

import os
import sys
import json
from datetime import datetime
from flask import Flask, render_template, jsonify, request

# Asegurar path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.security.password_analyzer import PasswordAnalyzer

app = Flask(__name__, template_folder="templates")


def load_recent_data():
    """Carga resultados recientes o datos sintéticos para el panel."""
    return {
        "summary": {
            "total_scans": 42,
            "vulnerabilities_detected": 15,
            "critical_risk_nodes": 2,
            "system_health": "92%"
        },
        "recent_scans": [
            {"target": "192.168.1.1", "status": "Clean", "open_ports": 3, "risk_score": 12.0, "time": "10:45 AM"},
            {"target": "192.168.1.105", "status": "Vulnerable", "open_ports": 7, "risk_score": 78.5, "time": "11:20 AM"},
            {"target": "10.0.0.1", "status": "Moderate", "open_ports": 5, "risk_score": 45.0, "time": "12:05 PM"},
            {"target": "127.0.0.1", "status": "Secure", "open_ports": 2, "risk_score": 5.0, "time": "12:30 PM"}
        ],
        "vulnerabilities": [
            {"id": "CVE-2021-44228", "title": "Log4Shell RCE", "severity": "CRITICAL", "cvss": 10.0, "host": "192.168.1.105"},
            {"id": "CVE-2021-34527", "title": "PrintNightmare", "severity": "HIGH", "cvss": 8.8, "host": "192.168.1.105"},
            {"id": "CVE-2014-0160", "title": "Heartbleed OpenSSL", "severity": "MEDIUM", "cvss": 7.5, "host": "10.0.0.1"}
        ]
    }


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/scan-results")
def api_scan_results():
    data = load_recent_data()
    return jsonify(data)


@app.route("/api/statistics")
def api_statistics():
    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "metrics": {
            "scans_completed_24h": 128,
            "threats_neutralized": 19,
            "integrity_status": "Monitored & Valid",
            "active_agents": 4
        }
    })


@app.route("/api/analyze-password", methods=["POST"])
def api_analyze_password():
    data = request.get_json() or {}
    pwd = data.get("password", "")
    analyzer = PasswordAnalyzer()
    report = analyzer.analyze(pwd)
    return jsonify(report.to_dict())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Iniciando Dashboard Web de Ciberseguridad en http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
