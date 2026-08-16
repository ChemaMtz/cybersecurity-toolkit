"""
Log Analyzer Module
===================
Analizador forense de logs para detección de intrusiones, inyecciones web y fuerza bruta.
"""

import sys
import re
import os
import argparse
import json
import urllib.parse
from typing import List, Dict, Any, Optional
from collections import Counter
from dataclasses import dataclass, asdict

# Configurar encoding seguro para Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass


@dataclass
class SecurityAlert:
    """Alerta de seguridad detectada en una línea de log."""
    line_number: int
    ip: str
    attack_type: str  # 'SQLi', 'XSS', 'Directory Traversal', 'Brute Force', 'Sensitive File Probe'
    severity: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    description: str
    raw_entry: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LogAuditReport:
    """Reporte consolidado del análisis de logs."""
    logfile: str
    total_lines: int
    parsed_lines: int
    top_client_ips: Dict[str, int]
    status_code_distribution: Dict[str, int]
    alerts_by_type: Dict[str, int]
    alerts_by_severity: Dict[str, int]
    total_alerts: int
    alerts: List[SecurityAlert]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class LogAnalyzer:
    """
    Analizador forense de logs web y de autenticación.
    """

    # Expresión regular estándar para Apache/Nginx Combined Log Format
    # IP - - [timestamp] "METHOD /path HTTP/1.1" status_code bytes "referer" "user_agent"
    WEB_LOG_REGEX = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<proto>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
    )

    # Patrones de firmas de ataques conocidos
    ATTACK_RULES = [
        {
            "type": "SQL Injection (SQLi)",
            "severity": "HIGH",
            "pattern": re.compile(
                r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|'|\bOR\b\s+['\d\w]+=['\d\w]+|--|;|/\*|\*/|\bSLEEP\(\d+\)|\bBENCHMARK\()",
                re.IGNORECASE
            ),
            "desc": "Intento de inyección SQL en parámetros de consulta o URI."
        },
        {
            "type": "Cross-Site Scripting (XSS)",
            "severity": "HIGH",
            "pattern": re.compile(
                r"(<script|%3Cscript|javascript:|onerror\s*=|onload\s*=|alert\(|<svg|<iframe)",
                re.IGNORECASE
            ),
            "desc": "Carga maliciosa XSS detectada en la petición."
        },
        {
            "type": "Directory Traversal / LFI",
            "severity": "CRITICAL",
            "pattern": re.compile(
                r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c|/etc/passwd|/etc/shadow|/windows/system32|win\.ini|boot\.ini)",
                re.IGNORECASE
            ),
            "desc": "Intento de escape de directorio o inclusión de archivos del sistema."
        },
        {
            "type": "Sensitive File Probing",
            "severity": "MEDIUM",
            "pattern": re.compile(
                r"(\.env|\.git/|wp-config\.php|phpinfo\.php|composer\.json|web\.config|server-status|/phpmyadmin)",
                re.IGNORECASE
            ),
            "desc": "Sondeo de archivos de configuración o paneles administrativos sensibles."
        },
        {
            "type": "Web Shell Execution",
            "severity": "CRITICAL",
            "pattern": re.compile(
                r"(cmd\.exe|/bin/sh|/bin/bash|powershell|c99\.php|r57\.php|eval\(base64_decode)",
                re.IGNORECASE
            ),
            "desc": "Intento de invocación de shells o ejecución remota de comandos."
        }
    ]

    def __init__(self, brute_force_threshold: int = 10):
        self.brute_force_threshold = brute_force_threshold

    def analyze_web_log(self, filepath: str) -> LogAuditReport:
        """
        Analiza un archivo de log de servidor web.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Archivo de log no encontrado: {filepath}")

        total_lines = 0
        parsed_lines = 0
        ip_counter = Counter()
        status_counter = Counter()
        ip_failed_auth_counter = Counter()
        alerts: List[SecurityAlert] = []

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_idx, line in enumerate(f, start=1):
                total_lines += 1
                line_str = line.strip()
                if not line_str:
                    continue

                match = self.WEB_LOG_REGEX.match(line_str)
                if match:
                    parsed_lines += 1
                    ip = match.group("ip")
                    uri = match.group("uri")
                    status = match.group("status")

                    ip_counter[ip] += 1
                    status_counter[status] += 1

                    # Rastrear posibles intentos de autenticación fallidos (401/403)
                    if status in ["401", "403"]:
                        ip_failed_auth_counter[ip] += 1

                    # Decodificar URI para detectar payloads codificados en URL (%20, %27, etc.)
                    decoded_uri = urllib.parse.unquote_plus(uri)

                    # Analizar URI contra firmas
                    for rule in self.ATTACK_RULES:
                        if rule["pattern"].search(uri) or rule["pattern"].search(decoded_uri):
                            alerts.append(SecurityAlert(
                                line_number=line_idx,
                                ip=ip,
                                attack_type=rule["type"],
                                severity=rule["severity"],
                                description=rule["desc"],
                                raw_entry=line_str
                            ))
                else:
                    decoded_raw = urllib.parse.unquote_plus(line_str)
                    for rule in self.ATTACK_RULES:
                        if rule["pattern"].search(line_str) or rule["pattern"].search(decoded_raw):
                            alerts.append(SecurityAlert(
                                line_number=line_idx,
                                ip="Unknown",
                                attack_type=rule["type"],
                                severity=rule["severity"],
                                description=rule["desc"],
                                raw_entry=line_str
                            ))

        # Detección de ataques de fuerza bruta por IP
        for ip, fail_count in ip_failed_auth_counter.items():
            if fail_count >= self.brute_force_threshold:
                alerts.append(SecurityAlert(
                    line_number=0,
                    ip=ip,
                    attack_type="Brute Force",
                    severity="HIGH",
                    description=f"Se detectaron {fail_count} respuestas de acceso denegado (401/403) desde esta IP.",
                    raw_entry=f"Fuerza bruta detectada para IP {ip}: {fail_count} intentos fallidos."
                ))

        # Métricas resumidas
        type_summary = Counter(a.attack_type for a in alerts)
        sev_summary = Counter(a.severity for a in alerts)

        return LogAuditReport(
            logfile=os.path.abspath(filepath),
            total_lines=total_lines,
            parsed_lines=parsed_lines,
            top_client_ips=dict(ip_counter.most_common(10)),
            status_code_distribution=dict(status_counter),
            alerts_by_type=dict(type_summary),
            alerts_by_severity=dict(sev_summary),
            total_alerts=len(alerts),
            alerts=alerts
        )

    def analyze_auth_log(self, filepath: str) -> LogAuditReport:
        """
        Analiza logs de autenticación de sistema (ej. /var/log/auth.log o secure).
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Archivo de log no encontrado: {filepath}")

        total_lines = 0
        ip_failed_logins = Counter()
        alerts: List[SecurityAlert] = []

        ssh_failed_pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_idx, line in enumerate(f, start=1):
                total_lines += 1
                line_str = line.strip()

                m = ssh_failed_pattern.search(line_str)
                if m:
                    user, ip = m.group(1), m.group(2)
                    ip_failed_logins[ip] += 1

        for ip, count in ip_failed_logins.items():
            if count >= self.brute_force_threshold:
                alerts.append(SecurityAlert(
                    line_number=0,
                    ip=ip,
                    attack_type="SSH Brute Force",
                    severity="CRITICAL",
                    description=f"{count} intentos de inicio de sesión fallidos por SSH detectados.",
                    raw_entry=f"IP sospechosa de ataque de diccionario SSH: {ip} ({count} fallos)"
                ))

        return LogAuditReport(
            logfile=os.path.abspath(filepath),
            total_lines=total_lines,
            parsed_lines=total_lines,
            top_client_ips=dict(ip_failed_logins.most_common(10)),
            status_code_distribution={},
            alerts_by_type=dict(Counter(a.attack_type for a in alerts)),
            alerts_by_severity=dict(Counter(a.severity for a in alerts)),
            total_alerts=len(alerts),
            alerts=alerts
        )


def main():
    parser = argparse.ArgumentParser(description="Analizador Forense de Logs y Detección de Amenazas.")
    parser.add_argument("logfile", help="Ruta al archivo de log a analizar")
    parser.add_argument("--type", choices=["web", "auth"], default="web", help="Tipo de log (web o auth)")
    parser.add_argument("--threshold", type=int, default=10, help="Umbral de fallos para fuerza bruta (default: 10)")
    parser.add_argument("-o", "--output", help="Ruta para exportar el informe JSON")

    args = parser.parse_args()

    analyzer = LogAnalyzer(brute_force_threshold=args.threshold)

    print("=" * 65)
    print(" [*] Cybersecurity Toolkit - Log Forensics Analyzer")
    print("=" * 65)
    print(f"[*] Archivo de log: {args.logfile}")
    print(f"[*] Tipo de análisis: {args.type.upper()}")
    print("-" * 65)

    try:
        if args.type == "web":
            report = analyzer.analyze_web_log(args.logfile)
        else:
            report = analyzer.analyze_auth_log(args.logfile)

        print(f"[*] Total de líneas procesadas: {report.total_lines}")
        print(f"[*] Total de alertas detectadas: {report.total_alerts}")
        print("-" * 65)
        print("📊 Alertas por Severidad:")
        for sev, count in report.alerts_by_severity.items():
            print(f" - {sev:<10}: {count}")

        print("\n🎯 Alertas por Tipo de Ataque:")
        for atype, count in report.alerts_by_type.items():
            print(f" - {atype:<28}: {count}")

        if report.top_client_ips:
            print("\n🌐 Top IPs Registradas:")
            for ip, count in list(report.top_client_ips.items())[:5]:
                print(f" - {ip:<20}: {count} peticiones")

        if report.alerts:
            print("\n🚨 Primeras Alertas Críticas / Altas:")
            for alert in report.alerts[:10]:
                print(f" [Línea {alert.line_number}] [{alert.severity}] {alert.attack_type} desde {alert.ip}")
                print(f"   └─ {alert.description}")

        print("=" * 65)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=4)
            print(f"[+] Reporte exportado a: {args.output}")

    except Exception as e:
        print(f"[!] Error analizando el log: {e}")


if __name__ == "__main__":
    main()
