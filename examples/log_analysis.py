"""
Ejemplo Práctico 3: Análisis Forense de Logs y Monitor de Integridad (FIM)
========================================================================
Este script demuestra cómo procesar registros de auditoría para identificar ciberataques
y cómo monitorear la integridad de archivos frente a alteraciones no autorizadas.
"""

import sys
import os
import tempfile
import time

# Configurar encoding seguro para Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

# Asegurar que el directorio raíz del toolkit esté en el PATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.forensics.log_analyzer import LogAnalyzer
from tools.forensics.file_integrity import FileIntegrityMonitor


def main():
    print("=" * 70)
    print(" [*] EJEMPLO DE USO: Análisis Forense Digital y Monitoreo FIM")
    print("=" * 70)

    # 1. Análisis de Logs Web Sintéticos
    synthetic_logs = [
        '192.168.1.10 - - [15/Aug/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',
        '192.168.1.10 - - [15/Aug/2026:10:00:05 +0000] "GET /about.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
        '45.33.32.156 - - [15/Aug/2026:10:01:20 +0000] "GET /search?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1" 200 8192 "-" "SQLMap"',
        '45.33.32.156 - - [15/Aug/2026:10:01:25 +0000] "GET /comments?text=<script>alert(document.cookie)</script> HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '185.220.101.5 - - [15/Aug/2026:10:02:10 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 404 250 "-" "curl/7.68.0"',
        '185.220.101.5 - - [15/Aug/2026:10:02:15 +0000] "GET /.env HTTP/1.1" 404 150 "-" "curl/7.68.0"',
        '185.220.101.5 - - [15/Aug/2026:10:02:20 +0000] "GET /wp-config.php HTTP/1.1" 404 150 "-" "curl/7.68.0"',
    ]

    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = os.path.join(temp_dir, "web_access.log")
        with open(log_file, "w", encoding="utf-8") as f:
            f.write("\n".join(synthetic_logs) + "\n")

        print("\n[1] Procesando registros de servidor web con LogAnalyzer...")
        analyzer = LogAnalyzer(brute_force_threshold=5)
        report = analyzer.analyze_web_log(log_file)

        print(f"[*] Total de peticiones: {report.total_lines}")
        print(f"[*] Amenazas detectadas: {report.total_alerts}")
        print("-" * 70)
        for alert in report.alerts:
            print(f" [!] [Línea {alert.line_number}] [{alert.severity}] {alert.attack_type} desde {alert.ip}")
            print(f"     └─ {alert.description}")

    # 2. File Integrity Monitor (FIM)
    print("\n[2] Demostración de File Integrity Monitor (FIM):")
    with tempfile.TemporaryDirectory() as monitored_dir:
        # A) Crear archivos iniciales
        conf_file = os.path.join(monitored_dir, "app_config.json")
        with open(conf_file, "w") as f:
            f.write('{"api_port": 8080, "debug": false}')

        secret_file = os.path.join(monitored_dir, "credentials.key")
        with open(secret_file, "w") as f:
            f.write("SUPER_SECRET_KEY_ORIGINAL_2026")

        fim = FileIntegrityMonitor(monitored_dir)
        baseline = fim.create_baseline()
        print(f"[*] Línea base creada para {len(baseline['files'])} archivos.")

        # B) Simular intrusión / cambios no autorizados
        print("[*] Simulando alteración de archivo y adición de archivo sospechoso...")
        # Modificar archivo existente
        with open(conf_file, "w") as f:
            f.write('{"api_port": 8080, "debug": true, "backdoor": "enabled"}')

        # Agregar archivo nuevo
        backdoor_file = os.path.join(monitored_dir, "shell.php")
        with open(backdoor_file, "w") as f:
            f.write("<?php system($_GET['cmd']); ?>")

        # C) Ejecutar verificación
        integrity_report = fim.verify_integrity(baseline)

        print(f"[*] Estado del Directorio: {'[!] COMPROMETIDO' if integrity_report.is_compromised else '[+] INTEGRO'}")
        print(f" - Archivos Nuevos:       {len(integrity_report.added_files)} -> {integrity_report.added_files}")
        print(f" - Archivos Modificados:  {len(integrity_report.modified_files)}")
        for m in integrity_report.modified_files:
            print(f"   └─ {m['file']} (Hash alterado)")

    print("\n" + "=" * 70)
    print(" [+] Demostración forense completada exitosamente.")
    print("=" * 70)


if __name__ == "__main__":
    main()
