# 🔥 Advanced Cybersecurity Toolkit - Nivel Profesional (v2.0)

[![Security Toolkit CI](https://github.com/ChemaMtz/cybersecurity-toolkit/actions/workflows/security-scan.yml/badge.svg)](https://github.com/ChemaMtz/cybersecurity-toolkit/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)](https://www.python.org/)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-blue)](docker-compose.yml)

Una suite empresarial completa y modular en Python diseñada para auditorías de vulnerabilidades, análisis de malware en sandbox, análisis forense digital de incidentes (DFIR), integración con SIEM y visualización en tiempo real.

---

## 🚀 Módulos Principales

### 🌐 1. Network Vulnerability Scanner (`tools/network/vulnerability_scanner.py`)
* **Escaneo Multi-hilo**: Detección de puertos abiertos y servicios con Nmap o sockets nativos.
* **Detección de CVEs**: Base de datos de vulnerabilidades críticas (Log4Shell, PrintNightmare, BlueKeep, EternalBlue, Heartbleed).
* **Análisis SSL/TLS**: Evaluación de certificados, suites de cifrado y detección de protocolos inseguros (TLS 1.0/1.1).
* **Enumeración DNS & WHOIS**: Resolución automática de registros A, AAAA, MX, NS, TXT y datos de registro.
* **Web Vulnerability Scan**: Detección heurística de vectores de inyección SQL (SQLi), Cross-Site Scripting (XSS) y Directory Traversal.

### 🦠 2. Advanced Malware Analysis Sandbox (`tools/security/malware_sandbox.py`)
* **Análisis Estático PE**: Inspección de cabeceras DOS/PE, cálculo de entropía por sección, tabla de imports y exports.
* **Firmas YARA**: Reglas para identificar inyección de procesos (APIs sospechosas), extensiones de ransomware y patrones de keyloggers.
* **Integración VirusTotal**: Consulta automática del score de reputación frente a 70+ motores antivirus.
* **Análisis de Comportamiento**: Trazabilidad y simulación de actividad de red (balizas C2) y persistencia en disco.

### 🔍 3. Advanced Digital Forensics Tool (`tools/forensics/forensic_analyzer.py`)
* **Extracción de Artefactos de Sistema**: Identificación de usuarios, conexiones de red activas, procesos en ejecución y servicios.
* **Inspección de Registro Windows**: Auditoría de persistencia (`Run`, `RunOnce`, `Services`, `Policies`).
* **Análisis de Logs de Seguridad**: Detección de fallos de autenticación por fuerza bruta, accesos no autorizados y fallos de memoria.
* **Línea de Tiempo y Reporte**: Cronología consolidada y métricas de severidad exportables a JSON.

### 📊 4. Dashboard Web y Visualización (`dashboard/app.py`)
* **Interfaz de Consola de Seguridad**: Visualización de métricas en tiempo real, tablas de CVEs activos, histórico de escaneos y auditor de contraseñas integrado.
* **API REST**: Endpoints listos para integración (`/api/scan-results`, `/api/statistics`).

### 🔄 5. Integración con SIEM (`tools/integrations/siem_integration.py`)
* Conectores nativos para **Elasticsearch**, **Splunk HTTP Event Collector (HEC)** y exportación a formato JSONL/CEF.

---

## 📁 Estructura del Proyecto

```text
cybersecurity-toolkit/
├── .github/
│   └── workflows/
│       └── security-scan.yml           # Pipeline CI/CD con escaneo de seguridad
├── dashboard/
│   ├── app.py                          # Servidor Web Flask
│   └── templates/
│       └── dashboard.html              # Interfaz gráfica moderna
├── docs/
│   ├── installation.md                 # Guía de instalación detallada
│   └── usage.md                        # Manual de uso CLI y API
├── examples/
│   ├── basic_scan.py                   # Ejemplo de escaneo de puertos
│   ├── log_analysis.py                 # Ejemplo de análisis forense y FIM
│   └── security_audit.py               # Ejemplo de auditoría de contraseñas y malware
├── tools/
│   ├── forensics/
│   │   ├── file_integrity.py           # Monitor de Integridad de Archivos (FIM)
│   │   ├── forensic_analyzer.py        # Analizador forense y extractor de artefactos
│   │   └── log_analyzer.py             # Analizador de logs web y de autenticación
│   ├── integrations/
│   │   └── siem_integration.py         # Conector con Elasticsearch / Splunk
│   ├── network/
│   │   ├── network_mapper.py           # Descubrimiento de hosts en subredes CIDR
│   │   ├── packet_sniffer.py           # Capturador/inspector de paquetes en vivo
│   │   ├── port_scanner.py             # Escáner de puertos TCP multi-hilo
│   │   └── vulnerability_scanner.py    # Escáner avanzado de vulnerabilidades y CVEs
│   └── security/
│       ├── hash_cracker.py             # Auditor de hashes con ataques de diccionario
│       ├── malware_detector.py         # Detector estático de malware y hashes
│       ├── malware_sandbox.py          # Sandbox avanzado con YARA y análisis PE
│       └── password_analyzer.py        # Evaluador de robustez y entropía de contraseñas
├── tests/
│   ├── test_forensic_analyzer.py
│   ├── test_log_analyzer.py
│   ├── test_malware_sandbox.py
│   ├── test_password_analyzer.py
│   ├── test_port_scanner.py
│   └── test_vulnerability_scanner.py
├── .gitignore
├── CONTRIBUTING.md
├── docker-compose.yml
├── Dockerfile
├── LICENSE
├── README.md
├── requirements.txt
├── requirements-advanced.txt
└── setup.py
```

---

## 🐳 Despliegue con Docker & Docker Compose

Para desplegar el entorno completo con **Elasticsearch**, **Kibana**, **Redis** y el **Web Dashboard**:

```bash
# Construir y levantar servicios
docker-compose up -d

# Acceder al Dashboard: http://localhost:5000
# Acceder a Kibana: http://localhost:5601
```

---

## 💻 Instalación Local

```bash
# 1. Clonar el repositorio
git clone https://github.com/ChemaMtz/cybersecurity-toolkit.git
cd cybersecurity-toolkit

# 2. Crear y activar entorno virtual
python -m venv venv
# Windows:
.\venv\Scripts\Activate.ps1
# Linux/macOS:
source venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt
pip install -r requirements-advanced.txt

# 4. (Opcional) Instalar en modo desarrollador para usar comandos globales
pip install -e .
```

---

## ⚡ Comandos Rápidos de Uso

```bash
# 1. Escaneo avanzado de vulnerabilidades
python tools/network/vulnerability_scanner.py 127.0.0.1 -o vuln_report.json

# 2. Análisis estático y sandbox de un archivo sospechoso
python tools/security/malware_sandbox.py archivo_sospechoso.exe -o malware_report.json

# 3. Triage forense del sistema
python tools/forensics/forensic_analyzer.py -o forensic_triage.json

# 4. Iniciar el Dashboard Web
python dashboard/app.py
```

---

## 🧪 Pruebas Automatizadas

```bash
python -m unittest discover -s tests
```

---

## 🛡️ Descargo de Responsabilidad (Disclaimer)

Este software ha sido diseñado exclusivamente para fines **educativos**, **investigación en ciberseguridad** y **auditorías autorizadas**. El uso no autorizado en sistemas ajenos está penado por la ley.

---

## 📄 Licencia

Distribuido bajo la **Licencia MIT**. Consulta [LICENSE](LICENSE) para más información.
