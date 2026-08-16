# Cybersecurity Toolkit 🛡️

Una suite profesional y modular en Python diseñada para auditorías de seguridad, diagnóstico de redes, análisis criptográfico y análisis forense digital.

---

## 📋 Características Principales

### 🌐 1. Herramientas de Red (`tools/network/`)
* **Port Scanner (`port_scanner.py`)**:
  * Escaneo multi-hilo TCP connect de alta velocidad.
  * Identificación de servicios comunes y captura de banners (Banner Grabbing).
  * Reportes formateados en terminal y exportación estructurada en JSON.
* **Packet Sniffer (`packet_sniffer.py`)**:
  * Captura e inspección en vivo de paquetes de red (IP, TCP, UDP, ICMP, ARP).
  * Filtrado granular por protocolos y límites de paquetes.
  * Estadísticas de tráfico en tiempo real.
* **Network Mapper (`network_mapper.py`)**:
  * Descubrimiento de hosts activos en subredes locales (notación CIDR `/24`, `/16`, etc.).
  * Resolución DNS inversa de nombres de host.
  * Medición de latencia por nodo detectado.

### 🔒 2. Herramientas de Seguridad (`tools/security/`)
* **Password Analyzer (`password_analyzer.py`)**:
  * Cálculo de entropía de Shannon (bits).
  * Verificación exhaustiva de complejidad (mayúsculas, minúsculas, dígitos, caracteres especiales).
  * Comprobación contra diccionario de contraseñas débiles más comunes.
  * Estimación matemática del tiempo de crackeo y recomendaciones de robustecimiento.
* **Hash Cracker (`hash_cracker.py`)**:
  * Auditoría y recuperación de contraseñas mediante ataques por diccionario multi-hilo.
  * Compatibilidad con algoritmos estándar: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.
  * Soporte de sales (salts) y métricas de velocidad (hashes por segundo).
* **Malware Detector (`malware_detector.py`)**:
  * Análisis estático de archivos mediante firmas hash conocidas (MD5 / SHA-256).
  * Detección heurística de empaquetamiento o cifrado malicioso mediante análisis de entropía de archivos.
  * Validación de cabeceras mágicas (PE Windows, ELF Linux, Mach-O macOS).

### 🔍 3. Herramientas Forenses (`tools/forensics/`)
* **Log Analyzer (`log_analyzer.py`)**:
  * Procesamiento e inspección de logs de servidores web (Apache / Nginx Combined) y logs de autenticación (Syslog / SSH).
  * Detección de patrones de ataque: inyección SQL (SQLi), Cross-Site Scripting (XSS), Directory Traversal (`../`), y ataques de fuerza bruta.
  * Extracción de top IPs atacantes y cronología de eventos.
* **File Integrity Monitor - FIM (`file_integrity.py`)**:
  * Creación de líneas base (baselines) criptográficas (SHA-256) de directorios críticos.
  * Detección en tiempo real de archivos modificados, creados, eliminados o con alteraciones de tamaño/metadatos.
  * Exportación de reportes de auditoría de integridad.

---

## 📁 Estructura del Proyecto

```text
cybersecurity-toolkit/
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── setup.py
├── docs/
│   ├── installation.md
│   └── usage.md
├── tools/
│   ├── __init__.py
│   ├── network/
│   │   ├── __init__.py
│   │   ├── port_scanner.py
│   │   ├── packet_sniffer.py
│   │   └── network_mapper.py
│   ├── security/
│   │   ├── __init__.py
│   │   ├── password_analyzer.py
│   │   ├── hash_cracker.py
│   │   └── malware_detector.py
│   └── forensics/
│       ├── __init__.py
│       ├── log_analyzer.py
│       └── file_integrity.py
├── tests/
│   ├── __init__.py
│   ├── test_port_scanner.py
│   ├── test_password_analyzer.py
│   └── test_log_analyzer.py
└── examples/
    ├── basic_scan.py
    ├── security_audit.py
    └── log_analysis.py
```

---

## 🚀 Instalación Rápida

1. **Clonar o descargar el repositorio**:
   ```bash
   cd cybersecurity-toolkit
   ```

2. **Crear y activar un entorno virtual**:
   * En Windows (PowerShell):
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```
   * En Linux/macOS:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Instalar dependencias**:
   ```bash
   pip install -r requirements.txt
   ```

4. **(Opcional) Instalar en modo editable para comandos CLI**:
   ```bash
   pip install -e .
   ```

---

## 💡 Ejemplos Rápidos de Uso

### 1. Escaneo de Puertos
```bash
python tools/network/port_scanner.py 127.0.0.1 -p 20-1000 -t 50
```

### 2. Análisis de Contraseña
```bash
python tools/security/password_analyzer.py "P@ssw0rd2026!Complex"
```

### 3. Detección de Malware Estática
```bash
python tools/security/malware_detector.py C:/ruta/a/analizar --entropy
```

### 4. Monitor de Integridad de Archivos (FIM)
```bash
# Crear línea base
python tools/forensics/file_integrity.py --init C:/carpeta/critica -o baseline.json

# Verificar cambios
python tools/forensics/file_integrity.py --check C:/carpeta/critica -b baseline.json
```

### 5. Análisis de Logs
```bash
python tools/forensics/log_analyzer.py access.log --type web
```

---

## 🧪 Pruebas Unitarias

Para ejecutar todas las pruebas automatizadas del proyecto:

```bash
python -m unittest discover -s tests
```

O utilizando `pytest`:
```bash
pytest tests/ -v
```

---

## ⚖️ Descargo de Responsabilidad (Ethics Disclaimer)

Este kit de herramientas está diseñado estrictamente para:
* Fines educativos y de investigación académica en ciberseguridad.
* Administradores de sistemas y profesionales de seguridad que realizan auditorías en infraestructuras propias o expresamente autorizadas por escrito.

El uso de estas herramientas contra sistemas o redes sin autorización previa y explícita es ilegal. Los desarrolladores no asumen responsabilidad alguna por el mal uso o daños derivados de este software.

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
