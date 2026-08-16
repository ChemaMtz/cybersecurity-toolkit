# Guía de Uso del Cybersecurity Toolkit 📖

Esta guía describe cómo utilizar cada uno de los módulos de la suite, tanto mediante la interfaz de línea de comandos (CLI) como importándolos como bibliotecas en tus propios scripts de Python.

---

## 🌐 1. Herramientas de Red (`tools/network/`)

### Port Scanner (`port_scanner.py`)
Escanea puertos TCP en un objetivo específico utilizando múltiples hilos.

#### Uso por Línea de Comandos:
```bash
# Escaneo de puertos comunes con 100 hilos
python tools/network/port_scanner.py 192.168.1.1 --ports common --threads 100

# Escaneo de un rango específico con captura de banner y salida a JSON
python tools/network/port_scanner.py 127.0.0.1 -p 20-1024 --banner -o scan_result.json
```

#### Uso en Python:
```python
from tools.network.port_scanner import PortScanner

scanner = PortScanner(target="127.0.0.1", timeout=1.0)
results = scanner.scan_ports(ports=[22, 80, 443, 8080], max_threads=20, grab_banner=True)

for res in results:
    print(f"Puerto {res.port} ({res.service}): {res.status} | Banner: {res.banner}")
```

---

### Network Mapper (`network_mapper.py`)
Descubre equipos activos en un segmento de red local (CIDR).

#### Uso por Línea de Comandos:
```bash
# Escanear subred local
python tools/network/network_mapper.py 192.168.1.0/24 --threads 50 -o hosts.json
```

#### Uso en Python:
```python
from tools.network.network_mapper import NetworkMapper

mapper = NetworkMapper(subnet="192.168.1.0/24")
active_hosts = mapper.scan(timeout=0.5, threads=50)

for host in active_hosts:
    print(f"IP: {host.ip} | Hostname: {host.hostname} | Latencia: {host.latency_ms:.2f}ms")
```

---

### Packet Sniffer (`packet_sniffer.py`)
Inspecciona paquetes de red en tiempo real.

#### Uso por Línea de Comandos:
```bash
# Capturar 50 paquetes filtrando por TCP
python tools/network/packet_sniffer.py --protocol TCP --count 50
```

---

## 🔒 2. Herramientas de Seguridad (`tools/security/`)

### Password Analyzer (`password_analyzer.py`)
Evalúa la seguridad y entropía de contraseñas.

#### Uso por Línea de Comandos:
```bash
python tools/security/password_analyzer.py "MiContraseñaSegura123!"
```

#### Uso en Python:
```python
from tools.security.password_analyzer import PasswordAnalyzer

analyzer = PasswordAnalyzer()
report = analyzer.analyze("Correct-Horse-Battery-Staple-2026!")

print(f"Fortaleza: {report.strength} ({report.score}/100)")
print(f"Entropía: {report.entropy_bits:.2f} bits")
print(f"Tiempo estimado de crackeo: {report.estimated_crack_time}")
for tip in report.suggestions:
    print(f" - {tip}")
```

---

### Hash Cracker (`hash_cracker.py`)
Audita hashes frente a un diccionario de contraseñas de referencia.

#### Uso por Línea de Comandos:
```bash
python tools/security/hash_cracker.py <hash> -a sha256 -w wordlist.txt
```

---

### Malware Detector (`malware_detector.py`)
Analiza archivos en busca de firmas sospechosas y patrones de entropía anómalos.

#### Uso por Línea de Comandos:
```bash
# Escaneo estático con análisis de entropía
python tools/security/malware_detector.py ./directorio_sospechoso --entropy
```

---

## 🔍 3. Herramientas Forenses (`tools/forensics/`)

### Log Analyzer (`log_analyzer.py`)
Analiza logs en busca de ataques web (SQLi, XSS, Path Traversal) o fuerza bruta.

#### Uso por Línea de Comandos:
```bash
python tools/forensics/log_analyzer.py access.log --type web -o report.json
```

---

### File Integrity Monitor (`file_integrity.py`)
Monitorea alteraciones no autorizadas en archivos de configuración o código fuente.

#### Uso por Línea de Comandos:
```bash
# 1. Crear línea base
python tools/forensics/file_integrity.py --init /etc/nginx -o baseline.json

# 2. Comprobar alteraciones posteriores
python tools/forensics/file_integrity.py --check /etc/nginx -b baseline.json
```
