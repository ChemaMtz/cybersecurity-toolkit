# Guía de Instalación 🛠️

Esta guía detalla los pasos para instalar y configurar el entorno de **Cybersecurity Toolkit** en diferentes plataformas.

---

## 📋 Requisitos Previos

- **Python**: Versión 3.8 o superior (se recomienda 3.10+).
- **Pip**: Administrador de paquetes de Python actualizado.
- **Git** (opcional, para clonar el repositorio).
- **Permisos de Administrador / Root**: Necesarios únicamente si se ejecutan módulos que requieren raw sockets (como `packet_sniffer.py` en ciertas configuraciones).

---

## 🪟 Instalación en Windows

1. **Abrir PowerShell o Símbolo del Sistema como Administrador** (opcional si no se requieren raw sockets).

2. **Navegar a la carpeta del proyecto**:
   ```powershell
   cd cybersecurity-toolkit
   ```

3. **Crear el entorno virtual de Python**:
   ```powershell
   python -m venv venv
   ```

4. **Activar el entorno virtual**:
   ```powershell
   # Si la ejecución de scripts está restringida:
   # Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   .\venv\Scripts\Activate.ps1
   ```

5. **Actualizar `pip` e instalar dependencias**:
   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

6. **(Opcional) Soporte de captura avanzada (Scapy & Npcap)**:
   - Si deseas usar captura avanzada de paquetes en Windows con Scapy, descarga e instala [Npcap](https://npcap.com/) activando la opción *"Install Npcap in WinPcap API-compatible Mode"*.

---

## 🐧 Instalación en Linux / macOS

1. **Instalar paquetes base de Python** (ejemplo en Debian/Ubuntu):
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip python3-venv libpcap-dev
   ```

2. **Navegar al directorio**:
   ```bash
   cd cybersecurity-toolkit
   ```

3. **Crear y activar el entorno virtual**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

4. **Instalar dependencias**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

5. **Permisos de captura de red**:
   - En Linux, para permitir a Python capturar paquetes sin necesidad de ejecutar todo como `root`, puedes asignar capacidades al binario de Python:
     ```bash
     sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
     ```
   - O bien ejecutar los comandos de sniffer con `sudo`.

---

## 📦 Instalación del Paquete CLI (`setup.py`)

Para poder utilizar los comandos globales en consola (`cyber-portscan`, `cyber-pwd-check`, etc.):

```bash
pip install -e .
```

Verifica la instalación:
```bash
cyber-pwd-check --help
```

---

## 🧪 Verificación de la Instalación

Para asegurar que todos los módulos y pruebas funcionan correctamente:

```bash
python -m unittest discover -s tests
```

Si todas las pruebas concluyen con `OK`, la suite está lista para usarse.
