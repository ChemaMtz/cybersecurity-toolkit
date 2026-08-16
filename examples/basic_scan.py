"""
Ejemplo Práctico 1: Escaneo Básico de Red y Puertos
===================================================
Este script demuestra cómo utilizar los módulos PortScanner y NetworkMapper
para auditar servicios de red locales y descubrir equipos.
"""

import sys
import os

# Configurar encoding seguro para Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

# Asegurar que el directorio raíz del toolkit esté en el PATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.network.port_scanner import PortScanner
from tools.network.network_mapper import NetworkMapper


def main():
    print("=" * 65)
    print(" [*] EJEMPLO DE USO: Escaneo de Puertos y Mapeo de Red")
    print("=" * 65)

    # 1. Escaneo de Puertos en Localhost
    target_ip = "127.0.0.1"
    test_ports = [21, 22, 80, 135, 443, 445, 3306, 3389, 5432, 8080]

    print(f"\n[1] Iniciando escaneo de puertos TCP sobre {target_ip}...")
    scanner = PortScanner(target_ip, timeout=0.5)
    results = scanner.scan_ports(ports=test_ports, max_threads=10, grab_banner=True, only_open=False)

    print(f"{'PUERTO':<10} {'ESTADO':<12} {'SERVICIO':<18} {'TIEMPO':<12} {'BANNER'}")
    print("-" * 65)
    for res in results:
        t_str = f"{res.response_time_ms} ms" if res.response_time_ms is not None else "-"
        banner_str = res.banner if res.banner else "-"
        print(f"{res.port:<10} {res.status:<12} {res.service:<18} {t_str:<12} {banner_str}")

    # 2. Mapeo de Subred / Host
    subnet = "127.0.0.1/32"
    print(f"\n[2] Realizando sondeo de host en la subred {subnet}...")
    mapper = NetworkMapper(subnet)
    hosts = mapper.scan(timeout=0.5, threads=5, only_alive=False)

    for h in hosts:
        status_label = "[+] ACTIVO" if h.is_alive else "[-] INACTIVO"
        lat = f"{h.latency_ms} ms" if h.latency_ms is not None else "-"
        print(f" - Host: {h.ip:<15} | Estado: {status_label:<12} | Latencia: {lat}")

    print("\n" + "=" * 65)
    print(" [+] Demostración de escaneo de red finalizada con éxito.")
    print("=" * 65)


if __name__ == "__main__":
    main()
