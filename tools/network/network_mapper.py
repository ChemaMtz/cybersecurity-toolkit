"""
Network Mapper Module
=====================
Herramienta de descubrimiento de hosts activos y mapeo de subredes locales.
"""

import sys
import time
import socket
import ipaddress
import subprocess
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, asdict

# Configurar encoding seguro para Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass


@dataclass
class HostInfo:
    """Información de un host descubierto en la red."""
    ip: str
    is_alive: bool
    hostname: Optional[str] = None
    latency_ms: Optional[float] = None
    open_probe_ports: Optional[List[int]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NetworkMapper:
    """
    Mapeador de subredes y descubrimiento de nodos activos.
    """

    # Puertos comunes para verificación TCP en caso de que ICMP esté bloqueado por firewall
    PROBE_PORTS = [80, 443, 22, 445, 135, 8080, 3389]

    def __init__(self, subnet: str):
        """
        Inicializa con una subred en formato CIDR (ej: '192.168.1.0/24') o IP individual.
        """
        self.subnet_str = subnet
        try:
            self.network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as e:
            raise ValueError(f"Formato de subred inválido ({subnet}): {e}")

    def _ping_host(self, ip_str: str, timeout_sec: float = 1.0) -> Optional[float]:
        """Realiza un ping ICMP nativo según el sistema operativo."""
        is_win = sys.platform.startswith("win")
        timeout_ms = int(timeout_sec * 1000)

        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip_str] if is_win else ["ping", "-c", "1", "-W", str(int(timeout_sec)), ip_str]

        start_time = time.perf_counter()
        try:
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_sec + 0.5)
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if res.returncode == 0:
                return round(elapsed_ms, 2)
        except Exception:
            pass
        return None

    def _tcp_probe(self, ip_str: str, timeout_sec: float = 0.5) -> List[int]:
        """Verifica si algún puerto clave responde para confirmar host activo si ICMP está bloqueado."""
        open_ports = []
        for port in self.PROBE_PORTS:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout_sec)
                try:
                    if s.connect_ex((ip_str, port)) == 0:
                        open_ports.append(port)
                except Exception:
                    pass
        return open_ports

    def _resolve_hostname(self, ip_str: str) -> Optional[str]:
        """Resuelve el nombre DNS inverso del host."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_str)
            return hostname
        except Exception:
            return None

    def probe_host(self, ip_str: str, timeout_sec: float = 0.8) -> HostInfo:
        """
        Verifica el estado de un host individual mediante ICMP y sondeo TCP alternativo.
        """
        latency = self._ping_host(ip_str, timeout_sec=timeout_sec)
        open_ports: List[int] = []

        is_alive = latency is not None
        if not is_alive:
            open_ports = self._tcp_probe(ip_str, timeout_sec=0.3)
            if open_ports:
                is_alive = True
                latency = 1.0  # Estimación basada en respuesta TCP

        hostname = self._resolve_hostname(ip_str) if is_alive else None

        return HostInfo(
            ip=ip_str,
            is_alive=is_alive,
            hostname=hostname,
            latency_ms=latency,
            open_probe_ports=open_ports if open_ports else None
        )

    def scan(
        self,
        timeout: float = 0.8,
        threads: int = 50,
        only_alive: bool = True
    ) -> List[HostInfo]:
        """
        Escanea todos los hosts de la subred utilizando múltiples hilos.
        """
        hosts = [str(ip) for ip in self.network.hosts()]
        if not hosts:  # Si es una /32
            hosts = [str(self.network.network_address)]

        results: List[HostInfo] = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_ip = {
                executor.submit(self.probe_host, ip, timeout): ip for ip in hosts
            }
            for future in as_completed(future_to_ip):
                try:
                    info = future.result()
                    if not only_alive or info.is_alive:
                        results.append(info)
                except Exception:
                    pass

        # Ordenar por IP numéricamente
        results.sort(key=lambda x: ipaddress.ip_address(x.ip))
        return results


def main():
    parser = argparse.ArgumentParser(description="Mapeador de Subredes y Descubrimiento de Dispositivos.")
    parser.add_argument("subnet", help="Subred a mapear en formato CIDR (ej: '192.168.1.0/24' o '127.0.0.1/32')")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Hilos concurrentes (default: 50)")
    parser.add_argument("--timeout", type=float, default=0.8, help="Timeout por host en segundos (default: 0.8)")
    parser.add_argument("-a", "--all", action="store_true", help="Mostrar todos los hosts, incluidos los inactivos")
    parser.add_argument("-o", "--output", help="Ruta para exportar resultados en JSON")

    args = parser.parse_args()

    print("=" * 65)
    print(" [*] Cybersecurity Toolkit - Network Mapper")
    print("=" * 65)
    print(f"[*] Subred objetivo: {args.subnet}")

    try:
        mapper = NetworkMapper(args.subnet)
        total_hosts = sum(1 for _ in mapper.network.hosts()) or 1
        print(f"[*] Total de hosts a verificar: {total_hosts}")
        print(f"[*] Hilos concurrentes: {args.threads} | Timeout: {args.timeout}s")
        print("-" * 65)

        start_time = time.time()
        results = mapper.scan(
            timeout=args.timeout,
            threads=args.threads,
            only_alive=not args.all
        )
        duration = time.time() - start_time

        print(f"{'DIRECCIÓN IP':<18} {'ESTADO':<10} {'LATENCIA':<12} {'NOMBRE DE HOST'}")
        print("-" * 65)
        for h in results:
            status = "ACTIVO" if h.is_alive else "INACTIVO"
            lat_str = f"{h.latency_ms} ms" if h.latency_ms is not None else "-"
            host_str = h.hostname if h.hostname else "-"
            print(f"{h.ip:<18} {status:<10} {lat_str:<12} {host_str}")

        print("-" * 65)
        alive_count = sum(1 for h in results if h.is_alive)
        print(f"[+] Escaneo completado en {duration:.2f} segundos.")
        print(f"[+] Dispositivos activos descubiertos: {alive_count} / {total_hosts}")

        if args.output:
            data = {
                "subnet": args.subnet,
                "scan_duration_seconds": round(duration, 2),
                "total_hosts": total_hosts,
                "alive_hosts_count": alive_count,
                "hosts": [h.to_dict() for h in results]
            }
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            print(f"[+] Resultados exportados en: {args.output}")

    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
