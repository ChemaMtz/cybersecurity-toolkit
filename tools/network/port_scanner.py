"""
Port Scanner Module
===================
Escáner de puertos TCP multi-hilo con detección de servicios y captura de banners.
"""

import sys
import socket
import argparse
import json
import time
from typing import List, Dict, Optional, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict

# Configurar encoding seguro para Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

# Diccionario de servicios estándar comunes
COMMON_PORTS: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS-SSN",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


@dataclass
class ScanResult:
    """Estructura de datos para el resultado del escaneo de un puerto."""
    port: int
    status: str  # 'OPEN', 'CLOSED', 'FILTERED'
    service: str
    banner: Optional[str] = None
    response_time_ms: Optional[float] = None

    def to_dict(self) -> dict:
        return asdict(self)


class PortScanner:
    """
    Clase para escanear puertos TCP en un objetivo determinado.
    """

    def __init__(self, target: str, timeout: float = 1.0):
        """
        Inicializa el escáner con el host objetivo y el tiempo de espera (timeout).
        """
        self.target = target
        self.timeout = timeout
        self.ip = self._resolve_target(target)

    def _resolve_target(self, target: str) -> str:
        """Resuelve el nombre de host o dominio a una dirección IPv4."""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"No se pudo resolver el host: {target}")

    def _grab_banner(self, sock: socket.socket) -> Optional[str]:
        """Intenta capturar el banner del servicio enviando un salto de línea o solicitud básica."""
        try:
            sock.settimeout(1.0)
            try:
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                if banner:
                    return banner
            except socket.timeout:
                pass

            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if banner:
                first_line = banner.split("\r\n")[0]
                return first_line[:120]
        except Exception:
            pass
        return None

    def scan_port(self, port: int, grab_banner: bool = False) -> ScanResult:
        """
        Escanea un único puerto TCP en el host objetivo.
        """
        service = COMMON_PORTS.get(port, "Desconocido")
        start_time = time.perf_counter()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            try:
                result = sock.connect_ex((self.ip, port))
                elapsed_ms = (time.perf_counter() - start_time) * 1000

                if result == 0:
                    banner = self._grab_banner(sock) if grab_banner else None
                    return ScanResult(
                        port=port,
                        status="OPEN",
                        service=service,
                        banner=banner,
                        response_time_ms=round(elapsed_ms, 2)
                    )
                else:
                    return ScanResult(
                        port=port,
                        status="CLOSED",
                        service=service,
                        banner=None,
                        response_time_ms=round(elapsed_ms, 2)
                    )
            except socket.timeout:
                return ScanResult(
                    port=port,
                    status="FILTERED",
                    service=service,
                    banner=None,
                    response_time_ms=None
                )
            except Exception:
                return ScanResult(
                    port=port,
                    status="ERROR",
                    service=service,
                    banner=None,
                    response_time_ms=None
                )

    def scan_ports(
        self,
        ports: List[int],
        max_threads: int = 50,
        grab_banner: bool = False,
        only_open: bool = True
    ) -> List[ScanResult]:
        """
        Escanea una lista de puertos usando un pool de hilos.
        """
        results: List[ScanResult] = []
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, p, grab_banner): p for p in ports
            }
            for future in as_completed(future_to_port):
                try:
                    res = future.result()
                    if not only_open or res.status == "OPEN":
                        results.append(res)
                except Exception:
                    pass

        results.sort(key=lambda x: x.port)
        return results


def parse_ports(port_arg: str) -> List[int]:
    """
    Parsea cadenas como '80', '80,443,8080', '1-1024', o 'common'.
    """
    if port_arg.lower() == "common":
        return sorted(list(COMMON_PORTS.keys()))

    ports = set()
    parts = port_arg.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"Rango de puertos inválido: {part}")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Puerto fuera de rango (1-65535): {p}")
            ports.add(p)
    return sorted(list(ports))


def main():
    parser = argparse.ArgumentParser(description="Escáner de Puertos TCP Multi-hilo Profesional.")
    parser.add_argument("target", help="Dirección IP o nombre de host a escanear")
    parser.add_argument("-p", "--ports", default="common", help="Puertos a escanear (ej: 'common', '80,443', '1-1000')")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Número de hilos concurrentes (default: 50)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Tiempo de espera en segundos (default: 1.0)")
    parser.add_argument("-b", "--banner", action="store_true", help="Capturar banners de servicios")
    parser.add_argument("-a", "--all", action="store_true", help="Mostrar puertos cerrados y filtrados además de abiertos")
    parser.add_argument("-o", "--output", help="Ruta para exportar el reporte en formato JSON")

    args = parser.parse_args()

    print("=" * 60)
    print(" [*] Cybersecurity Toolkit - Port Scanner")
    print("=" * 60)
    print(f"[*] Objetivo: {args.target}")
    
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] Error al parsear puertos: {e}")
        return

    try:
        scanner = PortScanner(args.target, timeout=args.timeout)
        print(f"[*] IP Resuelta: {scanner.ip}")
        print(f"[*] Puertos a escanear: {len(ports)}")
        print(f"[*] Hilos: {args.threads} | Timeout: {args.timeout}s")
        print("-" * 60)

        start_time = time.time()
        results = scanner.scan_ports(
            ports=ports,
            max_threads=args.threads,
            grab_banner=args.banner,
            only_open=not args.all
        )
        duration = time.time() - start_time

        print(f"{'PUERTO':<10} {'ESTADO':<10} {'SERVICIO':<18} {'TIEMPO':<10} {'BANNER'}")
        print("-" * 60)
        for res in results:
            t_str = f"{res.response_time_ms} ms" if res.response_time_ms is not None else "N/A"
            banner_str = res.banner if res.banner else "-"
            print(f"{res.port:<10} {res.status:<10} {res.service:<18} {t_str:<10} {banner_str}")

        print("-" * 60)
        open_count = sum(1 for r in results if r.status == "OPEN")
        print(f"[+] Escaneo finalizado en {duration:.2f} segundos.")
        print(f"[+] Puertos abiertos encontrados: {open_count}")

        if args.output:
            data = {
                "target": args.target,
                "ip": scanner.ip,
                "scan_time_seconds": round(duration, 2),
                "total_scanned": len(ports),
                "open_ports_count": open_count,
                "results": [r.to_dict() for r in results]
            }
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            print(f"[+] Reporte exportado en: {args.output}")

    except Exception as ex:
        print(f"[!] Error durante el escaneo: {ex}")


if __name__ == "__main__":
    main()
