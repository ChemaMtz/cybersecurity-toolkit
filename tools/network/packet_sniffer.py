"""
Packet Sniffer Module
=====================
Herramienta para capturar, decodificar e inspeccionar tráfico de red en tiempo real.
"""

import sys
import time
import argparse
import socket
import struct
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass, asdict

# Soporte opcional para Scapy si está instalado
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    pass


@dataclass
class PacketInfo:
    """Representación estructurada de un paquete capturado."""
    timestamp: float
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    length: int = 0
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PacketSniffer:
    """
    Capturador e inspector de paquetes de red.
    """

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.packet_count = 0
        self.stats: Dict[str, int] = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "ARP": 0,
            "OTHER": 0,
            "TOTAL": 0,
        }

    def _decode_ip_header(self, data: bytes) -> tuple:
        """Decodifica la cabecera IP de un paquete crudo."""
        version_ihl = data[0]
        ihl = (version_ihl & 0xF) * 4
        ttl, proto, src, dst = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
        src_ip = socket.inet_ntoa(src)
        dst_ip = socket.inet_ntoa(dst)
        return ihl, proto, src_ip, dst_ip

    def _decode_tcp_header(self, data: bytes) -> tuple:
        """Decodifica los puertos origen y destino de TCP."""
        src_port, dst_port = struct.unpack("! H H", data[:4])
        return src_port, dst_port

    def _decode_udp_header(self, data: bytes) -> tuple:
        """Decodifica los puertos origen y destino de UDP."""
        src_port, dst_port = struct.unpack("! H H", data[:4])
        return src_port, dst_port

    def start_sniffing_scapy(
        self,
        count: int = 0,
        filter_proto: Optional[str] = None,
        callback: Optional[Callable[[PacketInfo], None]] = None
    ):
        """Captura paquetes utilizando Scapy para máxima compatibilidad multiplataforma."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy no está instalado. Instálalo con 'pip install scapy'.")

        def _scapy_handler(packet):
            self.packet_count += 1
            self.stats["TOTAL"] += 1

            proto = "OTHER"
            src_ip, dst_ip = "0.0.0.0", "0.0.0.0"
            src_port, dst_port = None, None

            if packet.haslayer(ARP):
                proto = "ARP"
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst
            elif packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if packet.haslayer(TCP):
                    proto = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    proto = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif packet.haslayer(ICMP):
                    proto = "ICMP"

            self.stats[proto] = self.stats.get(proto, 0) + 1

            if filter_proto and proto.upper() != filter_proto.upper():
                return

            info = PacketInfo(
                timestamp=time.time(),
                protocol=proto,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                length=len(packet),
                summary=packet.summary()
            )

            if callback:
                callback(info)
            else:
                self.default_printer(info)

        sniff(
            iface=self.interface,
            prn=_scapy_handler,
            count=count,
            store=False
        )

    def start_sniffing_raw(
        self,
        count: int = 0,
        filter_proto: Optional[str] = None,
        callback: Optional[Callable[[PacketInfo], None]] = None
    ):
        """Captura paquetes mediante sockets raw nativos."""
        # En Windows los raw sockets sobre IP requieren socket.IPPROTO_IP y modo promiscuo
        is_windows = sys.platform.startswith("win")
        sock_proto = socket.IPPROTO_IP if is_windows else socket.htons(0x0800)

        with socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_proto) as raw_sock:
            if is_windows:
                # Enlazar al host local en Windows
                host = socket.gethostbyname(socket.gethostname())
                raw_sock.bind((host, 0))
                raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            try:
                captured = 0
                while count == 0 or captured < count:
                    raw_data, _ = raw_sock.recvfrom(65535)
                    captured += 1
                    self.stats["TOTAL"] += 1

                    ihl, proto_num, src_ip, dst_ip = self._decode_ip_header(raw_data)
                    payload = raw_data[ihl:]

                    proto = "OTHER"
                    src_port, dst_port = None, None

                    if proto_num == 6:  # TCP
                        proto = "TCP"
                        if len(payload) >= 4:
                            src_port, dst_port = self._decode_tcp_header(payload)
                    elif proto_num == 17:  # UDP
                        proto = "UDP"
                        if len(payload) >= 4:
                            src_port, dst_port = self._decode_udp_header(payload)
                    elif proto_num == 1:  # ICMP
                        proto = "ICMP"

                    self.stats[proto] = self.stats.get(proto, 0) + 1

                    if filter_proto and proto.upper() != filter_proto.upper():
                        continue

                    info = PacketInfo(
                        timestamp=time.time(),
                        protocol=proto,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        length=len(raw_data),
                        summary=f"{proto} {src_ip}:{src_port or '*'} -> {dst_ip}:{dst_port or '*'}"
                    )

                    if callback:
                        callback(info)
                    else:
                        self.default_printer(info)

            finally:
                if is_windows:
                    try:
                        raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    except Exception:
                        pass

    @staticmethod
    def default_printer(info: PacketInfo):
        """Imprime un resumen visual del paquete capturado."""
        t = time.strftime("%H:%M:%S", time.localtime(info.timestamp))
        src = f"{info.src_ip}:{info.src_port}" if info.src_port else info.src_ip
        dst = f"{info.dst_ip}:{info.dst_port}" if info.dst_port else info.dst_ip
        print(f"[{t}] [{info.protocol:<5}] {src:<22} -> {dst:<22} | {info.length} bytes")


def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer & Analyzer en Tiempo Real.")
    parser.add_argument("-c", "--count", type=int, default=20, help="Número de paquetes a capturar (0 para infinito)")
    parser.add_argument("-p", "--protocol", choices=["TCP", "UDP", "ICMP", "ARP"], help="Filtrar por protocolo")
    parser.add_argument("-i", "--interface", help="Interfaz de red específica")
    parser.add_argument("--use-raw", action="store_true", help="Forzar uso de sockets nativos en lugar de Scapy")

    args = parser.parse_args()

    print("=" * 65)
    print(" 📡  Cybersecurity Toolkit - Packet Sniffer")
    print("=" * 65)
    print(f"[*] Paquetes a capturar: {args.count if args.count > 0 else 'Continuo'}")
    print(f"[*] Filtro de protocolo: {args.protocol or 'Todos'}")
    print(f"[*] Motor: {'Raw Sockets' if args.use_raw or not SCAPY_AVAILABLE else 'Scapy'}")
    print("-" * 65)

    sniffer = PacketSniffer(interface=args.interface)

    try:
        if SCAPY_AVAILABLE and not args.use_raw:
            sniffer.start_sniffing_scapy(count=args.count, filter_proto=args.protocol)
        else:
            sniffer.start_sniffing_raw(count=args.count, filter_proto=args.protocol)
    except KeyboardInterrupt:
        print("\n[!] Captura interrumpida por el usuario.")
    except PermissionError:
        print("\n[!] Error: Se requieren privilegios de Administrador / Root para capturar paquetes.")
    except Exception as e:
        print(f"\n[!] Error durante la captura: {e}")

    print("-" * 65)
    print("📊 Estadísticas de Captura:")
    for proto, count in sniffer.stats.items():
        print(f" - {proto:<8}: {count}")
    print("=" * 65)


if __name__ == "__main__":
    main()
