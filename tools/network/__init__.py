"""
Módulo de Herramientas de Red
=============================
Contiene escáneres de puertos, capturador/analizador de paquetes, mapeador de subredes
y escáner avanzado de vulnerabilidades con detección de CVEs.
"""

from .port_scanner import PortScanner, ScanResult as PortScanResult
from .packet_sniffer import PacketSniffer
from .network_mapper import NetworkMapper, HostInfo
from .vulnerability_scanner import AdvancedVulnerabilityScanner, Vulnerability, ServiceInfo, ScanResult

__all__ = [
    "PortScanner",
    "PortScanResult",
    "PacketSniffer",
    "NetworkMapper",
    "HostInfo",
    "AdvancedVulnerabilityScanner",
    "Vulnerability",
    "ServiceInfo",
    "ScanResult"
]
