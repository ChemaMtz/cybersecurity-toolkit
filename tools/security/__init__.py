"""
Módulo de Herramientas de Seguridad
==================================
Contiene el evaluador de robustez de contraseñas, auditor de hashes y detector estático de malware.
"""

from .password_analyzer import PasswordAnalyzer, PasswordReport
from .hash_cracker import HashCracker, CrackResult
from .malware_detector import MalwareDetector, ScanReport, FileScanResult

__all__ = [
    "PasswordAnalyzer",
    "PasswordReport",
    "HashCracker",
    "CrackResult",
    "MalwareDetector",
    "ScanReport",
    "FileScanResult",
]
