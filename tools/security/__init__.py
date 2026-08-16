"""
Módulo de Herramientas de Seguridad
==================================
Contiene el evaluador de contraseñas, auditor de hashes, detector estático
y el sandbox de análisis avanzado de malware.
"""

from .password_analyzer import PasswordAnalyzer, PasswordReport
from .hash_cracker import HashCracker, CrackResult
from .malware_detector import MalwareDetector, ScanReport, FileScanResult
from .malware_sandbox import MalwareAnalyzer, MalwareAnalysis

__all__ = [
    "PasswordAnalyzer",
    "PasswordReport",
    "HashCracker",
    "CrackResult",
    "MalwareDetector",
    "ScanReport",
    "FileScanResult",
    "MalwareAnalyzer",
    "MalwareAnalysis",
]
