"""
File Integrity Monitor (FIM) Module
===================================
Herramienta para la creación de líneas base (baselines) y auditoría de integridad de archivos críticos.
"""

import os
import sys
import hashlib
import time
import argparse
import json
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict

# Configurar encoding seguro para Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass


@dataclass
class FileRecord:
    """Registro de estado e integridad de un archivo."""
    filepath: str
    relative_path: str
    sha256: str
    size_bytes: int
    modified_time: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IntegrityReport:
    """Reporte de diferencias frente a la línea base."""
    target_dir: str
    baseline_created_at: float
    check_timestamp: float
    total_baseline_files: int
    current_files_count: int
    added_files: List[str]
    deleted_files: List[str]
    modified_files: List[Dict[str, Any]]
    is_compromised: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FileIntegrityMonitor:
    """
    Monitor de Integridad de Archivos (FIM).
    """

    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)
        if not os.path.exists(self.target_dir):
            raise FileNotFoundError(f"Directorio no encontrado: {target_dir}")

    @staticmethod
    def _compute_hash(filepath: str) -> str:
        """Calcula el hash SHA-256 de un archivo en bloques."""
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()

    def create_baseline(self) -> Dict[str, Any]:
        """
        Escanea el directorio y genera el diccionario de línea base con metadatos y hashes.
        """
        records: Dict[str, Dict[str, Any]] = {}
        target_abs = os.path.abspath(self.target_dir)

        for root, _, files in os.walk(target_abs):
            for filename in files:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, target_abs)
                try:
                    h = self._compute_hash(full_path)
                    stat = os.stat(full_path)
                    records[rel_path] = {
                        "relative_path": rel_path,
                        "sha256": h,
                        "size_bytes": stat.st_size,
                        "modified_time": stat.st_mtime
                    }
                except Exception:
                    pass

        baseline_data = {
            "version": "1.0",
            "target_dir": target_abs,
            "created_at": time.time(),
            "file_count": len(records),
            "files": records
        }
        return baseline_data

    def save_baseline_file(self, output_path: str) -> str:
        """Genera y guarda la línea base en un archivo JSON."""
        data = self.create_baseline()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        return os.path.abspath(output_path)

    def verify_integrity(self, baseline_input: Union[str, Dict[str, Any]]) -> IntegrityReport:
        """
        Compara el estado actual del directorio contra la línea base provista.
        """
        if isinstance(baseline_input, str):
            with open(baseline_input, "r", encoding="utf-8") as f:
                baseline_data = json.load(f)
        else:
            baseline_data = baseline_input

        baseline_files = baseline_data.get("files", {})
        baseline_time = baseline_data.get("created_at", 0.0)

        # Generar snapshot actual
        current_snapshot = self.create_baseline()
        current_files = current_snapshot.get("files", {})

        added: List[str] = []
        deleted: List[str] = []
        modified: List[Dict[str, Any]] = []

        # 1. Comprobar archivos eliminados o modificados
        for rel_path, base_rec in baseline_files.items():
            if rel_path not in current_files:
                deleted.append(rel_path)
            else:
                curr_rec = current_files[rel_path]
                if base_rec["sha256"] != curr_rec["sha256"]:
                    modified.append({
                        "file": rel_path,
                        "expected_sha256": base_rec["sha256"],
                        "actual_sha256": curr_rec["sha256"],
                        "old_size": base_rec["size_bytes"],
                        "new_size": curr_rec["size_bytes"],
                    })

        # 2. Comprobar archivos nuevos agregados
        for rel_path in current_files.keys():
            if rel_path not in baseline_files:
                added.append(rel_path)

        is_compromised = bool(added or deleted or modified)

        return IntegrityReport(
            target_dir=self.target_dir,
            baseline_created_at=baseline_time,
            check_timestamp=time.time(),
            total_baseline_files=len(baseline_files),
            current_files_count=len(current_files),
            added_files=added,
            deleted_files=deleted,
            modified_files=modified,
            is_compromised=is_compromised
        )


def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitor (FIM) - Auditoría de Integridad.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--init", metavar="DIR", help="Crear línea base inicial para el directorio indicado")
    group.add_argument("--check", metavar="DIR", help="Verificar la integridad del directorio contra una línea base")

    parser.add_argument("-b", "--baseline", help="Ruta al archivo baseline.json (requerido para --check)")
    parser.add_argument("-o", "--output", default="baseline.json", help="Ruta de salida para baseline o reporte")

    args = parser.parse_args()

    print("=" * 65)
    print(" [*] Cybersecurity Toolkit - File Integrity Monitor (FIM)")
    print("=" * 65)

    if args.init:
        target = args.init
        print(f"[*] Modo: Creación de Línea Base Inicial")
        print(f"[*] Directorio objetivo: {target}")
        fim = FileIntegrityMonitor(target)
        out_file = fim.save_baseline_file(args.output)
        print(f"[+] Línea base generada exitosamente con SHA-256 en: {out_file}")
        print("=" * 65)

    elif args.check:
        target = args.check
        if not args.baseline:
            print("[!] Error: Se debe especificar el archivo de línea base con -b/--baseline.")
            return

        print(f"[*] Modo: Verificación de Integridad")
        print(f"[*] Directorio: {target}")
        print(f"[*] Archivo de línea base: {args.baseline}")
        print("-" * 65)

        fim = FileIntegrityMonitor(target)
        report = fim.verify_integrity(args.baseline)

        if not report.is_compromised:
            print("[+] INTEGRIDAD VERIFICADA: Todos los archivos coinciden exactamente con la línea base.")
        else:
            print("[!] ALERTA DE INTEGRIDAD: Se han detectado discrepancias en el directorio.")

        print("-" * 65)
        print(f"[*] Archivos en línea base: {report.total_baseline_files}")
        print(f"[*] Archivos actuales:      {report.current_files_count}")
        print(f"[*] Archivos Agregados:     {len(report.added_files)}")
        print(f"[*] Archivos Eliminados:    {len(report.deleted_files)}")
        print(f"[*] Archivos Modificados:   {len(report.modified_files)}")

        if report.added_files:
            print("\n[+] Archivos Nuevos Agregados:")
            for f in report.added_files:
                print(f"   + {f}")

        if report.deleted_files:
            print("\n[-] Archivos Eliminados:")
            for f in report.deleted_files:
                print(f"   - {f}")

        if report.modified_files:
            print("\n[!] Archivos con Modificación de Contenido:")
            for m in report.modified_files:
                print(f"   * {m['file']} (Hash alterado)")

        print("=" * 65)


if __name__ == "__main__":
    main()
