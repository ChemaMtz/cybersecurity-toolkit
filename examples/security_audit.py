"""
Ejemplo Práctico 2: Auditoría de Seguridad, Contraseñas y Detección de Amenazas
=============================================================================
Este script demuestra cómo evaluar la seguridad de credenciales, auditar hashes
y realizar análisis estático de archivos.
"""

import sys
import os
import tempfile
import hashlib

# Configurar encoding seguro para Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

# Asegurar que el directorio raíz del toolkit esté en el PATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.security.password_analyzer import PasswordAnalyzer
from tools.security.hash_cracker import HashCracker
from tools.security.malware_detector import MalwareDetector


def main():
    print("=" * 70)
    print(" [*] EJEMPLO DE USO: Auditoría de Seguridad Integral")
    print("=" * 70)

    # 1. Análisis de Contraseñas
    analyzer = PasswordAnalyzer()
    sample_passwords = [
        "123456",
        "admin2024",
        "P@ssw0rd!",
        "Tr0ub4dor&3_Secure_2026!"
    ]

    print("\n[1] Evaluación de Contraseñas y Entropía:")
    print(f"{'MÁSCARA':<20} {'LONGITUD':<10} {'ENTROPÍA':<14} {'PUNTAJE':<10} {'ROBUSTEZ'}")
    print("-" * 70)
    for pwd in sample_passwords:
        rep = analyzer.analyze(pwd)
        print(f"{rep.password_masked:<20} {rep.length:<10} {rep.entropy_bits:<14.2f} {rep.score:<10} {rep.strength}")

    # 2. Auditoría de Hash Criptográfico
    print("\n[2] Auditoría de Hash con Diccionario:")
    known_word = "cybersecurity"
    target_hash = hashlib.sha256(known_word.encode()).hexdigest()
    print(f"[*] Hash objetivo (SHA-256): {target_hash}")

    cracker = HashCracker(algorithm="sha256")
    res = cracker.crack(target_hash)
    if res.cracked:
        print(f"[+] [OK] Coincidencia hallada: '{res.plaintext}' ({res.attempts} intentos, {res.duration_seconds}s)")
    else:
        print("[-] [FAIL] No se encontró coincidencia.")

    # 3. Detección Estática de Malware en Archivos de Prueba
    print("\n[3] Análisis Estático de Archivos:")
    with tempfile.TemporaryDirectory() as temp_dir:
        # Crear archivo normal
        normal_file = os.path.join(temp_dir, "documento.txt")
        with open(normal_file, "w") as f:
            f.write("Este es un archivo de texto plano completamente legítimo y normal.")

        # Crear archivo simulado con firma de prueba (EICAR test string)
        test_file = os.path.join(temp_dir, "test_eicar.com")
        eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        with open(test_file, "wb") as f:
            f.write(eicar_bytes)

        detector = MalwareDetector()
        report = detector.scan_directory(temp_dir)

        print(f"[*] Total archivos analizados: {report.total_files}")
        print(f"[*] Limpios: {report.clean_files} | Sospechosos: {report.suspicious_files} | Maliciosos: {report.malicious_files}")
        for r in report.results:
            print(f" -> [{r.verdict}] {r.filename} (Tipo: {r.detected_type})")
            for reason in r.reasons:
                print(f"     └─ {reason}")

    print("\n" + "=" * 70)
    print(" [+] Auditoría de seguridad finalizada correctamente.")
    print("=" * 70)


if __name__ == "__main__":
    main()
