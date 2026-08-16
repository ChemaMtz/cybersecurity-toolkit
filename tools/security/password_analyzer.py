"""
Password Analyzer Module
========================
Evaluador avanzado de seguridad, entropía y vulnerabilidad de contraseñas.
"""

import sys
import math
import string
import re
import argparse
import json
from typing import List, Dict, Any
from dataclasses import dataclass, asdict

# Configurar encoding seguro para Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

# Lista integrada de las contraseñas más comunes y predecibles para auditoría rápida
COMMON_WEAK_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "welcome", "admin", "admin123", "root",
    "password123", "iloveyou", "princess", "football", "monkey", "charlie",
    "superman", "letmein", "sunshine", "master", "access", "shadow", "pass1234",
    "qwertyuiop", "trustno1", "starwars", "secret", "computer", "login"
}


@dataclass
class PasswordReport:
    """Reporte detallado de análisis de una contraseña."""
    password_masked: str
    length: int
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_special: bool
    entropy_bits: float
    score: int  # 0 a 100
    strength: str  # 'MUY DÉBIL', 'DÉBIL', 'MODERADA', 'FUERTE', 'MUY FUERTE'
    is_common: bool
    estimated_crack_time: str
    suggestions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PasswordAnalyzer:
    """
    Analizador de seguridad y complejidad de contraseñas.
    """

    def __init__(self):
        self.special_characters = set(string.punctuation)

    def calculate_entropy(self, password: str) -> float:
        """
        Calcula la entropía de la contraseña en bits.
        Entropía = L * log2(R) donde L es la longitud y R es el tamaño del conjunto de caracteres.
        """
        if not password:
            return 0.0

        pool_size = 0
        if any(c in string.ascii_lowercase for c in password):
            pool_size += 26
        if any(c in string.ascii_uppercase for c in password):
            pool_size += 26
        if any(c in string.digits for c in password):
            pool_size += 10
        if any(c in self.special_characters for c in password):
            pool_size += len(self.special_characters)
        if any(c for c in password if c not in string.ascii_letters and c not in string.digits and c not in self.special_characters):
            pool_size += 30  # Espacios u otros símbolos unicode

        if pool_size == 0:
            return 0.0

        entropy = len(password) * math.log2(pool_size)
        return round(entropy, 2)

    def _estimate_crack_time(self, entropy_bits: float) -> str:
        """
        Estima el tiempo necesario para romper la contraseña con un ataque de fuerza bruta
        asumiendo un clúster moderno con capacidad de 100 mil millones de hashes/segundo (100 GH/s).
        """
        if entropy_bits <= 0:
            return "Instantáneo"

        total_combinations = 2 ** entropy_bits
        hash_rate = 1e11  # 100 GH/s

        seconds = (total_combinations / 2) / hash_rate  # Promedio: mitad del espacio de búsqueda

        if seconds < 0.001:
            return "Instantáneo (< 1 milisegundo)"
        elif seconds < 1:
            return f"{seconds * 1000:.1f} milisegundos"
        elif seconds < 60:
            return f"{seconds:.1f} segundos"
        elif seconds < 3600:
            return f"{seconds / 60:.1f} minutos"
        elif seconds < 86400:
            return f"{seconds / 3600:.1f} horas"
        elif seconds < 31536000:
            return f"{seconds / 86400:.1f} días"
        elif seconds < 31536000 * 100:
            return f"{seconds / 31536000:.1f} años"
        elif seconds < 31536000 * 1000000:
            return f"{seconds / (31536000 * 1000):.1f} milenios"
        else:
            return "Centenares de millones de años"

    def analyze(self, password: str) -> PasswordReport:
        """
        Realiza una auditoría completa de la contraseña suministrada.
        """
        length = len(password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_special = any(c in self.special_characters for c in password)

        is_common = password.lower() in COMMON_WEAK_PASSWORDS

        entropy = self.calculate_entropy(password)
        suggestions: List[str] = []

        # Evaluación de patrones y vulnerabilidades
        if is_common:
            suggestions.append("[!] Esta contraseña forma parte de las listas de contraseñas más vulneradas y filtradas.")

        if length < 8:
            suggestions.append("Aumenta la longitud a mínimo 12-16 caracteres.")
        elif length < 12:
            suggestions.append("Considera utilizar una frase de contraseña (passphrase) de 14+ caracteres.")

        if not has_upper:
            suggestions.append("Incluye al menos una letra mayúscula (A-Z).")
        if not has_lower:
            suggestions.append("Incluye al menos una letra minúscula (a-z).")
        if not has_digit:
            suggestions.append("Agrega números para expandir el conjunto de caracteres.")
        if not has_special:
            suggestions.append("Agrega símbolos especiales (!@#$%^&*...).")

        # Detección de repeticiones o secuencias
        if re.search(r"(.)\1{2,}", password):
            suggestions.append("Evita repetir el mismo carácter 3 o más veces consecutivas.")
        if re.search(r"1234|abcd|qwert|admin", password.lower()):
            suggestions.append("Evita secuencias obvias de teclado como '1234' o 'qwerty'.")

        # Cálculo de puntuación base (0-100)
        score = 0
        if length >= 8:
            score += 20
        if length >= 12:
            score += 15
        if length >= 16:
            score += 15
        if has_lower:
            score += 10
        if has_upper:
            score += 10
        if has_digit:
            score += 15
        if has_special:
            score += 15

        # Penalizaciones
        if is_common:
            score = max(5, score - 60)
        if re.search(r"(.)\1{2,}", password):
            score = max(5, score - 15)

        score = min(100, max(0, score))

        # Clasificación
        if score < 30 or is_common:
            strength = "MUY DÉBIL"
        elif score < 55:
            strength = "DÉBIL"
        elif score < 75:
            strength = "MODERADA"
        elif score < 90:
            strength = "FUERTE"
        else:
            strength = "MUY FUERTE"

        # Máscara visual para privacidad
        masked = password[0] + ("*" * (length - 2)) + password[-1] if length > 2 else "*" * length

        return PasswordReport(
            password_masked=masked,
            length=length,
            has_upper=has_upper,
            has_lower=has_lower,
            has_digit=has_digit,
            has_special=has_special,
            entropy_bits=entropy,
            score=score,
            strength=strength,
            is_common=is_common,
            estimated_crack_time=self._estimate_crack_time(entropy if not is_common else 5.0),
            suggestions=suggestions
        )


def main():
    parser = argparse.ArgumentParser(description="Analizador y Evaluador de Contraseñas.")
    parser.add_argument("password", help="Contraseña a evaluar (o usar comillas)")
    parser.add_argument("-o", "--output", help="Ruta para exportar el resultado en JSON")

    args = parser.parse_args()

    analyzer = PasswordAnalyzer()
    report = analyzer.analyze(args.password)

    print("=" * 60)
    print(" [*] Cybersecurity Toolkit - Password Analyzer")
    print("=" * 60)
    print(f"[*] Contraseña evaluada: {report.password_masked}")
    print(f"[*] Longitud: {report.length} caracteres")
    print(f"[*] Entropía: {report.entropy_bits} bits")
    print(f"[*] Puntuación: {report.score}/100")
    print(f"[*] Nivel de Robustez: {report.strength}")
    print(f"[*] Tiempo estimado de crackeo (100 GH/s): {report.estimated_crack_time}")
    print("-" * 60)
    print("📌 Diversidad de Caracteres:")
    print(f" - Mayúsculas: {'[SI]' if report.has_upper else '[NO]'}")
    print(f" - Minúsculas: {'[SI]' if report.has_lower else '[NO]'}")
    print(f" - Dígitos:    {'[SI]' if report.has_digit else '[NO]'}")
    print(f" - Símbolos:   {'[SI]' if report.has_special else '[NO]'}")
    print("-" * 60)

    if report.suggestions:
        print("[!] Sugerencias de Mejora:")
        for s in report.suggestions:
            print(f" - {s}")
    else:
        print("[+] ¡Excelente! La contraseña cumple con altos estándares de seguridad.")
    print("=" * 60)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=4)
        print(f"[+] Reporte exportado a: {args.output}")


if __name__ == "__main__":
    main()
