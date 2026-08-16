"""
Hash Cracker Module
===================
Herramienta educativa y de auditoría de contraseñas mediante ataques de diccionario y verificación de hashes.
"""

import sys
import hashlib
import time
import argparse
import json
from typing import Optional, List, Dict, Any, Generator
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor

# Configurar encoding seguro para Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

# Diccionario base embebido para auditorías rápidas sin necesidad de archivos externos
BUILTIN_WORDLIST: List[str] = [
    "admin", "password", "123456", "12345678", "123456789", "qwerty", "12345",
    "dragon", "welcome", "iloveyou", "princess", "football", "monkey", "charlie",
    "letmein", "sunshine", "master", "shadow", "pass123", "password123",
    "admin123", "root", "toor", "test", "guest", "secret", "superman",
    "starwars", "login", "cybersecurity", "secure2024", "password1"
]


@dataclass
class CrackResult:
    """Resultado de la auditoría de un hash."""
    target_hash: str
    algorithm: str
    cracked: bool
    plaintext: Optional[str] = None
    attempts: int = 0
    duration_seconds: float = 0.0
    hash_rate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HashCracker:
    """
    Verificador y auditor de hashes criptográficos mediante listas de palabras.
    """

    SUPPORTED_ALGORITHMS = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
    }

    def __init__(self, algorithm: str = "sha256"):
        algo_key = algorithm.lower().replace("-", "")
        if algo_key not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Algoritmo '{algorithm}' no soportado. "
                f"Disponibles: {', '.join(self.SUPPORTED_ALGORITHMS.keys())}"
            )
        self.algorithm_name = algo_key
        self.hash_func = self.SUPPORTED_ALGORITHMS[algo_key]

    @staticmethod
    def identify_algorithm(hash_str: str) -> List[str]:
        """Identifica posibles algoritmos en base a la longitud hexadecimal del hash."""
        length = len(hash_str.strip())
        matches = []
        if length == 32:
            matches.append("md5")
        elif length == 40:
            matches.append("sha1")
        elif length == 56:
            matches.append("sha224")
        elif length == 64:
            matches.append("sha256")
        elif length == 96:
            matches.append("sha384")
        elif length == 128:
            matches.append("sha512")
        return matches

    def _hash_candidate(self, word: str, salt: Optional[str] = None, salt_position: str = "suffix") -> str:
        """Calcula el hash del candidato con o sin sal (salt)."""
        if salt:
            text = f"{salt}{word}" if salt_position == "prefix" else f"{word}{salt}"
        else:
            text = word
        return self.hash_func(text.encode("utf-8", errors="ignore")).hexdigest()

    def crack(
        self,
        target_hash: str,
        wordlist_path: Optional[str] = None,
        salt: Optional[str] = None,
        salt_position: str = "suffix",
        max_attempts: Optional[int] = None
    ) -> CrackResult:
        """
        Intenta recuperar el texto en claro probando cada palabra de la lista.
        """
        target = target_hash.strip().lower()
        start_time = time.perf_counter()
        attempts = 0

        # Seleccionar generador de palabras
        def word_generator() -> Generator[str, None, None]:
            if wordlist_path:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        yield line.strip()
            else:
                for w in BUILTIN_WORDLIST:
                    yield w

        plaintext = None
        for word in word_generator():
            if not word:
                continue

            attempts += 1
            calculated_hash = self._hash_candidate(word, salt=salt, salt_position=salt_position)

            if calculated_hash.lower() == target:
                plaintext = word
                break

            if max_attempts and attempts >= max_attempts:
                break

        duration = max(time.perf_counter() - start_time, 0.00001)
        hash_rate = attempts / duration

        return CrackResult(
            target_hash=target,
            algorithm=self.algorithm_name,
            cracked=plaintext is not None,
            plaintext=plaintext,
            attempts=attempts,
            duration_seconds=round(duration, 4),
            hash_rate=round(hash_rate, 2)
        )


def main():
    parser = argparse.ArgumentParser(description="Auditor y Verificador de Hashes de Contraseñas.")
    parser.add_argument("hash", help="Hash a auditar")
    parser.add_argument("-a", "--algo", help="Algoritmo (md5, sha1, sha256, sha512, etc.)")
    parser.add_argument("-w", "--wordlist", help="Ruta al archivo diccionario / wordlist (opcional, usa integrado si no se especifica)")
    parser.add_argument("-s", "--salt", help="Sal (salt) aplicada a la contraseña")
    parser.add_argument("--salt-pos", choices=["prefix", "suffix"], default="suffix", help="Posición de la sal (default: suffix)")
    parser.add_argument("-o", "--output", help="Ruta para exportar resultado en JSON")

    args = parser.parse_args()

    print("=" * 60)
    print(" [*] Cybersecurity Toolkit - Hash Cracker / Auditor")
    print("=" * 60)
    print(f"[*] Hash objetivo: {args.hash}")

    algo = args.algo
    if not algo:
        candidates = HashCracker.identify_algorithm(args.hash)
        if candidates:
            algo = candidates[0]
            print(f"[*] Algoritmo auto-detectado: {algo.upper()} (posibles: {', '.join(candidates)})")
        else:
            print("[!] No se pudo auto-detectar el algoritmo. Especifícalo con -a <algoritmo>.")
            return

    try:
        cracker = HashCracker(algorithm=algo)
        print(f"[*] Diccionario: {args.wordlist if args.wordlist else 'Diccionario Integrado'}")
        if args.salt:
            print(f"[*] Sal ({args.salt_pos}): {args.salt}")
        print("-" * 60)

        result = cracker.crack(
            target_hash=args.hash,
            wordlist_path=args.wordlist,
            salt=args.salt,
            salt_position=args.salt_pos
        )

        if result.cracked:
            print(f"[+] [EXITO] Contraseña encontrada: {result.plaintext}")
        else:
            print("[-] [FAIL] No se encontró coincidencia en el diccionario suministrado.")

        print("-" * 60)
        print(f"[*] Intentos totales: {result.attempts}")
        print(f"[*] Tiempo transcurrido: {result.duration_seconds} segundos")
        print(f"[*] Velocidad: {result.hash_rate:,.2f} hashes/segundo")
        print("=" * 60)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=4)
            print(f"[+] Resultado guardado en: {args.output}")

    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
