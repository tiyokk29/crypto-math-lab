"""Complexity benchmarks and journal concept mapping."""

import time
from secrets import randbits
from typing import Dict, List


def is_probable_prime(n: int, rounds: int = 8) -> bool:
    """Miller-Rabin probable-prime test for generated benchmark primes."""
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small_primes:
        return True
    if any(n % prime == 0 for prime in small_primes):
        return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(rounds):
        a = (randbits(n.bit_length() - 1) % (n - 3)) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate a probable prime with the requested bit length."""
    if not 12 <= bits <= 512:
        raise ValueError("Prime size must be between 12 and 512 bits.")
    while True:
        candidate = randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def semiprime_benchmark(prime_bits: int) -> Dict[str, float | int | str]:
    """Benchmark multiplication and trial-division factorization of a semiprime."""
    p = generate_prime(prime_bits)
    q = generate_prime(prime_bits)
    start = time.perf_counter()
    n = p * q
    multiplication_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    factors = []
    value = n
    divisor = 2
    while divisor * divisor <= value:
        if value % divisor == 0:
            factors.append(divisor)
            while value % divisor == 0:
                value //= divisor
        if divisor == 2:
            divisor = 3
        else:
            divisor += 2
    if value > 1:
        factors.append(value)
    factorization_ms = (time.perf_counter() - start) * 1000
    return {
        "prime_bits": prime_bits,
        "n": n,
        "n_bits": n.bit_length(),
        "multiplication_ms": multiplication_ms,
        "factorization_ms": factorization_ms,
        "factors_valid": bool(factors and factors[0] * factors[-1] == n),
    }


def brute_force_keyspace(key_bits: int) -> Dict[str, int | str]:
    """Calculate the brute-force keyspace and a human-readable value."""
    if key_bits <= 0:
        raise ValueError("Key size must be positive.")
    possibilities = 1 << key_bits
    return {
        "key_bits": key_bits,
        "formula": f"2^{key_bits}",
        "possibilities": possibilities,
        "decimal_digits": len(str(possibilities)),
    }


def journal_concept_table() -> List[Dict[str, str]]:
    """Return the journal's mathematical concept mapping."""
    return [
        {"Konsep": "Bilangan Prima", "Contoh/Kegunaan": "p dan q membentuk RSA",
         "Algoritma": "RSA", "Peran": "Dasar pembentukan kunci"},
        {"Konsep": "Aritmetika Modular", "Contoh/Kegunaan": "C = M^e mod n",
         "Algoritma": "RSA", "Peran": "Enkripsi dan dekripsi"},
        {"Konsep": "Teori Grup", "Contoh/Kegunaan": "Z_n^* dan operasi perkalian",
         "Algoritma": "RSA / Kriptografi", "Peran": "Invers dan eksponensiasi"},
        {"Konsep": "Medan Hingga", "Contoh/Kegunaan": "GF(2^8)",
         "Algoritma": "AES", "Peran": "Substitusi dan pencampuran byte"},
        {"Konsep": "Operasi XOR", "Contoh/Kegunaan": "A XOR B",
         "Algoritma": "AES", "Peran": "Penjumlahan biner reversibel"},
        {"Konsep": "Fungsi Satu Arah", "Contoh/Kegunaan": "n = p x q",
         "Algoritma": "RSA", "Peran": "Faktorisasi sulit"},
        {"Konsep": "Kompleksitas Komputasi", "Contoh/Kegunaan": "2^k ruang kunci",
         "Algoritma": "AES / DES", "Peran": "Daya tahan terhadap brute force"},
    ]
