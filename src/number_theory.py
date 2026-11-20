"""Number theory and RSA helpers implemented without cryptography dependencies."""

from math import gcd
from typing import Tuple


def mod_expression(a: int, n: int) -> int:
    """Return the residue r of a modulo n."""
    if n <= 0:
        raise ValueError("Modulus n must be positive.")
    return a % n


def is_prime(n: int) -> bool:
    """Return whether n is prime using deterministic trial division."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    divisor = 3
    while divisor * divisor <= n:
        if n % divisor == 0:
            return False
        divisor += 2
    return True


def euler_phi(n: int) -> int:
    """Calculate Euler's totient function phi(n)."""
    if n <= 0:
        raise ValueError("n must be positive.")
    result = n
    value = n
    factor = 2
    while factor * factor <= value:
        if value % factor == 0:
            while value % factor == 0:
                value //= factor
            result -= result // factor
        factor += 1
    if value > 1:
        result -= result // value
    return result


def extended_euclidean(a: int, b: int) -> Tuple[int, int, int]:
    """Return (gcd(a, b), x, y) satisfying ax + by = gcd(a, b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


def modular_inverse(a: int, modulus: int) -> int:
    """Return a inverse modulo modulus, or raise if no inverse exists."""
    if modulus <= 0:
        raise ValueError("Modulus must be positive.")
    gcd_value, inverse, _ = extended_euclidean(a % modulus, modulus)
    if gcd_value != 1:
        raise ValueError("Modular inverse does not exist.")
    return inverse % modulus


def generate_rsa_keys(p: int, q: int, e: int) -> dict:
    """Generate a small educational RSA key pair."""
    if not is_prime(p) or not is_prime(q):
        raise ValueError("p and q must be prime.")
    if p == q:
        raise ValueError("p and q must be distinct.")
    n = p * q
    phi = euler_phi(n)
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime to phi(n).")
    d = modular_inverse(e, phi)
    return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d}


def rsa_encrypt(message: int, e: int, n: int) -> int:
    """Encrypt an integer using C = M^e mod n."""
    if not 0 <= message < n:
        raise ValueError("Message M must satisfy 0 <= M < n.")
    return pow(message, e, n)


def rsa_decrypt(ciphertext: int, d: int, n: int) -> int:
    """Decrypt an integer using M = C^d mod n."""
    if not 0 <= ciphertext < n:
        raise ValueError("Ciphertext C must satisfy 0 <= C < n.")
    return pow(ciphertext, d, n)

