import unittest

from src.number_theory import (
    euler_phi,
    extended_euclidean,
    generate_rsa_keys,
    modular_inverse,
    rsa_encrypt,
    rsa_decrypt,
)
from src.galois_field import gf_multiply, xor_binary


class CryptoMathTests(unittest.TestCase):
    def test_rsa_journal_example(self):
        keys = generate_rsa_keys(5, 11, 3)
        self.assertEqual(keys["n"], 55)
        self.assertEqual(keys["phi"], 40)
        self.assertEqual(keys["d"], 27)
        ciphertext = rsa_encrypt(4, keys["e"], keys["n"])
        self.assertEqual(rsa_decrypt(ciphertext, keys["d"], keys["n"]), 4)

    def test_journal_xor_example(self):
        self.assertEqual(
            xor_binary("10101010", "11001100"),
            "01100110",
        )

    def test_xor_is_reversible(self):
        a = "10101010"
        b = "11001100"
        self.assertEqual(xor_binary(xor_binary(a, b), b), a)

    def test_euler_phi_and_inverse(self):
        self.assertEqual(euler_phi(55), 40)
        self.assertEqual(modular_inverse(3, 40), 27)

    def test_extended_euclidean_gcd(self):
        gcd_value, _, _ = extended_euclidean(3, 40)
        self.assertEqual(gcd_value, 1)

    def test_fips_galois_multiplication(self):
        # FIPS 197: 0x57 * 0x13 = 0xFE.
        self.assertEqual(gf_multiply(0x57, 0x13), 0xFE)


if __name__ == "__main__":
    unittest.main()
