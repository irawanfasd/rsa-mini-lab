"""Tes RSA Mini Lab. Jalankan: python -m unittest -v test_rsa"""
import random
import unittest

import rsa_core as rc
from rsa_core import RSAError


class TestMath(unittest.TestCase):
    def test_gcd(self):
        self.assertEqual(rc.gcd(48, 18), 6)

    def test_mod_inverse(self):
        self.assertEqual(rc.mod_inverse(13, 2436), 937)
        with self.assertRaises(RSAError):
            rc.mod_inverse(6, 12)

    def test_generate_keys(self):
        k = rc.generate_keys(43, 59, 13)
        self.assertEqual((k["n"], k["phi"], k["d"]), (2537, 2436, 937))

    def test_mod_pow_vs_builtin(self):
        rnd = random.Random(1)
        for _ in range(200):
            b, e, m = rnd.randint(0, 10**6), rnd.randint(0, 10**6), rnd.randint(1, 10**9)
            self.assertEqual(rc.mod_pow(b, e, m), pow(b, e, m))

    def test_is_prime(self):
        self.assertFalse(rc.is_prime(1))
        self.assertTrue(rc.is_prime(2))
        self.assertTrue(rc.is_prime(10007))
        self.assertFalse(rc.is_prime(10007 * 10009))


class TestBlockDigits(unittest.TestCase):
    def test_values(self):
        for n, w in [(2537, 4), (2525, 2), (2526, 4), (100, 2), (100160063, 8)]:
            self.assertEqual(rc.block_digits(n), w, n)

    def test_rejected(self):
        for n in (25, 6):
            with self.assertRaises(RSAError):
                rc.block_digits(n)


class TestMaterialExamples(unittest.TestCase):
    def test_stop(self):
        r = rc.encrypt("STOP", 2537, 13)
        self.assertEqual(r["blocks"], ["1819", "1415"])
        self.assertEqual(r["ciphertext"], "2081 2182")

    def test_help(self):
        r = rc.decrypt("0981 0461", 2537, 937)
        self.assertEqual(r["blocks"], ["0704", "1115"])
        self.assertEqual(r["plaintext"], "HELP")

    def test_meetatnoon(self):
        r = rc.encrypt("MEETATNOON", 2537, 13)
        self.assertEqual(r["blocks"], ["1204", "0419", "0019", "1314", "1413"])


class TestRoundTrip(unittest.TestCase):
    def test_hello_k2(self):
        r = rc.encrypt("HELLO", 2537, 13)
        self.assertEqual(r["blocks"], ["0704", "1111", "1423"])
        self.assertEqual(r["length"], 5)
        d = rc.decrypt(r["ciphertext"], 2537, 937, "5")
        self.assertEqual(d["plaintext"], "HELLO")
        self.assertFalse(d["warning"])
        d2 = rc.decrypt(r["ciphertext"], 2537, 937, "")
        self.assertEqual(d2["plaintext"], "HELLOX")
        self.assertTrue(d2["warning"])

    def test_hello_k4(self):
        keys = rc.generate_keys(10007, 10009, 65537)
        self.assertEqual(keys["n"], 100160063)
        r = rc.encrypt("HELLO", keys["n"], keys["e"])
        self.assertEqual(r["blocks"], ["07041111", "14232323"])
        d = rc.decrypt(r["ciphertext"], keys["n"], keys["d"], "5")
        self.assertEqual(d["plaintext"], "HELLO")

    def test_multiple_of_k_no_padding(self):
        r = rc.encrypt("ABAB", 2537, 13)
        self.assertEqual(r["blocks"], ["0001", "0001"])

    def test_k1_no_padding(self):
        # n=100 (k=1) dengan e=d=1; n=26 dengan e=d=5 (5*5 = 1 mod 12)
        for n, e, d in [(100, 1, 1), (26, 5, 5)]:
            self.assertEqual(rc.block_digits(n), 2)
            r = rc.encrypt("HELLO", n, e)
            self.assertEqual(r["blocks"], ["07", "04", "11", "11", "14"])
            self.assertEqual(rc.decrypt(r["ciphertext"], n, d, "5")["plaintext"], "HELLO")

    def test_leading_zero_and_normalization(self):
        r = rc.encrypt("AAAA", 2537, 13)
        self.assertEqual(r["blocks"], ["0000", "0000"])
        self.assertEqual(rc.decrypt(r["ciphertext"], 2537, 937, "4")["plaintext"], "AAAA")
        self.assertEqual(rc.encrypt("hello", 2537, 13)["plaintext"], "HELLO")
        self.assertEqual(rc.encrypt("  hello\n", 2537, 13)["plaintext"], "HELLO")

    def test_long_message(self):
        msg = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 3
        r = rc.encrypt(msg, 2537, 13)
        self.assertEqual(rc.decrypt(r["ciphertext"], 2537, 937, str(r["length"]))["plaintext"], msg)

    def test_ciphertext_width(self):
        r = rc.encrypt("AAAA", 2537, 13)
        for tok in r["ciphertext"].split():
            self.assertEqual(len(tok), 4)


class TestInvalid(unittest.TestCase):
    def test_keys(self):
        bad = [(5, 5, 3), (4, 7, 5), (10**9 + 7, 11, 3), (1000000007, 1000000009, 3),
               (43, 59, 1), (43, 59, 2436), (43, 59, 2), (43, 59, 0), (43, 59, -3)]
        for p, q, e in bad:
            with self.assertRaises(RSAError, msg=(p, q, e)):
                rc.generate_keys(p, q, e)

    def test_small_n(self):
        with self.assertRaises(RSAError):
            rc.encrypt("A", 6, 3)
        with self.assertRaises(RSAError):
            rc.decrypt("1", 25, 3)

    def test_nonpositive_exponent(self):
        with self.assertRaises(RSAError):
            rc.encrypt("A", 2537, 0)
        with self.assertRaises(RSAError):
            rc.decrypt("1", 2537, -1)

    def test_parse_int(self):
        for s in ("", "  ", "abc", "4.5", "1_0", "+5", "٣"):
            with self.assertRaises(RSAError, msg=s):
                rc.parse_int(s, "x")
        self.assertEqual(rc.parse_int(" 43 ", "x"), 43)

    def test_plaintext(self):
        for s in ("", "   ", "HE LLO", "HE1", "HI!", "é", "ß"):
            with self.assertRaises(RSAError, msg=s):
                rc.encrypt(s, 2537, 13)

    def test_ciphertext(self):
        for s in ("", "  ", "+5", "1_0", "abc", "2537", "9999", "-1", "٣"):
            with self.assertRaises(RSAError, msg=s):
                rc.decrypt(s, 2537, 937)

    def test_pair_over_25(self):
        # M = 26 (pasangan "26") -> 0026 ; C = 26^13 mod 2537
        c = rc.mod_pow(26, 13, 2537)
        with self.assertRaises(RSAError):
            rc.decrypt(str(c).zfill(4), 2537, 937)

    def test_block_not_fit(self):
        # n=2537 -> lebar 4; cari C dengan M >= 10^4 (mungkin dengan kunci d sembarang)
        n, d = 2537, 1
        # d=1 -> M = C < 2537 selalu muat; gunakan n lain: n=300 (k=1, lebar 2), M=C bisa >= 100
        with self.assertRaises(RSAError):
            rc.decrypt("150", 300, 1)

    def test_length_metadata(self):
        c = rc.encrypt("HELLO", 2537, 13)["ciphertext"]   # HELLOX
        for L in ("0", "-1", "abc", "1_0", "7", "4", "3", "+5"):
            with self.assertRaises(RSAError, msg=L):
                rc.decrypt(c, 2537, 937, L)
        # L membuang huruf bukan X
        c2 = rc.encrypt("HELLOA", 2537, 13)["ciphertext"]
        with self.assertRaises(RSAError):
            rc.decrypt(c2, 2537, 937, "5")
        self.assertEqual(rc.decrypt(c, 2537, 937, " 5 ")["plaintext"], "HELLO")
        self.assertEqual(rc.decrypt(c, 2537, 937, "6")["plaintext"], "HELLOX")


if __name__ == "__main__":
    unittest.main()
