"""
RSA dari nol (textbook RSA) - UNTUK BELAJAR, BUKAN UNTUK PRODUKSI.

Alur:
  1. Pilih dua bilangan prima acak p dan q        (Miller-Rabin)
  2. n = p * q                                    (modulus)
  3. phi(n) = (p-1) * (q-1)
  4. e = 65537, syarat gcd(e, phi) = 1            (eksponen publik)
  5. d = e^-1 mod phi                             (eksponen privat, Extended Euclid)
  6. Enkripsi  c = m^e mod n
  7. Dekripsi  m = c^d mod n

Kenapa tidak aman untuk produksi: tidak ada padding acak (OAEP), jadi pesan
yang sama selalu menghasilkan ciphertext yang sama dan RSA mudah diserang.
"""
import math
import secrets

E_DEFAULT = 65537

_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97,
]


# ---------- 1. Bilangan prima ----------
def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Tes primalitas Miller-Rabin."""
    if n < 2:
        return False
    for sp in _SMALL_PRIMES:
        if n == sp:
            return True
        if n % sp == 0:
            return False

    # tulis n-1 = 2^s * d dengan d ganjil
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # a di [2, n-2]
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # pasti komposit
    return True


def generate_prime(bits: int) -> int:
    """Prime acak dengan panjang tepat `bits` bit."""
    while True:
        # bit teratas = 1 (panjang pasti), bit terendah = 1 (ganjil)
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


# ---------- 2. Aritmetika modular ----------
def egcd(a: int, b: int):
    """Extended Euclid: kembalikan (g, x, y) dengan a*x + b*y = g."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("invers modular tidak ada (gcd != 1)")
    return x % m


# ---------- 3. Pembuatan kunci ----------
def generate_keypair(n_bits: int = 512, e: int = E_DEFAULT) -> dict:
    """Buat kunci RSA dengan modulus ~n_bits bit. Mengembalikan semua langkahnya."""
    if n_bits < 256 or n_bits % 2:
        raise ValueError("n_bits harus genap dan minimal 256")
    half = n_bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != n_bits:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            break
    d = modinv(e, phi)
    return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d, "bits": n_bits}


# ---------- 4. Enkripsi / dekripsi ----------
def _block_size(n: int) -> int:
    """Jumlah byte data per blok, sisakan 1 byte untuk penanda 0x01."""
    return (n.bit_length() - 1) // 8 - 1


def encrypt_text(text: str, n: int, e: int) -> list:
    """Teks -> daftar angka ciphertext (satu per blok)."""
    data = text.encode("utf-8")
    k = _block_size(n)
    if k < 1:
        raise ValueError("kunci terlalu kecil")
    out = []
    for i in range(0, len(data), k):
        # awalan 0x01 menjaga nol di depan agar tidak hilang saat jadi integer
        m = int.from_bytes(b"\x01" + data[i:i + k], "big")
        out.append(pow(m, e, n))
    return out


def decrypt_blocks(blocks: list, n: int, d: int) -> str:
    data = b""
    for c in blocks:
        if not 0 <= c < n:
            raise ValueError("blok ciphertext di luar jangkauan n")
        m = pow(c, d, n)
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
        if not raw or raw[0] != 1:
            raise ValueError("dekripsi gagal (kunci salah?)")
        data += raw[1:]
    return data.decode("utf-8")


# ---------- 5. Format ciphertext untuk dikirim/disimpan ----------
def blocks_to_str(blocks: list) -> str:
    return ".".join(format(b, "x") for b in blocks)


def str_to_blocks(s: str) -> list:
    return [int(x, 16) for x in s.strip().split(".") if x]


if __name__ == "__main__":
    kp = generate_keypair(512)
    msg = "Halo RSA dari nol!"
    ct = encrypt_text(msg, kp["n"], kp["e"])
    print("ciphertext:", blocks_to_str(ct)[:60], "...")
    print("plaintext :", decrypt_blocks(ct, kp["n"], kp["d"]))
