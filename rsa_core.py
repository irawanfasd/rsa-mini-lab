"""rsa_core.py - inti matematika RSA Mini Lab (Matdis II).

Semua fungsi ditulis manual tanpa library kriptografi. Aturan Baku A-H
mengacu pada PRD section 3.  Hanya untuk pembelajaran, bukan produksi.
"""
import re

MAX_PRIME = 10 ** 9          # batas p, q (keputusan implementasi)
PAD_VALUE = 23               # 'X' = 23
_INT_RE = re.compile(r"-?[0-9]+")   # digit ASCII saja


class RSAError(ValueError):
    """Kesalahan input/validasi dengan pesan yang ramah pengguna."""


# ---------------------------------------------------------------- parsing
def parse_int(text, nama):
    """Ubah teks jadi bilangan bulat; tolak kosong / bukan bilangan bulat."""
    s = str(text).strip()
    if not s:
        raise RSAError(f"{nama} tidak boleh kosong.")
    if not _INT_RE.fullmatch(s):
        raise RSAError(f"{nama} harus berupa bilangan bulat (contoh: 43).")
    try:
        return int(s)
    except ValueError:
        raise RSAError(f"{nama} terlalu panjang.")


# ------------------------------------------------------------ matematika
def gcd(a, b):
    """Algoritma Euclid."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """Extended Euclid: kembalikan (g, x, y) dengan a*x + b*y = g."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def mod_inverse(e, phi):
    """Invers modular e terhadap phi; RSAError jika tidak ada."""
    if phi <= 1:
        raise RSAError("Invers modular tidak ada (modulus harus > 1).")
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise RSAError(f"Invers modular tidak ada karena FPB({e}, {phi}) = {g}, bukan 1.")
    return x % phi


def is_prime(n):
    """Uji prima dengan pembagian sampai akar kuadrat."""
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def mod_pow(base, exp, mod):
    """Pemangkatan modular dengan square-and-multiply."""
    if mod <= 0:
        raise ValueError("modulus harus positif")
    if exp < 0:
        raise ValueError("eksponen tidak boleh negatif")
    result = 1 % mod
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


# ------------------------------------------------------------------ kunci
def generate_keys(p, q, e):
    """Bangkitkan kunci RSA dari p, q, e (Aturan: p, q prima, beda, < 10^9)."""
    for nama, v in (("p", p), ("q", q)):
        if v >= MAX_PRIME:
            raise RSAError(f"{nama} harus < 10^9 (batas program ini).")
        if not is_prime(v):
            raise RSAError(f"{nama} = {v} bukan bilangan prima.")
    if p == q:
        raise RSAError("p dan q harus berbeda.")
    n = p * q
    phi = (p - 1) * (q - 1)
    if not (1 < e < phi):
        raise RSAError(f"e harus memenuhi 1 < e < phi(n) = {phi}.")
    if gcd(e, phi) != 1:
        raise RSAError(f"e tidak valid: FPB(e, phi(n)) = {gcd(e, phi)}, harus 1.")
    d = mod_inverse(e, phi)
    return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d}


def validate_manual_key(n, exp, nama_exp):
    """Validasi kunci manual: n > 25, e/d bilangan bulat positif."""
    if n <= 25:
        raise RSAError("n harus > 25 (agar minimal satu huruf Z=25 muat).")
    if exp <= 0:
        raise RSAError(f"{nama_exp} harus bilangan bulat positif.")


# ---------------------------------------------------------------- encoding
def block_digits(n):
    """Lebar blok 2k digit; k = pasangan huruf terbanyak dengan 25..25 < n."""
    if n <= 25:
        raise RSAError("n harus > 25 untuk menentukan lebar blok.")
    k = 1
    while int("25" * (k + 1)) < n:
        k += 1
    return 2 * k


def normalize_plaintext(text):
    """strip() ujung, kapital; tolak kosong dan karakter selain A-Z."""
    s = text.strip()
    if not s:
        raise RSAError("Plaintext tidak boleh kosong.")
    for ch in s:
        if not (ch.isascii() and ch.isalpha()):
            nama = "spasi" if ch.isspace() else f"'{ch}'"
            raise RSAError(f"Karakter {nama} tidak diperbolehkan. Gunakan huruf A-Z saja "
                           "(tanpa spasi di tengah, angka, atau tanda baca).")
    return s.upper()


def encode_blocks(plaintext, n):
    """Plaintext ternormalisasi -> daftar blok digit (string, lebar 2k)."""
    width = block_digits(n)
    k = width // 2
    for ch in plaintext:
        if not ("A" <= ch <= "Z"):
            raise RSAError("Plaintext harus sudah dinormalisasi (A-Z).")
    pad = (-len(plaintext)) % k
    digits = "".join(f"{ord(c) - 65:02d}" for c in plaintext) + f"{PAD_VALUE:02d}" * pad
    blocks = [digits[i:i + width] for i in range(0, len(digits), width)]
    for b in blocks:
        if int(b) >= n:
            raise RSAError(f"Blok {b} tidak memenuhi M < n.")
    return blocks


def decode_blocks(blocks):
    """Daftar blok digit -> huruf; tolak pasangan di luar 00-25."""
    digits = "".join(blocks)
    letters = []
    for i in range(0, len(digits), 2):
        v = int(digits[i:i + 2])
        if v > 25:
            raise RSAError(f"Hasil dekripsi mengandung pasangan digit {digits[i:i+2]} "
                           "(di luar 00-25). Kunci atau ciphertext kemungkinan salah.")
        letters.append(chr(65 + v))
    return "".join(letters)


# -------------------------------------------------------- enkripsi/dekripsi
def encrypt_blocks(blocks, e, n):
    """C = M^e mod n untuk tiap blok."""
    return [mod_pow(int(b), e, n) for b in blocks]


def decrypt_blocks(cipher_ints, d, n):
    """M = C^d mod n; kembalikan blok string lebar 2k."""
    width = block_digits(n)
    out = []
    for c in cipher_ints:
        m = mod_pow(c, d, n)
        if m >= 10 ** width:
            raise RSAError(f"Hasil dekripsi {m} tidak muat dalam {width} digit. "
                           "Kunci atau ciphertext kemungkinan salah.")
        out.append(str(m).zfill(width))
    return out


def format_ciphertext(cipher_ints, n):
    """Blok desimal dipisah satu spasi, tiap blok len(str(n)) digit."""
    w = len(str(n))
    return " ".join(str(c).zfill(w) for c in cipher_ints)


def parse_ciphertext(text, n):
    """Split whitespace; tiap token digit ASCII murni dan 0 <= C < n."""
    tokens = text.split()
    if not tokens:
        raise RSAError("Ciphertext tidak boleh kosong.")
    result = []
    for tok in tokens:
        if not (tok.isascii() and tok.isdigit()):
            raise RSAError(f"Token '{tok}' bukan angka desimal murni (0-9).")
        c = int(tok)
        if c >= n:
            raise RSAError(f"Blok {tok} harus < n = {n}.")
        result.append(c)
    return result


def validate_length_metadata(raw, result_len, k, letters):
    """Validasi L opsional. Kembalikan int L, atau None jika kosong."""
    if raw is None:
        return None
    s = raw.strip()
    if not s:
        return None
    if not (s.isascii() and s.isdigit()):
        raise RSAError("Panjang asli (L) harus bilangan bulat positif (digit 0-9 saja).")
    length = int(s)
    if length < 1 or length > result_len:
        raise RSAError(f"L harus di antara 1 dan {result_len} (panjang hasil dekripsi).")
    if result_len - length >= k:
        raise RSAError(f"L tidak konsisten: padding paling banyak {k - 1} huruf, "
                       f"tetapi L = {length} membuang {result_len - length}.")
    if any(c != "X" for c in letters[length:]):
        raise RSAError("L tidak konsisten: huruf yang dibuang bukan semuanya 'X'.")
    return length


# ----------------------------------------------------------- alur lengkap
def encrypt(plaintext, n, e):
    """Alur Encrypt lengkap. Kembalikan dict hasil (termasuk L)."""
    validate_manual_key(n, e, "e")
    norm = normalize_plaintext(plaintext)
    blocks = encode_blocks(norm, n)
    cipher = encrypt_blocks(blocks, e, n)
    return {
        "plaintext": norm,
        "length": len(norm),
        "blocks": blocks,
        "cipher_ints": cipher,
        "ciphertext": format_ciphertext(cipher, n),
    }


def decrypt(ciphertext, n, d, length_text=None):
    """Alur Decrypt lengkap. 'warning' True jika L kosong."""
    validate_manual_key(n, d, "d")
    cipher = parse_ciphertext(ciphertext, n)
    blocks = decrypt_blocks(cipher, d, n)
    letters = decode_blocks(blocks)
    k = block_digits(n) // 2
    length = validate_length_metadata(length_text, len(letters), k, letters)
    if length is None:
        return {"plaintext": letters, "blocks": blocks, "warning": True, "length": None}
    return {"plaintext": letters[:length], "blocks": blocks, "warning": False, "length": length}
