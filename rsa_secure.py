"""
RSA mode aman memakai library `cryptography`.

- Enkripsi : RSA-OAEP (SHA-256). Untuk pesan panjang dipakai skema hibrida:
             kunci AES-256-GCM acak membungkus pesan, lalu kunci AES itu
             dienkripsi RSA-OAEP. Ini cara RSA dipakai di dunia nyata
             (RSA hanya muat ~190 byte untuk kunci 2048 bit).
- Tanda tangan: RSA-PSS (SHA-256).

Format ciphertext (base64):
    [2 byte panjang kunci terbungkus][kunci terbungkus][12 byte nonce][ciphertext+tag]
"""
import base64
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)
_PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


def generate_keypair(bits: int = 3072) -> dict:
    if bits not in (2048, 3072, 4096):
        raise ValueError("bits harus 2048, 3072, atau 4096")
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return {"private_key": private_pem, "public_key": public_pem, "bits": bits}


def _load_public(pem: str):
    key = serialization.load_pem_public_key(pem.strip().encode())
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("bukan kunci publik RSA")
    return key


def _load_private(pem: str):
    key = serialization.load_pem_private_key(pem.strip().encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("bukan kunci privat RSA")
    return key


def encrypt(text: str, public_pem: str) -> str:
    pub = _load_public(public_pem)
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    body = AESGCM(aes_key).encrypt(nonce, text.encode("utf-8"), None)
    wrapped = pub.encrypt(aes_key, _OAEP)
    blob = len(wrapped).to_bytes(2, "big") + wrapped + nonce + body
    return base64.b64encode(blob).decode()


def decrypt(token: str, private_pem: str) -> str:
    priv = _load_private(private_pem)
    blob = base64.b64decode(token.strip(), validate=True)
    klen = int.from_bytes(blob[:2], "big")
    wrapped = blob[2:2 + klen]
    nonce = blob[2 + klen:14 + klen]
    body = blob[14 + klen:]
    aes_key = priv.decrypt(wrapped, _OAEP)
    return AESGCM(aes_key).decrypt(nonce, body, None).decode("utf-8")


def sign(text: str, private_pem: str) -> str:
    sig = _load_private(private_pem).sign(text.encode("utf-8"), _PSS, hashes.SHA256())
    return base64.b64encode(sig).decode()


def verify(text: str, signature_b64: str, public_pem: str) -> bool:
    try:
        _load_public(public_pem).verify(
            base64.b64decode(signature_b64.strip(), validate=True),
            text.encode("utf-8"),
            _PSS,
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError):
        return False
