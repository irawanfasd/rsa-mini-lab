# RSA Mini Lab (Matematika Diskrit II)

Aplikasi web lokal (Python + Streamlit) yang mendemonstrasikan RSA: pembangkitan kunci, enkripsi, dan dekripsi. Perhitungan RSA ditulis sendiri di `rsa_core.py` tanpa library kriptografi; Streamlit hanya dipakai untuk UI.

> **Peringatan:** hanya untuk pembelajaran. Bilangan prima sangat kecil menurut standar modern. Jangan gunakan untuk data rahasia atau produksi.

## Instalasi
Butuh Python 3.9+.

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Menjalankan
```bash
streamlit run app.py
```
Buka alamat yang ditampilkan (biasanya http://localhost:8501). Setelah instalasi, tidak perlu internet, akun, atau database.

## Menjalankan tes
```bash
python -m unittest -v test_rsa
```

## Struktur
| File | Isi |
|---|---|
| `rsa_core.py` | Euclid, Extended Euclid, invers modular, uji prima, square-and-multiply, encoding, enkripsi, dekripsi |
| `app.py` | UI Streamlit (Key, Encrypt, Decrypt) |
| `test_rsa.py` | Tes unit |

## Contoh
Kunci default `p=43, q=59, e=13` menghasilkan `n=2537`, `φ(n)=2436`, `d=937`.

| Operasi | Hasil |
|---|---|
| Enkripsi `STOP` | blok `1819 1415` → ciphertext `2081 2182` |
| Dekripsi `0981 0461` | blok `0704 1115` → `HELP` |
| Enkripsi `MEETATNOON` | blok `1204 0419 0019 1314 1413` |
| Enkripsi `HELLO` (k=2) | `HELLOX`, blok `0704 1111 1423`, Panjang asli `5` |

## Aturan yang dipakai
1. **Alfabet:** A–Z saja, `A=00 … Z=25`.
2. **Normalisasi:** `strip()` di awal/akhir, ubah ke kapital. Plaintext kosong, atau berisi spasi di tengah, angka, tanda baca, atau karakter lain, ditolak.
3. **Lebar blok:** `2k` digit, `k` = jumlah pasangan huruf terbanyak sehingga `25…25` (k pasangan) `< n`. `n ≤ 25` ditolak.
4. **Padding:** huruf `X` (=23) ditambahkan sampai jumlah huruf kelipatan `k`.
5. **Ciphertext:** blok desimal dipisah satu spasi, tiap blok tepat `len(str(n))` digit (nol di depan dipertahankan).
6. **Panjang asli (L):** ditampilkan saat enkripsi. Saat dekripsi opsional; valid jika `1 ≤ L ≤ panjang hasil`, `panjang hasil − L < k`, dan huruf yang dibuang semuanya `X`. Jika kosong, tidak ada `X` yang dibuang dan UI memberi peringatan.
7. **Parsing ciphertext:** pisah dengan whitespace; tiap token digit ASCII murni dan `0 ≤ C < n`.
8. **Dekripsi:** `M = C^d mod n`, diformat `2k` digit; ditolak jika tidak muat atau ada pasangan digit di luar `00–25`.

## Keputusan implementasi (bukan aturan slide)
- Padding `X` dan metadata `L`.
- Batas `p, q < 10^9` dan uji prima dengan pembagian sederhana (slide memakai tes primalitas probabilistik untuk bilangan besar).
- Penolakan karakter selain A–Z.
- Syarat `M < n` (slide menulis "tidak melebihi n"; `M < n` adalah syarat RSA yang benar).
- Euclid, Extended Euclid, dan pemangkatan modular adalah metode implementasi; dasarnya ada pada bab FPB dan invers modular.

## Keterbatasan
- Ukuran prima sangat kecil, sehingga mudah dipecahkan.
- Tanpa padding acak seperti OAEP, jadi pola pesan bisa terbaca (RSA "textbook").
- Manual Key tidak memfaktorkan `n` dan tidak menjamin kunci valid secara RSA.
- Tidak ada AES, tanda tangan digital, hashing, atau pertukaran kunci.
