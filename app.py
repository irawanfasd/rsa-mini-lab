"""app.py - UI Streamlit untuk RSA Mini Lab (Matdis II)."""
import streamlit as st

import rsa_core as rc
from rsa_core import RSAError

st.set_page_config(page_title="RSA Mini Lab", page_icon="🔐")
st.title("🔐 RSA Mini Lab")
st.caption("Matematika Diskrit II — demonstrasi RSA: pembangkitan kunci, enkripsi, dekripsi.")
st.warning("Hanya untuk pembelajaran, **bukan untuk produksi**. Bilangan prima di sini sangat "
           "kecil menurut standar modern; jangan dipakai untuk data rahasia.")

with st.expander("Aturan ringkas"):
    st.markdown(
        "- Alfabet **A–Z** saja (`A=00 … Z=25`); spasi di awal/akhir dibuang, huruf kecil jadi kapital; "
        "spasi di tengah, angka, dan tanda baca ditolak.\n"
        "- Lebar blok `2k` digit, `k` = jumlah pasangan huruf terbanyak sehingga `25…25 < n`.\n"
        "- Padding huruf `X` (=23) sampai jumlah huruf kelipatan `k`; **Panjang asli (L)** dipakai "
        "saat dekripsi untuk membuang padding.\n"
        "- Ciphertext: blok desimal dipisah spasi, tiap blok `len(str(n))` digit.\n"
        "- `C = M^e mod n`, `M = C^d mod n`, dengan `0 ≤ M < n`.\n"
        "- Padding X, metadata L, batas `p, q < 10^9`, dan pembatasan A–Z adalah **keputusan "
        "implementasi**, bukan aturan slide. Penjelasan lengkap ada di README."
    )

# ------------------------------------------------------------------ KEY
st.header("1. Key")
mode = st.radio("Sumber kunci", ["Generate Key", "Manual Key"], horizontal=True)
st.caption("Generate: hitung dari p, q, e. Manual: masukkan kunci yang sudah ada "
           "(program tidak memfaktorkan n dan tidak menjamin kunci valid secara RSA).")

if mode == "Generate Key":
    c1, c2, c3 = st.columns(3)
    p_txt = c1.text_input("p", value="43")
    c1.caption("Bilangan prima, < 10^9.")
    q_txt = c2.text_input("q", value="59")
    c2.caption("Prima, berbeda dari p, < 10^9.")
    e_txt = c3.text_input("e", value="13")
    c3.caption("1 < e < φ(n) dan FPB(e, φ(n)) = 1.")
    if st.button("Generate Key"):
        try:
            keys = rc.generate_keys(rc.parse_int(p_txt, "p"), rc.parse_int(q_txt, "q"),
                                    rc.parse_int(e_txt, "e"))
            st.session_state["key"] = {"n": keys["n"], "e": keys["e"], "d": keys["d"],
                                       "phi": keys["phi"], "sumber": "generate"}
        except RSAError as err:
            st.session_state.pop("key", None)
            st.error(str(err))
else:
    n_txt = st.text_input("n", value="2537")
    st.caption("Bilangan bulat > 25.")
    e_man = st.text_input("e (untuk enkripsi)", value="13")
    st.caption("Bilangan bulat positif. Boleh dikosongkan jika hanya dekripsi.")
    d_man = st.text_input("d (untuk dekripsi)", value="937")
    st.caption("Bilangan bulat positif. Boleh dikosongkan jika hanya enkripsi.")
    if st.button("Pakai Manual Key"):
        try:
            n = rc.parse_int(n_txt, "n")
            e = rc.parse_int(e_man, "e") if e_man.strip() else None
            d = rc.parse_int(d_man, "d") if d_man.strip() else None
            if e is None and d is None:
                raise RSAError("Isi minimal salah satu: e (enkripsi) atau d (dekripsi).")
            if n <= 25:
                raise RSAError("n harus > 25.")
            if e is not None:
                rc.validate_manual_key(n, e, "e")
            if d is not None:
                rc.validate_manual_key(n, d, "d")
            st.session_state["key"] = {"n": n, "e": e, "d": d, "phi": None, "sumber": "manual"}
        except RSAError as err:
            st.session_state.pop("key", None)
            st.error(str(err))

key = st.session_state.get("key")
if key:
    st.success("Kunci aktif.")
    st.write(f"**n** = {key['n']}")
    if key["phi"] is not None:
        st.write(f"**φ(n)** = {key['phi']}")
    if key["e"] is not None:
        st.write(f"**Public key (n, e)** = ({key['n']}, {key['e']})")
    if key["d"] is not None:
        st.write(f"**Private key (n, d)** = ({key['n']}, {key['d']})")
    st.caption(f"Lebar blok plaintext: {rc.block_digits(key['n'])} digit "
               f"(k = {rc.block_digits(key['n']) // 2} huruf per blok).")
else:
    st.info("Belum ada kunci aktif. Generate atau isi kunci manual di atas.")

# -------------------------------------------------------------- ENCRYPT
st.header("2. Encrypt")
plain = st.text_input("Plaintext", value="STOP")
st.caption("Huruf A–Z saja; spasi di awal/akhir dibuang, huruf kecil menjadi kapital.")
if st.button("Enkripsi"):
    if not key:
        st.error("Atur kunci dulu di bagian Key.")
    elif key["e"] is None:
        st.error("Kunci aktif tidak punya e. Isi e pada Manual Key atau pakai Generate Key.")
    else:
        try:
            res = rc.encrypt(plain, key["n"], key["e"])
            st.write("Plaintext ternormalisasi:", f"`{res['plaintext']}`")
            st.write("Blok plaintext:", "`" + " ".join(res["blocks"]) + "`")
            st.write("Ciphertext:")
            st.code(res["ciphertext"], language=None)
            st.write(f"**Panjang asli: {res['length']}**")
            st.caption("Simpan Panjang asli untuk dekripsi agar padding X dibuang dengan benar.")
        except RSAError as err:
            st.error(str(err))

# -------------------------------------------------------------- DECRYPT
st.header("3. Decrypt")
cipher_in = st.text_area("Ciphertext", value="", placeholder="mis. 2081 2182")
st.caption("Blok desimal dipisah spasi atau baris baru; tiap blok harus < n.")
len_in = st.text_input("Panjang asli (L), opsional", value="")
st.caption("Kosongkan jika tidak tahu; X di akhir lalu tidak dibuang.")
if st.button("Dekripsi"):
    if not key:
        st.error("Atur kunci dulu di bagian Key.")
    elif key["d"] is None:
        st.error("Kunci aktif tidak punya d. Isi d pada Manual Key atau pakai Generate Key.")
    else:
        try:
            res = rc.decrypt(cipher_in, key["n"], key["d"], len_in)
            st.write("Blok hasil dekripsi:", "`" + " ".join(res["blocks"]) + "`")
            st.write("Plaintext:")
            st.code(res["plaintext"], language=None)
            if res["warning"]:
                st.warning("L tidak diisi: satu atau lebih `X` di akhir mungkin padding.")
        except RSAError as err:
            st.error(str(err))
