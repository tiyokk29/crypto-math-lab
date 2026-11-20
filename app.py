import math

import pandas as pd
import streamlit as st

from src.complexity import brute_force_keyspace, journal_concept_table, semiprime_benchmark
from src.galois_field import (
    add_round_key,
    gf_add,
    gf_multiply,
    mix_columns,
    polynomial_representation,
    shift_rows,
    state_to_hex_rows,
    sub_bytes,
    text_to_state,
    xor_binary,
)
from src.number_theory import (
    euler_phi,
    generate_rsa_keys,
    gcd,
    is_prime,
    mod_expression,
    rsa_decrypt,
    rsa_encrypt,
)


st.set_page_config(
    page_title="Mathematical Foundations of Cryptography Lab",
    page_icon="M",
    layout="wide",
)

st.markdown(
    """
    <style>
    :root { color-scheme: dark; }
    .block-container { max-width: 1180px; padding-top: 2rem; }
    h1, h2, h3 { letter-spacing: -0.02em; }
    [data-testid="stMetric"] {
        border: 1px solid #263956;
        border-radius: 10px;
        background: #111C2E;
        padding: 12px;
    }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] {
        border: 1px solid #263956;
        border-radius: 8px;
        padding: 8px 14px;
    }
    code, .stCode, [data-testid="stCodeBlock"] {
        font-family: "Cascadia Mono", "Consolas", monospace;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("Mathematical Foundations of Cryptography Lab")
st.caption("Laboratorium interaktif: Teori Bilangan, Medan Hingga, dan Kompleksitas Komputasi")

tab_number, tab_galois, tab_complexity = st.tabs([
    "01  Teori Bilangan & RSA",
    "02  Aljabar & GF(2^8)",
    "03  Kompleksitas & Jurnal",
])


# Tab 1
with tab_number:
    st.subheader("Aritmetika Modular")
    col_a, col_n, col_result = st.columns([1, 1, 1])
    with col_a:
        a = st.number_input("Bilangan a", value=17, step=1, key="mod_a")
    with col_n:
        modulus = st.number_input("Modulus n", value=5, min_value=1, step=1, key="mod_n")
    with col_result:
        try:
            residue = mod_expression(int(a), int(modulus))
            st.metric("Residue r", str(residue))
        except ValueError as error:
            st.error(str(error))
    st.code(f"{int(a)} mod {int(modulus)} = {residue if 'residue' in locals() else '?'}")

    st.divider()
    st.subheader("Simulator Kunci RSA")

    def load_journal_preset():
        st.session_state.rsa_p = 5
        st.session_state.rsa_q = 11
        st.session_state.rsa_e = 3

    col_preset, col_space = st.columns([1, 5])
    with col_preset:
        st.button("Gunakan contoh jurnal p=5, q=11, e=3", on_click=load_journal_preset)

    c1, c2, c3 = st.columns(3)
    with c1:
        p = st.number_input("Prima p", value=st.session_state.get("rsa_p", 5),
                            min_value=2, step=1, key="rsa_p")
    with c2:
        q = st.number_input("Prima q", value=st.session_state.get("rsa_q", 11),
                            min_value=2, step=1, key="rsa_q")
    with c3:
        e = st.number_input("Eksponen publik e", value=st.session_state.get("rsa_e", 3),
                            min_value=2, step=1, key="rsa_e")

    if st.button("Bentuk kunci RSA", type="primary"):
        try:
            keys = generate_rsa_keys(int(p), int(q), int(e))
            st.session_state.rsa_keys = keys
        except ValueError as error:
            st.error(str(error))

    if "rsa_keys" in st.session_state:
        keys = st.session_state["rsa_keys"]
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("n = p × q", str(keys["n"]))
        m2.metric("φ(n)", str(keys["phi"]))
        m3.metric("gcd(e, φ(n))", str(gcd(keys["e"], keys["phi"])))
        m4.metric("Eksponen privat d", str(keys["d"]))
        st.code(
            f"n = {keys['p']} × {keys['q']} = {keys['n']}\n"
            f"φ(n) = ({keys['p']}-1)({keys['q']}-1) = {keys['phi']}\n"
            f"gcd({keys['e']}, {keys['phi']}) = 1\n"
            f"d = {keys['e']}⁻¹ mod {keys['phi']} = {keys['d']}"
        )

        st.caption("Peringatan: Bilangan kecil pada lab ini hanya untuk simulasi edukasi, bukan untuk produksi.")
        message = st.number_input(
            "Pesan M (0 ≤ M < n)",
            min_value=0,
            max_value=max(0, keys["n"] - 1),
            value=min(4, keys["n"] - 1),
            step=1,
            key="rsa_message",
        )
        cipher = rsa_encrypt(int(message), keys["e"], keys["n"])
        plaintext = rsa_decrypt(cipher, keys["d"], keys["n"])
        st.code(
            f"C = M^e mod n = {int(message)}^{keys['e']} mod {keys['n']} = {cipher}\n"
            f"M = C^d mod n = {cipher}^{keys['d']} mod {keys['n']} = {plaintext}"
        )
        if plaintext == int(message):
            st.success("Dekripsi berhasil; M kembali sama dengan pesan awal.")
        else:
            st.error("Dekripsi tidak sesuai dengan pesan awal.")


# Tab 2
with tab_galois:
    st.subheader("Operasi XOR Biner")
    x1, x2 = st.columns(2)
    with x1:
        binary_a = st.text_input("A (biner)", value="10101010", key="xor_a")
    with x2:
        binary_b = st.text_input("B (biner)", value="11001100", key="xor_b")

    try:
        xor_result = xor_binary(binary_a, binary_b)
        reversible = xor_binary(xor_result, binary_b)
        st.code(
            f"{binary_a}\n"
            f"⊕ {binary_b}\n"
            f"= {xor_result}"
        )
        st.metric("Verifikasi A ⊕ B ⊕ B", reversible)
        if reversible == binary_a:
            st.success("Sifat reversibel terverifikasi.")
    except ValueError as error:
        st.error(str(error))

    st.divider()
    st.subheader("GF(2⁸) — Aritmetika Medan Hingga")
    g1, g2 = st.columns(2)
    with g1:
        gf_a = st.number_input("A (0–255)", min_value=0, max_value=255,
                               value=0x57, step=1, key="gf_a")
    with g2:
        gf_b = st.number_input("B (0–255)", min_value=0, max_value=255,
                               value=0x13, step=1, key="gf_b")

    sum_value = gf_add(int(gf_a), int(gf_b))
    product_value = gf_multiply(int(gf_a), int(gf_b))
    c1, c2 = st.columns(2)
    with c1:
        st.metric("Penjumlahan = XOR", f"{sum_value:02X}")
        st.code(f"Biner  {sum_value:08b}\nHex    0x{sum_value:02X}\nPolinom {polynomial_representation(sum_value)}")
    with c2:
        st.metric("Perkalian modulo 0x11B", f"{product_value:02X}")
        st.code(f"Biner  {product_value:08b}\nHex    0x{product_value:02X}\nPolinom {polynomial_representation(product_value)}")

    st.divider()
    st.subheader("Transformasi State AES 4 × 4")
    aes_text = st.text_input("Teks 16-byte (akan dipotong/ditambah NUL)",
                             value="CryptographyLab!",
                             max_chars=16)
    round_key_text = st.text_input("Kunci putaran 16-byte", value="0123456789abcdef",
                                   max_chars=16)
    round_key = round_key_text.encode("utf-8").ljust(16, b"\x00")[:16]

    state = text_to_state(aes_text)
    sub_state = sub_bytes(state)
    shift_state = shift_rows(sub_state)
    mix_state = mix_columns(shift_state)
    final_state = add_round_key(mix_state, round_key)

    names = ("State awal", "SubBytes", "ShiftRows", "MixColumns", "AddRoundKey")
    states = (state, sub_state, shift_state, mix_state, final_state)
    cols = st.columns(5)
    for col, name, current in zip(cols, names, states):
        with col:
            st.markdown(f"**{name}**")
            st.code("\n".join(state_to_hex_rows(current)))


# Tab 3
with tab_complexity:
    st.subheader("Fungsi Satu Arah: Multiplikasi vs Faktorisasi")
    prime_bits = st.select_slider("Ukuran prima", options=[16, 24, 32, 40, 48],
                                  value=24)
    if st.button("Jalankan benchmark", type="primary"):
        with st.spinner("Membentuk semiprime dan memfaktorkan…"):
            result = semiprime_benchmark(int(prime_bits))
        b1, b2, b3 = st.columns(3)
        b1.metric("n terbangkitkan", f"{result['n_bits']} bit")
        b2.metric("Waktu kalikan", f"{result['multiplication_ms']:.4f} ms")
        b3.metric("Waktu faktorisasi", f"{result['factorization_ms']:.4f} ms")
        st.code(str(result["n"]))
        st.caption("Benchmark lokal bersifat informatif dan menggunakan trial division untuk ukuran kecil.")

    st.divider()
    st.subheader("Ruang Kunci Brute Force")
    key_rows = []
    for key_bits in (56, 128, 192, 256):
        item = brute_force_keyspace(key_bits)
        key_rows.append({
            "Ukuran kunci": f"{key_bits} bit",
            "Kemungkinan": item["formula"],
            "Urutan nilai": f"≈10^{int(key_bits * math.log10(2))}",
        })
    st.dataframe(pd.DataFrame(key_rows), use_container_width=True, hide_index=True)

    st.caption(
        "DES 56-bit memiliki 2⁵⁶ kemungkinan kunci; AES-128, AES-192, dan AES-256 "
        "bertambah hingga 2²⁵⁶ kemungkinan."
    )

    st.divider()
    st.subheader("Pemetaan Dasar Matematika Jurnal")
    st.dataframe(pd.DataFrame(journal_concept_table()), use_container_width=True, hide_index=True)
