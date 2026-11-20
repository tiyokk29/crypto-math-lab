# Security Audit — Mathematical Foundations of Cryptography Lab

**Tanggal:** 2026-11-20

## Scope

Audit source statis difokuskan pada:

- `app.py`
- `src/*.py`
- `tests/*.py`

## Ringkasan

Tidak ditemukan kerentanan keamanan yang terkonfirmasi pada scope yang diaudit.

## Pemeriksaan

| Area | Hasil |
|---|---|
| HTML dinamis dari input pengguna | Tidak ada interpolasi input pengguna ke HTML |
| `unsafe_allow_html=True` | Hanya dipakai untuk stylesheet statis di `app.py`; tidak memuat teks pengguna |
| XSS / script injection | Tidak ditemukan sink eksekusi HTML atau JavaScript dari input |
| Command injection | Tidak ada pemanggilan shell, `os.system`, atau `subprocess` |
| Eksekusi dinamis | Tidak ada `eval`, `exec`, atau loader objek tidak aman |
| Secret | Tidak ada kredensial, API key, atau secret yang disimpan dalam source |
| Serialisasi tidak aman | Tidak ada `pickle`, `yaml.load`, atau deserialisasi jaringan |
| Validasi input | Nilai RSA dibatasi primer/positif; GF dibatasi 0–255; XOR memvalidasi panjang/karakter biner |

## Temuan

Tidak ada temuan severity rendah sampai kritis yang terkonfirmasi.

## Catatan Edukasi

Implementasi RSA dan benchmark sengaja dibuat untuk pembelajaran. RSA dengan bilangan kecil tidak boleh dipakai untuk keamanan produksi. Prime generation pada modul benchmark menggunakan uji Miller-Rabin tanpa jaminan kriptografis dan bukan pengganti implementasi kunci standar.
