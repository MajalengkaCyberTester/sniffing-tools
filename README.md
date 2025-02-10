# Network Security Toolkit - Majalengka Cyber Tester

## Deskripsi
Toolkit ini dirancang untuk membantu dalam pemantauan jaringan, pemindaian perangkat, serangan ARP poisoning, dan penganalisisan paket. Skrip ini menggunakan `Scapy` untuk manipulasi paket dan `Colorama` untuk tampilan yang lebih menarik di terminal.

**Fitur utama:**
- Menampilkan daftar antarmuka jaringan yang dikenali oleh Scapy.
- Memindai jaringan untuk menemukan perangkat yang terhubung.
- Verifikasi perangkat aktif menggunakan metode `ping`.
- Menampilkan informasi alamat IP dan MAC dari perangkat dalam jaringan.
- ARP Poisoning untuk pengalihan lalu lintas jaringan.
- Pemantauan paket untuk mendeteksi data sensitif.
- Pemantauan perubahan jaringan untuk mendeteksi perangkat baru.

## Instalasi
Sebelum menjalankan skrip ini, pastikan Python telah terinstal pada sistem Anda.

1. **Kloning repositori ini:**
   ```bash
   git clone [https://github.com/username/reponame.git](https://github.com/MajalengkaCyberTester/sniffing-tools.git)
   cd sniffing-tools
   ```

2. **Instal dependensi yang diperlukan:**
   ```bash
   pip install scapy
   pip install netifaces
   pip install colorama
   pip install twisted==21.2.0
   pip install sslstrip --no-deps
   ```

## Penggunaan
Jalankan skrip dengan perintah berikut:

```bash
python sniffing.py
```

Kemudian pilih antarmuka jaringan yang tersedia dan ikuti instruksi pada layar.

## Persyaratan Sistem
- Python 3.x
- Windows/Linux dengan akses administrator/root
- Modul Python: `scapy`, `colorama`, `netifaces`, `twisted==21.2.0`, `sslstrip`

## Peringatan
**Gunakan alat ini hanya untuk tujuan pembelajaran dan pengujian keamanan yang sah. Penyalahgunaan alat ini dapat melanggar hukum yang berlaku.** Majalengka Cyber Tester tidak bertanggung jawab atas penyalahgunaan alat ini.

---

© 2025 Majalengka Cyber Tester
