# DDoS Detection System

Sistem deteksi DDoS real-time yang kuat dengan kemampuan monitoring jaringan, pendeteksian anomali, dan pemblokiran IP otomatis. Sistem ini dirancang untuk melindungi infrastruktur jaringan dari serangan DDoS dengan melakukan analisis lalu lintas jaringan secara terus menerus.

## Fitur Utama

- 🔍 Monitoring jaringan real-time
- 🚨 Deteksi anomali berbasis threshold
- 🛡️ Pemblokiran IP otomatis
- ⏲️ Sistem pemblokiran sementara (5 menit)
- 📊 Statistik monitoring real-time
- 📝 Pencatatan serangan komprehensif
- 🎨 Interface konsol berwarna
- ⚪ Sistem whitelist dan blacklist

## Persyaratan Sistem

- Python 3.6+
- Linux/Unix sistem operasi (untuk fungsi iptables)
- Root/sudo akses (untuk manipulasi iptables)

## Dependensi

```bash
pip install scapy
pip install colorama
```

## Instalasi

1. Clone repository ini:
```bash
git clone https://github.com/kingzuy/ddos_detector.git
cd ddos-detection-system
```

Jalankan program sebagai root/sudo user:

```bash
sudo python3 ddos_detector.py
```

## Konfigurasi

Sistem menggunakan beberapa parameter threshold yang dapat dikonfigurasi:

```python
THRESHOLD_CONNECTIONS = 1000  # Maksimum koneksi per IP
THRESHOLD_PACKETS = 5000      # Maksimum paket per IP
THRESHOLD_BANDWIDTH = 10000000  # Maksimum bandwidth dalam bytes
TIME_WINDOW = 60             # Periode monitoring dalam detik
BLOCK_DURATION = 300         # Durasi pemblokiran dalam detik
```

## Cara Kerja

1. **Monitoring Jaringan**
   - Memantau semua lalu lintas jaringan menggunakan Scapy
   - Mengumpulkan statistik per IP address

2. **Deteksi Anomali**
   - Memeriksa jumlah koneksi
   - Menghitung jumlah paket
   - Mengukur penggunaan bandwidth

3. **Sistem Proteksi**
   - Pemblokiran IP otomatis menggunakan iptables
   - Pembatasan waktu blokir
   - Sistem whitelist untuk IP terpercaya

## Fitur Logging

- Logging berwarna di konsol
- Pencatatan ke file (ddos_detection.log)
- History serangan lengkap
- Statistik real-time

## Interface Konsol

Program menggunakan sistem warna untuk memudahkan monitoring:
- 🔴 Merah: Pesan alert/serangan
- 🔵 Biru: Informasi umum
- 🟢 Hijau: Pesan sukses

## Penanganan Exit

- Tekan Ctrl+C untuk keluar
- Menampilkan ringkasan serangan sebelum keluar
- Konfirmasi sebelum menutup program

## Keamanan

- Implementasi whitelist untuk IP terpercaya
- Blacklist untuk IP mencurigakan
- Pemblokiran otomatis untuk IP yang terdeteksi melakukan serangan
- Pembersihan data secara periodik untuk mencegah memory leaks

## Pemantauan

Sistem menyediakan beberapa metrik pemantauan:
- Total koneksi
- Jumlah paket
- Penggunaan bandwidth
- Daftar IP yang diblokir
- History serangan

## Pengembangan Lebih Lanjut

Beberapa area yang dapat dikembangkan:
- Implementasi machine learning untuk deteksi anomali
- Integrasi dengan sistem notifikasi eksternal
- Dashboard web untuk monitoring
- API untuk integrasi dengan sistem lain
- Dukungan untuk IPv6

## Kontribusi

Kontribusi sangat diterima! Silakan buat pull request untuk:
- Perbaikan bug
- Fitur baru
- Peningkatan dokumentasi
- Optimisasi kode

