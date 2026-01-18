========================================
PHP SECURITY SCANNER
Directory Scanner & Backdoor Detector
========================================

FITUR UTAMA:
1. Scan direktori untuk file PHP yang mencurigakan
2. Deteksi 15+ pattern backdoor umum
3. Authentication system sederhana
4. Session timeout (1 jam)
5. Recursive scanning
6. Preview konten file

CARA PENGGUNAAN:
1. Upload semua file ke web server
2. Buka index.php di browser
3. Login dengan password default: pentest123
4. Ubah password di baris 7 file index.php
5. Masukkan path direktori yang ingin discan
6. Klik "Start Scanning"

PENTING:
- Tool ini HANYA untuk testing keamanan sistem Anda sendiri
- Dilarang digunakan untuk mengakses sistem tanpa izin
- Illegal access adalah tindakan kriminal
- Selalu dapatkan izin tertulis sebelum melakukan scanning

POLA YANG DILACAK:
- eval(), base64_decode(), gzinflate()
- system(), exec(), shell_exec(), passthru()
- proc_open(), popen(), assert()
- create_function()
- Dan pattern berbahaya lainnya

KEAMANAN:
- Ubah password default ADMIN_PASSWORD
- Simpan di lingkungan yang aman
- Hanya gunakan pada sistem yang Anda miliki/kendalikan
- Hapus tool setelah digunakan
