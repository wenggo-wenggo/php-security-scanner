# 🛡️ PHP Security Scanner Pro

![PHP Version](https://img.shields.io/badge/PHP-7.4%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Security-Testing-orange)
![Patterns](https://img.shields.io/badge/Detection-40%2B_patterns-red)

**Directory Scanner & PHP Backdoor Detector** - Advanced tool untuk mendeteksi backdoor, malware, dan file mencurigakan pada server PHP.

## 📋 Daftar Isi

- [Fitur Utama](#-fitur-utama)
- [Teknologi](#-teknologi)
- [Instalasi](#-instalasi)
- [Penggunaan](#-penggunaan)
- [Pattern Detection](#-pattern-detection)
- [Security Features](#-security-features)
- [Screenshots](#-screenshots)
- [Disclaimer](#-disclaimer)
- [License](#-license)

## ✨ Fitur Utama

### 🔍 **Advanced Detection**
- **40+ pattern deteksi** backdoor dan malware PHP
- **Hex encoding detection** (`\xXX` patterns)
- **Base64 obfuscation** detection
- **Command injection** patterns
- **Webshell signatures** (WSO, c99, r57)
- **XOR encryption** detection
- **Unicode/Octal escapes** detection

### 📊 **Analytics & Reporting**
- **Threat Level Classification** (High/Medium/Low)
- **Statistical Dashboard** dengan visualisasi
- **Line-by-line analysis** untuk file mencurigakan
- **File metadata** (size, modified date, path)
- **Pattern match highlighting**

### 🔒 **Security Features**
- **Authentication System** dengan session management
- **Session timeout** (1 jam)
- **Input sanitization** dan XSS protection
- **Path restriction** untuk keamanan server
- **Error suppression** pada production mode

### 🎨 **User Interface**
- **Modern responsive design**
- **Real-time scanning progress**
- **Color-coded threat levels**
- **Exportable results**
- **Mobile-friendly interface**

## 🛠️ Teknologi

- **PHP 7.4+** (Compatible dengan PHP 8.x)
- **HTML5 & CSS3** (Modern flexbox/grid layout)
- **JavaScript** (Vanilla, no dependencies)
- **Regular Expressions** (Advanced pattern matching)
- **Session-based Authentication**

## 🚀 Instalasi

### Prerequisites
- Web server (Apache/Nginx)
- PHP 7.4 atau lebih baru
- Akses file system untuk scanning

### Langkah Instalasi

1. **Clone/Download**
   ```bash
   git clone https://github.com/wenggo-wenggo/php-security-scanner.git
   ```
   Atau download ZIP dan ekstrak ke web server.

2. **Upload ke Server**
   ```bash
   scp -r php-security-scanner user@yourserver:/var/www/html/security-scanner/
   ```

3. **Konfigurasi Keamanan** (WAJIB)
   Edit file `index.php` baris 7:
   ```php
   // UBAH PASSWORD DEFAULT!
   define('ADMIN_PASSWORD', 'password_anda_yang_kuat');
   ```

4. **Permissions**
   ```bash
   chmod 755 php-security-scanner/
   chmod 644 php-security-scanner/*.php
   ```

5. **Akses Aplikasi**
   ```
   http://domain-anda.com/security-scanner/
   ```

## 📖 Penggunaan

### 1. Login
- Buka aplikasi di browser
- Login dengan password yang telah diatur
- Default: `pentest123` (SEGERA UBAH!)

### 2. Konfigurasi Scan
| Parameter | Deskripsi | Contoh |
|-----------|-----------|---------|
| Directory Path | Path yang akan discan | `.`, `/var/www`, `C:\xampp\htdocs` |
| File Extensions | Ekstensi file yang discan | `php,php5,phtml,inc,php7` |
| Recursive Scan | Scan subdirektori | ☑ Aktifkan untuk scan mendalam |

### 3. Start Scanning
- Klik tombol **"🚀 Start Scanning"**
- Tunggu proses scanning selesai
- Hasil akan ditampilkan secara real-time

### 4. Analisis Hasil
- **File mencurigakan** ditampilkan dengan warna:
  - 🔴 **RED**: High threat (eval, system, shell_exec)
  - 🟡 **YELLOW**: Medium threat (base64_decode, gzinflate)
  - 🟢 **GREEN**: Low threat (suspicious patterns)

- **Detail setiap file**:
  - Path lengkap file
  - Ukuran dan tanggal modifikasi
  - Pattern yang terdeteksi
  - Sample konten (1000 karakter pertama)
  - Line numbers yang mencurigakan

## 🎯 Pattern Detection

### Kategori Pattern

#### 🔴 **Critical Threats**
```regex
/eval\s*\(/i                    # Direct code evaluation
/system\s*\(/i                  # System command execution
/shell_exec\s*\(/i             # Shell command execution
/exec\s*\(/i                   # Command execution
/\$_(POST|GET|REQUEST)\[.*\]\s*\(/i  # Direct user input execution
/`.*`/                         # Backtick operator execution
```

#### 🟡 **High Threats**
```regex
/base64_decode\s*\(/i          # Base64 decoding (often for payloads)
/gzinflate\s*\(/i              # Gzip inflation (compressed malware)
/assert\s*\(/i                 # Assert function (code execution)
/\\x[0-9a-f]{2}/i              # HEX ENCODING (\xXX pattern)
/file_put_contents\s*\(.*\$_(POST|GET|REQUEST)/i # File write from input
```

#### 🟢 **Medium Threats**
```regex
/create_function\s*\(/i        # Anonymous function creation
/hex2bin\s*\(/i                # Hex to binary conversion
/pack\s*\(\s*["']H[*\d]+["']/i # Pack function with hex format
/\\\\u[0-9a-f]{4}/i            # Unicode escape sequences
/\^[\s\S]*['"]\s*\^/           # XOR encryption pattern
```

#### 📋 **Additional Patterns**
- **Webshell Signatures**: WSO, c99, r57 patterns
- **Obfuscation**: str_rot13(), chr(), ord()
- **Remote Access**: fsockopen(), curl_exec()
- **Database**: mysql_query dengan user input
- **Error Manipulation**: @ini_set, error suppression

## 🔒 Security Features

### Authentication System
- Session-based login
- Password hashing (implement sendiri untuk production)
- Session timeout 1 jam
- Automatic logout

### Input Protection
- Input sanitization
- XSS prevention
- Path traversal protection
- Directory restriction

### Safe Operations
- Error reporting disabled
- Limited file operations
- No execution of scanned code
- Read-only file access

## 📸 Screenshots

### Login Screen
```
🔒 Security Scanner Login
[Password input]
🚀 Login Button
```

### Dashboard
```
📊 Scan Statistics
├── 🔴 High Threat: 3 files
├── 🟡 Medium Threat: 8 files
└── 🟢 Low Threat: 12 files
```

### Scan Results
```html
📄 suspicious-file.php [🔴 HIGH THREAT]
📍 Path: /var/www/html/malware.php
📏 Size: 4.2 KB
🕒 Modified: 2024-01-15 14:30
🔍 Patterns: eval(), base64_decode(), system()
📝 Content Sample: [First 1000 characters]
```

## ⚠️ Disclaimer

### **PENGGUNAAN YANG DIIZINKAN**
✅ Testing sistem **milik sendiri**  
✅ Penetration testing **dengan izin tertulis**  
✅ Educational purposes **dalam lingkungan terkontrol**  
✅ Security audit **dengan persetujuan pemilik**

### **PENGGUNAAN YANG DILARANG**
❌ **Illegal access** ke sistem orang lain  
❌ **Unauthorized scanning** tanpa izin  
❌ **Malicious activities** apapun bentuknya  
❌ **Distribution** untuk tujuan kriminal  

### **PERINGATAN HUKUM**
- **Illegal access** adalah tindakan kriminal
- **Hacking tanpa izin** dapat dikenakan pasal UU ITE
- **Gunakan dengan tanggung jawab**
- **Dapatkan izin tertulis** sebelum scanning

## 📄 License

MIT License

Copyright (c) 2024 PHP Security Scanner Pro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

1. **Ethical Use Only**: Software ini hanya boleh digunakan untuk tujuan keamanan yang legal dan etis.
2. **No Malicious Use**: Dilarang menggunakan software ini untuk aktivitas ilegal atau berbahaya.
3. **Ownership Only**: Hanya scan sistem yang Anda miliki atau memiliki izin tertulis.

Lihat file [LICENSE](LICENSE) untuk detail lengkap.

## 🆘 Support

### Issues & Bug Reports
1. Cek [Issues](https://github.com/wenggo-wenggo/php-security-scanner/issues)
2. Buat issue baru dengan template yang disediakan
3. Sertakan error log dan screenshot

### Feature Requests
- Tambahkan pattern deteksi baru
- Reporting improvements
- Export features (PDF, CSV)
- API integration

### Security Reports
Email: security@yourdomain.com  
**JANGAN publikasikan vulnerability di issue tracker!**

## 🤝 Contributing

Kontribusi dipersilakan! Ikuti langkah:

1. Fork repository
2. Buat feature branch
3. Commit changes
4. Push ke branch
5. Buat Pull Request

### Contribution Guidelines
- Tambahkan test untuk perubahan baru
- Update documentation
- Ikuti coding style yang ada
- Jangan push password/credentials

## 📈 Roadmap

### Version 2.1 (Q2 2024)
- [ ] Export results (PDF/CSV)
- [ ] API endpoint untuk integration
- [ ] Scheduled scanning
- [ ] Email notifications

### Version 2.2 (Q3 2024)
- [ ] Machine learning detection
- [ ] YARA rules integration
- [ ] Cloud storage scanning
- [ ] Multi-user support

### Version 3.0 (Q4 2024)
- [ ] Real-time monitoring
- [ ] SIEM integration
- [ ] Compliance reporting
- [ ] Plugin architecture

---

## 📚 References & Resources

### Learning Resources
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Security_Cheat_Sheet.html)
- [PHP Security Best Practices](https://www.php.net/manual/en/security.php)
- [Web Application Security Testing](https://owasp.org/www-project-web-security-testing-guide/)

### Similar Tools
- [PHP Malware Finder](https://github.com/nbs-system/php-malware-finder)
- [ClamAV](https://www.clamav.net/) - Antivirus untuk server
- [LMD](https://www.rfxn.com/projects/linux-malware-detect/) - Linux Malware Detect

### Security Standards
- OWASP Top 10
- PCI DSS Requirements
- ISO 27001 Controls

---

**⚠️ PERHATIAN:** Tool ini adalah senjata tajam. Gunakan dengan kebijaksanaan dan tanggung jawab penuh. Developer tidak bertanggung jawab atas penyalahgunaan tool ini.

**Stay Ethical, Stay Secure!** 🔐

---

*Terakhir diperbarui: Januari 2024*  
*Versi: 2.0*  
*Developer: Security Team*
