<?php
session_start();
error_reporting(0);
ini_set('display_errors', 0);

// Autentikasi sederhana (ubah password di bawah)
define('ADMIN_PASSWORD', 'pentest123');

// Deteksi backdoor patterns - ENHANCED VERSION
$backdoor_patterns = [
    // Eval dan eksekusi kode
    '/eval\s*\(/i',
    '/assert\s*\(/i',
    '/create_function\s*\(/i',
    '/preg_replace\s*\(\s*["\']\/.*\/e["\']/i',
    
    // System commands
    '/system\s*\(/i',
    '/shell_exec\s*\(/i',
    '/exec\s*\(/i',
    '/passthru\s*\(/i',
    '/proc_open\s*\(/i',
    '/popen\s*\(/i',
    
    // Base64 encoding/decoding
    '/base64_decode\s*\(/i',
    '/base64_encode\s*\(/i',
    
    // Compression functions (often used in obfuscation)
    '/gzinflate\s*\(/i',
    '/gzuncompress\s*\(/i',
    '/gzdecode\s*\(/i',
    '/gzencode\s*\(/i',
    '/str_rot13\s*\(/i',
    
    // Hex encoding/decoding - TAMBAHAN PATTERN \x
    '/\\\x[0-9a-f]{2}/i',  // Pattern \x untuk hex encoding
    '/chr\s*\(\s*\d+\s*\)/i',
    '/hex2bin\s*\(/i',
    '/bin2hex\s*\(/i',
    '/pack\s*\(\s*["\']H[*\d]+["\']/i',
    
    // File manipulation untuk backdoor
    '/file_put_contents\s*\(.*\$_(POST|GET|REQUEST)/i',
    '/file_get_contents\s*\(.*php:\/\/input/i',
    '/fwrite\s*\(.*\$_(POST|GET|REQUEST)/i',
    
    // Command injection patterns
    '/`.*`/',
    '/\$\{(.*)\}/',
    
    // Direct variable execution
    '/\$_(POST|GET|REQUEST|COOKIE|SERVER)\[.*\]\s*\(/i',
    '/\$\w+\s*\(/i', // Variable function calls like $f()
    
    // Obfuscation techniques
    '/\\\u[0-9a-f]{4}/i', // Unicode escapes
    '/\\\[0-7]{1,3}/', // Octal escapes
    
    // WSO, c99, r57 specific patterns
    '/WSO\s*=/i',
    '/\$GLOBALS\[\'___\w+\'\]/i',
    '/@ini_set\s*\(\s*["\']display_errors["\']/i',
    
    // Dangerous includes
    '/include\s*\(\s*\$_(POST|GET|REQUEST)/i',
    '/require\s*\(\s*\$_(POST|GET|REQUEST)/i',
    
    // Backconnect patterns
    '/fsockopen\s*\(.*\$_(POST|GET|REQUEST)/i',
    '/curl_exec\s*\(/i',
    '/curl_setopt\s*\(/i',
    
    // Database backdoors
    '/mysql_query\s*\(\s*\$_(POST|GET|REQUEST)/i',
    '/mysqli_query\s*\(\s*\$_(POST|GET|REQUEST)/i',
    
    // XOR encryption (common in malware)
    '/\^[\s\S]*[\'"]\s*\^/',
    
    // JavaScript execution in PHP
    '/<script[^>]*>.*<\/script>/is',
    '/echo\s*[\'"]<script/i',
    
    // Suspicious error suppression
    '/@\s*(eval|exec|system|shell_exec|passthru|assert)/i',
    
    // Long strings of random characters (obfuscation)
    '/[\'\"][a-zA-Z0-9\+\/=]{50,}[\'\"]/',
    
    // Remote file inclusion
    '/include\s*\(\s*[\'"]http[s]?:/i',
    '/require\s*\(\s*[\'"]http[s]?:/i',
    
    // Password/access patterns
    '/password\s*=\s*[\'"]\w+[\'\"]/i',
    '/login\s*=\s*[\'"]\w+[\'\"]/i',
    '/admin\s*=\s*[\'"]\w+[\'\"]/i',
    
    // Encryption functions (might be malicious)
    '/openssl_encrypt\s*\(/i',
    '/openssl_decrypt\s*\(/i',
    '/mcrypt_encrypt\s*\(/i',
    '/mcrypt_decrypt\s*\(/i',
];

// Pattern descriptions untuk tampilan yang lebih informatif
$pattern_descriptions = [
    '/eval\s*\(/i' => 'eval() function - Direct code execution',
    '/\\\x[0-9a-f]{2}/i' => 'Hex encoding (\xXX) - Common in obfuscated code',
    '/base64_decode\s*\(/i' => 'base64_decode() - Often used for payload decoding',
    '/gzinflate\s*\(/i' => 'gzinflate() - Compression used in malware',
    '/system\s*\(/i' => 'system() - Command execution',
    '/shell_exec\s*\(/i' => 'shell_exec() - Command execution',
    '/exec\s*\(/i' => 'exec() - Command execution',
    '/passthru\s*\(/i' => 'passthru() - Command execution',
    '/proc_open\s*\(/i' => 'proc_open() - Process execution',
    '/popen\s*\(/i' => 'popen() - Process execution',
    '/assert\s*\(/i' => 'assert() - Code execution',
    '/create_function\s*\(/i' => 'create_function() - Anonymous function creation',
    '/file_put_contents\s*\(.*\$_(POST|GET|REQUEST)/i' => 'File write from user input',
    '/\$_(POST|GET|REQUEST)\[.*\]\s*\(/i' => 'Direct execution of user input',
    '/`.*`/' => 'Backtick operator - Command execution',
    '/@ini_set\s*\(\s*["\']display_errors["\']/i' => 'Error display manipulation',
    '/include\s*\(\s*\$_(POST|GET|REQUEST)/i' => 'Dynamic include from user input',
    '/fsockopen\s*\(.*\$_(POST|GET|REQUEST)/i' => 'Socket connection from user input',
    '/chr\s*\(\s*\d+\s*\)/i' => 'chr() function - Character generation (often in obfuscation)',
    '/hex2bin\s*\(/i' => 'hex2bin() - Hex to binary conversion',
    '/pack\s*\(\s*["\']H[*\d]+["\']/i' => 'pack() with hex format',
    '/\\\\u[0-9a-f]{4}/i' => 'Unicode escape sequences',
    '/\\\\[0-7]{1,3}/' => 'Octal escape sequences',
    '/WSO\s*=/i' => 'WSO webshell signature',
    '/\^[\s\S]*[\'"]\s*\^/' => 'XOR encryption pattern',
    '/@\s*(eval|exec|system|shell_exec|passthru|assert)/i' => 'Error suppressed dangerous function',
    '/[\'\"][a-zA-Z0-9\+\/=]{50,}[\'\"]/' => 'Long base64-like string',
    '/include\s*\(\s*[\'"]http[s]?:/i' => 'Remote file inclusion',
];

// Fungsi untuk mendapatkan deskripsi pattern
function get_pattern_description($pattern) {
    global $pattern_descriptions;
    return isset($pattern_descriptions[$pattern]) ? $pattern_descriptions[$pattern] : 'Suspicious pattern detected';
}

// Fungsi login
function require_login() {
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        header('Location: ?action=login');
        exit();
    }
}

// Login handler
if (isset($_GET['action']) && $_GET['action'] == 'login') {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $password = $_POST['password'] ?? '';
        if ($password === ADMIN_PASSWORD) {
            $_SESSION['logged_in'] = true;
            $_SESSION['login_time'] = time();
            header('Location: index.php');
            exit();
        } else {
            $error = "Password salah!";
        }
    }
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Security Scanner</title>
        <style>
            body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 50px; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
            .login-box { max-width: 400px; width: 100%; background: white; padding: 40px; border-radius: 15px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
            h2 { text-align: center; color: #333; margin-bottom: 30px; }
            input[type="password"] { width: 100%; padding: 15px; margin: 10px 0 20px; border: 2px solid #ddd; border-radius: 8px; font-size: 16px; transition: border 0.3s; }
            input[type="password"]:focus { border-color: #667eea; outline: none; }
            button { width: 100%; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 15px; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: 600; transition: transform 0.2s; }
            button:hover { transform: translateY(-2px); }
            .error { color: #ff4757; margin: 10px 0; text-align: center; }
            .info { font-size: 12px; color: #666; text-align: center; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>🔒 Security Scanner Login</h2>
            <?php if (isset($error)) echo "<div class='error'>$error</div>"; ?>
            <form method="POST">
                <input type="password" name="password" placeholder="Enter password" required>
                <button type="submit">Login</button>
            </form>
            <div class="info">
                <p>Default password: pentest123</p>
                <p><strong>Ubah password di source code sebelum digunakan!</strong></p>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit();
}

// Logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit();
}

require_login();

// Cek session timeout (1 jam)
if (time() - $_SESSION['login_time'] > 3600) {
    session_destroy();
    header('Location: index.php');
    exit();
}

// Fungsi untuk mengklasifikasikan tingkat bahaya
function get_threat_level($patterns) {
    $high_threat = [
        '/eval\s*\(/i',
        '/system\s*\(/i',
        '/shell_exec\s*\(/i',
        '/exec\s*\(/i',
        '/passthru\s*\(/i',
        '/`.*`/',
        '/\$_(POST|GET|REQUEST)\[.*\]\s*\(/i',
        '/include\s*\(\s*\$_(POST|GET|REQUEST)/i',
    ];
    
    $medium_threat = [
        '/base64_decode\s*\(/i',
        '/gzinflate\s*\(/i',
        '/assert\s*\(/i',
        '/create_function\s*\(/i',
        '/file_put_contents\s*\(.*\$_(POST|GET|REQUEST)/i',
        '/fsockopen\s*\(.*\$_(POST|GET|REQUEST)/i',
    ];
    
    $high_count = 0;
    $medium_count = 0;
    
    foreach ($patterns as $pattern) {
        if (in_array($pattern, $high_threat)) {
            $high_count++;
        } elseif (in_array($pattern, $medium_threat)) {
            $medium_count++;
        }
    }
    
    if ($high_count > 0) return 'high';
    if ($medium_count > 0) return 'medium';
    return 'low';
}

// Fungsi scan direktori
function scan_directory($dir, $recursive = false, $ext_filter = ['php', 'php5', 'phtml', 'php7', 'phps', 'inc']) {
    global $backdoor_patterns;
    $results = [];
    
    if (!is_dir($dir)) {
        return ['error' => "Directory '$dir' not found or not accessible"];
    }
    
    $files = scandir($dir);
    foreach ($files as $file) {
        if ($file == '.' || $file == '..') continue;
        
        $full_path = $dir . DIRECTORY_SEPARATOR . $file;
        
        if (is_dir($full_path) && $recursive) {
            $sub_results = scan_directory($full_path, $recursive, $ext_filter);
            if (isset($sub_results['error'])) {
                // Skip directory errors
                continue;
            }
            $results = array_merge($results, $sub_results);
        } elseif (is_file($full_path)) {
            $ext = strtolower(pathinfo($full_path, PATHINFO_EXTENSION));
            if (in_array($ext, $ext_filter)) {
                $content = @file_get_contents($full_path);
                if ($content === false) continue;
                
                $suspicious = false;
                $matched_patterns = [];
                
                foreach ($backdoor_patterns as $pattern) {
                    if (preg_match_all($pattern, $content, $matches)) {
                        $suspicious = true;
                        if (!in_array($pattern, $matched_patterns)) {
                            $matched_patterns[] = $pattern;
                        }
                    }
                }
                
                if ($suspicious) {
                    // Ambil line yang mengandung pattern
                    $lines = explode("\n", $content);
                    $suspicious_lines = [];
                    foreach ($lines as $line_num => $line) {
                        foreach ($matched_patterns as $pattern) {
                            if (preg_match($pattern, $line)) {
                                $suspicious_lines[] = [
                                    'line' => $line_num + 1,
                                    'content' => substr(trim($line), 0, 200)
                                ];
                                break;
                            }
                        }
                        if (count($suspicious_lines) >= 5) break; // Batasi jumlah line
                    }
                    
                    $results[] = [
                        'path' => $full_path,
                        'filename' => $file,
                        'size' => filesize($full_path),
                        'modified' => date('Y-m-d H:i:s', filemtime($full_path)),
                        'patterns' => $matched_patterns,
                        'threat_level' => get_threat_level($matched_patterns),
                        'pattern_count' => count($matched_patterns),
                        'content_sample' => substr($content, 0, 1000),
                        'suspicious_lines' => $suspicious_lines
                    ];
                }
            }
        }
    }
    return $results;
}

// Handle scan request
$scan_results = [];
$scan_dir = $_POST['directory'] ?? '.';
$recursive = isset($_POST['recursive']);
$file_types = $_POST['file_types'] ?? 'php,php5,phtml,inc';
$scanned = false;
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['scan'])) {
    $scanned = true;
    $ext_filter = array_map('trim', explode(',', $file_types));
    $scan_result = scan_directory($scan_dir, $recursive, $ext_filter);
    
    if (isset($scan_result['error'])) {
        $error = $scan_result['error'];
        $scan_results = [];
    } else {
        $scan_results = $scan_result;
    }
}

// Sort results by threat level
usort($scan_results, function($a, $b) {
    $threat_order = ['high' => 3, 'medium' => 2, 'low' => 1];
    return ($threat_order[$b['threat_level']] ?? 0) - ($threat_order[$a['threat_level']] ?? 0);
});
?>
<!DOCTYPE html>
<html>
<head>
    <title>PHP Security Scanner - Enhanced</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8f9fa; color: #333; line-height: 1.6; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 0; text-align: center; border-radius: 15px; margin-bottom: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
        header h1 { font-size: 2.8em; margin-bottom: 10px; }
        header p { font-size: 1.2em; opacity: 0.9; }
        .card { background: white; border-radius: 15px; padding: 30px; margin-bottom: 30px; box-shadow: 0 5px 20px rgba(0,0,0,0.08); }
        .form-group { margin-bottom: 25px; }
        label { display: block; margin-bottom: 10px; font-weight: 600; color: #444; font-size: 1.1em; }
        input[type="text"] { width: 100%; padding: 15px; border: 2px solid #e0e0e0; border-radius: 10px; font-size: 16px; transition: all 0.3s; }
        input[type="text"]:focus { border-color: #667eea; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1); outline: none; }
        .checkbox { display: flex; align-items: center; margin: 15px 0; }
        .checkbox input { margin-right: 12px; transform: scale(1.2); }
        .checkbox label { margin-bottom: 0; }
        .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 16px 32px; border-radius: 10px; cursor: pointer; font-size: 16px; font-weight: 600; transition: all 0.3s; display: inline-flex; align-items: center; gap: 10px; }
        .btn:hover { transform: translateY(-3px); box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3); }
        .btn-logout { background: #ff4757; margin-left: 15px; }
        .btn-settings { background: #2ed573; }
        .results-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }
        .results-count { font-size: 1.3em; color: #666; font-weight: 600; }
        .result-item { border-radius: 12px; padding: 25px; margin-bottom: 25px; transition: transform 0.2s; }
        .result-item:hover { transform: translateX(5px); }
        .result-item.high { border-left: 6px solid #ff4757; background: linear-gradient(90deg, #fff8f8 0%, #ffffff 100%); }
        .result-item.medium { border-left: 6px solid #ffa502; background: linear-gradient(90deg, #fff8e6 0%, #ffffff 100%); }
        .result-item.low { border-left: 6px solid #2ed573; background: linear-gradient(90deg, #f8fff8 0%, #ffffff 100%); }
        .file-path { font-weight: bold; color: #2f3542; margin-bottom: 15px; font-size: 1.2em; display: flex; align-items: center; gap: 10px; }
        .file-meta { font-size: 0.95em; color: #666; margin-bottom: 20px; display: flex; gap: 20px; }
        .pattern-badge { display: inline-block; padding: 8px 16px; border-radius: 20px; font-size: 0.85em; margin-right: 10px; margin-bottom: 10px; font-weight: 500; }
        .pattern-badge.high { background: #ff4757; color: white; }
        .pattern-badge.medium { background: #ffa502; color: white; }
        .pattern-badge.low { background: #2ed573; color: white; }
        .content-sample { background: #f8f9fa; padding: 20px; border-radius: 10px; font-family: 'Courier New', monospace; font-size: 0.95em; overflow-x: auto; margin-top: 20px; border: 1px solid #e9ecef; }
        .alert { padding: 20px; border-radius: 12px; margin-bottom: 25px; }
        .alert-info { background: linear-gradient(90deg, #e7f3ff 0%, #ffffff 100%); color: #0066cc; border-left: 6px solid #0066cc; }
        .alert-warning { background: linear-gradient(90deg, #fff8e6 0%, #ffffff 100%); color: #cc8500; border-left: 6px solid #cc8500; }
        .alert-danger { background: linear-gradient(90deg, #ffe6e6 0%, #ffffff 100%); color: #cc0000; border-left: 6px solid #cc0000; }
        .alert-success { background: linear-gradient(90deg, #e6ffe6 0%, #ffffff 100%); color: #00a300; border-left: 6px solid #00a300; }
        .footer { text-align: center; margin-top: 50px; color: #888; font-size: 0.9em; }
        .loading { display: none; text-align: center; padding: 40px; }
        .spinner { border: 5px solid #f3f3f3; border-top: 5px solid #667eea; border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; margin: 0 auto 20px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .threat-badge { padding: 8px 20px; border-radius: 20px; font-weight: bold; font-size: 0.9em; }
        .threat-high { background: #ff4757; color: white; }
        .threat-medium { background: #ffa502; color: white; }
        .threat-low { background: #2ed573; color: white; }
        .pattern-section { margin-top: 20px; }
        .pattern-desc { font-size: 0.9em; color: #666; margin-left: 10px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .stat-box { background: white; padding: 25px; border-radius: 12px; text-align: center; box-shadow: 0 5px 15px rgba(0,0,0,0.05); }
        .stat-number { font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }
        .stat-label { color: #666; font-size: 1.1em; }
        .stat-high { color: #ff4757; }
        .stat-medium { color: #ffa502; }
        .stat-low { color: #2ed573; }
        .line-number { color: #666; padding-right: 15px; border-right: 2px solid #ddd; }
        .suspicious-line { background: #fff8e6; padding: 10px; margin: 5px 0; border-radius: 5px; font-family: monospace; }
        @media (max-width: 768px) { 
            .container { padding: 15px; } 
            header h1 { font-size: 2em; }
            .stats { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ PHP Security Scanner Pro</h1>
            <p>Advanced Directory Scanner & Backdoor Detector with 40+ Patterns</p>
            <div style="margin-top: 25px;">
                <a href="?logout" class="btn btn-logout">🚪 Logout</a>
            </div>
        </header>

        <div class="card">
            <h2 style="margin-bottom: 25px; color: #2f3542; font-size: 1.8em;">⚙️ Scan Configuration</h2>
            <form method="POST" id="scanForm">
                <div class="form-group">
                    <label for="directory">📁 Directory Path:</label>
                    <input type="text" id="directory" name="directory" value="<?php echo htmlspecialchars($scan_dir); ?>" placeholder="Contoh: . atau /var/www/html atau C:\xampp\htdocs">
                    <p style="font-size: 0.95em; color: #666; margin-top: 8px;">Gunakan '.' untuk direktori saat ini atau masukkan path lengkap</p>
                </div>
                
                <div class="form-group">
                    <label for="file_types">📄 File Extensions to Scan:</label>
                    <input type="text" id="file_types" name="file_types" value="<?php echo htmlspecialchars($file_types); ?>" placeholder="php,php5,phtml,inc">
                    <p style="font-size: 0.95em; color: #666; margin-top: 8px;">Pisahkan dengan koma (default: php,php5,phtml,inc)</p>
                </div>
                
                <div class="checkbox">
                    <input type="checkbox" id="recursive" name="recursive" value="1" <?php echo $recursive ? 'checked' : ''; ?>>
                    <label for="recursive">🔍 Scan subdirectories (recursive)</label>
                </div>
                
                <button type="submit" name="scan" value="1" class="btn" onclick="showLoading()">
                    🚀 Start Scanning
                </button>
            </form>
            
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p style="font-size: 1.1em; color: #666; margin-top: 15px;">Scanning files, please wait. This may take a while...</p>
            </div>
        </div>

        <?php if ($scanned): ?>
        <div class="card">
            <?php if ($error): ?>
                <div class="alert alert-danger">
                    ❌ <strong>Error:</strong> <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>
            
            <div class="results-header">
                <h2 style="color: #2f3542; font-size: 1.8em;">📊 Scan Results</h2>
                <div class="results-count">
                    <?php 
                    $high_count = count(array_filter($scan_results, fn($r) => $r['threat_level'] == 'high'));
                    $medium_count = count(array_filter($scan_results, fn($r) => $r['threat_level'] == 'medium'));
                    $low_count = count(array_filter($scan_results, fn($r) => $r['threat_level'] == 'low'));
                    ?>
                    Total: <?php echo count($scan_results); ?> files | 
                    <span style="color:#ff4757">High: <?php echo $high_count; ?></span> | 
                    <span style="color:#ffa502">Medium: <?php echo $medium_count; ?></span> | 
                    <span style="color:#2ed573">Low: <?php echo $low_count; ?></span>
                </div>
            </div>
            
            <?php if (count($scan_results) == 0): ?>
                <div class="alert alert-success">
                    ✅ <strong>Clean scan!</strong> Tidak ditemukan file yang mencurigakan berdasarkan <?php echo count($backdoor_patterns); ?> pattern deteksi.
                </div>
            <?php else: ?>
                <div class="stats">
                    <div class="stat-box">
                        <div class="stat-number stat-high"><?php echo $high_count; ?></div>
                        <div class="stat-label">High Threat Files</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number stat-medium"><?php echo $medium_count; ?></div>
                        <div class="stat-label">Medium Threat Files</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number stat-low"><?php echo $low_count; ?></div>
                        <div class="stat-label">Low Threat Files</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number"><?php echo count($scan_results); ?></div>
                        <div class="stat-label">Total Suspicious Files</div>
                    </div>
                </div>
                
                <div class="alert alert-danger">
                    ⚠️ <strong>Security Warning!</strong> Ditemukan <?php echo count($scan_results); ?> file yang mencurigakan. 
                    <?php if ($high_count > 0): ?>
                        <span style="color:#ff4757; font-weight:bold;"><?php echo $high_count; ?> file dengan HIGH THREAT level!</span>
                    <?php endif; ?>
                </div>
                
                <?php foreach ($scan_results as $result): ?>
                <div class="result-item <?php echo $result['threat_level']; ?>">
                    <div class="file-path">
                        📄 <?php echo htmlspecialchars($result['filename']); ?>
                        <span class="threat-badge threat-<?php echo $result['threat_level']; ?>">
                            <?php echo strtoupper($result['threat_level']); ?> THREAT
                        </span>
                        <span style="margin-left: auto; font-size: 0.9em; color: #666;">
                            <?php echo $result['pattern_count']; ?> patterns detected
                        </span>
                    </div>
                    
                    <div class="file-meta">
                        <span>📍 Path: <?php echo htmlspecialchars($result['path']); ?></span>
                        <span>📏 Size: <?php echo number_format($result['size']); ?> bytes</span>
                        <span>🕒 Modified: <?php echo $result['modified']; ?></span>
                    </div>
                    
                    <div class="pattern-section">
                        <strong>🔍 Detected Patterns:</strong><br>
                        <?php foreach ($result['patterns'] as $pattern): 
                            $threat_class = in_array($pattern, [
                                '/eval\s*\(/i',
                                '/system\s*\(/i',
                                '/shell_exec\s*\(/i',
                                '/exec\s*\(/i',
                                '/`.*`/',
                                '/\$_(POST|GET|REQUEST)\[.*\]\s*\(/i'
                            ]) ? 'high' : 
                            (in_array($pattern, [
                                '/base64_decode\s*\(/i',
                                '/gzinflate\s*\(/i',
                                '/assert\s*\(/i',
                                '/file_put_contents\s*\(.*\$_(POST|GET|REQUEST)/i'
                            ]) ? 'medium' : 'low');
                        ?>
                            <span class="pattern-badge <?php echo $threat_class; ?>" title="<?php echo htmlspecialchars($pattern); ?>">
                                <?php 
                                $pattern_name = substr($pattern, 0, 30);
                                if (strlen($pattern) > 30) $pattern_name .= '...';
                                echo htmlspecialchars($pattern_name);
                                ?>
                            </span>
                        <?php endforeach; ?>
                    </div>
                    
                    <?php if (!empty($result['suspicious_lines'])): ?>
                    <div class="pattern-section">
                        <strong>📝 Suspicious Lines:</strong><br>
                        <?php foreach ($result['suspicious_lines'] as $line): ?>
                            <div class="suspicious-line">
                                <span class="line-number">Line <?php echo $line['line']; ?>:</span>
                                <?php echo htmlspecialchars($line['content']); ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                    
                    <div class="content-sample">
                        <strong>📋 Content Sample (first 1000 chars):</strong><br><br>
                        <?php echo nl2br(htmlspecialchars($result['content_sample'])); ?>
                    </div>
                </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
        
        <div class="card">
            <div class="alert alert-info">
                <h3 style="margin-bottom: 15px;">ℹ️ Enhanced Pattern Detection</h3>
                <p><strong>Pattern yang dideteksi (40+ patterns):</strong></p>
                <div style="columns: 2; column-gap: 40px; margin-top: 15px;">
                    <ul style="padding-left: 20px; margin-bottom: 15px;">
                        <li><strong>Hex Encoding (\xXX):</strong> Pattern \x untuk hex encoding backdoor</li>
                        <li><strong>Base64 Obfuscation:</strong> base64_decode() dan base64_encode()</li>
                        <li><strong>Command Execution:</strong> system(), exec(), shell_exec()</li>
                        <li><strong>Eval-based:</strong> eval(), assert(), create_function()</li>
                        <li><strong>Compression:</strong> gzinflate(), gzuncompress()</li>
                        <li><strong>File Manipulation:</strong> file_put_contents dengan user input</li>
                        <li><strong>Direct Execution:</strong> $_POST['cmd']() pattern</li>
                        <li><strong>Backticks:</strong> `command` execution</li>
                        <li><strong>Hex Functions:</strong> hex2bin(), bin2hex(), pack()</li>
                        <li><strong>Character Encoding:</strong> chr(), ord() patterns</li>
                    </ul>
                    <ul style="padding-left: 20px;">
                        <li><strong>Escape Sequences:</strong> \x, \u, \octal patterns</li>
                        <li><strong>Webshell Signatures:</strong> WSO, c99 patterns</li>
                        <li><strong>XOR Encryption:</strong> ^ operator untuk obfuscation</li>
                        <li><strong>Error Suppression:</strong> @ dengan fungsi berbahaya</li>
                        <li><strong>Long Strings:</strong> Base64-like strings panjang</li>
                        <li><strong>Remote Includes:</strong> include dengan URL remote</li>
                        <li><strong>Socket Connections:</strong> fsockopen() dari user input</li>
                        <li><strong>Database Injection:</strong> mysql_query dengan user input</li>
                        <li><strong>JavaScript Injection:</strong> Script tags dalam PHP</li>
                        <li><strong>Credential Patterns:</strong> password, login, admin strings</li>
                    </ul>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <div class="footer">
            <p>🛡️ PHP Security Scanner Pro v2.0 | Enhanced with 40+ detection patterns</p>
            <p>⚠️ <strong>Security Notice:</strong> Tool ini hanya untuk legitimate security testing dengan izin tertulis.</p>
            <p>📞 <strong>Emergency:</strong> Jika menemukan backdoor di server, segera hubungi administrator!</p>
        </div>
    </div>

    <script>
        function showLoading() {
            document.getElementById('loading').style.display = 'block';
            document.querySelector('button[name="scan"]').disabled = true;
            document.querySelector('button[name="scan"]').innerHTML = '⏳ Scanning...';
        }
        
        // Auto-hide loading setelah scan
        <?php if ($scanned): ?>
            document.getElementById('loading').style.display = 'none';
            document.querySelector('button[name="scan"]').disabled = false;
            document.querySelector('button[name="scan"]').innerHTML = '🚀 Start Scanning';
        <?php endif; ?>
        
        // Scroll ke hasil setelah scan
        <?php if ($scanned && count($scan_results) > 0): ?>
            window.scrollTo({
                top: document.querySelector('.results-header').offsetTop - 20,
                behavior: 'smooth'
            });
        <?php endif; ?>
    </script>
</body>
</html>
