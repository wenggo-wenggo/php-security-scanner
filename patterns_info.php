<?php
/**
 * PHP Backdoor Pattern Database
 * Total: 40+ detection patterns
 */

$patterns_database = [
    // Critical Patterns (HIGH RISK)
    [
        'pattern' => '/eval\s*\(/i',
        'description' => 'Direct PHP code evaluation - Most dangerous',
        'risk' => 'CRITICAL',
        'examples' => ['eval($_POST["cmd"]);', 'eval(base64_decode("..."));']
    ],
    
    [
        'pattern' => '/\\\x[0-9a-f]{2}/i',
        'description' => 'Hex character encoding (\xXX) - Common in obfuscated malware',
        'risk' => 'HIGH',
        'examples' => ['"\x65\x76\x61\x6c"', 'echo "\x48\x45\x4c\x4c\x4f";']
    ],
    
    [
        'pattern' => '/system\s*\(/i',
        'description' => 'System command execution',
        'risk' => 'CRITICAL',
        'examples' => ['system($_GET["cmd"]);', 'system("ls -la");']
    ],
    
    // High Risk Patterns
    [
        'pattern' => '/base64_decode\s*\(/i',
        'description' => 'Base64 decoding - Often used to hide payloads',
        'risk' => 'HIGH',
        'examples' => ['eval(base64_decode("ZXZhbCgkX1BPU1RbJ2NtZCddKTs="));']
    ],
    
    [
        'pattern' => '/gzinflate\s*\(/i',
        'description' => 'Gzip inflation - Used in compressed malware',
        'risk' => 'HIGH',
        'examples' => ['eval(gzinflate(base64_decode("...")))']
    ],
    
    // Medium Risk Patterns
    [
        'pattern' => '/create_function\s*\(/i',
        'description' => 'Anonymous function creation - Can be abused',
        'risk' => 'MEDIUM',
        'examples' => ['create_function("$a", "echo $a;");']
    ],
    
    // Common Web Shell Patterns
    [
        'pattern' => '/WSO\s*=/i',
        'description' => 'WSO Web Shell signature',
        'risk' => 'HIGH',
        'examples' => ['$WSO = "2.3";', 'if($_POST["WSO"])']
    ],
    
    // Newly Added Patterns
    [
        'pattern' => '/\\\\u[0-9a-f]{4}/i',
        'description' => 'Unicode escape sequences',
        'risk' => 'MEDIUM',
        'examples' => ['"\u0065\u0076\u0061\u006c"']
    ],
    
    [
        'pattern' => '/\^[\s\S]*[\'"]\s*\^/',
        'description' => 'XOR encryption pattern',
        'risk' => 'MEDIUM',
        'examples' => ['$a = "ABC" ^ "xyz";']
    ]
];
