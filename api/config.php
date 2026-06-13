<?php
// Database configuration
define('DB_HOST', 'db.scorpion.codes');
define('DB_PORT', '5432');
define('DB_NAME', 'wallet_scorpion');
define('DB_USER', 'lobster');
define('DB_PASS', '26843545');

// Security settings
define('RATE_LIMIT_ATTEMPTS', 5);      // Max login attempts per minute
define('LOCKOUT_ATTEMPTS', 10);         // Lock account after this many failures
define('LOCKOUT_DURATION', 15 * 60);    // Lockout duration in seconds (15 min)
define('SESSION_LIFETIME', 365 * 24 * 60 * 60); // 1 year - persistent login for mobile/PWA users

// Secure session configuration
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Lax'); // Changed from Strict for better cross-origin compatibility
ini_set('session.use_strict_mode', 1);
ini_set('session.gc_maxlifetime', SESSION_LIFETIME);
ini_set('session.cookie_lifetime', SESSION_LIFETIME); // Cookie persists for 1 year

// Hide PHP version
header_remove('X-Powered-By');

// Start session
session_start();

// Set headers for JSON API
header('Content-Type: application/json');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Database connection
function getDB() {
    static $pdo = null;
    if ($pdo === null) {
        try {
            $dsn = "pgsql:host=" . DB_HOST . ";port=" . DB_PORT . ";dbname=" . DB_NAME;
            $pdo = new PDO($dsn, DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false
            ]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => 'Service unavailable']);
            exit;
        }
    }
    return $pdo;
}

// Get client IP address
function getClientIP() {
    $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip = $_SERVER[$header];
            if (strpos($ip, ',') !== false) {
                $ip = trim(explode(',', $ip)[0]);
            }
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return '0.0.0.0';
}

// Check rate limit for login attempts
function checkRateLimit($username = null) {
    $db = getDB();
    $ip = getClientIP();
    $cutoff = date('Y-m-d H:i:s', time() - 60); // Last minute
    
    // Check IP-based rate limit
    $stmt = $db->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND created_at > ? AND success = FALSE");
    $stmt->execute([$ip, $cutoff]);
    if ($stmt->fetchColumn() >= RATE_LIMIT_ATTEMPTS) {
        return ['blocked' => true, 'reason' => 'Too many attempts. Please wait a minute.'];
    }
    
    // Check account lockout
    if ($username) {
        $lockoutCutoff = date('Y-m-d H:i:s', time() - LOCKOUT_DURATION);
        $stmt = $db->prepare("SELECT COUNT(*) FROM login_attempts WHERE username = ? AND created_at > ? AND success = FALSE");
        $stmt->execute([strtolower($username), $lockoutCutoff]);
        if ($stmt->fetchColumn() >= LOCKOUT_ATTEMPTS) {
            return ['blocked' => true, 'reason' => 'Account temporarily locked. Try again in 15 minutes.'];
        }
    }
    
    return ['blocked' => false];
}

// Log login attempt
function logLoginAttempt($username, $success) {
    $db = getDB();
    $ip = getClientIP();
    $stmt = $db->prepare("INSERT INTO login_attempts (ip_address, username, success) VALUES (?, ?, ?)");
    $stmt->execute([$ip, strtolower($username), $success]);
}

// Check if user is logged in
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

// Get current user ID
function getUserId() {
    return $_SESSION['user_id'] ?? null;
}

// Validate password strength
function validatePassword($password) {
    if (strlen($password) < 8) {
        return 'Password must be at least 8 characters';
    }
    if (!preg_match('/[A-Z]/', $password)) {
        return 'Password must contain at least one uppercase letter';
    }
    if (!preg_match('/[a-z]/', $password)) {
        return 'Password must contain at least one lowercase letter';
    }
    if (!preg_match('/[0-9]/', $password)) {
        return 'Password must contain at least one number';
    }
    return null;
}

// Sanitize output
function sanitize($str) {
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}

// Generate remember token for persistent login (iOS PWA fix)
function createRememberToken($userId) {
    $db = getDB();
    $token = bin2hex(random_bytes(32)); // 64 char token
    $expiresAt = date('Y-m-d H:i:s', time() + (365 * 24 * 60 * 60)); // 1 year
    
    // Delete old tokens for this user
    $stmt = $db->prepare("DELETE FROM remember_tokens WHERE user_id = ?");
    $stmt->execute([$userId]);
    
    // Create new token
    $stmt = $db->prepare("INSERT INTO remember_tokens (user_id, token, expires_at) VALUES (?, ?, ?)");
    $stmt->execute([$userId, $token, $expiresAt]);
    
    return $token;
}

// Set remember token as HTTP cookie (survives iOS PWA closes)
function setRememberCookie($token) {
    $expires = time() + (365 * 24 * 60 * 60); // 1 year
    setcookie('wallet_remember', $token, [
        'expires' => $expires,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
}

// Clear remember cookie
function clearRememberCookie() {
    setcookie('wallet_remember', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
}

// Get remember token from cookie or header
function getRememberTokenFromRequest() {
    // Try cookie first (most reliable for iOS PWA)
    if (!empty($_COOKIE['wallet_remember'])) {
        return $_COOKIE['wallet_remember'];
    }
    // Fallback to header
    $headers = getallheaders();
    return $headers['X-Remember-Token'] ?? null;
}

// Validate remember token
function validateRememberToken($token) {
    if (empty($token)) return null;
    
    $db = getDB();
    $stmt = $db->prepare("
        SELECT r.user_id, u.username 
        FROM remember_tokens r 
        JOIN users u ON r.user_id = u.id 
        WHERE r.token = ? AND r.expires_at > NOW()
    ");
    $stmt->execute([$token]);
    return $stmt->fetch();
}

// Delete remember token (logout)
function deleteRememberToken($token) {
    if (empty($token)) return;
    $db = getDB();
    $stmt = $db->prepare("DELETE FROM remember_tokens WHERE token = ?");
    $stmt->execute([$token]);
}

// Get user's transactions (paginated) - raw amounts
function getUserTransactions($userId, $limit = 100, $offset = 0) {
    $db = getDB();
    $stmt = $db->prepare("
        SELECT id, type, amount, description, original_currency, created_at 
        FROM transactions 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
    ");
    $stmt->execute([$userId, $limit, $offset]);
    return $stmt->fetchAll();
}

// Get user's transactions with amounts converted to display currency
function getUserTransactionsConverted($userId, $displayCurrency, $limit = 100, $offset = 0) {
    $transactions = getUserTransactions($userId, $limit, $offset);
    
    foreach ($transactions as &$tx) {
        $originalCurrency = $tx['original_currency'] ?? 'EGP';
        $originalAmount = floatval($tx['amount']);
        
        // Convert to display currency
        $tx['display_amount'] = convertCurrency($originalAmount, $originalCurrency, $displayCurrency);
        $tx['display_currency'] = $displayCurrency;
    }
    
    return $transactions;
}

// Add transaction with optional description and currency
function addTransaction($userId, $type, $amount, $description = null, $originalCurrency = 'EGP') {
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO transactions (user_id, type, amount, description, original_currency) VALUES (?, ?, ?, ?, ?)");
    $stmt->execute([$userId, $type, $amount, $description, $originalCurrency]);
    return $db->lastInsertId();
}

// Get exchange rates - live from open.er-api.com with 1-hour cache
function getExchangeRates($baseCurrency = 'USD') {
    $cacheFile = '/tmp/wallet_exchange_rates.json';
    $cacheTime = 3600; // 1 hour
    
    // Fallback rates if API fails (approximate Jan 2026)
    $fallbackRates = [
        'USD' => ['USD' => 1, 'EGP' => 47.34, 'QAR' => 3.64],
        'EGP' => ['USD' => 0.0211, 'EGP' => 1, 'QAR' => 0.0769],
        'QAR' => ['USD' => 0.2747, 'EGP' => 13.01, 'QAR' => 1]
    ];
    
    // Check cache first
    if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < $cacheTime) {
        $cached = json_decode(file_get_contents($cacheFile), true);
        if ($cached && isset($cached[$baseCurrency])) {
            return $cached[$baseCurrency];
        }
    }
    
    // Fetch fresh rates
    try {
        $url = "https://open.er-api.com/v6/latest/USD";
        $context = stream_context_create([
            'http' => ['timeout' => 3, 'ignore_errors' => true]
        ]);
        $response = @file_get_contents($url, false, $context);
        
        if ($response !== false) {
            $data = json_decode($response, true);
            if ($data && $data['result'] === 'success' && isset($data['rates'])) {
                $usdToEgp = $data['rates']['EGP'] ?? 47.34;
                $usdToQar = $data['rates']['QAR'] ?? 3.64;
                
                $allRates = [
                    'USD' => ['USD' => 1, 'EGP' => $usdToEgp, 'QAR' => $usdToQar],
                    'EGP' => ['USD' => round(1 / $usdToEgp, 6), 'EGP' => 1, 'QAR' => round($usdToQar / $usdToEgp, 6)],
                    'QAR' => ['USD' => round(1 / $usdToQar, 6), 'EGP' => round($usdToEgp / $usdToQar, 6), 'QAR' => 1]
                ];
                
                // Cache it
                @file_put_contents($cacheFile, json_encode($allRates));
                
                return $allRates[$baseCurrency] ?? $allRates['USD'];
            }
        }
    } catch (Exception $e) {
        // Ignore errors, use fallback
    }
    
    return $fallbackRates[$baseCurrency] ?? $fallbackRates['USD'];
}

// Convert amount from one currency to another
function convertCurrency($amount, $from, $to) {
    if ($from === $to) return $amount;
    
    $rates = getExchangeRates($from);
    $rate = $rates[$to] ?? 1;
    
    return round($amount * $rate, 2);
}

// Send JSON response
function respond($data, $code = 200) {
    http_response_code($code);
    echo json_encode($data);
    exit;
}
