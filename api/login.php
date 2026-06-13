<?php
require_once __DIR__ . '/config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(['success' => false, 'error' => 'Method not allowed'], 405);
}

// Get JSON input
$input = json_decode(file_get_contents('php://input'), true);

$username = trim($input['username'] ?? '');
$password = $input['password'] ?? '';

// Validation
if (empty($username) || empty($password)) {
    respond(['success' => false, 'error' => 'Username and password are required'], 400);
}

// Check rate limit BEFORE processing
$rateCheck = checkRateLimit($username);
if ($rateCheck['blocked']) {
    respond(['success' => false, 'error' => $rateCheck['reason']], 429);
}

try {
    $db = getDB();
    
    // Find user
    $stmt = $db->prepare("SELECT id, username, password_hash FROM users WHERE LOWER(username) = LOWER(?)");
    $stmt->execute([$username]);
    $user = $stmt->fetch();
    
    if (!$user || !password_verify($password, $user['password_hash'])) {
        // Log failed attempt
        logLoginAttempt($username, false);
        respond(['success' => false, 'error' => 'Invalid username or password'], 401);
    }
    
    // Log successful attempt
    logLoginAttempt($username, true);
    
    // Regenerate session ID to prevent session fixation
    session_regenerate_id(true);
    
    // Get wallet data
    $stmt = $db->prepare("SELECT balance, currency, base_currency, base_balance FROM wallet_data WHERE user_id = ?");
    $stmt->execute([$user['id']]);
    $wallet = $stmt->fetch();
    
    $displayCurrency = $wallet['currency'] ?? 'EGP';
    $baseCurrency = $wallet['base_currency'] ?? 'EGP';
    $baseBalance = floatval($wallet['base_balance'] ?? $wallet['balance'] ?? 0);
    
    // Convert balance to display currency
    $displayBalance = convertCurrency($baseBalance, $baseCurrency, $displayCurrency);
    
    // Get recent transactions with converted amounts
    $transactions = getUserTransactionsConverted($user['id'], $displayCurrency, 100);
    
    // Create remember token for persistent login
    $rememberToken = createRememberToken($user['id']);
    
    // Set HTTP cookie for iOS PWA persistence
    setRememberCookie($rememberToken);
    
    // Set session
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['login_time'] = time();
    
    respond([
        'success' => true,
        'message' => 'Login successful',
        'remember_token' => $rememberToken,
        'user' => [
            'id' => $user['id'],
            'username' => sanitize($user['username'])
        ],
        'wallet' => [
            'balance' => $displayBalance,
            'currency' => $displayCurrency,
            'base_currency' => $baseCurrency,
            'base_balance' => $baseBalance,
            'transactions' => $transactions
        ]
    ]);
    
} catch (PDOException $e) {
    respond(['success' => false, 'error' => 'Login failed'], 500);
}
