<?php
require_once __DIR__ . '/config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(['success' => false, 'error' => 'Method not allowed'], 405);
}

// Check rate limit for registration
$rateCheck = checkRateLimit();
if ($rateCheck['blocked']) {
    respond(['success' => false, 'error' => $rateCheck['reason']], 429);
}

// Get JSON input
$input = json_decode(file_get_contents('php://input'), true);

$username = trim($input['username'] ?? '');
$password = $input['password'] ?? '';
$passwordConfirm = $input['password_confirm'] ?? '';

// Username validation
if (empty($username)) {
    respond(['success' => false, 'error' => 'Username is required'], 400);
}

if (strlen($username) < 3 || strlen($username) > 50) {
    respond(['success' => false, 'error' => 'Username must be 3-50 characters'], 400);
}

if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    respond(['success' => false, 'error' => 'Username can only contain letters, numbers, and underscores'], 400);
}

// Password validation
$passwordError = validatePassword($password);
if ($passwordError) {
    respond(['success' => false, 'error' => $passwordError], 400);
}

if ($password !== $passwordConfirm) {
    respond(['success' => false, 'error' => 'Passwords do not match'], 400);
}

try {
    $db = getDB();
    
    // Check if username exists (case-insensitive)
    $stmt = $db->prepare("SELECT id FROM users WHERE LOWER(username) = LOWER(?)");
    $stmt->execute([$username]);
    if ($stmt->fetch()) {
        respond(['success' => false, 'error' => 'Username already exists'], 400);
    }
    
    // Create user with strong password hash
    $passwordHash = password_hash($password, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost' => 4,
        'threads' => 3
    ]);
    
    $stmt = $db->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?) RETURNING id");
    $stmt->execute([$username, $passwordHash]);
    $userId = $stmt->fetchColumn();
    
    // Create wallet data for user with base currency
    $stmt = $db->prepare("INSERT INTO wallet_data (user_id, balance, base_balance, currency, base_currency) VALUES (?, 0, 0, 'EGP', 'EGP')");
    $stmt->execute([$userId]);
    
    // Regenerate session ID
    session_regenerate_id(true);
    
    // Create remember token for iOS PWA persistence
    $rememberToken = createRememberToken($userId);
    
    // Set HTTP cookie
    setRememberCookie($rememberToken);
    
    // Log them in
    $_SESSION['user_id'] = $userId;
    $_SESSION['username'] = $username;
    $_SESSION['login_time'] = time();
    
    respond([
        'success' => true,
        'message' => 'Account created successfully',
        'remember_token' => $rememberToken,
        'user' => [
            'id' => $userId,
            'username' => sanitize($username)
        ],
        'wallet' => [
            'balance' => 0,
            'currency' => 'EGP',
            'base_currency' => 'EGP',
            'base_balance' => 0,
            'transactions' => []
        ]
    ]);
    
} catch (PDOException $e) {
    respond(['success' => false, 'error' => 'Registration failed'], 500);
}
