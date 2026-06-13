<?php
require_once __DIR__ . '/config.php';

// Get remember token for auth
$rememberToken = getRememberTokenFromRequest();

// Restore session from token if needed
if (!isLoggedIn() && $rememberToken) {
    $tokenData = validateRememberToken($rememberToken);
    if ($tokenData) {
        $_SESSION['user_id'] = $tokenData['user_id'];
        $_SESSION['username'] = $tokenData['username'];
    }
}

if (!isLoggedIn()) {
    respond(['success' => false, 'error' => 'Not authenticated'], 401);
}

$db = getDB();
$userId = getUserId();

// GET - return current currency and converted balance
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    try {
        $stmt = $db->prepare("SELECT currency, base_currency, base_balance FROM wallet_data WHERE user_id = ?");
        $stmt->execute([$userId]);
        $result = $stmt->fetch();
        
        $displayCurrency = $result['currency'] ?? 'EGP';
        $baseCurrency = $result['base_currency'] ?? 'EGP';
        $baseBalance = floatval($result['base_balance'] ?? 0);
        
        // Convert to display currency
        $displayBalance = convertCurrency($baseBalance, $baseCurrency, $displayCurrency);
        
        respond([
            'success' => true,
            'currency' => $displayCurrency,
            'base_currency' => $baseCurrency,
            'balance' => $displayBalance,
            'base_balance' => $baseBalance
        ]);
    } catch (PDOException $e) {
        respond(['success' => false, 'error' => 'Failed to get currency'], 500);
    }
}

// POST - update display currency (converts balance to new currency)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $newCurrency = strtoupper(trim($input['currency'] ?? ''));
    
    // Validate currency
    $allowed = ['EGP', 'USD', 'QAR'];
    if (!in_array($newCurrency, $allowed)) {
        respond(['success' => false, 'error' => 'Invalid currency. Use: EGP, USD, or QAR'], 400);
    }
    
    try {
        // Get current base values
        $stmt = $db->prepare("SELECT base_currency, base_balance FROM wallet_data WHERE user_id = ?");
        $stmt->execute([$userId]);
        $current = $stmt->fetch();
        
        $baseCurrency = $current['base_currency'] ?? 'EGP';
        $baseBalance = floatval($current['base_balance'] ?? 0);
        
        // Update display currency
        $stmt = $db->prepare("UPDATE wallet_data SET currency = ? WHERE user_id = ?");
        $stmt->execute([$newCurrency, $userId]);
        
        // Convert base balance to new display currency
        $displayBalance = convertCurrency($baseBalance, $baseCurrency, $newCurrency);
        
        respond([
            'success' => true,
            'message' => 'Currency updated',
            'currency' => $newCurrency,
            'balance' => $displayBalance,
            'base_currency' => $baseCurrency,
            'base_balance' => $baseBalance
        ]);
    } catch (PDOException $e) {
        respond(['success' => false, 'error' => 'Failed to update currency'], 500);
    }
}

respond(['success' => false, 'error' => 'Method not allowed'], 405);
