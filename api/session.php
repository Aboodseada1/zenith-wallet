<?php
require_once __DIR__ . '/config.php';

// Get remember token from cookie or header
$rememberToken = getRememberTokenFromRequest();

// Helper function to get wallet data with conversion
function getWalletWithConversion($userId) {
    $db = getDB();
    
    // Get wallet data
    $stmt = $db->prepare("SELECT balance, currency, base_currency, base_balance FROM wallet_data WHERE user_id = ?");
    $stmt->execute([$userId]);
    $wallet = $stmt->fetch();
    
    if (!$wallet) return null;
    
    $displayCurrency = $wallet['currency'] ?? 'EGP';
    $baseCurrency = $wallet['base_currency'] ?? 'EGP';
    $baseBalance = floatval($wallet['base_balance'] ?? $wallet['balance'] ?? 0);
    
    // Convert balance to display currency
    $displayBalance = convertCurrency($baseBalance, $baseCurrency, $displayCurrency);
    
    // Get transactions with converted amounts
    $transactions = getUserTransactionsConverted($userId, $displayCurrency, 100);
    
    return [
        'balance' => $displayBalance,
        'currency' => $displayCurrency,
        'base_currency' => $baseCurrency,
        'base_balance' => $baseBalance,
        'transactions' => $transactions
    ];
}

// First try PHP session
if (isLoggedIn()) {
    try {
        $db = getDB();
        
        // Verify user still exists
        $stmt = $db->prepare("SELECT id, username FROM users WHERE id = ?");
        $stmt->execute([getUserId()]);
        $user = $stmt->fetch();
        
        if (!$user) {
            session_destroy();
            respond(['success' => false, 'authenticated' => false, 'error' => 'Session expired'], 401);
        }
        
        $wallet = getWalletWithConversion(getUserId());
        
        if (!$wallet) {
            session_destroy();
            respond(['success' => false, 'authenticated' => false, 'error' => 'Session expired'], 401);
        }
        
        respond([
            'success' => true,
            'authenticated' => true,
            'user' => [
                'id' => $user['id'],
                'username' => sanitize($user['username'])
            ],
            'wallet' => $wallet
        ]);
        
    } catch (PDOException $e) {
        respond(['success' => false, 'error' => 'Failed to fetch session'], 500);
    }
}

// Try remember token (iOS PWA persistent login via cookie)
if ($rememberToken) {
    $tokenData = validateRememberToken($rememberToken);
    
    if ($tokenData) {
        // Restore session from remember token
        $_SESSION['user_id'] = $tokenData['user_id'];
        $_SESSION['username'] = $tokenData['username'];
        
        try {
            $wallet = getWalletWithConversion($tokenData['user_id']);
            
            respond([
                'success' => true,
                'authenticated' => true,
                'user' => [
                    'id' => $tokenData['user_id'],
                    'username' => sanitize($tokenData['username'])
                ],
                'wallet' => $wallet ?: ['balance' => 0, 'currency' => 'EGP', 'transactions' => []]
            ]);
            
        } catch (PDOException $e) {
            respond(['success' => false, 'error' => 'Failed to restore session'], 500);
        }
    }
}

// Not authenticated
respond([
    'success' => false,
    'authenticated' => false,
    'error' => 'Not authenticated'
], 401);
