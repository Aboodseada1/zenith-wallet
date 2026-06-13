<?php
require_once __DIR__ . '/config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(['success' => false, 'error' => 'Method not allowed'], 405);
}

// Get remember token for auth if session expired
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

// Get JSON input
$input = json_decode(file_get_contents('php://input'), true);

$transaction = $input['transaction'] ?? null;
$setBudget = $input['set_budget'] ?? null;

try {
    $db = getDB();
    $userId = getUserId();
    
    // Get current wallet data
    $stmt = $db->prepare("SELECT currency, base_currency FROM wallet_data WHERE user_id = ?");
    $stmt->execute([$userId]);
    $wallet = $stmt->fetch();
    $displayCurrency = $wallet['currency'] ?? 'EGP';
    
    // Handle set budget (sets base balance in current currency)
    if ($setBudget !== null) {
        $amount = floatval($setBudget);
        $stmt = $db->prepare("UPDATE wallet_data SET base_balance = ?, base_currency = ?, balance = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?");
        $stmt->execute([$amount, $displayCurrency, $amount, $userId]);
        
        respond([
            'success' => true,
            'message' => 'Budget set successfully',
            'base_balance' => $amount,
            'base_currency' => $displayCurrency
        ]);
    }
    
    // Add transaction if provided
    $transactionId = null;
    if ($transaction && isset($transaction['type']) && isset($transaction['amount'])) {
        $amount = floatval($transaction['amount']);
        $type = $transaction['type'];
        $description = $transaction['description'] ?? null;
        
        // Get current base balance
        $stmt = $db->prepare("SELECT base_balance, base_currency FROM wallet_data WHERE user_id = ?");
        $stmt->execute([$userId]);
        $current = $stmt->fetch();
        $baseBalance = floatval($current['base_balance'] ?? 0);
        $baseCurrency = $current['base_currency'] ?? 'EGP';
        
        // Convert transaction amount to base currency
        $amountInBase = convertCurrency($amount, $displayCurrency, $baseCurrency);
        
        // Update base balance
        if ($type === 'income') {
            $newBaseBalance = $baseBalance + $amountInBase;
        } else {
            $newBaseBalance = $baseBalance - $amountInBase;
        }
        
        $stmt = $db->prepare("UPDATE wallet_data SET base_balance = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?");
        $stmt->execute([$newBaseBalance, $userId]);
        
        // Store transaction in display currency (what user entered)
        $transactionId = addTransaction($userId, $type, $amount, $description, $displayCurrency);
        
        // Convert new balance back to display currency for response
        $newDisplayBalance = convertCurrency($newBaseBalance, $baseCurrency, $displayCurrency);
        
        respond([
            'success' => true,
            'message' => 'Transaction saved',
            'transaction_id' => $transactionId,
            'new_balance' => $newDisplayBalance,
            'base_balance' => $newBaseBalance
        ]);
    }
    
    respond(['success' => false, 'error' => 'No action specified'], 400);
    
} catch (PDOException $e) {
    respond(['success' => false, 'error' => 'Sync failed: ' . $e->getMessage()], 500);
}
