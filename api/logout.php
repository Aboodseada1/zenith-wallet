<?php
require_once __DIR__ . '/config.php';

// Get remember token to delete
$rememberToken = getRememberTokenFromRequest();

// Delete remember token from database
deleteRememberToken($rememberToken);

// Clear the HTTP cookie
clearRememberCookie();

// Destroy PHP session
session_destroy();

respond([
    'success' => true,
    'message' => 'Logged out successfully'
]);
