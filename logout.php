<?php
// logout.php - Handle user logout

// Start session
session_start();

// Include database configuration
require_once 'config.php';

// Get session token
$sessionToken = isset($_SESSION['session_token']) ? $_SESSION['session_token'] : null;

// Delete session from database
if ($sessionToken) {
    $conn = getDatabaseConnection();
    setCharset($conn);
    
    $stmt = $conn->prepare("DELETE FROM user_sessions WHERE session_token = ?");
    $stmt->bind_param("s", $sessionToken);
    $stmt->execute();
    $stmt->close();
    $conn->close();
}

// Destroy session
session_unset();
session_destroy();

// Delete remember me cookie
if (isset($_COOKIE['session_token'])) {
    setcookie('session_token', '', time() - 3600, '/');
}

// Return JSON response
header('Content-Type: application/json');
echo json_encode([
    'success' => true,
    'message' => 'Logged out successfully',
    'redirectUrl' => 'consumersigninpage.html'
]);
?>