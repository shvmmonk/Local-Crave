<?php
// signin.php - Handle user authentication

// Start session
session_start();

// Include database configuration
require_once 'config.php';

// Set response header to JSON
header('Content-Type: application/json');

// Enable error reporting for debugging (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Check if request method is POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Invalid request method']);
    exit;
}

// Get JSON input
$input = file_get_contents('php://input');
$data = json_decode($input, true);

// Validate required fields
if (empty($data['email']) || empty($data['password'])) {
    echo json_encode(['success' => false, 'message' => 'Email and password are required']);
    exit;
}

// Extract and sanitize data
$email = trim(strtolower($data['email']));
$password = $data['password'];
$remember = isset($data['remember']) ? $data['remember'] : false;

// Validate email format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['success' => false, 'message' => 'Invalid email format']);
    exit;
}

// Get database connection
$conn = getDatabaseConnection();
setCharset($conn);

// Check if user exists and get their data
$stmt = $conn->prepare("SELECT id, first_name, last_name, email, password, status FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    echo json_encode(['success' => false, 'message' => 'Invalid email or password. Please sign up if you don\'t have an account.']);
    $stmt->close();
    $conn->close();
    exit;
}

$user = $result->fetch_assoc();
$stmt->close();

// Check if account is active
if ($user['status'] !== 'active') {
    echo json_encode(['success' => false, 'message' => 'Your account has been ' . $user['status'] . '. Please contact support.']);
    $conn->close();
    exit;
}

// Verify password
if (!password_verify($password, $user['password'])) {
    echo json_encode(['success' => false, 'message' => 'Invalid email or password']);
    $conn->close();
    exit;
}

// Generate session token
$sessionToken = bin2hex(random_bytes(32));

// Get user's IP address
$ipAddress = $_SERVER['REMOTE_ADDR'];

// Get user agent
$userAgent = $_SERVER['HTTP_USER_AGENT'];

// Set session expiration (7 days if remember me, otherwise session only)
if ($remember) {
    $expiresAt = date('Y-m-d H:i:s', strtotime('+7 days'));
} else {
    $expiresAt = date('Y-m-d H:i:s', strtotime('+1 day'));
}

// Store session in database
$stmt = $conn->prepare("INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)");
$stmt->bind_param("issss", $user['id'], $sessionToken, $ipAddress, $userAgent, $expiresAt);
$stmt->execute();
$stmt->close();

// Set session variables
$_SESSION['user_id'] = $user['id'];
$_SESSION['email'] = $user['email'];
$_SESSION['first_name'] = $user['first_name'];
$_SESSION['last_name'] = $user['last_name'];
$_SESSION['session_token'] = $sessionToken;
$_SESSION['logged_in'] = true;

// Set cookie if remember me is checked
if ($remember) {
    setcookie('session_token', $sessionToken, time() + (7 * 24 * 60 * 60), '/');
}

// Close connection
$conn->close();

// Return success response
echo json_encode([
    'success' => true,
    'message' => 'Sign in successful!',
    'user' => [
        'id' => $user['id'],
        'firstName' => $user['first_name'],
        'lastName' => $user['last_name'],
        'email' => $user['email']
    ],
    'sessionToken' => $sessionToken,
    'redirectUrl' => 'consumerdashboard.html'
]);
?>