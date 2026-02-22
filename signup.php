<?php
// signup.php - Handle user registration

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
$requiredFields = ['firstName', 'lastName', 'email', 'phone', 'address', 'password', 'confirmPassword', 'terms'];
$missingFields = [];

foreach ($requiredFields as $field) {
    if (empty($data[$field])) {
        $missingFields[] = $field;
    }
}

if (!empty($missingFields)) {
    echo json_encode([
        'success' => false, 
        'message' => 'Missing required fields: ' . implode(', ', $missingFields)
    ]);
    exit;
}

// Extract and sanitize data
$firstName = trim($data['firstName']);
$lastName = trim($data['lastName']);
$email = trim(strtolower($data['email']));
$phone = trim($data['phone']);
$address = trim($data['address']);
$password = $data['password'];
$confirmPassword = $data['confirmPassword'];
$terms = $data['terms'];
$newsletter = isset($data['newsletter']) ? $data['newsletter'] : false;

// Validate email format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['success' => false, 'message' => 'Invalid email format']);
    exit;
}

// Validate passwords match
if ($password !== $confirmPassword) {
    echo json_encode(['success' => false, 'message' => 'Passwords do not match']);
    exit;
}

// Validate password strength (minimum 8 characters)
if (strlen($password) < 8) {
    echo json_encode(['success' => false, 'message' => 'Password must be at least 8 characters long']);
    exit;
}

// Validate terms acceptance
if (!$terms) {
    echo json_encode(['success' => false, 'message' => 'You must accept the Terms of Service']);
    exit;
}

// Get database connection
$conn = getDatabaseConnection();
setCharset($conn);

// Check if email already exists
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    echo json_encode(['success' => false, 'message' => 'Email already registered']);
    $stmt->close();
    $conn->close();
    exit;
}
$stmt->close();

// Hash password
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

// Insert user into database
$stmt = $conn->prepare("INSERT INTO users (first_name, last_name, email, phone, address, password, newsletter, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())");
$stmt->bind_param("ssssssi", $firstName, $lastName, $email, $phone, $address, $hashedPassword, $newsletter);

if ($stmt->execute()) {
    $userId = $conn->insert_id;
    
    echo json_encode([
        'success' => true, 
        'message' => 'Account created successfully!',
        'userId' => $userId,
        'user' => [
            'firstName' => $firstName,
            'lastName' => $lastName,
            'email' => $email
        ]
    ]);
} else {
    echo json_encode([
        'success' => false, 
        'message' => 'Error creating account: ' . $stmt->error
    ]);
}

$stmt->close();
$conn->close();
?>