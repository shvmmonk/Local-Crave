<?php
// config.php - Database configuration file

// Database credentials
define('DB_HOST', 'localhost');
define('DB_USER', 'root'); // Change to your MySQL username
define('DB_PASS', ''); // Change to your MySQL password
define('DB_NAME', 'DBMS');

// Create connection
function getDatabaseConnection() {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    
    return $conn;
}

// Set charset to utf8mb4 for proper character support
function setCharset($conn) {
    if (!$conn->set_charset("utf8mb4")) {
        printf("Error loading character set utf8mb4: %s\n", $conn->error);
    }
}
?>