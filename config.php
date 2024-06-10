<?php
// Database configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASSWORD', '');
define('DB_NAME', 'lspu_iptbm_rtms');

// Create connection
$conn = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);

// Check connection
if ($conn->connect_error) {
  $response = array(
    'success' => false,
    'message' => 'Database connection failed: ' . $conn->connect_error
  );
  echo json_encode($response);
  exit();
}
?>
