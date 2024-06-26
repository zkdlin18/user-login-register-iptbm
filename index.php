<?php
// Security Headers
function cors() {
  if (isset($_SERVER['HTTP_ORIGIN'])) {
    header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Max-Age: 86400');
  }

  if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD'])) {
      header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE");
    }
    if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'])) {
      header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");
    }
    exit(0);
  }
}

cors();

require 'config.php';
require 'router.php';
require 'controllers/auth.php';
require 'controllers/website.php';
require 'controllers/admin.php';

// Initialize Router
$router = new Router();

// Post Requests
$router->post('/api/auth/register', 'AuthController@register');
$router->post('/api/auth/login', 'AuthController@login');
$router->post('/api/auth/mailToken', 'AuthController@mailToken');
$router->post('/api/auth/passReset', 'AuthController@passReset');
$router->post('/api/website/contact', 'WebsiteController@contact');
$router->post('/api/admin/add-record', 'AdminController@addRecord');


// Get Requests
$router->get('/api/user/register', 'AuthController@register');
$router->get('/api/user/login', 'AuthController@login');
$router->get('/api/auth/mailToken', 'AuthController@mailToken');
$router->get('/api/auth/passReset', 'AuthController@passReset');
$router->get('/api/admin/inventors', function() {
  $user_id = $_GET['user_id'] ?? '';

  if (!empty($user_id)) {
      $adminController = new AdminController();
      $adminController->getInventors($user_id);
  } else {
      echo json_encode(['status' => 'error', 'message' => 'Invalid user ID.']);
  }
});
$router->get('/api/admin/technologies', function() {
  $user_id = $_GET['user_id'] ?? '';

  if (!empty($user_id)) {
      $adminController = new AdminController();
      $adminController->getTechnologies($user_id);
  } else {
      echo json_encode(['status' => 'error', 'message' => 'Invalid user ID.']);
  }
});


// Put Requests
$router->put('/api/user/register', 'AuthController@register');
$router->put('/api/user/login', 'AuthController@login');
$router->put('/api/auth/mailToken', 'AuthController@mailToken');
$router->put('/api/auth/passReset', 'AuthController@passReset');

// Delete Requests
$router->delete('/api/user/register', 'AuthController@register');
$router->delete('/api/user/login', 'AuthController@login');
$router->delete('/api/auth/mailToken', 'AuthController@mailToken');
$router->delete('/api/auth/passReset', 'AuthController@passReset');

// Dispatch the request
$router->dispatch();
?>
