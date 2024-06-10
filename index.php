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

// Initialize Router
$router = new Router();

// Post Requests
$router->post('/api/auth/register', 'AuthController@register');
$router->post('/api/auth/login', 'AuthController@login');
$router->post('/api/auth/mailToken', 'AuthController@mailToken');
$router->post('/api/auth/passReset', 'AuthController@passReset');

// Get Requests
$router->get('/api/user/register', 'AuthController@register');
$router->get('/api/user/login', 'AuthController@login');
$router->post('/api/auth/mailToken', 'AuthController@mailToken');
$router->post('/api/auth/passReset', 'AuthController@passReset');

// Put Requests
$router->put('/api/user/register', 'AuthController@register');
$router->put('/api/user/login', 'AuthController@login');
$router->post('/api/auth/mailToken', 'AuthController@mailToken');
$router->post('/api/auth/passReset', 'AuthController@passReset');

// Delete Requests
$router->delete('/api/user/register', 'AuthController@register');
$router->delete('/api/user/login', 'AuthController@login');
$router->post('/api/auth/mailToken', 'AuthController@mailToken');
$router->post('/api/auth/passReset', 'AuthController@passReset');

// Dispatch the request
$router->dispatch();
?>
