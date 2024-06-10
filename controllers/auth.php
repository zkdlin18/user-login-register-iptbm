<?php
class AuthController {
  //register
  public function register() {
    global $conn;

    $response = array();

    $profile_picture = $_POST['profile_picture'] ?? '';
    $first_name = $_POST['first_name'] ?? '';
    $last_name = $_POST['last_name'] ?? '';
    $phone_no = $_POST['phone_no'] ?? '';
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $branch = $_POST['branch'] ?? ''; 
    $status = $_POST['status'] ?? '';

    if (empty($first_name)) {
        $response['status'] = 'error';
        $response['message'] = 'First Name is required.';
        echo json_encode($response);
        return;
    }

    if (empty($last_name)) {
        $response['status'] = 'error';
        $response['message'] = 'Last Name is required.';
        echo json_encode($response);
        return;
    }

    if (empty($email)) {
        $response['status'] = 'error';
        $response['message'] = 'Email is required.';
        echo json_encode($response);
        return;
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response['status'] = 'error';
        $response['message'] = 'Invalid email format.';
        echo json_encode($response);
        return;
    }

    if (empty($password)) {
        $response['status'] = 'error';
        $response['message'] = 'Password is required.';
        echo json_encode($response);
        return;
    } elseif (strlen($password) < 6) {
        $response['status'] = 'error';
        $response['message'] = 'Password must be at least 6 characters long.';
        echo json_encode($response);
        return;
    }

    if ($password !== $confirm_password) {
        $response['status'] = 'error';
        $response['message'] = 'Passwords do not match.';
        echo json_encode($response);
        return;
    }

    if (empty($phone_no)) {
        $response['status'] = 'error';
        $response['message'] = 'Phone number is required.';
        echo json_encode($response);
        return;
    }

    // validating phone number
    if (!preg_match('/^(09|\+639)\d{9}$/', $phone_no)) {
        $response['status'] = 'error';
        $response['message'] = 'Invalid phone number format.';
        echo json_encode($response);
        return;
    }

    if (empty($branch) || !in_array($branch, ['siniloan', 'sta cruz', 'san pablo', 'los banos', 'extension campuses'])) {
        $response['status'] = 'error';
        $response['message'] = 'Invalid branch specified.';
        echo json_encode($response);
        return;
    }

    if (empty($status) || !in_array($status, ['admin', 'super-admin', 'user'])) {
        $response['status'] = 'error';
        $response['message'] = 'Invalid status specified.';
        echo json_encode($response);
        return;
    }

    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $stmt->close();

    if ($result->num_rows > 0) {
        $response['status'] = 'error';
        $response['message'] = 'Email already exists.';
        echo json_encode($response);
        return;
    }

    $stmt = $conn->prepare("SELECT * FROM users WHERE phone_no = ?");
    $stmt->bind_param("s", $phone_no);
    $stmt->execute();
    $result = $stmt->get_result();
    $stmt->close();

    if ($result->num_rows > 0) {
        $response['status'] = 'error';
        $response['message'] = 'Phone number already exists.';
        echo json_encode($response);
        return;
    }

    $prefix = '';
    switch ($branch) {
        case 'siniloan':
            $prefix = 'SI';
            break;
        case 'sta cruz':
            $prefix = 'SC';
            break;
        case 'san pablo':
            $prefix = 'SP';
            break;
        case 'los banos':
            $prefix = 'LB';
        case 'extension campuses':
            $prefix = 'EX';
            break;
    }

    $suffix_length = ($status == 'super-admin') ? 2 : 4;
    $like_pattern = $prefix . '-%';
    $stmt = $conn->prepare("SELECT MAX(CAST(SUBSTRING(user_id, 4) AS UNSIGNED)) AS max_id FROM users WHERE user_id LIKE ?");
    $stmt->bind_param("s", $like_pattern);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    $stmt->close();

    $max_id = $row['max_id'] ?? 0;
    $new_id_number = str_pad($max_id + 1, $suffix_length, '0', STR_PAD_LEFT);
    $user_id = $prefix . '-' . $new_id_number;

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $conn->prepare("INSERT INTO users (user_id, profile_picture, first_name, last_name, phone_no, email, branch, status, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssssssss", $user_id, $profile_picture, $first_name, $last_name, $phone_no, $email, $branch, $status, $hashed_password);

    if ($stmt->execute()) {
        $response['status'] = 'success';
        $response['message'] = 'User registered successfully.';
        echo json_encode($response);
    } else {
        $response['status'] = 'error';
        $response['message'] = 'Error registering user: ' . $conn->error;
        echo json_encode($response);
    }

    $stmt->close();
  }

  //log in
  public function login() {
    global $conn;

    $response = array();

    $identifier = $_POST['identifier'] ?? ''; //identifier na lang nilagay ko kasi it's either email or phone
    $password = $_POST['password'] ?? '';

    if (empty($identifier)) {
        $response['status'] = 'error';
        $response['message'] = 'Email or phone number is required.';
        echo json_encode($response);
        return;
    }

    if (empty($password)) {
        $response['status'] = 'error';
        $response['message'] = 'Password is required.';
        echo json_encode($response);
        return;
    } elseif (strlen($password) < 6) {
        $response['status'] = 'error';
        $response['message'] = 'Password must be at least 6 characters long.';
        echo json_encode($response);
        return;
    }

    $query = filter_var($identifier, FILTER_VALIDATE_EMAIL) ? "email" : "phone_no";
    $stmt = $conn->prepare("SELECT user_id, first_name, last_name, email, phone_no, created_at, branch, status, password FROM users WHERE $query = ?");
    $stmt->bind_param("s", $identifier);
    $stmt->execute();
    $result = $stmt->get_result();
    $stmt->close();

    if ($result->num_rows == 0) {
        $response['status'] = 'error';
        $response['message'] = 'User not found.';
        echo json_encode($response);
        return;
    }

    $user = $result->fetch_assoc();

    if (!password_verify($password, $user['password'])) {
        $response['status'] = 'error';
        $response['message'] = 'Invalid email or phone number or password.';
        echo json_encode($response);
    } else {
        unset($user['password']); // para di makita pass sa response
        $response['status'] = 'success';
        $response['message'] = 'Login successful.';
        $response['user'] = $user;
        echo json_encode($response);
    }
  }


  //token sent to email
  public function mailToken() {
    global $conn;

    $response = array();

    $email = $_POST["email"] ?? '';

    if (empty($email)) {
        $response['status'] = 'error';
        $response['message'] = 'Email is required.';
        echo json_encode($response);
        return;
    }

    $token = bin2hex(random_bytes(16));
    $token_hash = hash("sha256", $token);
    $expiry = date("Y-m-d H:i:s", time() + 60 * 30); //expires in 30 minutes

    $stmt = $conn->prepare("UPDATE users SET reset_token_hash = ?, reset_token_expires_at = ? WHERE email = ?");
    $stmt->bind_param("sss", $token_hash, $expiry, $email);
    $stmt->execute();

    if ($stmt->affected_rows > 0) {
        $mail = require __DIR__ . "/mailer.php";

        $mail->clearAddresses(); 
        $mail->addAddress($email);
        $mail->Subject = "Password Reset";
        $mail->Body = <<<END
        Click <a href="localhost/iptbm/reset-password.php?token=$token">here</a> 
        to reset your password.
        END; 

        try {
            $mail->send();
            $response['status'] = 'success';
            $response['message'] = 'Message sent, please check your inbox.';
        } catch (Exception $e) {
            $response['status'] = 'error';
            $response['message'] = "Message could not be sent. Mailer error: {$mail->ErrorInfo}";
        }
    } else {
        $response['status'] = 'error';
        $response['message'] = 'Email not found.';
    }

    echo json_encode($response);
  }

  // process to reset pass
  public function passReset() {
    global $conn;

    $response = array();
    $token = $_POST["token"] ?? '';

    if (empty($token)) {
        $response['status'] = 'error';
        $response['message'] = 'Token is required.';
        echo json_encode($response);
        return;
    }

    $token_hash = hash("sha256", $token);

    $stmt = $conn->prepare("SELECT * FROM users WHERE reset_token_hash = ?");
    $stmt->bind_param("s", $token_hash);

    $stmt->execute();

    $result = $stmt->get_result();

    $user = $result->fetch_assoc();

    if ($user === null) {
        $response['status'] = 'error';
        $response['message'] = 'Token not found.';
        echo json_encode($response);
        return;
    }

    if (strtotime($user["reset_token_expires_at"]) <= time()) {
        $response['status'] = 'error';
        $response['message'] = 'Token has expired.';
        echo json_encode($response);
        return;
    }

    $password = $_POST["password"] ?? '';
    $confirm_password = $_POST["confirm_password"] ?? '';

    if (strlen($password) < 6) {
        $response['status'] = 'error';
        $response['message'] = 'Password must be at least 6 characters.';
        echo json_encode($response);
        return;
    }

    if ($password !== $confirm_password) {
        $response['status'] = 'error';
        $response['message'] = 'Passwords must match.';
        echo json_encode($response);
        return;
    }

    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $conn->prepare("UPDATE users SET password = ?, reset_token_hash = NULL, reset_token_expires_at = NULL WHERE id = ?");
    $stmt->bind_param("si", $password_hash, $user["id"]);

    if ($stmt->execute()) {
        $response['status'] = 'success';
        $response['message'] = 'Password updated. You can now login.';
    } else {
        $response['status'] = 'error';
        $response['message'] = 'Error updating password.';
    }

    echo json_encode($response);
  }
}
?>