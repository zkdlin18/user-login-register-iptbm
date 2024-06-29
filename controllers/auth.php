<?php
class AuthController {
    // register
    public function register() {
        global $conn;

        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');

        $response = array();

        $profile_picture = $_FILES['profile_picture'] ?? null;
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
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        if (empty($last_name)) {
            $response['status'] = 'error';
            $response['message'] = 'Last Name is required.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        if (empty($email)) {
            $response['status'] = 'error';
            $response['message'] = 'Email is required.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $response['status'] = 'error';
            $response['message'] = 'Invalid email format.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        if (empty($password)) {
            $response['status'] = 'error';
            $response['message'] = 'Password is required.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        } elseif (strlen($password) < 6) {
            $response['status'] = 'error';
            $response['message'] = 'Password must be at least 6 characters long.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        if ($password !== $confirm_password) {
            $response['status'] = 'error';
            $response['message'] = 'Passwords do not match.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        if (empty($phone_no)) {
            $response['status'] = 'error';
            $response['message'] = 'Phone number is required.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        // validating phone number
        if (!preg_match('/^(09|\+639)\d{9}$/', $phone_no)) {
            $response['status'] = 'error';
            $response['message'] = 'Invalid phone number format.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        if (empty($branch) || !in_array($branch, ['siniloan', 'sta cruz', 'san pablo', 'los banos', 'extension campuses'])) {
            $response['status'] = 'error';
            $response['message'] = 'Invalid branch specified.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        if (empty($status) || !in_array($status, ['admin', 'super-admin', 'user'])) {
            $response['status'] = 'error';
            $response['message'] = 'Invalid status specified.';
            echo "data: " . json_encode($response) . "\n\n";
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
            echo "data: " . json_encode($response) . "\n\n";
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
            echo "data: " . json_encode($response) . "\n\n";
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
                break;
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

        $profile_picture_filename = null;
        if ($profile_picture && $profile_picture['error'] == UPLOAD_ERR_OK) {
            $profile_directory = 'Uploads/Profile/';
            $profile_picture_filename = $user_id . '_' . basename($profile_picture['name']);
            $profile_picture_path = $profile_directory . $profile_picture_filename;

            if (!move_uploaded_file($profile_picture['tmp_name'], $profile_picture_path)) {
                $response['status'] = 'error';
                $response['message'] = 'Error uploading profile picture.';
                echo "data: " . json_encode($response) . "\n\n";

                return;
            }
        }

        $stmt = $conn->prepare("INSERT INTO users (user_id, profile_picture, first_name, last_name, phone_no, email, branch, status, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("sssssssss", $user_id, $profile_picture_filename, $first_name, $last_name, $phone_no, $email, $branch, $status, $hashed_password);

        if ($stmt->execute()) {
            $response['status'] = 'success';
            $response['message'] = 'User registered successfully.';
        } else {
            $response['status'] = 'error';
            $response['message'] = 'Error registering user: ' . $conn->error;
        }

        $stmt->close();

        echo "data: " . json_encode($response) . "\n\n";
    }

    // log in
    public function login() {
        global $conn;

        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');
        $response = array();

        $identifier = $_POST['identifier'] ?? ''; // either email or phone
        $password = $_POST['password'] ?? '';

        if (empty($identifier)) {
            $response['status'] = 'error';
            $response['message'] = 'Email or phone number is required.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        if (empty($password)) {
            $response['status'] = 'error';
            $response['message'] = 'Password is required.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        } elseif (strlen($password) < 6) {
            $response['status'] = 'error';
            $response['message'] = 'Password must be at least 6 characters long.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        $query = filter_var($identifier, FILTER_VALIDATE_EMAIL) ? "email" : "phone_no";
        $stmt = $conn->prepare("SELECT user_id, first_name, last_name, email, phone_no, created_at, branch, status, password FROM users WHERE $query = ?");
        $stmt->bind_param("s", $identifier);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();

        if (!$user) {
            $response['status'] = 'error';
            $response['message'] = 'Email or phone number not found.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        $stmt = $conn->prepare("SELECT * FROM login_attempts WHERE identifier = ? AND created_at > DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
        $stmt->bind_param("s", $identifier);
        $stmt->execute();
        $attempts_result = $stmt->get_result();
        $attempts_count = $attempts_result->num_rows;
        $stmt->close();

        if ($attempts_count >= 5) {
            $response['status'] = 'error';
            $response['message'] = 'Too many login attempts. Please try again later.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        if (password_verify($password, $user['password'])) {
            session_start();
            $_SESSION['user_id'] = $user['user_id'];
            $_SESSION['first_name'] = $user['first_name'];
            $_SESSION['last_name'] = $user['last_name'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['phone_no'] = $user['phone_no'];
            $_SESSION['created_at'] = $user['created_at'];
            $_SESSION['branch'] = $user['branch'];
            $_SESSION['status'] = $user['status'];

            $response['status'] = 'success';
            $response['message'] = 'Login successful.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        } else {
            $stmt = $conn->prepare("INSERT INTO login_attempts (identifier, created_at) VALUES (?, NOW())");
            $stmt->bind_param("s", $identifier);
            $stmt->execute();
            $stmt->close();

            $response['status'] = 'error';
            $response['message'] = 'Incorrect password.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }
    }

    // send email token
    public function mailToken() {
        global $conn;

        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');

        $response = array();

        $email = $_POST['email'] ?? '';

        if (empty($email)) {
            $response['status'] = 'error';
            $response['message'] = 'Email is required.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $response['status'] = 'error';
            $response['message'] = 'Invalid email format.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        $stmt = $conn->prepare("SELECT user_id, email FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        $stmt->close();

        if ($result->num_rows == 0) {
            $response['status'] = 'error';
            $response['message'] = 'Email not found.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        $token = bin2hex(random_bytes(16));

        $stmt = $conn->prepare("INSERT INTO password_resets (email, token, created_at) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE token = VALUES(token), created_at = NOW()");
        $stmt->bind_param("ss", $email, $token);

        if ($stmt->execute()) {
            $reset_link = "https://example.com/reset_password.php?token=$token";

            $subject = 'Password Reset Request';
            $message = "Please click the following link to reset your password: $reset_link";
            $headers = "From: noreply@example.com";

            if (mail($email, $subject, $message, $headers)) {
                $response['status'] = 'success';
                $response['message'] = 'Password reset email sent.';
            } else {
                $response['status'] = 'error';
                $response['message'] = 'Failed to send email.';
            }
        } else {
            $response['status'] = 'error';
            $response['message'] = 'Failed to generate reset token.';
        }

        $stmt->close();

        echo "data: " . json_encode($response) . "\n\n";
    }

    // reset Password
    public function passReset() {
        global $conn;

        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');

        $response = array();

        $token = $_POST['token'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';

        if (empty($token)) {
            $response['status'] = 'error';
            $response['message'] = 'Token is required.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        if (empty($new_password)) {
            $response['status'] = 'error';
            $response['message'] = 'New password is required.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        } elseif (strlen($new_password) < 6) {
            $response['status'] = 'error';
            $response['message'] = 'Password must be at least 6 characters long.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        if ($new_password !== $confirm_password) {
            $response['status'] = 'error';
            $response['message'] = 'Passwords do not match.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        $stmt = $conn->prepare("SELECT email FROM password_resets WHERE token = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)");
        $stmt->bind_param("s", $token);
        $stmt->execute();
        $result = $stmt->get_result();
        $stmt->close();

        if ($result->num_rows == 0) {
            $response['status'] = 'error';
            $response['message'] = 'Invalid or expired token.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        $row = $result->fetch_assoc();
        $email = $row['email'];
        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

        $stmt = $conn->prepare("UPDATE users SET password = ? WHERE email = ?");
        $stmt->bind_param("ss", $hashed_password, $email);

        if ($stmt->execute()) {
            $stmt = $conn->prepare("DELETE FROM password_resets WHERE token = ?");
            $stmt->bind_param("s", $token);
            $stmt->execute();
            $stmt->close();

            $response['status'] = 'success';
            $response['message'] = 'Password reset successful.';
        } else {
            $response['status'] = 'error';
            $response['message'] = 'Failed to reset password.';
        }

        $stmt->close();

        echo "data: " . json_encode($response) . "\n\n";
    }
}
?>
