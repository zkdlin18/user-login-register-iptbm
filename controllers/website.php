<?php
class WebsiteController {
    public function contact() {
        global $conn;
        session_start(); //start the session to store last email sent time

        $response = array();

        date_default_timezone_set('Asia/Manila');
        $created_at = date('Y-m-d H:i:s');

        $full_name = $_POST['name'] ?? ''; 
        $email_address = $_POST['email'] ?? ''; 
        $subject = $_POST['subject'] ?? ''; 
        $message = $_POST['message'] ?? ''; 
        $status = 'pending'; 

        if (isset($_SESSION['last_email_time'])) {
            $last_email_time = $_SESSION['last_email_time'];
            $current_time = time();

            if ($current_time - $last_email_time < 30) {
                $response['status'] = 'error';
                $response['message'] = 'Please wait before sending another message.';
                echo json_encode($response);
                return;
            }
        }

        $suffix_length = ($status == 'super-admin') ? 2 : 4;
        $prefix = 'contact';
        $like_pattern = $prefix . '-%';

        do {
            $stmt_check = $conn->prepare("SELECT MAX(CAST(SUBSTRING(contact_id, 9) AS UNSIGNED)) AS max_id FROM contacts WHERE contact_id LIKE ?");
            $stmt_check->bind_param("s", $like_pattern);
            $stmt_check->execute();
            $result_check = $stmt_check->get_result();
            $row_check = $result_check->fetch_assoc();
            $stmt_check->close();
            $max_id = $row_check['max_id'] ?? 0;
            $new_id_number = str_pad($max_id + 1, $suffix_length, '0', STR_PAD_LEFT);
            $contact_id = $prefix . '-' . $new_id_number;
        } while ($row_check && $row_check['max_id'] + 1 != $max_id + 1);

        if (empty($full_name)) {
            $response['status'] = 'error';
            $response['message'] = 'Name is required.';
            echo json_encode($response);
            return;
        }

        if (empty($email_address)) {
            $response['status'] = 'error';
            $response['message'] = 'Email is required.';
            echo json_encode($response);
            return;
        } elseif (!filter_var($email_address, FILTER_VALIDATE_EMAIL)) {
            $response['status'] = 'error';
            $response['message'] = 'Invalid email format.';
            echo json_encode($response);
            return;
        }

        if (empty($subject)) {
            $response['status'] = 'error';
            $response['message'] = 'Subject is required.';
            echo json_encode($response);
            return;
        }

        if (empty($message)) {
            $response['status'] = 'error';
            $response['message'] = 'Message is required.';
            echo json_encode($response);
            return;
        }

        $stmt = $conn->prepare("INSERT INTO contacts (contact_id, full_name, email_address, subject, message, created_at, status) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("sssssss", $contact_id, $full_name, $email_address, $subject, $message, $created_at, $status);

        if ($stmt->execute()) {
            $_SESSION['last_email_time'] = time();

            $to = $email_address;
            $confirmation_subject = "Contact Form Submission Confirmation";
            $confirmation_message = "
            <html>
            <head>
                <style>
                    .bold { font-weight: bold; }
                </style>
            </head>
            <body>
                <p class='bold'>Dear $full_name,</p>
                <p>Thank you for contacting us. We have received your message:</p>
                <p class='bold'>Subject:</p><p>$subject</p>
                <p class='bold'>Message:</p><p>$message</p>
                <p>We will get back to you soon.</p>
                <p>Regards,<br/>
                IPTBM Team
                </p>
            </body>
            </html>
            ";
            $headers = "MIME-Version: 1.0\r\n";
            $headers .= "Content-type:text/html;charset=UTF-8\r\n";
            $headers .= 'From: andreagecoleaa@gmail.com' . "\r\n"; //email ko muna nialagay ko, palitan na lang
            $headers .= 'Reply-To: andreagecoleaa@gmail.com' . "\r\n";

            if (mail($to, $confirmation_subject, $confirmation_message, $headers)) {
                $response['status'] = 'success';
                $response['message'] = 'Message submitted successfully. A confirmation email has been sent.';
            } else {
                $response['status'] = 'error';
                $response['message'] = 'Message submitted, but confirmation email could not be sent.';
            }
        } else {
            $response['status'] = 'error';
            $response['message'] = 'Error submitting message: ' . $conn->error;
        }

        $stmt->close();
        echo json_encode($response);
    }
}
?>