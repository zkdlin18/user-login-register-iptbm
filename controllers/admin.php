<?php
class AdminController {
    //add record
    public function addRecord() {
        global $conn;

        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');

        $response = array();

        $user_id = $_GET['user_id'] ?? '';
        $banner = $_FILES['banner'] ?? null;
        $technology = $_POST['technology'] ?? '';
        $intellectual_property = $_POST['intellectual_property'] ?? '';
        $year = $_POST['year'] ?? '';
        $date_of_filing = $_POST['date_of_filing'] ?? '';
        $application_no = $_POST['application_no'] ?? '';
        $abstract = $_POST['abstract'] ?? '';
        $inventors = $_POST['inventors'] ?? '';
        $status = $_POST['status'] ?? '';

        $stmt = $conn->prepare("SELECT branch FROM users WHERE user_id = ?");
        $stmt->bind_param("s", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $stmt->close();

        if ($result->num_rows == 0) {
            $response['status'] = 'error';
            $response['message'] = 'Invalid user ID.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        $user_data = $result->fetch_assoc();
        $branch = $user_data['branch'];

        if (empty($technology) || empty($intellectual_property) || empty($year) || empty($date_of_filing) || empty($application_no) || empty($abstract) || empty($inventors) || empty($status)) {
            $response['status'] = 'error';
            $response['message'] = 'All fields are required.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        //banner
        $banner_path = null;
        if ($banner && $banner['error'] == 0) {
            $prefix = 'rec';
            $suffix_length = 4;
            $like_pattern = $prefix . '-%';

            $stmt_check = $conn->prepare("SELECT MAX(CAST(SUBSTRING(record_id, 5) AS UNSIGNED)) AS max_id FROM records WHERE record_id LIKE ?");
            $stmt_check->bind_param("s", $like_pattern);
            $stmt_check->execute();
            $result_check = $stmt_check->get_result();
            $row_check = $result_check->fetch_assoc();
            $stmt_check->close();
            $max_id = $row_check['max_id'] ?? 0;
            $new_id_number = str_pad($max_id + 1, $suffix_length, '0', STR_PAD_LEFT);
            $record_id = $prefix . '-' . $new_id_number;

            $banner_filename = $record_id . '_' . basename($banner['name']);
            $banner_path = 'Uploads/Records/' . $banner_filename;

            if (!move_uploaded_file($banner['tmp_name'], $banner_path)) {
                $response['status'] = 'error';
                $response['message'] = 'Failed to upload banner image.';
                echo "data: " . json_encode($response) . "\n\n";

                return;
            }
        }

        //unique record_id
        $prefix = 'rec';
        $suffix_length = 4;
        $like_pattern = $prefix . '-%';

        $stmt_check = $conn->prepare("SELECT MAX(CAST(SUBSTRING(record_id, 5) AS UNSIGNED)) AS max_id FROM records WHERE record_id LIKE ?");
        $stmt_check->bind_param("s", $like_pattern);
        $stmt_check->execute();
        $result_check = $stmt_check->get_result();
        $row_check = $result_check->fetch_assoc();
        $stmt_check->close();
        $max_id = $row_check['max_id'] ?? 0;
        $new_id_number = str_pad($max_id + 1, $suffix_length, '0', STR_PAD_LEFT);
        $record_id = $prefix . '-' . $new_id_number;

        $stmt = $conn->prepare("INSERT INTO records (record_id, banner, technology, intellectual_property, year, date_of_filing, application_no, abstract, inventors, status, branch) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("ssssissssss", $record_id, $banner_path, $technology, $intellectual_property, $year, $date_of_filing, $application_no, $abstract, $inventors, $status, $branch);

        if ($stmt->execute()) {
            $response['status'] = 'success';
            $response['message'] = 'Record added successfully.';
        } else {
            $response['status'] = 'error';
            $response['message'] = 'Error adding record: ' . $conn->error;
        }

        $stmt->close();
        echo "data: " . json_encode($response) . "\n\n";
    }

    //inventors
    public function getInventors($user_id) {
        global $conn;

        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');

        $response = array();

        $stmt = $conn->prepare("SELECT branch FROM users WHERE user_id = ?");
        $stmt->bind_param("s", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows == 0) {
            $response['status'] = 'error';
            $response['message'] = 'Invalid user ID.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        $user_data = $result->fetch_assoc();
        $branch = $user_data['branch'];
        $stmt->close();

        $stmt = $conn->prepare("SELECT record_id, branch, technology, inventors, status 
                               FROM records
                               WHERE branch = ?");
        $stmt->bind_param("s", $branch);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $response['status'] = 'success';
            $response['message'] = 'Records found for branch: ' . $branch;
            $response['data'] = array();

            while ($row = $result->fetch_assoc()) {
                $inventors = explode(',', $row['inventors']);
                foreach ($inventors as $inventor) {
                    $inventor_info = array(
                        'record_id' => $row['record_id'],
                        'branch' => $row['branch'],
                        'technology' => $row['technology'],
                        'inventor' => trim($inventor),
                        'status' => $row['status']
                    );
                    $response['data'][] = $inventor_info;
                }
            }
        } else {
            $response['status'] = 'error';
            $response['message'] = 'No records found for branch: ' . $branch;
        }

        $stmt->close();

        echo "data: " . json_encode($response) . "\n\n";
    }

    //technologies
    public function getTechnologies($user_id) {
        global $conn;

        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');

        $response = array();

        $stmt = $conn->prepare("SELECT branch FROM users WHERE user_id = ?");
        $stmt->bind_param("s", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows == 0) {
            $response['status'] = 'error';
            $response['message'] = 'Invalid user ID.';
            echo "data: " . json_encode($response) . "\n\n";
            return;
        }

        $user_data = $result->fetch_assoc();
        $branch = $user_data['branch'];
        $stmt->close();

        $stmt = $conn->prepare("SELECT record_id, year, technology FROM records WHERE branch = ?");
        $stmt->bind_param("s", $branch);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $response['status'] = 'success';
            $response['message'] = 'Technologies found for branch: ' . $branch;
            $response['data'] = array();

            while ($row = $result->fetch_assoc()) {
                $technology_info = array(
                    'record_id' => $row['record_id'],
                    'year' => $row['year'],
                    'technology' => $row['technology']
                );
                $response['data'][] = $technology_info;
            }
        } else {
            $response['status'] = 'error';
            $response['message'] = 'No technology records found for branch: ' . $branch;
        }

        $stmt->close();

        echo "data: " . json_encode($response) . "\n\n";
    }
}

?>
