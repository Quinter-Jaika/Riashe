<?php
session_start();

// Database configuration
$db_host = 'localhost';
$db_username = 'root';
$db_password = '';
$db_name = 'riashe_db';

// Connect to database
$conn = new mysqli($db_host, $db_username, $db_password, $db_name);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Process login
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    
    // Find user in database
    $stmt = $conn->prepare("SELECT id, username, password_hash, is_admin FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        
    if (password_verify($password, $user['password_hash'])) {
        // Password is correct - now check with HIBP
        $hibpResult = checkHIBP($password);
        
        // Record password check in database
        recordPasswordCheck(
            $conn, 
            $user['id'], 
            $user['password_hash'], 
            $hibpResult['is_compromised'], 
            $hibpResult['breach_count']
        );
        
        // Set session variables
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['is_admin'] = ($user['is_admin'] == 1); // Explicit boolean conversion
        
        // Handle compromised password warning
        if ($hibpResult['is_compromised']) {
            $_SESSION['password_warning'] = "Warning: This password has appeared in ".$hibpResult['breach_count']." data breaches!";
                // Notify admin
                $user_details = "User: {$_SESSION['username']} (ID: {$_SESSION['user_id']})";
                $message = "Password breach detected!\n$user_details\nBreach count: {$hibpResult['breach_count']}";
                sendAdminNotification('Security Alert', $message);
        }
        
        // Redirect based on admin status
        if (($_SESSION['is_admin']) == true) {
            header("Location: admin.php");
        } else {
            header("Location: dashboard.php");
        }
        exit();
    }        

        // Verify password
        if (password_verify($password, $user['password_hash'])) {
            // Password is correct - now check with HIBP
            $hibpResult = checkHIBP($password);
            
            // Record password check in database
            recordPasswordCheck(
                $conn, 
                $user['id'], 
                $user['password_hash'], 
                $hibpResult['is_compromised'], 
                $hibpResult['breach_count']
            );
            
            if ($hibpResult['is_compromised']) {
                // Password is compromised - warn user but allow login
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['password_warning'] = "Warning: This password has appeared in ".$hibpResult['breach_count']." data breaches!";
                header("Location: dashboard.php");
                exit();
            } else {
                // Password is clean
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['is_admin'] = $user['is_admin'] == 1; 
                header("Location: dashboard.php");
                exit();
            }
        } else {
            // Invalid password
            header("Location: login.php?error=Invalid username or password");
            exit();
        }
    } else {
        // User not found
        header("Location: login.php?error=Invalid username or password");
        exit();
    }
}

function checkHIBP($password) {
    // Hash the password with SHA-1 (required by HIBP API)
    $sha1_password = strtoupper(sha1($password));
    $prefix = substr($sha1_password, 0, 5);
    $suffix = substr($sha1_password, 5);
    
    // Make API request to HIBP
    $url = "https://api.pwnedpasswords.com/range/" . $prefix;
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    
    // Parse response
    $result = [
        'is_compromised' => false,
        'breach_count' => 0
    ];
    
    if ($response) {
        $lines = explode("\n", $response);
        foreach ($lines as $line) {
            list($hash_suffix, $count) = explode(":", trim($line));
            if ($hash_suffix === $suffix) {
                $result['is_compromised'] = true;
                $result['breach_count'] = (int)$count;
                break;
            }
        }
    }
    
    return $result;
}

function recordPasswordCheck($conn, $user_id, $password_hash, $is_compromised, $breach_count) {
    $stmt = $conn->prepare("INSERT INTO password_security 
        (user_id, password_hash, is_compromised, breach_count, check_date) 
        VALUES (?, ?, ?, ?, NOW())");
    $stmt->bind_param("isii", $user_id, $password_hash, $is_compromised, $breach_count);
    $stmt->execute();
    $stmt->close();
        if ($is_compromised) {
        notifyAdminAboutBreach($user_id, $breach_count);
    }
}

function notifyAdminAboutBreach($user_id, $breach_count) {
    $ntfy_topic = "riashe_breach_alerts"; // Choose a secret topic name
    $ntfy_url = "https://ntfy.sh";

    $message = "🚨 Security Alert: User ID $user_id has a password found in $breach_count breaches!";
    
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: text/plain\r\n",
            'content' => $message
        ]
    ]);
    
    @file_get_contents("$ntfy_url/$ntfy_topic", false, $context);
}

$conn->close();
?>