<?php
session_start();

require_once '../database/db_connect.php';
require_once '../process/notifications.php';

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
            $_SESSION['is_admin'] = ($user['is_admin'] == 1);
            
            if ($hibpResult['is_compromised']) {
                // Force password reset on next login
                $stmt = $conn->prepare("UPDATE users SET force_password_reset = TRUE WHERE id = ?");
                $stmt->bind_param("i", $user['id']);
                $stmt->execute();
                
                header("Location: ../templates/reset_password.php");
                exit();
            }
            
            // Redirect based on admin status
            if ($_SESSION['is_admin']) {
                header("Location: ../templates/admin.php");
            } else {
                header("Location: ../templates/dashboard.php");
            }
            exit();
        } else {
            // Invalid password
            header("Location: ../templates/login.php?error=Invalid username or password");
            exit();
        }
    } else {
        // User not found
        header("Location: ../templates/login.php?error=Invalid username or password");
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

$conn->close();
?>