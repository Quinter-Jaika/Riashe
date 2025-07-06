<?php
session_start();

// Redirect to login if not authenticated
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Database configuration
$db_host = 'localhost';
$db_username = 'root';
$db_password = '';
$db_name = 'riashe';

// Connect to database
$conn = new mysqli($db_host, $db_username, $db_password, $db_name);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Initialize variables
$error = '';
$success = '';

// Process form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $current_password = $_POST['current_password'];
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];
    
    // Validate inputs
    if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
        $error = "All fields are required.";
    } elseif ($new_password !== $confirm_password) {
        $error = "New passwords do not match.";
    } elseif (strlen($new_password) < 8) {
        $error = "Password must be at least 8 characters long.";
    } else {
        // Verify current password
        $stmt = $conn->prepare("SELECT password_hash FROM users WHERE id = ?");
        $stmt->bind_param("i", $_SESSION['user_id']);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            
            if (password_verify($current_password, $user['password_hash'])) {
                // Check new password against HIBP
                $hibpResult = checkHIBP($new_password);
                
                if ($hibpResult['is_compromised']) {
                    $error = "This password has appeared in ".$hibpResult['breach_count']." breaches. Please choose a different one.";
                } else {
                    // Update password
                    $new_hash = password_hash($new_password, PASSWORD_DEFAULT);
                    $update_stmt = $conn->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
                    $update_stmt->bind_param("si", $new_hash, $_SESSION['user_id']);
                    
                    if ($update_stmt->execute()) {
                        // Record password change
                        recordPasswordChange($conn, $_SESSION['user_id'], $new_hash, 0, 0);
                        $success = "Password changed successfully!";
                    } else {
                        $error = "Error updating password: " . $conn->error;
                    }
                    $update_stmt->close();
                }
            } else {
                $error = "Current password is incorrect.";
            }
        } else {
            $error = "User not found.";
        }
        $stmt->close();
    }
}

// HIBP Check Function
function checkHIBP($password) {
    $sha1_password = strtoupper(sha1($password));
    $prefix = substr($sha1_password, 0, 5);
    $suffix = substr($sha1_password, 5);
    
    $url = "https://api.pwnedpasswords.com/range/" . $prefix;
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    
    $result = ['is_compromised' => false, 'breach_count' => 0];
    
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

// Record Password Change Function
function recordPasswordChange($conn, $user_id, $password_hash, $is_compromised, $breach_count) {
    $stmt = $conn->prepare("INSERT INTO password_security 
                          (user_id, password_hash, is_compromised, breach_count, check_date) 
                          VALUES (?, ?, ?, ?, NOW())");
    $stmt->bind_param("isii", $user_id, $password_hash, $is_compromised, $breach_count);
    $stmt->execute();
    $stmt->close();
}

$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/theme.css">
    <title>Reset Password</title>
</head>
<body>
    <div class="card">
        <h1>Reset Your Password</h1>
        
        <?php if (!empty($error)): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if (!empty($success)): ?>
            <div class="success"><?php echo htmlspecialchars($success); ?></div>
            <p><a href="dashboard.php" class="back-link">Return to Dashboard</a></p>
        <?php else: ?>
            <form action="reset_password.php" method="post">
                <div class="form-group">
                    <label for="current_password">Current Password</label>
                    <input type="password" id="current_password" name="current_password" required>
                </div>
                
                <div class="form-group">
                    <label for="new_password">New Password</label>
                    <input type="password" id="new_password" name="new_password" required 
                           oninput="checkPasswordStrength(this.value)">
                    <div class="password-strength">
                        <div class="strength-bar" id="strengthBar"></div>
                    </div>
                    <div id="passwordFeedback" style="margin-top: 5px; font-size: 14px;"></div>
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm New Password</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>
                
                <button type="submit">Change Password</button>
            </form>
            
            <div class="requirements">
                <h3>Password Requirements</h3>
                <ul>
                    <li>Minimum 8 characters</li>
                    <li>Not found in any known data breaches</li>
                    <li>Different from your current password</li>
                </ul>
            </div>
            
            <a href="dashboard.php" class="back-link">Cancel and return to Dashboard</a>
        <?php endif; ?>
    </div>

    <script>
        function checkPasswordStrength(password) {
            let strength = 0;
            const feedback = document.getElementById('passwordFeedback');
            const bar = document.getElementById('strengthBar');
            
            // Length check
            if (password.length >= 8) strength += 1;
            if (password.length >= 12) strength += 1;
            
            // Character variety
            if (password.match(/[a-z]/)) strength += 1;
            if (password.match(/[A-Z]/)) strength += 1;
            if (password.match(/[0-9]/)) strength += 1;
            if (password.match(/[^a-zA-Z0-9]/)) strength += 1;
            
            // Update UI
            const width = (strength / 7) * 100;
            bar.style.width = width + '%';
            
            if (strength <= 2) {
                bar.style.background = '#e74c3c';
                feedback.textContent = 'Weak password';
                feedback.style.color = '#e74c3c';
            } else if (strength <= 4) {
                bar.style.background = '#f39c12';
                feedback.textContent = 'Moderate password';
                feedback.style.color = '#f39c12';
            } else if (strength <= 6) {
                bar.style.background = '#3498db';
                feedback.textContent = 'Strong password';
                feedback.style.color = '#3498db';
            } else {
                bar.style.background = '#2ecc71';
                feedback.textContent = 'Very strong password!';
                feedback.style.color = '#2ecc71';
            }
        }
    </script>
</body>
</html>