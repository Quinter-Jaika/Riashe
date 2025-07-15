<?php
require_once '../database/db_connect.php';
require_once 'password_strength.php';

function checkHIBP($sha1_hash) {
    $prefix = substr($sha1_hash, 0, 5);
    $suffix = substr($sha1_hash, 5);
    
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

function checkLocalBreachDB($conn, $hash_type, $hash_value) {
    $stmt = $conn->prepare("SELECT breach_count FROM breached_passwords 
                          WHERE password_hash = ? AND hash_algorithm = ?");
    $stmt->bind_param("ss", $hash_value, $hash_type);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $response = [
        'is_compromised' => false,
        'breach_count' => 0
    ];
    
    if ($result->num_rows > 0) {
        $data = $result->fetch_assoc();
        $response['is_compromised'] = true;
        $response['breach_count'] = (int)$data['breach_count'];
    }
    
    return $response;
}

function createPasswordHashes($password) {
    return [
        'bcrypt' => password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]),
        'sha256' => hash('sha256', $password),
        'sha1' => strtoupper(sha1($password)), // Uppercase for HIBP compatibility
        'md5' => md5($password)
    ];
}

// Process form data
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Start session for error handling
    session_start();
    
    // Validate and sanitize input
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    $email = trim($_POST['email']);
    
    // Basic validation
    $errors = [];
    
    if (empty($username)) {
        $errors[] = "Username is required.";
    }
    
    if (empty($password)) {
        $errors[] = "Password is required.";
    } elseif (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long.";
    }
    
    if (empty($email)) {
        $errors[] = "Email is required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    }
    
    // Check password strength
    $strength = checkPasswordStrength($password);
    if (!$strength['is_acceptable']) {
        $errors[] = "Password is too weak. " . implode(" ", $strength['feedback']);
    }
    
    // If no errors, proceed with registration
    if (empty($errors)) {
        // Create all password hashes
        $hashes = createPasswordHashes($password);
        
        // Check hashes against breach databases
        $breachResults = [];
        $breachResults['sha1'] = checkHIBP($hashes['sha1']);
        $breachResults['sha256'] = checkLocalBreachDB($conn, 'sha256', $hashes['sha256']);
        $breachResults['md5'] = checkLocalBreachDB($conn, 'md5', $hashes['md5']);
        
        // If any hash is compromised, reject the password
        foreach ($breachResults as $type => $result) {
            if ($result['is_compromised']) {
                $errors[] = "This password has appeared in {$result['breach_count']} breaches (hash type: $type)";
                break;
            }
        }
        
        if (empty($errors)) {
            // Get current timestamp
            $created_at = date('Y-m-d H:i:s');
            
            // Start transaction
            $conn->begin_transaction();
            
            try {
                // Prepare user insert statement
                $stmt = $conn->prepare("INSERT INTO users 
                    (username, email, created_at, password_strength_score,
                    bcrypt_password_hash, sha256_password_hash, sha1_password_hash, md5_password_hash,
                    bcrypt_breach_count, sha256_breach_count, sha1_breach_count, md5_breach_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

                if (!$stmt) {
                    throw new Exception("Error preparing user statement: " . $conn->error);
                }

                // Create variables for binding
                $bcrypt_breach_count = 0; // Not actually checked, so default to 0
                $sha256_breach_count = $breachResults['sha256']['breach_count'];
                $sha1_breach_count = $breachResults['sha1']['breach_count'];
                $md5_breach_count = $breachResults['md5']['breach_count'];

                if (!$stmt->bind_param("sssissssiiii", 
                    $username,
                    $email,
                    $created_at,
                    $strength['score'],
                    $hashes['bcrypt'],
                    $hashes['sha256'],
                    $hashes['sha1'],
                    $hashes['md5'],
                    $bcrypt_breach_count,
                    $sha256_breach_count,
                    $sha1_breach_count,
                    $md5_breach_count
                )) {
                    throw new Exception("Error binding user parameters: " . $stmt->error);
                }

                // Execute user insert
                if (!$stmt->execute()) {
                    throw new Exception("Error executing user insert: " . $stmt->error);
                }

                $user_id = $conn->insert_id;
                
                // Prepare password security statement
                $stmt2 = $conn->prepare("INSERT INTO password_security 
                    (user_id, is_compromised, breach_count, check_date)
                    VALUES (?, ?, ?, ?)");
                
                if (!$stmt2) {
                    throw new Exception("Error preparing security statement: " . $conn->error);
                }
                
                $is_compromised = 0;
                $max_breach_count = max($sha256_breach_count, $sha1_breach_count, $md5_breach_count);
                
                if (!$stmt2->bind_param("iiis", $user_id, $is_compromised, $max_breach_count, $created_at)) {
                    throw new Exception("Error binding security parameters: " . $stmt2->error);
                }
                
                if (!$stmt2->execute()) {
                    throw new Exception("Error executing security insert: " . $stmt2->error);
                }
                
                // Commit transaction
                $conn->commit();
                
                // Close statements
                $stmt->close();
                $stmt2->close();
                
                // Redirect to success page
                header("Location: ../templates/login.php?registration=success");
                exit();
                
            } catch (Exception $e) {
                // Rollback transaction on error
                $conn->rollback();
                $errors[] = "Registration failed: " . $e->getMessage();
            }
        }
    }
    
    // If we got here, there were errors
    $_SESSION['registration_errors'] = $errors;
    $_SESSION['form_data'] = [
        'username' => $username,
        'email' => $email
    ];
    header("Location: ../templates/register.php");
    exit();
}

// Close connection
$conn->close();
?>