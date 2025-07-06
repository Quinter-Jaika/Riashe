<?php

require_once 'db_connect.php';

// Process form data
if ($_SERVER["REQUEST_METHOD"] == "POST") {
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
    
    // If no errors, proceed with registration
    if (empty($errors)) {
        // Hash the password
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        
        // Get current timestamp
        $created_at = date('Y-m-d H:i:s');
        
        // Prepare and bind
        $stmt = $conn->prepare("INSERT INTO users (username, password_hash, email, created_at) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $username, $password_hash, $email, $created_at);
        
        // Execute the statement
        if ($stmt->execute()) {
            echo "<p>Registration successful! You can now login.</p>";
        } else {
            echo "<p>Error: " . $stmt->error . "</p>";
        }
        
        // Close statement
        $stmt->close();
    } else {
        // Display errors
        echo "<div class='error'>";
        foreach ($errors as $error) {
            echo "<p>$error</p>";
        }
        echo "</div>";
        echo "<p><a href='register.php'>Try again</a></p>";
    }
}

// Close connection
$conn->close();
?>