<?php
// generate_test_users.php
require_once '../database/db_connect.php';
require_once '../process/password_strength.php';

// Verify database connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// List of common compromised passwords from known breaches
$compromised_passwords = [
    '123456', 'password', '123456789', '12345678', '12345',
    '1234567', '1234567890', 'qwerty', 'abc123', 'password1',
    '123123', '111111', 'admin', 'letmein', 'welcome',
    'monkey', 'sunshine', 'password123', 'football', 'iloveyou'
];

// List of secure passwords with varying complexity
$secure_passwords = [
    'BlueSky$2023!', 'J@vaScriptR0cks', 'P@ssw0rd$ecure1',
    'WinterIsC0ming#', 'C0mplexP@ss!2023', 'G00dP@ssw0rd',
    'MyD0gHas2Ears!', 'S3cur!tyF1rst', 'L0ngP@ssphrase',
    'B1gB@ngTh3ory', 'QuantumLeap@2023', 'M1cr0s0ftW1ndows'
];

// Generate random user data with more variety
function generateRandomUser($index) {
    $first_names = ['Alex', 'Jamie', 'Taylor', 'Morgan', 'Casey', 'Jordan', 'Riley'];
    $last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Miller', 'Davis'];
    $domains = ['test.com', 'example.org', 'demo.net', 'fakeemail.io'];
    
    $username = strtolower(
        $first_names[array_rand($first_names)] . 
        $last_names[array_rand($last_names)] . 
        ($index < 10 ? '0'.$index : $index)
    );
    $email = $username . '@' . $domains[array_rand($domains)];
    
    return [
        'username' => $username,
        'email' => $email,
        'is_admin' => ($index % 10 === 0) ? 1 : 0 // Every 10th user is admin
    ];
}

// Insert users into database
try {
    $conn->begin_transaction();
    
    // Clear existing test users if any
    $conn->query("DELETE FROM users WHERE email LIKE '%@test.com' OR email LIKE '%@example.org' OR email LIKE '%@demo.net' OR email LIKE '%@fakeemail.io'");
    
    // Insert test users (20 compromised, 80 secure)
    $compromised_count = 0;
    $secure_count = 0;
    
    for ($i = 1; $i <= 100; $i++) {
        $user = generateRandomUser($i);
        
        // Determine password type (20% compromised, 80% secure)
        $is_compromised = ($i % 5 === 0); // Every 5th user gets compromised password
        if ($is_compromised) {
            $password = $compromised_passwords[array_rand($compromised_passwords)];
            $compromised_count++;
        } else {
            $password = $secure_passwords[array_rand($secure_passwords)];
            // Sometimes modify the secure password slightly
            if (rand(1, 100) <= 40) {
                $password = str_replace('2023', rand(2020, 2025), $password);
            }
            $secure_count++;
        }
        
        // Create all password hashes
        $hashes = [
            'bcrypt' => password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]),
            'sha256' => hash('sha256', $password),
            'sha1' => strtoupper(sha1($password)),
            'md5' => md5($password)
        ];
        
        // Check password strength
        $strength = checkPasswordStrength($password);
        
        // Check hashes against breach databases (simulated)
        $breachResults = [
            'sha1' => $is_compromised ? ['is_compromised' => true, 'breach_count' => rand(100, 10000)] : ['is_compromised' => false, 'breach_count' => 0],
            'sha256' => ['is_compromised' => false, 'breach_count' => 0],
            'md5' => $is_compromised ? ['is_compromised' => true, 'breach_count' => rand(100, 5000)] : ['is_compromised' => false, 'breach_count' => 0]
        ];
        
        // Prepare and execute user insert
        $stmt = $conn->prepare("INSERT INTO users 
            (username, email, is_admin, created_at, password_strength_score,
             bcrypt_password_hash, sha256_password_hash, sha1_password_hash, md5_password_hash,
             bcrypt_breach_count, sha256_breach_count, sha1_breach_count, md5_breach_count)
            VALUES (?, ?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        
        if (!$stmt) {
            throw new Exception("Prepare failed: " . $conn->error);
        }
        
        $bcrypt_breach_count = 0; // bcrypt hashes aren't in breach databases
        $sha256_breach_count = $breachResults['sha256']['breach_count'];
        $sha1_breach_count = $breachResults['sha1']['breach_count'];
        $md5_breach_count = $breachResults['md5']['breach_count'];
        
        $stmt->bind_param("sssissssiiii", 
            $user['username'],
            $user['email'],
            $user['is_admin'],
            $strength['score'],
            $hashes['bcrypt'],
            $hashes['sha256'],
            $hashes['sha1'],
            $hashes['md5'],
            $bcrypt_breach_count,
            $sha256_breach_count,
            $sha1_breach_count,
            $md5_breach_count
        );
        
        if (!$stmt->execute()) {
            throw new Exception("Execute failed: " . $stmt->error);
        }
        
        $user_id = $conn->insert_id;
        
        // Record password security check
        $stmt2 = $conn->prepare("INSERT INTO password_security 
            (user_id, is_compromised, breach_count, check_date)
            VALUES (?, ?, ?, NOW())");
        
        $max_breach_count = max($sha1_breach_count, $md5_breach_count);
        $is_compromised_flag = ($max_breach_count > 0) ? 1 : 0;
        
        $stmt2->bind_param("iii", $user_id, $is_compromised_flag, $max_breach_count);
        $stmt2->execute();
        
        $stmt->close();
        $stmt2->close();
    }
    
    $conn->commit();
    
    echo "Successfully generated test users:\n";
    echo "- Total users: 100\n";
    echo "- Compromised passwords: $compromised_count\n";
    echo "- Secure passwords: $secure_count\n";
    echo "- Admin accounts: 10\n";
    echo "\nSample compromised passwords: " . implode(', ', array_slice($compromised_passwords, 0, 5)) . "\n";
    echo "Sample secure passwords: " . implode(', ', array_slice($secure_passwords, 0, 5)) . "\n";
    
} catch (Exception $e) {
    $conn->rollback();
    echo "Error: " . $e->getMessage();
}

$conn->close();
?>