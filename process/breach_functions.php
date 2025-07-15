<?php
require_once '../database/db_connect.php';

// Include the HIBP checking function
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

// Include the local breach checking function
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

function checkSingleUserBreaches($conn, $user_id) {
    $stmt = $conn->prepare("SELECT 
        sha256_password_hash, 
        sha1_password_hash, 
        md5_password_hash 
        FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $hashes = $stmt->get_result()->fetch_assoc();
    
    $sha1_result = checkHIBP($hashes['sha1_password_hash']);
    $sha256_result = checkLocalBreachDB($conn, 'sha256', $hashes['sha256_password_hash']);
    $md5_result = checkLocalBreachDB($conn, 'md5', $hashes['md5_password_hash']);
    
    $max_breach = max($sha1_result['breach_count'], $sha256_result['breach_count'], $md5_result['breach_count']);
    
    $update = $conn->prepare("UPDATE users SET
        sha1_breach_count = ?,
        sha256_breach_count = ?,
        md5_breach_count = ?,
        last_breach_check = NOW()
        WHERE id = ?");
    $update->bind_param("iiii", 
        $sha1_result['breach_count'],
        $sha256_result['breach_count'],
        $md5_result['breach_count'],
        $user_id
    );
    $update->execute();
    
    return [
        'user_id' => $user_id,
        'sha1' => $sha1_result,
        'sha256' => $sha256_result,
        'md5' => $md5_result
    ];
}

function checkAllUsersBreaches($conn) {
    $users = $conn->query("SELECT id FROM users");
    while ($user = $users->fetch_assoc()) {
        checkSingleUserBreaches($conn, $user['id']);
    }
}
?>