<?php
require_once 'db_connect.php';

function detectHashAlgorithm($hash) {
    $length = strlen($hash);
    if ($length === 32) return 'md5';
    if ($length === 40) return 'sha1';
    if ($length === 64) return 'sha256';
    return 'unknown';
}

function importBreachData($conn, $filePath) {
    if (!file_exists($filePath)) {
        die("Error: File not found");
    }

    // Prepare statements
    $checkStmt = $conn->prepare("SELECT id, breach_count FROM breached_passwords 
                               WHERE password_hash = ? AND hash_algorithm = ?");
    $insertStmt = $conn->prepare("INSERT INTO breached_passwords 
                                (password_hash, hash_algorithm, breach_count, first_seen) 
                                VALUES (?, ?, ?, CURDATE())");
    $updateStmt = $conn->prepare("UPDATE breached_passwords 
                                SET breach_count = ?, last_updated = CURRENT_TIMESTAMP 
                                WHERE id = ?");

    $file = fopen($filePath, 'r');
    $imported = 0;
    $updated = 0;
    $skipped = 0;

    while (($line = fgets($file)) !== false) {
        $parts = explode(':', trim($line));
        if (count($parts) !== 2) {
            $skipped++;
            continue;
        }

        $hash = strtolower(trim($parts[0]));
        $count = (int)$parts[1];
        $algorithm = detectHashAlgorithm($hash);

        if ($algorithm === 'unknown') {
            $skipped++;
            continue;
        }

        // Check if hash already exists
        $checkStmt->bind_param("ss", $hash, $algorithm);
        $checkStmt->execute();
        $result = $checkStmt->get_result();

        if ($result->num_rows > 0) {
            // Update existing record
            $row = $result->fetch_assoc();
            $newCount = $row['breach_count'] + $count;
            $updateStmt->bind_param("ii", $newCount, $row['id']);
            $updateStmt->execute();
            $updated++;
        } else {
            // Insert new record
            $insertStmt->bind_param("ssi", $hash, $algorithm, $count);
            $insertStmt->execute();
            $imported++;
        }
    }

    fclose($file);
    echo sprintf(
        "Import complete: %d new, %d updated, %d skipped\n",
        $imported,
        $updated,
        $skipped
    );
}

// Usage
importBreachData($conn, 'breach_data.txt');
?>