<?php
require_once '../database/db_connect.php';

function detectHashAlgorithm($hash) {
    $length = strlen($hash);
    if ($length === 32) return 'md5';
    if ($length === 40) return 'sha1';
    if ($length === 64) return 'sha256';
    return 'unknown';
}

function parseFileLine($line, $fileExtension) {
    $line = trim($line);
    
    // Handle different file formats
    switch ($fileExtension) {
        case 'md5sum':
            // Format: hash  filename
            if (preg_match('/^([a-f0-9]{32})\s+/i', $line, $matches)) {
                return [$matches[1], 1]; // Default count of 1 for md5sum files
            }
            break;
            
        case 'rti1':
        case 'rti2':
            // Format: hash:count
            $parts = explode(':', $line);
            if (count($parts) >= 2) {
                return [trim($parts[0]), (int)$parts[1]];
            }
            break;
            
        case 'part':
            // Format: hash=count
            $parts = explode('=', $line);
            if (count($parts) >= 2) {
                return [trim($parts[0]), (int)$parts[1]];
            }
            break;
            
        case 'torrent':
            // Format: hash|count (or other delimiter)
            if (preg_match('/^([a-f0-9]{32,64})[\|:](\\d+)/i', $line, $matches)) {
                return [$matches[1], (int)$matches[2]];
            }
            break;
            
        default:
            // Try common formats as fallback
            if (strpos($line, ':') !== false) {
                $parts = explode(':', $line);
                if (count($parts) >= 2) {
                    return [trim($parts[0]), (int)$parts[1]];
                }
            } elseif (strpos($line, '=') !== false) {
                $parts = explode('=', $line);
                if (count($parts) >= 2) {
                    return [trim($parts[0]), (int)$parts[1]];
                }
            }
    }
    
    return null; // Unparseable line
}

function importBreachData($conn, $filePath) {
    if (!file_exists($filePath)) {
        die("Error: File not found at $filePath");
    }

    $fileExtension = pathinfo($filePath, PATHINFO_EXTENSION);
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
    $lineNumber = 0;

    while (($line = fgets($file)) !== false) {
        $lineNumber++;
        $parsed = parseFileLine($line, $fileExtension);
        
        if (!$parsed) {
            $skipped++;
            continue;
        }

        list($hash, $count) = $parsed;
        $hash = strtolower($hash);
        $algorithm = detectHashAlgorithm($hash);

        if ($algorithm === 'unknown') {
            $skipped++;
            continue;
        }

        // Check if hash exists
        $checkStmt->bind_param("ss", $hash, $algorithm);
        $checkStmt->execute();
        $result = $checkStmt->get_result();

        if ($result->num_rows > 0) {
            // Update existing
            $row = $result->fetch_assoc();
            $newCount = $row['breach_count'] + $count;
            $updateStmt->bind_param("ii", $newCount, $row['id']);
            $updateStmt->execute();
            $updated++;
        } else {
            // Insert new
            $insertStmt->bind_param("ssi", $hash, $algorithm, $count);
            $insertStmt->execute();
            $imported++;
        }
    }

    fclose($file);
    return [
        'imported' => $imported,
        'updated' => $updated,
        'skipped' => $skipped,
        'total' => $lineNumber
    ];
}

// Handle command line or web execution
if (php_sapi_name() === 'cli') {
    if ($argc < 2) {
        die("Usage: php import_breach_data.php <filename>\n");
    }
    $result = importBreachData($conn, $argv[1]);
    echo sprintf(
        "Processed %d lines: %d new, %d updated, %d skipped\n",
        $result['total'],
        $result['imported'],
        $result['updated'],
        $result['skipped']
    );
} else {
    // Web interface
    if (isset($_FILES['breachfile'])) {
        $tempFile = $_FILES['breachfile']['tmp_name'];
        $originalName = $_FILES['breachfile']['name'];
        $result = importBreachData($conn, $tempFile);
        
        echo "<h2>Import Results</h2>";
        echo "<p>File: " . htmlspecialchars($originalName) . "</p>";
        echo "<ul>";
        echo "<li>Total lines: " . $result['total'] . "</li>";
        echo "<li>New records: " . $result['imported'] . "</li>";
        echo "<li>Updated records: " . $result['updated'] . "</li>";
        echo "<li>Skipped lines: " . $result['skipped'] . "</li>";
        echo "</ul>";
    } else {
        echo '
        <form method="post" enctype="multipart/form-data">
            <h2>Upload Breach Data File</h2>
            <input type="file" name="breachfile" required>
            <p>Supported formats: .md5sum, .rti1, .rti2, .part, .torrent</p>
            <button type="submit">Import</button>
        </form>
        ';
    }
}
?>