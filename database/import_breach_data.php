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
            if (preg_match('/^([a-f0-9]{32})\s+/i', $line, $matches)) {
                return [$matches[1], 1];
            }
            break;
            
        case 'rti1':
        case 'rti2':
            $parts = explode(':', $line);
            if (count($parts) >= 2) {
                return [trim($parts[0]), max(1, (int)$parts[1])];
            }
            break;
            
        case 'part':
            $parts = explode('=', $line);
            if (count($parts) >= 2) {
                return [trim($parts[0]), max(1, (int)$parts[1])];
            }
            break;
            
        case 'torrent':
            if (preg_match('/^([a-f0-9]{32,64})[\|:](\\d+)/i', $line, $matches)) {
                return [$matches[1], max(1, (int)$matches[2])];
            }
            break;
            
        default:
            if (strpos($line, ':') !== false) {
                $parts = explode(':', $line);
                if (count($parts) >= 2) {
                    return [trim($parts[0]), max(1, (int)$parts[1])];
                }
            } elseif (strpos($line, '=') !== false) {
                $parts = explode('=', $line);
                if (count($parts) >= 2) {
                    return [trim($parts[0]), max(1, (int)$parts[1])];
                }
            }
    }
    
    return null;
}

function importBreachData($conn, $filePath) {
    if (!file_exists($filePath)) {
        die("Error: File not found at $filePath");
    }

    $fileExtension = pathinfo($filePath, PATHINFO_EXTENSION);
    
    // Check if table exists
    $tableCheck = $conn->query("SHOW TABLES LIKE 'breached_passwords'");
    if ($tableCheck->num_rows == 0) {
        die("Error: breached_passwords table does not exist in the database");
    }

    // Use UPSERT (INSERT ON DUPLICATE KEY UPDATE)
    $upsertSql = "INSERT INTO breached_passwords 
                 (password_hash, hash_algorithm, breach_count, first_seen, last_breach_date) 
                 VALUES (?, ?, ?, CURDATE(), CURRENT_DATE)
                 ON DUPLICATE KEY UPDATE 
                 breach_count = breach_count + VALUES(breach_count),
                 last_breach_date = VALUES(last_breach_date)";
    
    $upsertStmt = $conn->prepare($upsertSql);
    if (!$upsertStmt) {
        die("Error preparing upsert statement: " . $conn->error);
    }

    $file = fopen($filePath, 'r');
    if (!$file) {
        die("Error opening file: $filePath");
    }

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

        // Ensure count is at least 1
        $count = max(1, (int)$count);

        // Execute upsert
        $upsertStmt->bind_param("ssi", $hash, $algorithm, $count);
        if ($upsertStmt->execute()) {
            if ($conn->affected_rows == 1) {
                $imported++;
            } else {
                $updated++;
            }
        } else {
            error_log("Failed to process hash: $hash - " . $upsertStmt->error);
            $skipped++;
        }
    }

    fclose($file);
    $upsertStmt->close();
    
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
    echo '<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="../css/theme.css">
        <title>Import Breach Data</title>
    </head>
    <body>
        <nav class="navbar">
            <a href="/templates/admin.php" class="navbar-brand">RIASHE</a>
        </nav>
        
        <div class="container" style="max-width: 800px; margin: 2rem auto;">';

    if (isset($_FILES['breachfile'])) {
        $tempFile = $_FILES['breachfile']['tmp_name'];
        $originalName = $_FILES['breachfile']['name'];
        
        // Verify upload was successful
        if ($_FILES['breachfile']['error'] !== UPLOAD_ERR_OK) {
            echo '<div class="error">File upload failed with error code: ' . $_FILES['breachfile']['error'] . '</div>';
        } else {
            $result = importBreachData($conn, $tempFile);
            
            echo '<div class="card">
                    <h2>Import Results</h2>
                    <p>File: ' . htmlspecialchars($originalName) . '</p>
                    <ul>
                        <li>Total lines: ' . $result['total'] . '</li>
                        <li>New records: ' . $result['imported'] . '</li>
                        <li>Updated records: ' . $result['updated'] . '</li>
                        <li>Skipped lines: ' . $result['skipped'] . '</li>
                    </ul>
                    <a href="import_breach_data.php" class="btn">Import Another</a>
                </div>';
        }
    } else {
        echo '<div class="card">
                <h2>Upload Breach Data File</h2>
                <form method="post" enctype="multipart/form-data">
                    <input type="file" name="breachfile" required>
                    <p>Supported formats: .md5sum, .rti1, .rti2, .part, .torrent</p>
                    <button type="submit" class="btn">Import</button>
                </form>
            </div>';
    }

    echo '</div></body></html>';
}
?>