<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

require_once '../database/db_connect.php';

// Get user's latest password security check
$stmt = $conn->prepare("
    SELECT ps.*, u.username 
    FROM password_security ps
    JOIN users u ON ps.user_id = u.id
    WHERE ps.user_id = ?
    ORDER BY ps.check_date DESC
    LIMIT 1
");
$stmt->bind_param("i", $_SESSION['user_id']);
$stmt->execute();
$security_data = $stmt->get_result()->fetch_assoc();
$stmt->close();

// Get password change history count
$stmt = $conn->prepare("SELECT COUNT(*) as change_count FROM password_security WHERE user_id = ?");
$stmt->bind_param("i", $_SESSION['user_id']);
$stmt->execute();
$change_count = $stmt->get_result()->fetch_assoc()['change_count'];
$stmt->close();

$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../css/theme.css">
    <title>Password Security Dashboard</title>
</head>
<body>
<nav class="navbar">
    <a href="dashboard.php" class="navbar-brand">RIASHE</a>
    <div class="navbar-nav">
        <a href="home.html#home" class="nav-link">Home</a>
        <a href="dashboard.php#security" class="nav-link">Security</a>
        <a href="reset_password.php" class="nav-link">Change Password</a>
        <a href="logout.php" class="nav-link logout">Logout</a>
    </div>
</nav>

    <div class="container">
        <section id="home" class="home-section">
            <h1 class="section-title">Welcome to Your Dashboard</h1>
            <p>Hello, <?php echo htmlspecialchars($_SESSION['username']); ?>! This is your password security dashboard where you can monitor your account's security status.</p>
            
            <div class="stat-grid">
                <div class="stat-item">
                    <div class="stat-value"><?php echo $change_count; ?></div>
                    <div class="stat-label">Password Changes</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value"><?php echo $security_data['breach_count']; ?></div>
                    <div class="stat-label">Breach Appearances</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">
                        <?php echo date('M j, Y', strtotime($security_data['check_date'])); ?>
                    </div>
                    <div class="stat-label">Last Checked</div>
                </div>
            </div>
            
            <a href="reset_password.php" class="btn">Change Password</a>
        </section>

        <section id="security" class="card">
            <h2 class="section-title">Password Security Status</h2>
            <?php if ($security_data['is_compromised']): ?>
                <div class="breach-alert">
                    <h3>⚠️ Compromised Password Alert</h3>
                    <p>Your current password has appeared in <strong><?php echo $security_data['breach_count']; ?></strong> known data breaches.</p>
                    <p class="security-fact">This means your password is publicly available to attackers and should be changed immediately.</p>
                    <p>Last checked on <?php echo date('M j, Y g:i a', strtotime($security_data['check_date'])); ?></p>
                    <a href="reset_password.php" class="btn btn-warning">Change Password Now</a>
                </div>
            <?php else: ?>
                <div class="safe-status">
                    <h3>✅ No Known Breaches Detected</h3>
                    <p>Your password hasn't been found in any known data breaches.</p>
                    <p class="security-fact">While this is good, we recommend changing your password regularly as a security best practice.</p>
                    <p>Last checked on <?php echo date('M j, Y g:i a', strtotime($security_data['check_date'])); ?></p>
                </div>
            <?php endif; ?>
        </section>

        <section class="card">
            <h2 class="section-title">Security Recommendations</h2>
            <ul>
                <li><strong>Change passwords immediately</strong> if marked as compromised</li>
                <li><strong>Use unique passwords</strong> for each of your accounts</li>
                <li><strong>Consider a password manager</strong> to generate and store strong passwords</li>
                <li><strong>Enable two-factor authentication</strong> wherever available</li>
                <li><strong>Change passwords every 3-6 months</strong> even if not compromised</li>
                <li><strong>Be cautious of phishing attempts</strong> - never enter credentials on suspicious sites</li>
            </ul>
            <a href="reset_password.php" class="btn">Update Password</a>
        </section>
    </div>
</body>
</html>