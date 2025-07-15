<?php
session_start();

// Redirect to login if not authenticated
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Check if user is admin
if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
    // For security, don't reveal that the admin page exists
    header("HTTP/1.1 403 Forbidden");
    // Or redirect to dashboard with error message
    $_SESSION['error'] = "You don't have permission to access the admin area";
    header("Location: dashboard.php");
    exit();
}

require_once '../database/db_connect.php';
// Include breach checking functions
require_once '../process/breach_functions.php';

// Get all compromised passwords
$breaches_query = "
    SELECT ps.*, u.username, u.email 
    FROM (
        SELECT user_id, MAX(check_date) as latest_check
        FROM password_security
        WHERE is_compromised = 1
        GROUP BY user_id
    ) as latest
    JOIN password_security ps ON ps.user_id = latest.user_id AND ps.check_date = latest.latest_check
    JOIN users u ON ps.user_id = u.id
    ORDER BY ps.breach_count DESC, ps.check_date DESC
";

// Get stats for dashboard
$stats_query = "
    SELECT 
        COUNT(DISTINCT ps.user_id) as affected_users,
        SUM(ps.breach_count) as total_breaches,
        MAX(ps.check_date) as last_checked
    FROM (
        SELECT user_id, MAX(check_date) as latest_check
        FROM password_security
        WHERE is_compromised = 1
        GROUP BY user_id
    ) as latest
    JOIN password_security ps ON ps.user_id = latest.user_id AND ps.check_date = latest.latest_check
";

// Additional stats
$user_stats_query = "SELECT 
    COUNT(*) as total_users,
    SUM(sha1_breach_count > 0 OR md5_breach_count > 0) as compromised_users,
    MAX(last_breach_check) as last_check
    FROM users";

// Execute queries
$breaches_result = $conn->query($breaches_query);
$stats_result = $conn->query($stats_query);
$user_stats_result = $conn->query($user_stats_query);

if (!$breaches_result || !$stats_result || !$user_stats_result) {
    die("Database error: " . $conn->error);
}

$stats = $stats_result->fetch_assoc();
$user_stats = $user_stats_result->fetch_assoc();

// Process breach check actions
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['check_all_users'])) {
        checkAllUsersBreaches($conn);
        $_SESSION['admin_message'] = "Breach check completed for all users";
    } elseif (isset($_POST['check_single_user']) && !empty($_POST['user_id'])) {
        checkSingleUserBreaches($conn, $_POST['user_id']);
        $_SESSION['admin_message'] = "Breach check completed for user ID " . $_POST['user_id'];
    }
    header("Location: admin.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../css/theme.css">
    <title>Admin Dashboard - Breach Review</title>
</head>
<body>
    <nav class="navbar">
        <a href="admin.php" class="navbar-brand">Admin Dashboard</a>
        <div class="navbar-nav">
            <a href="admin.php" class="nav-link">Breach Review</a>
            <a href="../database/import_breach_data.php" class="nav-link">Database Update</a>
            <a href="dashboard.php" class="nav-link">User View</a>
            <a href="logout.php" class="nav-link logout">Logout</a>
        </div>
    </nav>

    <div class="container">
        <div class="dashboard-header">
            <h1>Password Breach Review</h1>
            <p>Monitor and manage all compromised passwords in the system</p>
        </div>

        <div class="stat-grid">
            <div class="stat-card danger">
                <div class="stat-value"><?php echo $stats['affected_users']; ?></div>
                <div class="stat-label">Affected Users</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-value"><?php echo $stats['total_breaches']; ?></div>
                <div class="stat-label">Total Breach Incidents</div>
            </div>
            <div class="stat-card info">
                <div class="stat-value">
                    <?php echo $stats['last_checked'] ? date('M j, Y', strtotime($stats['last_checked'])) : 'N/A'; ?>
                </div>
                <div class="stat-label">Last Check Date</div>
            </div>
        </div>

        <!-- Breach Check Tools -->
        <div class="card">
            <h2>Password Breach Tools</h2>
            
            <?php if (isset($_SESSION['admin_message'])): ?>
                <div class="alert alert-info"><?= htmlspecialchars($_SESSION['admin_message']) ?></div>
                <?php unset($_SESSION['admin_message']); ?>
            <?php endif; ?>
            
            <div class="row">
                <div class="col-md-6">
                    <form method="post">
                        <button type="submit" name="check_all_users" class="btn btn-warning">
                            Check All Users for Breaches
                        </button>
                        <p class="text-muted">Checks all user passwords against HIBP and local breach DB</p>
                    </form>
                </div>
                
                <div class="col-md-6">
                    <form method="post" class="form-inline">
                        <div class="form-group">
                            <input type="number" name="user_id" class="form-control" placeholder="User ID" required>
                            <button type="submit" name="check_single_user" class="btn btn-primary ml-2">
                                Check Single User
                            </button>
                        </div>
                    </form>
                </div>
            </div>
            
            <h3 class="mt-4">Breach Statistics</h3>
            <ul>
                <li>Total Users: <?= $user_stats['total_users'] ?></li>
                <li>Compromised Passwords: <?= $user_stats['compromised_users'] ?></li>
                <li>Last System-wide Check: <?= $user_stats['last_check'] ? date('M j, Y g:i a', strtotime($user_stats['last_check'])) : 'Never' ?></li>
            </ul>
        </div>

        <div class="card">
            <h2>Compromised Passwords</h2>
            
            <div class="search-filter">
                <input type="text" id="searchInput" placeholder="Search by username or email...">
                <select id="breachFilter">
                    <option value="all">All Breaches</option>
                    <option value="major">Major Breaches (50+ occurrences)</option>
                    <option value="minor">Minor Breaches (<50 occurrences)</option>
                </select>
            </div>

            <div style="overflow-x: auto;">
                <table id="breachTable">
                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Email</th>
                            <th>Breach Count</th>
                            <th>Last Checked</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($breach = $breaches_result->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($breach['username']); ?></td>
                            <td><?php echo htmlspecialchars($breach['email']); ?></td>
                            <td>
                                <span class="badge <?php echo $breach['breach_count'] > 50 ? 'badge-danger' : 'badge-warning'; ?>">
                                    <?php echo $breach['breach_count']; ?> breaches
                                </span>
                            </td>
                            <td><?php echo date('M j, Y H:i', strtotime($breach['check_date'])); ?></td>
                            <td>
                                <?php if ($breach['breach_count'] > 1000): ?>
                                    <span style="color: var(--danger-color);">Critical</span>
                                <?php elseif ($breach['breach_count'] > 100): ?>
                                    <span style="color: var(--warning-color);">High Risk</span>
                                <?php else: ?>
                                    <span style="color: var(--gray-color);">Risk</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <button class="action-btn btn-notify" onclick="notifyUser(<?php echo $breach['user_id']; ?>)">Notify User</button>
                                <button class="action-btn btn-force-reset" onclick="forcePasswordReset(<?php echo $breach['user_id']; ?>)">Force Reset</button>
                            </td>
                        </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>

            <div class="pagination">
                <a href="#">&laquo;</a>
                <a href="#" class="active">1</a>
                <a href="#">2</a>
                <a href="#">3</a>
                <a href="#">&raquo;</a>
            </div>
        </div>
    </div>

    <script>
        // Simple table filtering
        document.getElementById('searchInput').addEventListener('keyup', function() {
            const filter = this.value.toLowerCase();
            const rows = document.querySelectorAll('#breachTable tbody tr');
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(filter) ? '' : 'none';
            });
        });

        document.getElementById('breachFilter').addEventListener('change', function() {
            const filterValue = this.value;
            const rows = document.querySelectorAll('#breachTable tbody tr');
            
            rows.forEach(row => {
                const count = parseInt(row.querySelector('td:nth-child(3) span').textContent);
                if (filterValue === 'all') {
                    row.style.display = '';
                } else if (filterValue === 'major' && count >= 50) {
                    row.style.display = '';
                } else if (filterValue === 'minor' && count < 50) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });

        function forcePasswordReset(userId) {
            if (confirm('Force this user to reset their password on next login?')) {
                // AJAX call to force password reset
                alert('Password reset required for user #' + userId);
                // In production: fetch('force_reset.php?user_id=' + userId);
            }
        }
    </script>
</body>
</html>
<?php
$conn->close();
?>