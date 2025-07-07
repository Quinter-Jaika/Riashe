<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/theme.css">
    <title>Login - Riashe</title>
</head>
<body>
    <nav class="navbar">
        <a href="index.php" class="navbar-brand">RIASHE</a>
        <div class="navbar-nav">
            <a href="register.php" class="nav-link">Register</a>
        </div>
    </nav>

    <div class="container">
        <div class="login-container">
            <div class="login-header">
                <h2>Login to Your Account</h2>
                <?php if (isset($_GET['error'])): ?>
                    <div class="error"><?php echo htmlspecialchars($_GET['error']); ?></div>
                <?php endif; ?>
            </div>
            
            <form action="process_login.php" method="post">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <button type="submit" class="btn" style="width: 100%;">Login</button>
            </form>
            
            <div class="login-footer">
                <p>Don't have an account? <a href="register.php">Register here</a></p>
            </div>
        </div>
    </div>
</body>
</html>