<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../css/theme.css">
    <title>User Registration</title>
</head>
<body>
    <nav class="navbar">
       <a href="index.php" class="navbar-brand">RIASHE</a>
        <div class="navbar-nav">
        </div>
    </nav>
    <div class="container">
        <div class="login-container">
            <div class="login-header">
                 <h2>User Registration</h2>
            </div>
            <form action="../process/process_registration.php" method="post">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" required>
                </div>
                
                <button type="submit" class="btn" style="width: 100%">Register</button>

                <div class="login-footer">
                    <p>Already have an account? <a href="login.php">Login here</a></p>
                </div>
            </form>
        </div>
    </div>
</body>
</html>