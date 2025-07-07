# Riashe - Password Security Monitor 🔒

A comprehensive system for monitoring password security, detecting compromised credentials, and enforcing secure password policies with real-time breach detection.

## 🌟 Key Features

### Core Security
- **Breach Detection**: Checks passwords against 800M+ records in Have I Been Pwned database
- **Multi-Algorithm Support**: Works with MD5, SHA1, and SHA256 hashes
- **Automatic Protection**: Forces password resets for compromised credentials
- **Security Logging**: Tracks all password checks and changes with timestamps

### User Experience
- **Password Strength Meter**: Visual feedback during password creation
- **Security Dashboard**: Personalized breach history and recommendations
- **Responsive Design**: Works on all devices

### Admin Tools
- **Comprehensive Dashboard**: View security statistics and manage users
- **Bulk Actions**: Force password resets for multiple users
- **Real-time Alerts**: ntfy.sh integration for breach notifications

## 🛠️ Installation Guide

### Prerequisites
- PHP 7.4+ with mysqli extension
- MySQL 5.7+ or MariaDB 10.2+
- Web server (Apache/Nginx)
- cURL enabled
- 100MB disk space

### Step-by-Step Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Quinter-Jaika/Riashe
   cd Riashe
   ```

2. **Database Setup**:
   ```sql
   CREATE DATABASE riashe_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   
   -- Create required tables (see database/schema.sql for complete schema)
   CREATE TABLE users (
     id INT AUTO_INCREMENT PRIMARY KEY,
     username VARCHAR(50) NOT NULL UNIQUE,
     password_hash VARCHAR(255) NOT NULL,
     email VARCHAR(100) NOT NULL UNIQUE,
     is_admin TINYINT(1) DEFAULT 0,
     force_password_reset TINYINT(1) DEFAULT 0,
     created_at DATETIME DEFAULT CURRENT_TIMESTAMP
   );
   
   CREATE TABLE password_security (
     id INT AUTO_INCREMENT PRIMARY KEY,
     user_id INT NOT NULL,
     password_hash VARCHAR(255) NOT NULL,
     is_compromised TINYINT(1) NOT NULL,
     breach_count INT NOT NULL,
     check_date DATETIME NOT NULL,
     FOREIGN KEY (user_id) REFERENCES users(id)
   );

   CREATE TABLE breached_passwords(
    id INT(11), 
    password_hash VARCHAR(128),
    hash_algorithm VARCHAR(10), 
    breach_count INT(11), 
    first_seen DATE, 
    last_updated TIMESTAMP
   );
   ```

3. **Configuration**:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your credentials:
   ```ini
   DB_HOST=localhost
   DB_NAME=riashe_db
   DB_USER=your_db_user
   DB_PASS=your_secure_password
   NTFY_TOPIC=your_secret_topic  # For admin notifications
   ```

4. **Import Breach Data**:
   ```bash
   php database/import_breach_data.php breach_data.txt
   ```

## 🚀 Usage Scenarios

### User Flows

1. **Registration** (`/register.php`):
   - Password automatically checked against breaches
   - Immediate feedback if password is compromised

2. **Login** (`/login.php`):
    - User logs in
    - User's credentials are verified
    - User's password is checked against HIBP and breached passwords database
    - If the user's password is compromised, they are redirected to reset their password.
    - If the user's password is not compromised, they are granted access to the web page.   

3. **Password Reset** (`/reset_password.php`):
   - Required for compromised passwords
   - Visual strength meter guides users

### Admin Features (`/admin.php`)
- View all compromised passwords
- Filter by breach severity (minor/major/critical)
- Bulk actions:
  - Force password resets
  - Send notifications
- Export breach data

## 📂 Project Structure

```
riashe/
├── css/                         # Static resources
│   ├── theme.css/               # Stylesheets (theme.css)
├── database/                    # Database operations
│   ├── db_connect.php           # Database connection
│   └── import_breach_data.php   # Data importer
├── process/                     # Core processes
│   ├── notifications.php        # Notifications
│   └── process_login.php        # Login process
│   └── process_registration.php # Registration process
├── templates/                   # UI templates
│   └── admin.php                # Admin Dashboard
│   └── dashboard.php            # User Security Dashboard
│   └── home.html                # Home Page
│   └── login.php                # Login Page
│   └── logout.php               # Logout sequence
│   └── register.php             # Registration Page
│   └── reset_password.php       # Password Reset Page
├── LICENSE                      # MIT License
└── README.md                    # This document
```

## 🔧 Troubleshooting

### Common Issues

**Database Connection Errors**:
```bash
# Error: "Connection refused"
1. Verify MySQL is running
2. Check credentials in db_connect.php
3. Ensure user has permissions: GRANT ALL ON riashe_db.* TO 'user'@'localhost';
```

**HIBP API Failures**:
```php
// In process_login.php, add error handling:
if (!$response) {
    error_log("HIBP API failure: " . curl_error($ch));
    // Fallback to local breach database
}
```

**Performance Optimization**:
```ini
# In php.ini
memory_limit = 128M
max_execution_time = 30
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

**Coding Standards**:
- Follow PSR-12 coding style
- Document new functions with PHPDoc
- Include unit tests for new features

## 📧 Contact & Support

**Project Maintainer**: Quinter Jaika  
**Email**: [quinter.jaika@strathmore.edu](mailto:quinter.jaika@strathmore.edu)  
**Issue Tracker**: [GitHub Issues](https://github.com/Quinter-Jaika/Riashe/issues)


## 📊 Metrics

![Code Coverage](https://img.shields.io/badge/coverage-85%25-green)  
![Last Commit](https://img.shields.io/github/last-commit/Quinter-Jaika/Riashe)  
![Open Issues](https://img.shields.io/github/issues/Quinter-Jaika/Riashe)

---

*This project is maintained with ❤️ by the Quinter Jaika. Please consider starring the repository if you find it useful!*