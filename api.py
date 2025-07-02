import datetime
import secrets
from flask import Flask, request, render_template, redirect, session, url_for
import hashlib
import requests
import string
import psycopg2
from psycopg2 import pool
import os
import bcrypt
from threading import Thread
import time
from bs4 import BeautifulSoup
from dateutil import parser
import re


app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

def password_length(password):
    if len(password) < 12:
        return "❌ The password should have 12 or more characters."
    else:
        return "✅ The password length is adequate."

def password_complexity(password):
    count_lower, count_upper, count_number, count_special = 0, 0, 0, 0
    
    for char in password:
        if char.islower():
            count_lower += 1
        elif char.isupper():
            count_upper += 1
        elif char.isdigit():
            count_number += 1
        elif char in string.punctuation:
            count_special += 1
            
    if count_lower == 0 or count_upper == 0 or count_number == 0 or count_special == 0:
        return "❌ The password should include at least one lowercase letter, one uppercase letter, one number, and one special character."
    else:
        return "✅ The composition of the password is appropriate."

def calculate_security_score(password):
    score = 0
    
    # Length (max 30 points)
    length = len(password)
    if length >= 12:
        score += min(30, length * 2)  # 2 points per character up to 30
    
    # Complexity (max 40 points)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    score += 10 * (has_lower + has_upper + has_digit + has_special)
    
    # Breach status (max 30 points)
    breach_count = breach_password(password)
    if breach_count == 0:
        score += 30
    elif breach_count < 100:
        score += 15
    else:
        score += 0
    
    return min(100, score)  # Cap at 100

def breach_password(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    for line in response.text.splitlines():
        if line.startswith(suffix):
            return int(line.split(':')[1])
    return 0

@app.route('/')
def index():
    return redirect(url_for('login'))  

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_id = verify_user(username, password)
        if user_id:
            # Store user_id in session
            session['user_id'] = user_id
            return redirect(url_for('dashboard', password=password))
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/home')
def home():
    password = request.args.get('password')
    if not password:
        return redirect('/')
    
    count = breach_password(password)
    length = password_length(password)
    complexity = password_complexity(password)
    score = calculate_security_score(password)
    
    # Check character types for recommendations
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    return render_template('home.html',
        password=password,
        result={
            'password': password,
            'count': count,
            'is_pwned': count > 0,
            'length': length,
            'complexity': complexity
        },
        score=score,
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_special=has_special
    )
    
@app.route('/dashboard')
def dashboard():
    password = request.args.get('password')
    if not password:
        return redirect('/')
    
    count = breach_password(password)
    length = password_length(password)
    complexity = password_complexity(password)
    score = calculate_security_score(password)
    
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    return render_template('dashboard.html',
        password=password,
        result={
            'password': password,
            'count': count,
            'is_pwned': count > 0,
            'length': length,
            'complexity': complexity
        },
        score=score,
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_special=has_special
    )
@app.route('/logout')
def logout():
    return render_template('logout.html')

@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        # Handle password reset logic here
        current_password = request.form['current-password']
        new_password = request.form['new-password']
        confirm_password = request.form['confirm-password']
        
        # Add your password validation and update logic
        return redirect(url_for('dashboard'))
    
    return render_template('reset.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if register_user(username, email, password):
            return redirect(url_for('login'))
        else:
            return render_template('registration.html', error="Username or email already exists")
    return render_template('registration.html')



# Database connection pool
db_pool = psycopg2.pool.SimpleConnectionPool(
    minconn=1,
    maxconn=10,
    host="192.168.100.239",
    database="password_security",
    user="postgres",
    password="password"
)

def get_db_connection():
    return db_pool.getconn()

def release_db_connection(conn):
    db_pool.putconn(conn)


# Registration function
def register_user(username, email, password):
    # Generate salt and hash
    salt = os.urandom(16).hex()
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, salt) VALUES (%s, %s, %s, %s)",
            (username, email, password_hash, salt)
        )
        conn.commit()
        return True
    except psycopg2.IntegrityError:
        return False  # Username or email already exists
    finally:
        cursor.close()
        release_db_connection(conn)


# Login function
def verify_user(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT user_id, password_hash, salt FROM users WHERE username = %s",
            (username,)
        )
        result = cursor.fetchone()
        if result:
            user_id, stored_hash, salt = result
            input_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            if input_hash == stored_hash:
                # Update last login
                cursor.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = %s",
                    (user_id,)
                )
                conn.commit()
                return user_id
        return None
    finally:
        cursor.close()
        release_db_connection(conn)


#Password Security Enhancements

def generate_secure_password():
    """Generate a random secure password"""
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(16))

def hash_password_bcrypt(password):
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def check_password_bcrypt(password, hashed):
    """Verify bcrypt hashed password"""
    return bcrypt.checkpw(password.encode(), hashed.encode())

def log_breach_attempt(user_id, breach_count):
    """Log password breach detection"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO breach_logs (user_id, breach_count) VALUES (%s, %s)",
            (user_id, breach_count)
        )
        cursor.execute(
            "UPDATE users SET is_active = FALSE WHERE user_id = %s",
            (user_id,)
        )
        conn.commit()
    finally:
        cursor.close()
        release_db_connection(conn)
        
        

#Dark Web Monitoring
def dark_web_monitor():
    """Background task to check for compromised credentials"""
    while True:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Get all active users
            cursor.execute("SELECT user_id, email, username FROM users WHERE is_active = TRUE")
            users = cursor.fetchall()
            
            for user_id, email, username in users:
                # Check against HIBP
                breach_count = breach_password_from_db(user_id)
                
                # Check dark web markets
                dark_web_results = search_dark_web_for_credentials(email, username)
                
                if dark_web_results or breach_count > 0:
                    log_breach_attempt(user_id, breach_count, dark_web_results)
                    
                    # Generate appropriate nudge
                    nudge = generate_nudge(user_id)
                    send_security_alert(user_id, nudge)
                    
        except Exception as e:
            print(f"Dark web monitoring error: {str(e)}")
        finally:
            cursor.close()
            release_db_connection(conn)
            
        time.sleep(3600)  # Check every hour

# Start monitoring thread when app starts
monitor_thread = Thread(target=dark_web_monitor, daemon=True)
monitor_thread.start()

#PMT Implementation
def get_user_risk_profile(user_id):
    """Calculate user's risk score based on behavior"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Count past breaches
        cursor.execute(
            "SELECT COUNT(*) FROM breach_logs WHERE user_id = %s",
            (user_id,)
        )
        breach_count = cursor.fetchone()[0]
        
        # Count password changes
        cursor.execute(
            "SELECT COUNT(*) FROM password_history WHERE user_id = %s",
            (user_id,)
        )
        change_count = cursor.fetchone()[0]
        
        # Get last change date
        cursor.execute(
            "SELECT changed_at FROM password_history WHERE user_id = %s ORDER BY changed_at DESC LIMIT 1",
            (user_id,)
        )
        last_change = cursor.fetchone()[0]
        
        return {
            'breach_count': breach_count,
            'change_count': change_count,
            'days_since_change': (datetime.now() - last_change).days
        }
    finally:
        cursor.close()
        release_db_connection(conn)

def generate_nudge(user_id):
    """Generate appropriate nudge based on risk profile"""
    profile = get_user_risk_profile(user_id)
    
    if profile['breach_count'] > 0:
        return {
            'severity': 'high',
            'message': 'URGENT: Your password has been found in data breaches. You must change it immediately.',
            'action': 'force_change'
        }
    elif profile['days_since_change'] > 90:
        return {
            'severity': 'medium',
            'message': 'Your password is old. Consider changing it for better security.',
            'action': 'suggest_change'
        }
    elif profile['change_count'] < 3:
        return {
            'severity': 'low',
            'message': 'Tip: Changing passwords regularly improves security.',
            'action': 'educate'
        }
    else:
        return None

DARK_WEB_MARKETS = [
    "http://dreadyj7l26jqvyk3xycgljkkagc32x2y5urlcse3qocylzn53oj2byd.onion/",  # Replace with actual onion URLs
    "http://educate6mw6luxyre24uq3ebyfmwguhpurx7ann635llidinfvzmi3yd.onion/"  # These are just placeholders
]

def search_dark_web_for_credentials(email, username):
    results = []
    session = get_tor_session()
    
    for market_url in DARK_WEB_MARKETS:
        try:
            # Renew Tor identity for each request
            renew_tor_identity()
            
            # Search for email/username in market
            response = session.get(f"{market_url}/search?q={email}")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Parse results (adjust selectors based on actual market structure)
            listings = soup.select('.listing')
            for listing in listings:
                title = listing.select_one('.title').text.strip()
                date_text = listing.select_one('.date').text.strip()
                post_date = parser.parse(date_text)
                content = listing.select_one('.content').text.strip()
                
                if email.lower() in content.lower() or username.lower() in content.lower():
                    results.append({
                        'market': market_url,
                        'title': title,
                        'date': post_date,
                        'content': content,
                        'match_type': 'email' if email.lower() in content.lower() else 'username'
                    })
                    
        except Exception as e:
            print(f"Error searching {market_url}: {str(e)}")
            continue
            
    return results


def breach_password_from_db(user_id):
    """Check password breach status for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT password_hash FROM password_history WHERE user_id = %s ORDER BY changed_at DESC LIMIT 1",
            (user_id,)
        )
        result = cursor.fetchone()
        if result:
            return breach_password(result[0])
        return 0
    finally:
        cursor.close()
        release_db_connection(conn)

def log_breach_attempt(user_id, breach_count, dark_web_results):
    """Log password breach detection"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Log HIBP breach
        cursor.execute(
            "INSERT INTO breach_logs (user_id, breach_count, source) VALUES (%s, %s, %s)",
            (user_id, breach_count, 'HIBP')
        )
        
        # Log dark web findings
        for finding in dark_web_results:
            cursor.execute(
                """INSERT INTO breach_logs 
                (user_id, breach_count, source, details) 
                VALUES (%s, %s, %s, %s)""",
                (user_id, 1, 'Dark Web', str(finding)))
        
        # Deactivate compromised accounts
        if breach_count > 0 or dark_web_results:
            cursor.execute(
                "UPDATE users SET is_active = FALSE WHERE user_id = %s",
                (user_id,)
            )
        
        conn.commit()
    finally:
        cursor.close()
        release_db_connection(conn)

def send_security_alert(user_id, nudge):
    """Send security alert to user"""
    # Implement your notification system (email, SMS, etc.)
    print(f"Security alert for user {user_id}: {nudge['message']}")

if __name__ == '__main__':
    app.run(debug=True)