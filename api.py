from flask import Flask, request, render_template, redirect, url_for
import hashlib
import requests
import string

app = Flask(__name__)

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

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        password = request.form['password']
        return redirect(url_for('home', password=password))
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

if __name__ == '__main__':
    app.run(debug=True)