from flask import Flask, request, render_template
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
    result = None
    if request.method == 'POST':
        password = request.form['password']
        count = breach_password(password)
        length = password_length(password)
        complexity = password_complexity(password)
        result = {
            'password': password,
            'count': count,
            'is_pwned': count > 0,
            'length': length,
            'complexity': complexity
        }
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)