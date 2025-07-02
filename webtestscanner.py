import requests

# Fetch a public paste (example)
url = "https://ibighit.com/bts/eng/profile"  # Example Pastebin URL
try:
    response = requests.get(url, timeout=10)
    if response.status_code == 200:
        leaks = response.text
        print(f"Scraped data: {leaks[:200]}...")  # Print snippet
except Exception as e:
    print(f"Error: {e}")\

def is_valid_password(password):
    # At least 8 chars, no spaces, contains letter + number/symbol
    return (len(password) >= 8 and 
            re.match(r"^\S+$", password) and 
            re.match(r"^(?=.*[a-zA-Z])(?=.*[\d!@#$%^&*]).+$", password))

valid_passwords = {p for p in passwords if is_valid_password(p)}
print("Valid passwords:", valid_passwords)
