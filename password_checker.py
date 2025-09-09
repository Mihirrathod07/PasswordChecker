import re
import hashlib
import requests
import string
import random
import json
import os

DATA_FILE = "password_data.json"

# Load stored password mapping
def load_password_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    else:
        return {}

# Save mapping
def save_password_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Password strength check (same as before)
def check_strength(password):
    strength_points = 0
    feedback = []

    if len(password) >= 8:
        strength_points += 1
    else:
        feedback.append("Password should be at least 8 characters long.")

    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        strength_points += 1
    else:
        feedback.append("Password should have both uppercase and lowercase letters.")

    if re.search(r'\d', password):
        strength_points += 1
    else:
        feedback.append("Password should contain at least one number.")

    if re.search(r'[@$!%*?&]', password):
        strength_points += 1
    else:
        feedback.append("Password should contain at least one special character (@$!%*?&).")

    if strength_points == 4:
        return "Strong password ✅", []
    elif strength_points >= 2:
        return "Moderate password ⚠️", feedback
    else:
        return "Weak password ❌", feedback

# Breach check (same as before)
def check_breach(password):
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5, tail = sha1pass[:5], sha1pass[5:]

    url = f"https://api.pwnedpasswords.com/range/{first5}"
    response = requests.get(url)

    if response.status_code != 200:
        return "Error: Could not check breach status (API issue)."

    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == tail:
            return f"⚠️ Password found {count} times in data breaches!"
    return "✅ Password not found in breaches."

# Generate a strong password
def generate_strong_password(length=16):
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "@$!%*?&"

    password = [
        random.choice(upper),
        random.choice(lower),
        random.choice(digits),
        random.choice(special)
    ]

    all_chars = upper + lower + digits + special
    password += random.choices(all_chars, k=length-4)
    random.shuffle(password)

    return ''.join(password)

# Main function
def main():
    password_data = load_password_data()
    password = input("Enter a password to check: ")

    # Strength check
    print("\n[Password Strength]")
    strength, feedback = check_strength(password)
    print(strength)
    if feedback:
        for f in feedback:
            print("- " + f)

    # Breach check
    print("\n[Breach Check]")
    breach_result = check_breach(password)
    print(breach_result)

    # Suggest strong password if weak or breached
    if strength != "Strong password ✅" or "⚠️" in breach_result:
        # Check if we already generated a strong password for this input
        if password in password_data:
            new_password = password_data[password]
        else:
            new_password = generate_strong_password()
            password_data[password] = new_password
            save_password_data(password_data)

        print("\n[Suggested Strong Password]")
        print(f"Here is a strong password you can use: {new_password}")
    else:
        print("\nYour password is strong and safe! ✅")

if __name__ == "__main__":
    main()
