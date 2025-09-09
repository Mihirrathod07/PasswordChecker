import streamlit as st
import re
import hashlib
import requests
import string
import random
import json
import os

# --- File paths ---
DATA_FILE = "password_data.json"
LOG_FILE = "usage_stats.txt"

# --- Load & Save password mapping ---
def load_password_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    else:
        return {}

def save_password_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# --- Password strength check ---
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

# --- Breach check ---
def check_breach(password):
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5, tail = sha1pass[:5], sha1pass[5:]
    url = f"https://api.pwnedpasswords.com/range/{first5}"
    response = requests.get(url)

    if response.status_code != 200:
        return "Error checking breach."

    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == tail:
            return f"⚠️ Found {count} times in data breaches!"
    return "✅ Not found in breaches."

# --- Generate strong password ---
def generate_strong_password(length=16):
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "@$!%*?&"
    password = [random.choice(upper), random.choice(lower), random.choice(digits), random.choice(special)]
    all_chars = upper + lower + digits + special
    password += random.choices(all_chars, k=length-4)
    random.shuffle(password)
    return ''.join(password)

# --- Safe logging function ---
def log_usage(password, strength):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open(LOG_FILE, "a") as f:
        f.write(f"{hashed_password} | {strength}\n")

# --- Streamlit UI ---
st.title("🔒 Password Strength & Breach Checker")

user_password = st.text_input("Enter your password:", type="password")

if st.button("Check Password"):
    password_data = load_password_data()

    # Strength
    strength, feedback = check_strength(user_password)
    st.subheader("Password Strength")
    st.write(strength)
    for f in feedback:
        st.write("- " + f)

    # Breach
    breach_result = check_breach(user_password)
    st.subheader("Breach Check")
    st.write(breach_result)

    # Safe logging
    log_usage(user_password, strength)

    # Suggest strong password if weak or breached
    if strength != "Strong password ✅" or "⚠️" in breach_result:
        if user_password in password_data:
            new_password = password_data[user_password]
        else:
            new_password = generate_strong_password()
            password_data[user_password] = new_password
            save_password_data(password_data)

        st.subheader("Suggested Strong Password")
        st.code(new_password)
    else:
        st.success("Your password is strong and safe! ✅")
