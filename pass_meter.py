import streamlit as st
import zxcvbn  # Password strength analysis
import bcrypt  # Secure password hashing
import sqlite3  # Database storage
import re  # Regex for additional password checks
import secrets  # Secure password generation
import string
import os

def generate_secure_password(length, is_upper, is_lower, is_number, is_symbol):
    characters = ""
    if is_upper:
        characters += string.ascii_uppercase
    if is_lower:
        characters += string.ascii_lowercase
    if is_number:
        characters += string.digits
    if is_symbol:
        characters += string.punctuation
    
    if not characters:
        characters = string.ascii_letters + string.digits + string.punctuation
    
    return ''.join(secrets.choice(characters) for _ in range(length))

def check_password_strength(password):
    result = zxcvbn.zxcvbn(password)
    score = result['score']  # Score ranges from 0 (weak) to 10 (strong)
    feedback = result['feedback']['suggestions']
    
    # Additional security checks
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\\d", password))
    has_special = bool(re.search(r"[@$!%*?&]", password))
    length_ok = len(password) >= 12
    
    additional_score = sum([has_upper, has_lower, has_digit, has_special, length_ok])
    final_score = min(score + additional_score, 10)  # Ensure the max score remains 10
    
    if final_score < 10:
        if not has_upper:
            feedback.append("Add at least one uppercase letter.")
        if not has_lower:
            feedback.append("Add at least one lowercase letter.")
        if not has_digit:
            feedback.append("Include at least one number.")
        if not has_special:
            feedback.append("Use special characters like @$!%*?&.")
        if not length_ok:
            feedback.append("Make your password at least 12 characters long.")
    
    return final_score, feedback

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password)

def store_user(username, hashed_password):
    conn = sqlite3.connect(f"{username}.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect(f"{username}.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def update_password(username, new_password):
    hashed_password = hash_password(new_password)
    conn = sqlite3.connect(f"{username}.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
    conn.commit()
    conn.close()

def delete_user(username):
    confirm = st.checkbox("Are you sure you want to delete your account? This action cannot be undone.")
    if confirm and st.button("Confirm Deletion"):
        db_file = f"{username}.db"
        if os.path.exists(db_file):
            os.remove(db_file)
        st.session_state.logged_in_user = None
        st.success("Account and database file deleted successfully!")
        st.rerun()

def password_strength_popup():
    st.subheader("Password Strength Check")
    new_password = st.text_input("Enter Password to Check 'Strength'", type="password")
    if st.button("Check Strength"):
        score, feedback = check_password_strength(new_password)
        st.markdown(f"**Strength Score:** {score}/10")
        st.progress(score / 10)
        if feedback:
            st.warning("Suggestions: " + ", ".join(feedback))
    
    st.subheader("Generate Auto-Suggested Password")
    is_upper = st.checkbox("Include Uppercase Letters")
    is_lower = st.checkbox("Include Lowercase Letters")
    is_number = st.checkbox("Include Numbers")
    is_symbol = st.checkbox("Include Symbols")
    
    password_length = st.slider("Select Password Length", 4, 18, 13)
    
    if st.button("Generate Now"):
        strong_password = generate_secure_password(password_length, is_upper, is_lower, is_number, is_symbol)
        st.text(f"Suggested Password: {strong_password}")

def user_dashboard():
    st.subheader(f"Welcome, {st.session_state.logged_in_user}!")
    password_strength_popup()
    
    st.subheader("New Password Updation")
    new_password = st.text_input("Enter New Password", type="password")
    if st.button("Update Password"):
        update_password(st.session_state.logged_in_user, new_password)
        st.success("Password updated successfully!")
    if st.button("Delete Account"):
        delete_user(st.session_state.logged_in_user)
    if st.button("Logout"):
        st.session_state.logged_in_user = None
        st.success("Logged out successfully!")
        st.rerun()
    st.info("Note: All data will be deleted when you delete your account.")


def main():
        
    if "logged_in_user" not in st.session_state:
        st.session_state.logged_in_user = None
    
    if st.session_state.logged_in_user:
        user_dashboard()
    else:
        option = st.radio("Select an option", ["Register", "Login"])
        if option == "Register":
            username = st.text_input("Enter Username")
            password = st.text_input("Enter Password", type="password")
            if st.button("Register"):
                if password:
                    hashed_password = hash_password(password)
                    store_user(username, hashed_password)
                    st.success("Account registered successfully! Please log in.")
                else:
                    st.error("Please enter a password!")
        elif option == "Login":
            username = st.text_input("Enter Username")
            password = st.text_input("Enter Password", type="password")
            if st.button("Login"):
                user = get_user(username)
                if user and verify_password(password, user[0]):
                    st.session_state.logged_in_user = username
                    st.success("Login successful! Redirecting...")
                    st.rerun()
                else:
                    st.error("Invalid username or password")

st.title("🔒 Secure Password Strength Meter & User Management")
main()

st.text("Developer: Fahad Khakwani")
st.write("Version: 1.1.20")
