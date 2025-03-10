Features of the Password Strength Meter & User Management System
This Secure Password Strength Meter & User Management System is built using Streamlit and provides a user-friendly interface for password security, user authentication, and secure storage. Below are the key features:


🔑 1. Password Strength Meter
Uses the zxcvbn library to analyze password strength.
Provides a score from 0 to 4, where 0 is weakest and 4 is strongest.
Displays feedback and suggestions to improve password security.
Uses additional regex checks for uppercase, lowercase, numbers, symbols, and length.
Displays a progress bar to visualize password strength.

🔐 2. Secure Password Hashing & Verification
Uses bcrypt for secure password hashing.
Passwords are stored as hashed values, preventing plain-text storage.
Provides login authentication by verifying user-entered passwords against stored hashes.

🛠 3. Secure Password Generator
Allows users to generate strong passwords with customizable criteria:
✅ Uppercase letters
✅ Lowercase letters
✅ Numbers
✅ Symbols
Users can select the password length (4-18 characters).
Generates passwords using secrets.choice(), which is cryptographically secure.

👥 4. User Registration & Authentication
New users can register with a username and password.
Passwords are securely hashed before being stored in an SQLite database.
Existing users can log in, and their credentials are verified using bcrypt.
Users remain logged in using st.session_state.

🔄 5. User Account Management
Update Password: Users can change their password anytime.
Delete Account: Users can delete their account, removing the database file.
Logout: Users can securely log out of the system.

📊 6. Developer Info & Versioning
    Sidebar provides developer details (Fahad Khakwani, tech stack, GitHub/LinkedIn).
    Displays application version (1.1.08).
    💻 Will This Work?
    ✅ Yes! This system will work as intended.

Why?

Streamlit provides an easy-to-use UI for interactions.
zxcvbn ensures accurate password strength analysis.
bcrypt secures passwords using strong cryptographic hashing.
SQLite stores user credentials securely.
secrets module ensures randomly generated passwords are cryptographically strong.
Session state in Streamlit maintains login states effectively.
🚀 Possible Enhancements:
🔹 Implement OAuth authentication (Google, GitHub login).
🔹 Improve UI/UX design using custom CSS or Streamlit themes.
🔹 Add email verification for account creation.
🔹 Expand to a full authentication system with password reset options.




**Password Strength Meter & User Management System Documentation**

**Overview:**
This application is a secure password strength meter and user management system built using Python and Streamlit. It provides functionalities for checking password strength, generating secure passwords, registering and logging in users, updating passwords, and deleting accounts. It also utilizes bcrypt for password hashing and SQLite for user data storage.

**Features:**
1. **Password Strength Checking** - Evaluates the strength of a password using zxcvbn and additional security checks.
2. **Secure Password Generation** - Generates random, strong passwords based on user preferences.
3. **User Registration & Authentication** - Stores hashed passwords securely in an SQLite database.
4. **Password Update & Account Deletion** - Allows users to update their passwords and delete their accounts securely.
5. **Session Management** - Handles user login sessions with Streamlit session state.

**Dependencies:**
Ensure you have the following Python packages installed:
```sh
pip install streamlit zxcvbn bcrypt sqlite3
```

**Modules & Functions:**
1. **generate_secure_password(length, is_upper, is_lower, is_number, is_symbol)**
   - Generates a secure password based on user-selected criteria.

2. **check_password_strength(password)**
   - Evaluates password strength using zxcvbn and additional security rules.

3. **hash_password(password)**
   - Hashes a password using bcrypt before storing it in the database.

4. **verify_password(password, hashed_password)**
   - Compares an entered password with its stored hash.

5. **store_user(username, hashed_password)**
   - Stores new user credentials in an SQLite database.

6. **get_user(username)**
   - Retrieves stored password hash for user authentication.

7. **update_password(username, new_password)**
   - Updates the stored password hash for a given user.

8. **delete_user(username)**
   - Deletes a user account and its associated database file.

9. **password_strength_popup()**
   - Provides a UI for users to check password strength and generate secure passwords.

10. **user_dashboard()**
    - Displays user-specific options such as updating passwords and deleting accounts.

11. **main()**
    - Manages application flow, including user registration, login, and dashboard access.

**Usage Instructions:**
1. **Run the Application:**
   ```sh
   streamlit run app.py
   ```
2. **Register a New User:**
   - Enter a username and password.
   - Passwords are securely hashed and stored in SQLite.
3. **Log In:**
   - Enter the registered credentials.
   - The system verifies the password using bcrypt.
4. **Check Password Strength:**
   - Enter a password to evaluate its strength.
   - Receive feedback and improvement suggestions.
5. **Generate a Secure Password:**
   - Select password length and character types.
   - Generate a random, strong password.
6. **Update Password:**
   - Enter a new password and save changes.
7. **Delete Account:**
   - Confirm account deletion.
   - The SQLite database file associated with the user is removed.

**Developer Information:**
- **Author:** Fahad Khakwani  
- **Tech Stack:** Python, Streamlit, bcrypt, SQLite  
- **Version:** 1.0.0  
- **GitHub:** [Link](https://github.com/)  
- **LinkedIn:** [Link](https://linkedin.com/)  

This documentation provides an overview of the project, its features, and how to use it. For further enhancements, consider implementing email verification, multi-factor authentication, or password breach detection using an external API.
