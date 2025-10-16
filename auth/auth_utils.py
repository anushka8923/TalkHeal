import sqlite3
import bcrypt
from datetime import datetime
import re
import logging
logging.basicConfig(
    filename="user_auth.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

DB_NAME = "users.db"
def get_connection():
    """Create and return a new database connection."""
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())
    def is_valid_email(email):
    """Validate email format."""
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def register_user(name, email, password):
    if not is_valid_email(email):
        return False, "Invalid email format."

    conn = get_connection()
    cursor = conn.cursor()
    hashed_pw = hash_password(password)
    current_time = datetime.now().isoformat()
    
    try:
        cursor.execute("""
            INSERT INTO users (name, email, password, updated_at) 
            VALUES (?, ?, ?, ?)
        """, (name, email, hashed_pw, current_time))
        conn.commit()
        logging.info(f"User registered: {email}")
        return True, "User registered successfully"
    except sqlite3.IntegrityError:
        logging.warning(f"Duplicate registration attempt: {email}")
        return False, "Email already registered"
    except sqlite3.Error as e:
        logging.error(f"Database error during registration: {str(e)}")
        return False, f"Database error: {str(e)}"
    finally:
        conn.close()

def authenticate_user(email, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT name, password FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    conn.close()
    if result and check_password(password, result[1]):
        logging.info(f"User logged in: {email}")
        user = {"name": result[0], "email": email}
        return True, user
        logging.warning(f"Failed login attempt: {email}")
    return False, None

def check_user(email):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return True , result[4]
    return False , None

def reset_password(email, new_password):
    hashed_pw = hash_password(new_password)
    current_time = datetime.now().isoformat()
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        result = cursor.fetchone()

        if not result:
            conn.close()
            return False, "User with this email does not exist."

        cursor.execute("UPDATE users SET password = ? , updated_at = ? WHERE email = ?", (hashed_pw, current_time, email))
        conn.commit()
        conn.close()
        logging.info(f"Password updated successfully for {email}")
        return True, "Password updated successfully."
    except sqlite3.Error as e:
        conn.close()
        logging.error(f"Database error during password reset: {str(e)}")
        return False, f"Database error: {str(e)}"

def verify_token_count(email, token_updated_at):
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT updated_at FROM users WHERE email = ?", (email,))
        result = cursor.fetchone()
        if not result:
            conn.close()
            return False, "User with this email does not exist."

        db_updated_at = result[0]

        if str(db_updated_at) != str(token_updated_at):
            conn.close()
            return False, "Reset link is no longer valid (token outdated)."

        conn.close()
        return True, None

    except sqlite3.Error as e:
        conn.close()
        return False, f"Database error: {str(e)}"
