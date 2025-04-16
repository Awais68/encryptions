import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import os
import json

# Function to load or generate a Fernet key
def load_key():
    key_file = "secret.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        return key

# Initialize Fernet cipher
KEY = load_key()
cipher = Fernet(KEY)

# In-memory data storage (for simplicity; consider a database for production)
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {"user1": {"encrypted_text": "xyz", "passkey": "hashed"}}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(data, passkey):
    return cipher.encrypt(data.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    try:
        hashed_passkey = hash_passkey(passkey)
        # Check if the encrypted text exists and the passkey matches
        for user_id, value in st.session_state.stored_data.items():
            if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
                st.session_state.failed_attempts = 0
                return cipher.decrypt(encrypted_text.encode()).decode()
        st.session_state.failed_attempts += 1
        return None
    except Exception:
        st.session_state.failed_attempts += 1
        return None

# Streamlit page configuration
st.set_page_config(
    page_title="Encryption for Security",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="auto"
)

# Custom CSS for background
st.markdown("""
    <style>
    .stApp {
        background-color: #ADD8E6;  /* Light gray-blue background */
    }
    </style>
""", unsafe_allow_html=True)

# Sidebar menu
menu = ["Home", "Login", "Register", "Encrypt", "Decrypt"]
choice = st.sidebar.radio("Menu", menu)

if choice == "Home":
    st.title("Welcome to Secure Data Storage!")
    st.write("Use unique passkeys to securely store and retrieve your data.")
    st.image(
        "https://static.vecteezy.com/system/resources/thumbnails/036/338/682/small/ai-generated-hands-holding-a-miniature-house-concept-of-home-ownership-photo.jpg",
        caption="Secure Data"
    )

elif choice == "Encrypt":
    st.subheader("Encrypt Your Data & Store It Securely")
    user_id = st.text_input("Enter a unique user ID:")
    user_data = st.text_area("Enter your data to encrypt:")
    passkey = st.text_input("Enter a unique passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_id and user_data and passkey:
            if user_id in st.session_state.stored_data:
                st.error("User ID already exists. Please choose a different one.")
            else:
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)
                st.session_state.stored_data[user_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                st.success("✅ Data Stored Successfully")
                st.write(f"**Encrypted Data:** \n \t\t {encrypted_text}")
                st.write(f"**Passkey (hashed):** \n\t\t {hashed_passkey}")
        else:
            st.error("Please enter a user ID, data, and passkey.")

elif choice == "Decrypt":
    st.subheader("Retrieve Your Data")
    user_id = st.text_input("Enter your user ID:")
    encrypted_text = st.text_area("Enter the encrypted data:")
    passkey = st.text_input("Enter the unique passkey:", type="password")

    if st.button("Decrypt"):
        if user_id and encrypted_text and passkey:
            if st.session_state.failed_attempts >= 3:
                st.warning("🔒 Too many failed attempts. Please try again later.")
            else:
                decrypted_text = decrypt_data(encrypted_text, passkey)
                if decrypted_text:
                    st.success(f"**Decrypted Data:** \n\t\t {decrypted_text}")
                else:
                    st.error("Failed to decrypt. Please check the user ID, encrypted text, and passkey.")
        else:
            st.error("Please enter a user ID, encrypted text, and passkey.")

elif choice == "Login":
    st.subheader("Re-Authorization Required")
    login_pass = st.text_input("Enter your master password:", type="password")
    master_pass_hash = hash_passkey("Super369")  # In production, store this securely

    if st.button("Login"):
        if hash_passkey(login_pass) == master_pass_hash:
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! You can now access other features.")
        else:
            st.error("Invalid password. Please try again.")
            st.session_state.failed_attempts += 1

elif choice == "Register":
    st.subheader("Register a New User")
    st.write("Registration is not fully implemented yet. Please use a unique user ID in the Encrypt section.")

    user_name = st.text_input("Enter a new user ID:")
    user_pass = st.text_input("Enter a new passkey:", type="password")
    confirm_pass = st.text_input("Confirm passkey:", type="password")

    if st.button("Register"):
        if user_name and user_pass and confirm_pass:
            if user_pass == confirm_pass:
                if user_name in st.session_state.stored_data:
                    st.error("User ID already exists. Please Choose a different one.  Thank You!")
                else:
                    hashed_passkey = hash_passkey(user_pass)
                    st.session_state.stored_data[user_name] = {
                        "encrypted_text": "",
                        "passkey": hashed_passkey
                    }
                    st.success("✅ User Registered Successfully")
            else:
                st.error("Passkeys do not match. Please try again.")
        else:
            st.error("Please enter a user ID and passkeys.")

