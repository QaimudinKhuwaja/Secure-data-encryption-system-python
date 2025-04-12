import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# ----- Constants -----
DATA_FILE = "encrypted_data.json"

# ----- Session State Initialization -----
if 'KEY' not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.KEY)

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'page' not in st.session_state:
    st.session_state.page = "Home"

if 'last_passkey' not in st.session_state:
    st.session_state.last_passkey = ""

# ----- File-Based Storage Functions -----
def load_data_from_file():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            st.session_state.stored_data = json.load(f)
     

def save_data_to_file():
    with open(DATA_FILE, "w") as f:
        json.dump(st.session_state.stored_data, f)
        

# Load existing data once when app starts
load_data_from_file()

# ----- Helper Functions -----
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return st.session_state.cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for entry in st.session_state.stored_data.values():
        if entry['encrypted_text'] == encrypted_text and entry['passkey'] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# ----- Navigation -----
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
page = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.page))
st.session_state.page = page

# ----- Pages -----
if page == "Home":
    st.title("🔐 Secure Data Encryption System")
    st.subheader("Welcome to the Secure Data System")
    st.write("Encrypt and store your data securely using a passkey. Retrieve it later by entering the correct passkey.")

elif page == "Store Data":
    st.title("📂 Store Data")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            save_data_to_file()  # ✅ Save to JSON
            st.session_state.last_passkey = passkey
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Both fields are required!")

elif page == "Retrieve Data":
    st.title("🔍 Retrieve Data")

    if st.session_state.failed_attempts >= 3:
        st.warning("🔒 Too many failed attempts! Redirecting to Login.")
        st.session_state.page = "Login"
        st.rerun()

    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            st.session_state.last_passkey = passkey
            decrypted = decrypt_data(encrypted_text, passkey)
            if decrypted:
                st.success(f"✅ Decrypted Data: {decrypted}")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
        else:
            st.error("⚠️ Both fields are required!")

elif page == "Login":
    st.title("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Your Last Used Passkey:", type="password")

    if st.button("Login"):
        hashed_login = hash_passkey(login_pass)
        found = False

        for entry in st.session_state.stored_data.values():
            if entry["passkey"] == hashed_login:
                found = True
                break

        if found:
            st.success("✅ Login successful. Redirecting to Retrieve Data.")
            st.session_state.failed_attempts = 0
            st.session_state.page = "Retrieve Data"
            st.rerun()
        else:
            st.error("❌ Incorrect passkey! Please try again.")