import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import secrets  # 🔐 Import secrets module for secure random passkey generation

# 🔑 Generate a key if not already in session
if 'KEY' not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.KEY)

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0    

def hash_passkey(key):
    return hashlib.sha256(key.encode()).hexdigest()

def encrypt_data(text):
    return st.session_state.cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_data, passkey):
    hashed_passkey = hash_passkey(passkey)
    for value in st.session_state.stored_data.values():
        if value['encrypted_data'] == encrypted_data and value['hashed_passkey'] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return st.session_state.cipher.decrypt(encrypted_data.encode()).decode()
        st.session_state.failed_attempts += 1
    return None

st.set_page_config(page_title="Secure Data Encryption System", page_icon="🔒")    

st.title("🔐 Secure Data Encryption System")

menu = ["🏠 Home", "🛡️ Encrypt Data", "🔓 Decrypt Data", "🔑 Login"]
choice = st.sidebar.selectbox("📋 Select an Option", menu)

if choice == "🏠 Home":
    st.subheader("👋 Welcome to the Secure Data Encryption System")
    st.write("🔐 This system allows you to encrypt and decrypt data securely.")
    st.write("📌 Use the sidebar to navigate through the options.")

elif choice == "🛡️ Encrypt Data":
    st.subheader("🗄️ Store Data")
    data = st.text_area("📝 Enter the data you want to encrypt:")
    passkey = st.text_input("🔑 Enter a passkey (or generate one):", type="password")
    if st.button("🎲 Generate Passkey"):
        passkey = secrets.token_urlsafe(16)  # 🔒 Generate a secure random passkey
        st.write(f"✅ Generated Passkey: {passkey}")
    if st.button("🔐 Encrypt"):
        if data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_data = encrypt_data(data)
            st.session_state.stored_data[hashed_passkey] = {
                'encrypted_data': encrypted_data,
                'hashed_passkey': hashed_passkey
            }
            st.success("✅ Data encrypted and stored successfully!")
        else:
            st.error("⚠️ Please enter both data and passkey.")

elif choice == "🔓 Decrypt Data":
    st.subheader("🔍 Retrieve Data")
    encrypted_data = st.text_input("🔒 Enter the encrypted data:")
    passkey = st.text_input("🔑 Enter the passkey:", type="password")
    if st.session_state.failed_attempts >= 3:
        st.warning("🚫 Too many failed attempts. Please try again later.")
        st.experimental_set_query_params(nav="🔑 Login")
        st.experimental_rerun()
    if st.button("🔓 Decrypt"):
        if encrypted_data and passkey:
            decrypted_data = decrypt_data(encrypted_data, passkey)
            if decrypted_data:
                st.success(f"✅ Decrypted Data: {decrypted_data}")
            else:
                remaining_attempts = max(0, 3 - st.session_state.failed_attempts)
                st.error(f"❌ Decryption failed. {remaining_attempts} attempts remaining.")
        else:
            st.error("⚠️ Please enter both encrypted data and passkey.")    

elif choice == "🔑 Login":
    st.subheader("🔐 Reauthorization Required")
    st.write("🔁 You have been logged out due to too many failed attempts.")
    login_pass = st.text_input("🔑 Enter the passkey to reauthorize:", type="password")
    if st.button("✅ Login"):
        if login_pass:
            hashed_passkey = hash_passkey(login_pass)
            if hashed_passkey in st.session_state.stored_data:
                st.session_state.failed_attempts = 0
                st.success("🔓 Reauthorized successfully!")
                st.experimental_set_query_params(nav="🏠 Home")
                st.experimental_rerun()
            else:
                st.error("❌ Invalid passkey. Please try again.")
        else:
            st.error("⚠️ Please enter a passkey.")
