import streamlit as st
import base64

# Caesar cipher decryption (fixed offset 5)
def decrypt_text(cipher_text):
    payload = 5
    return ''.join(chr(ord(ch) - payload) for ch in cipher_text)

# Base64 decode
def decode_base64(encoded_text):
    try:
        decoded_bytes = base64.b64decode(encoded_text)
        return decoded_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error decoding Base64: {e}"

# Page settings
st.set_page_config(page_title="Decryption Tool", layout="centered")

st.title("🔓 Decryption Tool")

# Input section
st.subheader("Enter Encrypted Text")
encrypted_text = st.text_area("Paste your encrypted text here...", height=150)

# Action buttons
col1, col2 = st.columns(2)
with col1:
    decipher_btn = st.button("🔑 Decipher (Caesar Cipher)")
with col2:
    base64_btn = st.button("🗝️ Decode Base64")

# Output section
st.subheader("Decrypted Text")

# Placeholder for result
result = ""

if decipher_btn and encrypted_text:
    result = decrypt_text(encrypted_text)

if base64_btn and encrypted_text:
    result = decode_base64(encrypted_text)

if result:
    # Copy button above the text
    copy_col, _ = st.columns([1,5])
    with copy_col:
        if st.button("📋 Copy"):
            st.code(result, language=None)
            st.info("Copy the above text manually (Cmd+C / Ctrl+C)")

    # Show decrypted text (full height)
    st.text_area("Result", value=result, height=len(result.splitlines())*25 + 50, disabled=True)
