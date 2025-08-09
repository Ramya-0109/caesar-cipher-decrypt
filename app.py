
import streamlit as st

# Caesar cipher decryption function
def decrypt_text(cipher_text, payload):
    return ''.join(chr(ord(ch) - payload) for ch in cipher_text)

# Page settings
st.set_page_config(page_title="Caesar Cipher Decryptor", layout="centered")

# Title
st.title("🔓 Caesar Cipher Decryptor")

# Top section: Input
st.subheader("Enter Encrypted Text")
encrypted_text = st.text_area("Encrypted text here...", height=150)
offset = st.number_input("Cipher offset", min_value=1, value=5)

# Bottom section: Output
st.subheader("Decrypted Text")
decrypted_text = ""
if encrypted_text:
    decrypted_text = decrypt_text(encrypted_text, offset)
    st.text_area("Result", value=decrypted_text, height=150, disabled=True)

    # Copy button
    if st.button("📋 Copy to Clipboard"):
        st.code(decrypted_text, language=None)
        st.info("Copy the above text manually (press Cmd + C or Ctrl + C)")
