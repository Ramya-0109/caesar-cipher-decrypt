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

# Action buttons side by side
col1, col2 = st.columns(2)
with col1:
    decipher_btn = st.button("🔑 Decipher (Caesar Cipher)")
with col2:
    base64_btn = st.button("🗝️ Decode Base64")

# Output section
st.subheader("Decrypted Text")

result = ""

if decipher_btn and encrypted_text:
    result = decrypt_text(encrypted_text)

if base64_btn and encrypted_text:
    result = decode_base64(encrypted_text)

if result:
    # Container for output with copy button on top right
    with st.container():
        # Use columns to align the copy button to the right
        copy_col, empty_col = st.columns([1, 20])
        with copy_col:
            if st.button("📋 Copy"):
                st.experimental_set_query_params()  # Hack to clear focus
                st.experimental_rerun()
                # Actually copy text to clipboard via JS (hacky but works)
                st.write(
                    f"""
                    <script>
                    navigator.clipboard.writeText(`{result.replace("`", "'")}`);
                    </script>
                    """,
                    unsafe_allow_html=True,
                )
                st.success("Copied to clipboard!")
        
        # Large scrollable text area with the result
        st.text_area("Result", value=result, height=300, disabled=True)
else:
    st.info("Please enter encrypted text and select an action above.")
