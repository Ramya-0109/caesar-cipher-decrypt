import streamlit as st
import base64
import json
import xml.etree.ElementTree as ET
import csv
import io
from typing import Dict, Any
import re
import streamlit.components.v1 as components

# Page configuration
st.set_page_config(
    page_title="Text Decryption Tool",
    page_icon="🔓",
    layout="wide"
)

# Initialize session state once
if 'process_text' not in st.session_state:
    st.session_state.process_text = False
if 'decrypted_results' not in st.session_state:
    st.session_state.decrypted_results = {}
if 'last_processed_text' not in st.session_state:
    st.session_state.last_processed_text = ""

def copy_to_clipboard(text, button_key):
    """Create a copy to clipboard button using JavaScript"""
    # Escape quotes and newlines for JavaScript
    escaped_text = text.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
    
    copy_script = f"""
    <div>
        <button onclick="copyToClipboard{button_key}()" style="
            background-color: #ff4b4b;
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            cursor: pointer;
            font-size: 0.8rem;
        ">📋 Copy</button>
        <span id="copied{button_key}" style="color: green; margin-left: 10px; display: none;">Copied!</span>
    </div>
    <script>
    function copyToClipboard{button_key}() {{
        const text = "{escaped_text}";
        navigator.clipboard.writeText(text).then(function() {{
            document.getElementById('copied{button_key}').style.display = 'inline';
            setTimeout(function() {{
                document.getElementById('copied{button_key}').style.display = 'none';
            }}, 2000);
        }}).catch(function(err) {{
            console.error('Could not copy text: ', err);
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {{
                document.execCommand('copy');
                document.getElementById('copied{button_key}').style.display = 'inline';
                setTimeout(function() {{
                    document.getElementById('copied{button_key}').style.display = 'none';
                }}, 2000);
            }} catch (err) {{
                console.error('Fallback: Could not copy text: ', err);
            }}
            document.body.removeChild(textArea);
        }});
    }}
    </script>
    """
    return copy_script

@st.cache_data
def decode_base64(text: str) -> str:
    """Decode Base64 encoded text"""
    try:
        # Remove whitespace and newlines
        cleaned_text = re.sub(r'\s+', '', text)
        
        # Add padding if necessary
        missing_padding = len(cleaned_text) % 4
        if missing_padding:
            cleaned_text += '=' * (4 - missing_padding)
        
        decoded_bytes = base64.b64decode(cleaned_text)
        return decoded_bytes.decode('utf-8')
    except Exception as e:
        return f"Base64 decoding failed: {str(e)}"

def decrypt_text(cipher_text: str, payload: int) -> str:
    """Decrypt text using simple ASCII offset - your working code"""
    plain_text = map(lambda ch: chr(ord(ch) - payload), cipher_text)
    return str(''.join(plain_text))

def encrypt_text(plain_text: str, payload: int) -> str:
    """Encrypt text using simple ASCII offset - your working code"""
    cipher_text = map(lambda ch: chr(ord(ch) + payload), plain_text)
    return str(''.join(cipher_text))

def decode_hex(hex_text: str) -> str:
    """Decode hexadecimal encoded text"""
    try:
        # Remove spaces and make uppercase
        cleaned_hex = hex_text.replace(' ', '').replace('\n', '').upper()
        
        # Remove 0x prefix if present
        if cleaned_hex.startswith('0X'):
            cleaned_hex = cleaned_hex[2:]
        
        # Ensure even length
        if len(cleaned_hex) % 2 != 0:
            cleaned_hex = '0' + cleaned_hex
        
        # Convert hex to bytes then to string
        bytes_data = bytes.fromhex(cleaned_hex)
        return bytes_data.decode('utf-8')
    except Exception as e:
        return f"Hex decoding failed: {str(e)}"

def decode_binary(binary_text: str) -> str:
    """Decode binary encoded text"""
    try:
        # Remove spaces and newlines
        cleaned_binary = binary_text.replace(' ', '').replace('\n', '')
        
        # Ensure length is multiple of 8
        while len(cleaned_binary) % 8 != 0:
            cleaned_binary = '0' + cleaned_binary
        
        # Split into 8-bit chunks and convert to characters
        result = ""
        for i in range(0, len(cleaned_binary), 8):
            byte = cleaned_binary[i:i+8]
            if len(byte) == 8 and all(c in '01' for c in byte):
                char_code = int(byte, 2)
                result += chr(char_code)
            else:
                return f"Invalid binary format at position {i}"
        
        return result
    except Exception as e:
        return f"Binary decoding failed: {str(e)}"

def convert_to_json(text: str) -> str:
    """Convert text to JSON format or validate existing JSON"""
    try:
        # Try to parse as JSON first
        parsed = json.loads(text)
        return json.dumps(parsed, indent=2)
    except json.JSONDecodeError:
        # If not valid JSON, create a simple JSON structure
        return json.dumps({"decrypted_text": text}, indent=2)

def convert_to_xml(text: str) -> str:
    """Convert text to XML format"""
    try:
        # Try to parse as existing XML
        root = ET.fromstring(text)
        return ET.tostring(root, encoding='unicode')
    except ET.ParseError:
        # Create new XML structure
        root = ET.Element("decrypted_data")
        content = ET.SubElement(root, "content")
        content.text = text
        return ET.tostring(root, encoding='unicode')

def convert_to_csv(text: str) -> str:
    """Convert text to CSV format"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Try to detect if text contains structured data
    lines = text.strip().split('\n')
    if len(lines) > 1 and (',' in text or '\t' in text):
        # Appears to be structured data
        for line in lines:
            if ',' in line:
                writer.writerow(line.split(','))
            elif '\t' in line:
                writer.writerow(line.split('\t'))
            else:
                writer.writerow([line])
    else:
        # Simple text conversion
        writer.writerow(["decrypted_text"])
        writer.writerow([text])
    
    return output.getvalue()

def main():
    st.title("🔓 Text Decryption Tool")
    st.markdown("---")
    
    # Create three columns for the partitions - equal input and output areas
    col1, col2, col3 = st.columns([2, 1, 2])
    
    # First Partition - Input Area
    with col1:
        st.subheader("📝 Encrypted Text Input")
        encrypted_text = st.text_area(
            "Paste your encrypted text here:",
            height=400,
            placeholder="Enter your encrypted text here..."
        )
    
    # Second Partition - Action Buttons
    with col2:
        st.subheader("🔧 Actions")
        
        # Add some spacing
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Decipher button
        decipher_clicked = st.button("🔍 Decipher", use_container_width=True, type="primary")
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Decode Base64 button  
        decode_clicked = st.button("📦 Decode Base64", use_container_width=True, type="secondary")
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Decode Hex button
        hex_clicked = st.button("🔢 Decode Hex", use_container_width=True, type="secondary")
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Decode Binary button
        binary_clicked = st.button("💻 Decode Binary", use_container_width=True, type="secondary")
        
        # Process button clicks immediately without rerun
        if decipher_clicked and encrypted_text.strip():
            st.session_state.decryption_type = "cipher"
            st.session_state.process_text = True
        elif decipher_clicked:
            st.error("Please enter text to decipher!")
                
        if decode_clicked and encrypted_text.strip():
            st.session_state.decryption_type = "base64" 
            st.session_state.process_text = True
        elif decode_clicked:
            st.error("Please enter text to decode!")
            
        if hex_clicked and encrypted_text.strip():
            st.session_state.decryption_type = "hex"
            st.session_state.process_text = True
        elif hex_clicked:
            st.error("Please enter hex text to decode!")
            
        if binary_clicked and encrypted_text.strip():
            st.session_state.decryption_type = "binary"
            st.session_state.process_text = True
        elif binary_clicked:
            st.error("Please enter binary text to decode!")
        
        # Add cipher shift option for decipher
        st.markdown("---")
        st.subheader("⚙️ Cipher Options")
        cipher_shift = st.number_input("Cipher offset", min_value=1, max_value=25, value=5, help="Number of positions to shift")
    
    # Third Partition - Output Area
    with col3:
        # Container for the output section with copy button
        output_container = st.container()
        
        with output_container:
            # Header with copy button aligned to the right
            header_col1, header_col2 = st.columns([3, 1])
            
            with header_col1:
                st.subheader("📋 Decrypted Output")
            
            # Process text based on selected action
            current_text = encrypted_text.strip()
            
            # Process text based on selected action
            if current_text and (st.session_state.get('process_text', False) or 
                               st.session_state.get('decryption_type') in ['base64', 'cipher', 'hex', 'binary']):
                
                if st.session_state.get('decryption_type') == "base64":
                    result = decode_base64(current_text)
                    st.session_state.decrypted_results = {"Base64 Decoded": result}
                elif st.session_state.get('decryption_type') == "cipher":
                    result = decrypt_text(current_text, cipher_shift)
                    st.session_state.decrypted_results = {f"Decrypted (Offset {cipher_shift})": result}
                elif st.session_state.get('decryption_type') == "hex":
                    result = decode_hex(current_text)
                    st.session_state.decrypted_results = {"Hex Decoded": result}
                elif st.session_state.get('decryption_type') == "binary":
                    result = decode_binary(current_text)
                    st.session_state.decrypted_results = {"Binary Decoded": result}
                
                st.session_state.last_processed_text = current_text
                st.session_state.process_text = False
            
            # Display results
            if st.session_state.decrypted_results:
                # Tabs for different formats
                tab1, tab2, tab3, tab4 = st.tabs(["📝 Plain Text", "📊 JSON", "🏷️ XML", "📈 CSV"])
                
                # Get the primary result (first one)
                primary_result = list(st.session_state.decrypted_results.values())[0]
                
                with tab1:
                    # Display all decryption results in a more compact way
                    for method, result in st.session_state.decrypted_results.items():
                        col_text, col_copy = st.columns([4, 1])
                        
                        with col_text:
                            st.text_area(
                                method,
                                result,
                                height=400,
                                key=f"plain_{method}",
                                label_visibility="visible"
                            )
                        
                        with col_copy:
                            st.markdown("<br>", unsafe_allow_html=True)
                            copy_html = copy_to_clipboard(result, f"plain_{method}")
                            components.html(copy_html, height=50)
                
                with tab2:
                    try:
                        json_result = convert_to_json(primary_result)
                        col_json, col_copy_json = st.columns([4, 1])
                        with col_json:
                            st.text_area("JSON Format", json_result, height=400, key="json_output", label_visibility="collapsed")
                        with col_copy_json:
                            st.markdown("<br>", unsafe_allow_html=True)
                            copy_html = copy_to_clipboard(json_result, "json")
                            components.html(copy_html, height=50)
                    except Exception as e:
                        st.error(f"JSON conversion failed: {str(e)}")
                        st.write(f"Primary result preview: {primary_result[:100]}...")
                
                with tab3:
                    try:
                        xml_result = convert_to_xml(primary_result)
                        col_xml, col_copy_xml = st.columns([4, 1])
                        with col_xml:
                            st.text_area("XML Format", xml_result, height=400, key="xml_output", label_visibility="collapsed")
                        with col_copy_xml:
                            st.markdown("<br>", unsafe_allow_html=True)
                            copy_html = copy_to_clipboard(xml_result, "xml")
                            components.html(copy_html, height=50)
                    except Exception as e:
                        st.error(f"XML conversion failed: {str(e)}")
                        st.write(f"Primary result preview: {primary_result[:100]}...")
                
                with tab4:
                    try:
                        csv_result = convert_to_csv(primary_result)
                        col_csv, col_copy_csv = st.columns([4, 1])
                        with col_csv:
                            st.text_area("CSV Format", csv_result, height=400, key="csv_output", label_visibility="collapsed")
                        with col_copy_csv:
                            st.markdown("<br>", unsafe_allow_html=True)
                            copy_html = copy_to_clipboard(csv_result, "csv")
                            components.html(copy_html, height=50)
                    except Exception as e:
                        st.error(f"CSV conversion failed: {str(e)}")
                        st.write(f"Primary result preview: {primary_result[:100]}...")
            
            else:
                st.info("👆 Enter encrypted text and click a button to decrypt it")
                st.markdown("### How to use:")
                st.markdown("- **🔍 Decipher**: For text encrypted with ASCII offset (default offset: 5)")
                st.markdown("- **📦 Decode Base64**: For Base64 encoded text (like: SGVsbG8gV29ybGQ=)")
                st.markdown("- **🔢 Decode Hex**: For hexadecimal encoded text (like: 48656C6C6F)")
                st.markdown("- **💻 Decode Binary**: For binary encoded text (like: 01001000 01100101)")
                st.markdown("### Output options:")
                st.markdown("- View results as Plain Text, JSON, XML, or CSV format")
                st.markdown("- Click 📋 to copy any result to clipboard")

    # Footer
    st.markdown("---")
    st.markdown(
        """
        <div style='text-align: center; color: #666;'>
            🔓 Text Decryption Tool | Supports Base64 decoding and Caesar cipher decryption
        </div>
        """,
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()
