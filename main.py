import streamlit as st
import pandas as pd
from io import BytesIO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import hashlib
import re

# Encryption
def encrypt_message(key, message):
    # Pad the message to be a multiple of 16 bytes (AES block size)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()

    # Generate a random initialization vector (IV)
    iv = b'\x00' * 16

    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    # Encrypt the message
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the ciphertext
    return ciphertext

# Decryption
def decrypt_message(key, iv, ciphertext):
    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    # Decrypt the message
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the message
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_data) + unpadder.finalize()

    return message

# Transfer the password into 16-bytes hash string
def hash_password(password):
    # Encode the password as bytes
    password_bytes = password.encode('utf-8')

    # Use the SHA-256 hash function
    hashed_bytes = hashlib.sha256(password_bytes).digest()

    # Take the first 16 bytes of the hash
    result = hashed_bytes[:16]

    return result

def is_valid_password(password, min_length=8):
    # Check if the password meets the criteria
    return (
        len(password) >= min_length and
        re.search(r'[a-z]', password) and  # At least one lowercase letter
        re.search(r'[A-Z]', password) and  # At least one uppercase letter
        re.search(r'\d', password)          # At least one digit
    )

st.title("Encoding")

# File upload widget
excel_file = st.file_uploader("Upload an Excel file", type=[".xls", ".xlsx"])

# Password input for encoding and decoding
password = st.text_input("Enter a password for encoding", type="password")

if is_valid_password(password):
    st.success("Password is valid!")
else:
    st.warning("Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, and one digit.")

encrypted_key = hash_password(password)

# Columns selection
if excel_file is not None and password:
    # Number of rows to delete
    rows_to_delete = st.number_input("Number of rows to delete from the top", value=0, min_value=0)

    df = pd.read_excel(excel_file, skiprows = rows_to_delete)

    selected_columns = st.multiselect("Select columns to encode", df.columns)
    for col in selected_columns:
        for index, value in df[col].items():
            value = str(value).encode('utf-8')
            ciphertext = encrypt_message(encrypted_key, value)
            df.at[index, col] = b64encode(ciphertext).decode()
    st.write(df)

    output_filename = 'Encoded_'+ excel_file.name   

    st.write('Click below to download the encoded Excel file:')

    def download_excel(df):
    # Save DataFrame to BytesIO object as Excel file
        excel_buffer = BytesIO()
        df.to_excel(excel_buffer, index=False)
        excel_buffer.seek(0)
        return excel_buffer

    if st.button('Generate Encoded File'):
        excel_buffer = download_excel(df)
        st.download_button(label='Download Excel', data=excel_buffer, file_name=output_filename, mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


# Decoding section
st.title("Decoding")

encoded_file = st.file_uploader("Upload an encoded Excel file", type=[".xls", ".xlsx"])

password_1 = st.text_input("Enter a password for decoding", type="password")

if is_valid_password(password_1):
    st.success("Password is valid!")
else:
    st.warning("Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, and one digit.")

key_1 = hash_password(password_1)

if encoded_file is not None and password_1:
    df_encoded = pd.read_excel(encoded_file)

    selected_columns_encoded = st.multiselect("Select columns to decode", df_encoded.columns)

    for col in selected_columns_encoded:
        for index, value in df_encoded[col].items():
            value = str(value)
            iv, ciphertext = b'\x00' * 16, b64decode(value)
            decrypted_message = decrypt_message(key_1, iv, ciphertext)
            df_encoded.at[index, col] = decrypted_message.decode()

    st.write(df_encoded)

    output_filename_d = 'Decoded_'+ encoded_file.name   

    def download_excel(df):
    # Save DataFrame to BytesIO object as Excel file
        excel_buffer = BytesIO()
        df.to_excel(excel_buffer, index=False)
        excel_buffer.seek(0)
        return excel_buffer

    st.write('Click below to download the decoded Excel file:')
    if st.button('Generate Decoded File'):
        excel_buffer = download_excel(df_encoded)
        st.download_button(label='Download Excel', data=excel_buffer, file_name=output_filename_d, mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


