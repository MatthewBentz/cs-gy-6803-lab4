# User password in database, from SQL injection
# b'0123456789abcdef\xd7\xfa]\x82\xa1\xdf\x98\x9bu/\x06\x8d+vS\x7f\xddl\x02I\xe6\xb4\x80\xde\xbbw\xef\x10Q\xbbR\xe5\xb7\x9eqHq\xaf}\xf8'

password = b'0123456789abcdef\xd7\xfa]\x82\xa1\xdf\x98\x9bu/\x06\x8d+vS\x7f\xddl\x02I\xe6\xb4\x80\xde\xbbw\xef\x10Q\xbbR\xe5\xb7\x9eqHq\xaf}\xf8'

# the decryption function, as written by app.py

# # Function to encrypt the password using AES encryption
# def encrypt_password(password):
#     key = bytearray(b'\x93n\x12\xcbC\xe0|\xd0\xa6%7(?KW\xa9\xc2\x02\x97\xc6\\\xd6\xd9c\xf4x\xb9\xe2\x89\x88<\x9d')
#     nonce = b'0123456789abcdef'
#     cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
#     ciphertext, tag = cipher.encrypt_and_digest(password.encode())
#     return cipher.nonce + tag + ciphertext

# To decrypt the password, we need to reverse the symmetric AES encryption process. Since the key/IV are the same, this should be easy.

from Crypto.Cipher import AES

def decrypt_password(encrypted_password):
    key = bytearray(b'\x93n\x12\xcbC\xe0|\xd0\xa6%7(?KW\xa9\xc2\x02\x97\xc6\\\xd6\xd9c\xf4x\xb9\xe2\x89\x88<\x9d')
    nonce = encrypted_password[:16]
    tag = encrypted_password[16:32]
    ciphertext = encrypted_password[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_password.decode('utf-8')

decrypted_password = decrypt_password(password)
print("Decrypted password:", decrypted_password)

# Output:
# Decrypted password: SQLi_is_easier_than_this