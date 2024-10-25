import dns.resolver
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    return base64.urlsafe_b64encode(key)

def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    # Don't double-encode to base64
    return encrypted_data

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    # Directly decrypt the Fernet token
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

def test_encryption():
    # Test parameters
    salt = b'Tandon'
    password = "gf2457@nyu.edu"
    input_string = "AlwaysWatching"
    
    # Test encryption
    encrypted = encrypt_with_aes(input_string, password, salt)
    print(f"Encrypted data (raw): {encrypted}")
    print(f"Encrypted data (base64): {base64.b64encode(encrypted).decode('utf-8')}")
    
    # Test decryption
    decrypted = decrypt_with_aes(encrypted, password, salt)
    print(f"Decrypted data: {decrypted}")
    
    # Verify the round trip
    assert decrypted == input_string, "Encryption/decryption round trip failed!"
    print("Encryption/decryption test passed!")

if __name__ == '__main__':
    test_encryption()
