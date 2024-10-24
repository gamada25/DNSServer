import unittest
import dns.message
import dns.rdatatype
import dns.resolver
import threading
import time
import socket
import sys
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Import your DNS server code here
# from your_dns_server import run_dns_server, encrypt_with_aes, decrypt_with_aes, generate_aes_key

class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start DNS server in a separate thread
        cls.server_thread = threading.Thread(target=run_dns_server_user)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(1)  # Give the server time to start

    def setUp(self):
        # Create a DNS resolver for testing
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['127.0.0.1']
        self.resolver.port = 53
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    def test_DNSServer_query(self):
        """Test basic DNS query functionality"""
        try:
            # Test A record query
            answer = self.resolver.resolve('example.com', 'A')
            self.assertEqual(str(answer[0]), '192.168.1.101')

            # Test MX record query
            answer = self.resolver.resolve('example.com', 'MX')
            self.assertEqual(str(answer[0].exchange), 'mail.example.com.')
            self.assertEqual(answer[0].preference, 10)

            # Test SOA record query
            answer = self.resolver.resolve('example.com', 'SOA')
            self.assertEqual(str(answer[0].mname), 'ns1.example.com.')
            
        except Exception as e:
            self.fail(f"DNS query test failed: {str(e)}")

    def test_DNSServer_ipv6_query(self):
        """Test IPv6 (AAAA) record queries"""
        try:
            # Test AAAA record query
            answer = self.resolver.resolve('example.com', 'AAAA')
            self.assertEqual(str(answer[0]), '2001:db8:85a3::8a2e:370:7334')

            # Test AAAA record for another domain
            answer = self.resolver.resolve('nyu.edu', 'AAAA')
            self.assertEqual(str(answer[0]), '2607:f600:1002:6113::100')
            
        except Exception as e:
            self.fail(f"IPv6 query test failed: {str(e)}")

    def test_exfiltrate(self):
        """Test data exfiltration through encrypted DNS TXT records"""
        try:
            # Test parameters
            salt = b'dns_salt_value'
            password = 'dns_secure_password'
            original_email = 'gf2457@nyu.edu'

            # Query the TXT record
            answer = self.resolver.resolve('nyu.edu', 'TXT')
            encrypted_data = answer[0].strings[0].encode()

            # Decrypt the received data
            decrypted_email = decrypt_with_aes(encrypted_data, password, salt)

            # Verify the decrypted email matches the original
            self.assertEqual(decrypted_email, original_email)

            # Test encryption roundtrip
            test_data = "test@example.com"
            encrypted = encrypt_with_aes(test_data, password, salt)
            decrypted = decrypt_with_aes(encrypted, password, salt)
            self.assertEqual(test_data, decrypted)
            
        except Exception as e:
            self.fail(f"Exfiltration test failed: {str(e)}")

if __name__ == '__main__':
    unittest.main()
