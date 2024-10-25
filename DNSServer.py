import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Generate AES Key function
def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

# Encrypt with AES
def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    encrypted_data_str = base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
    print("Encrypted data for TXT record:", encrypted_data_str)  # Debugging output
    return encrypted_data_str

# Decrypt with AES
def decrypt_with_aes(encrypted_data, password, salt):
    try:
        key = generate_aes_key(password, salt)
        f = Fernet(key)
        encrypted_data_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
        decrypted_data = f.decrypt(encrypted_data_bytes)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        print(f"Decrypt error! Type: {type(e)} Value: {e}")
        raise

# Parameters for encryption
salt = b'Tandon'
password = "gf2457@nyu.edu"
input_string = "AlwaysWatching"

# Encrypt and verify decryption
encrypted_value = encrypt_with_aes(input_string, password, salt)
try:
    decrypted_value = decrypt_with_aes(encrypted_value, password, salt)
    print("Decrypted value:", decrypted_value)  # Ensure correct decryption
except Exception as e:
    print("Failed to decrypt:", e)

# DNS records setup
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',
            'admin.example.com.',
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: (encrypted_value,),  # Store encrypted string in TXT record
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
}

# DNS Server Function
def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("0.0.0.0", 53))

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(dns.rdataclass.IN, dns.rdatatype.SOA, mname, rname, serial, refresh, retry, expire, minimum)
                    rdata_list.append(rdata)
                else:
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, data) for data in answer_data]

                for rdata in rdata_list:
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                    rrset.add(rdata)
                    response.answer.append(rrset)

            response.flags |= 1 << 10  # Set AA (Authoritative Answer) flag
            server_socket.sendto(response.to_wire(), addr)
            print("Responding to request:", qname)

        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)

# Run server with user input to quit
def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()

if __name__ == '__main__':
    run_dns_server_user()
    # Uncomment to see encrypted/decrypted values
    # print("Encrypted Value:", encrypted_value)
    # print("Decrypted Value:", decrypted_value)
