import dns.message
import dns.rdatatype
import dns.rdataclass
from dns.rdtypes.ANY.MX import MX
import dns.rdata
import socket
import threading
import signal
import os
import sys
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
    return base64.urlsafe_b64encode(key)

# Encrypt with AES
def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    return encrypted_data  # Return bytes directly

# Decrypt with AES
def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    try:
        # Ensure encrypted_data is in bytes
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode('utf-8')
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return None

# Prepare Encryption Parameters
salt = b'Tandon'
password = "gf2457@nyu.edu"
input_string = "AlwaysWatching"

# Encrypt the input string
encrypted_value = encrypt_with_aes(input_string, password, salt)

# DNS records - store the encrypted value as bytes encoded in base64
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
    },
    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
    },
    'google.com.': {
        dns.rdatatype.A: '192.168.1.103',
    },
    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104',
    },
    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105',
    },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: (base64.b64encode(encrypted_value).decode('utf-8'),),  # Store base64 encoded string
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
}

# DNS Server Function
def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 53))

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # Check if domain and type exist in dns_records
            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.TXT:
                    # For TXT records, use the stored base64 encoded string
                    txt_data = answer_data[0]  # Get the base64 encoded string
                    rdata_list.append(dns.rdata.from_text(dns.rdataclass.IN, qtype, f'"{txt_data}"'))
                else:
                    rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]

                # Add the resource record to the response
                rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                for rdata in rdata_list:
                    rrset.add(rdata)
                response.answer.append(rrset)

            response.flags |= dns.flags.AA  # Set AA (Authoritative Answer) flag
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
