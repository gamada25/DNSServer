import dns.message
import dns.rdatatype
import dns.rdataclass
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
    return base64.b64encode(encrypted_data).decode('utf-8')  # Encode to base64 for storage

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_bytes = base64.b64decode(encrypted_data)  # Decode from base64
    decrypted_data = f.decrypt(encrypted_bytes)
    return decrypted_data.decode('utf-8')

# Prepare Encryption Parameters
salt = b'Tandon'  # Salt must be a byte-object
password = "gf2457@nyu.edu"  # Your actual NYU email
input_string = "AlwaysWatching"  # Secret data to encrypt

# Encrypt the input string
encrypted_value = encrypt_with_aes(input_string, password, salt)

# DNS records
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',  # mname
            'admin.example.com.',  # rname
            2023081401,  # serial
            3600,  # refresh
            1800,  # retry
            604800,  # expire
            86400,  # minimum
        ),
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
        dns.rdatatype.TXT: (encrypted_value,),  # Store the encrypted data as TXT
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
}

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
                    response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype))
                    response.answer[-1].add(rdata)

            response.flags |= dns.flags.AA

            print("Responding to request:", qname)
            server_socket.sendto(response.to_wire(), addr)
        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)

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
