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
        dns.rdatatype.A: '192.0.2.1',  # Example IP address
        dns.rdatatype.AAAA: '2001:0db8::1',  # Example IPv6 address
        dns.rdatatype.MX: [(10, 'mail.nyu.edu.')],
        dns.rdatatype.NS: 'ns.nyu.edu.',
        dns.rdatatype.TXT: ('NYU is a university.',),
    },
    'safebank.com.': {
        dns.rdatatype.A: '203.0.113.1',  # Example IP address
        dns.rdatatype.AAAA: '2001:0db8::2',  # Example IPv6 address
        dns.rdatatype.MX: [(10, 'mail.safebank.com.')],
        dns.rdatatype.NS: 'ns.safebank.com.',
        dns.rdatatype.TXT: ('Safe Bank offers secure banking.',),
    },
}
