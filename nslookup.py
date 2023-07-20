import dns.resolver

def get_dns_records(domain):
    dns_records = {}
    record_types = ['A', 'AAAA', 'ANY', 'CAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT']

    print("*" * 50)

    for record_type in record_types:
        try:
            records = dns.resolver.resolve(domain, record_type)
            dns_records[record_type] = []
            for record in records:
                print(f"{record_type} Record:", record.to_text())
                dns_records[record_type].append(record.to_text())
        except dns.resolver.NoAnswer:
            print(f"No {record_type} record found.")
        except dns.exception.DNSException as e:
            print(f"Error while querying {record_type} records: {e}")

        print("*" * 50)

    return dns_records


