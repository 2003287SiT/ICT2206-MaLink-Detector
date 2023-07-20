import dns.resolver


def get_dns_records(domain):
    dns_records = {}
    record_types = ['A', 'AAAA', 'ANY', 'CAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT']

    print("-" * 50)
    print("DNS lookup for " + domain + "\n")

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

        print("-" * 50)

    return dns_records


if __name__ == "__main__":
    user_domain = input("Enter the domain you want to look up: ")
    dns_records = get_dns_records(user_domain)

    if dns_records:
        print(f"DNS records for '{user_domain}':")
        for record_type, records in dns_records.items():
            print(f"{record_type}:")
            for record in records:
                print(f"  {record}")
