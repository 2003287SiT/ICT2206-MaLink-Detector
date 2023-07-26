import dns.resolver


def get_dns_records(domain):
    dns_records = {}
    record_types = ['A', 'AAAA', 'ANY', 'CAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT']

    result = ""
    for record_type in record_types:
        try:
            records = dns.resolver.resolve(domain, record_type)
            dns_records[record_type] = []
            for record in records:
                dns_records[record_type].append(record.to_text())

            if dns_records[record_type]:
                result += f"{record_type}:\n"
                for record in dns_records[record_type]:
                    result += f"{record}\n"
                result += "\n"  # Add an extra newline after each record type
            else:
                result += f"{record_type}:\nNo {record_type} record found.\n\n"
        except dns.resolver.NoAnswer:
            result += f"{record_type}:\nNo {record_type} record found.\n\n"
        except dns.exception.DNSException as e:
            result += f"Error while querying {record_type} records: {e}\n\n"

    return result.strip()
