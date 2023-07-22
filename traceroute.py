from scapy.all import *
from scapy.layers.inet import ICMP, IP
from colorama import Fore, init

# Initialize colorama for colored output
init()


def resolve(ip_addr):
    try:
        hostname = socket.gethostbyaddr(ip_addr)[0]
        return hostname
    except socket.herror:
        return ip_addr


def traceroute(target, max_hops=30):
    # Process the target to handle different URL formats
    target = target.replace("http://", "").replace("www.", "")

    print(f"Traceroute to {Fore.YELLOW}{target}{Fore.RESET} ({socket.gethostbyname(target)})")
    print("-" * 50)
    tracer_list = []
    print(colorama.Fore.GREEN + "{:<5} {:<20} {:<30} {:<10}".format("TTL", "IP Address", "Hostname",
                                                                    "RTT (ms)" + colorama.Style.RESET_ALL))
    for ttl in range(1, max_hops + 1):
        packet = IP(dst=target, ttl=ttl) / ICMP()

        # Send the packet and wait for the response
        reply = sr1(packet, verbose=False, timeout=2)

        if reply is None:
            # No response received, print a timeout message and continue to the next hop
            print("{:<5} {:<20} {:<30} {:10.4s}".format(ttl, "*", "*", "*"))
            tracer_list.append({"TTL": ttl, "IP Address": "*", "Hostname": "*", "RTT": "*"})
        else:
            # A response is received
            ip_address = reply.src
            hostname = resolve(ip_address)
            rtt = round(reply.time * 1000, 2)  # Convert to milliseconds
            print("{:<5} {:<20} {:<30} {:<10.4f}".format(ttl, ip_address, hostname, rtt))
            tracer_list.append({"TTL": ttl, "IP Address": ip_address, "Hostname": hostname, "RTT": rtt})

        # Check if the response is an ICMP Echo Reply (type 0)
        if reply and reply.type == 0:
            break

    return tracer_list


if __name__ == "__main__":
    target = input("Enter the target URL or IP address: ")
    traceroute_result = traceroute(target)

    # You can use traceroute_result for further analysis or display purposes if needed.

