import argparse
from datetime import datetime
from collections import Counter
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw, get_if_list, wrpcap

def has_icmpv6(packet):
    """
    Detect whether an IPv6 packet contains an ICMPv6 message via Next Header (58).
    """
    if not packet.haslayer(IPv6):
        return False

    return packet[IPv6].nh == 58

def non_negative_int(value):
    """
    Validate and convert command-line arguments to non-negative integers.
    """
    try:
        value = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("count must be an integer.")

    if value < 0:
        raise argparse.ArgumentTypeError("count cannot be negative")

    return value

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Live TCP/UDP/ICMP network packet sniffer"
    )

    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Network interface to capture packets from"
    )

    parser.add_argument(
        "-c",
        "--count",
        type=non_negative_int,
        default=0,
        help="Number of packets to capture; 0 means capture continuously"
    )

    parser.add_argument(
        "-f",
        "--filter",
        choices=["tcp", "udp", "icmp", "all"],
        default="all",
        help="Protocol filter"
    )

    parser.add_argument(
        "-b",
        "--bpf",
        default=None,
        help="BPF filter string (e.g., 'tcp port 80')"
    )

    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Save captured packets to a PCAP file"
    )

    return parser.parse_args()

def format_tcp_flags(flags):
    """
    Convert Scapy TCP flags into comma-separated human-readable names.
    """
    flag_names = {
        "f": "FIN",
        "S": "SYN",
        "A": "ACK",
        "P": "PSH",
        "R": "RST",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }

    readable_flags = [flag_names.get(flag, flag) for flag in str(flags)]

    if not readable_flags:
        return "-"

    return ",".join(readable_flags)

def packet_matches_filter(packet, protocol_filter):
    """
    Check if a packet matches the selected application-level protocol filter.
    """
    if protocol_filter == "all":
        return True
    
    if protocol_filter == "tcp":
        return packet.haslayer(TCP)
    
    if protocol_filter == "udp":
        return packet.haslayer(UDP)
    
    if protocol_filter == "icmp":
        return packet.haslayer(ICMP) or has_icmpv6(packet)

    return False

def get_network_addresses(packet):
    """
    Extract source IP, destination IP, and IP version from a packet.
    """
    if packet.haslayer(IP):
        return (packet[IP].src, packet[IP].dst, 4)
    
    if packet.haslayer(IPv6):
        return (packet[IPv6].src, packet[IPv6].dst, 6)
    return None

def get_payload_preview(packet, limit=32):
    """
    Extract a hexadecimal preview of the Raw payload up to the specified byte limit.
    """
    if not packet.haslayer(Raw):
        return None
    
    payload = packet[Raw].load

    if not payload:
        return None

    return payload[:limit].hex()

def process_packet(packet, protocol_filter, statistics):
    """
    Process, format, and log a single captured network packet.
    """
    packet_length = len(packet)

    statistics["total"] += 1
    statistics["bytes"] += packet_length

    if packet.haslayer(IP):
        statistics["ipv4"] += 1
    elif packet.haslayer(IPv6):
        statistics["ipv6"] += 1

    if packet.haslayer(TCP):
        statistics["tcp_packets"] += 1
        statistics["tcp_bytes"] += packet_length
    elif packet.haslayer(UDP):
        statistics["udp_packets"] += 1
        statistics["udp_bytes"] += packet_length
    elif packet.haslayer(ICMP) or has_icmpv6(packet):
        statistics["icmp_packets"] += 1
        statistics["icmp_bytes"] += packet_length
    else:
        statistics["other_packets"] += 1
        statistics["other_bytes"] += packet_length

    if not packet_matches_filter(packet, protocol_filter):
        return

    network_info = get_network_addresses(packet)
    if network_info is None:
        return

    source_ip, destination_ip, ip_version = network_info

    statistics["source_ips"][source_ip] += 1
    statistics["destination_ips"][destination_ip] += 1

    timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S:%f")[:-3]

    if packet.haslayer(TCP):
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        statistics["source_ports"][source_port] += 1
        statistics["destination_ports"][destination_port] += 1

        flags = format_tcp_flags(packet[TCP].flags)
        source = f"{source_ip}:{source_port}"
        destination = f"{destination_ip}:{destination_port}"
        payload_preview = get_payload_preview(packet)

        print(
            f"{timestamp}  "
            f"IPv{ip_version}  "
            f"TCP  "
            f"{source:<22}  ->  "
            f"{destination:<22}  "
            f"[{flags:<11}]  "
            f"{packet_length:>4} bytes"
        )

        if payload_preview:
            print(f"                   Payload: {payload_preview}")

    elif packet.haslayer(UDP):
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

        statistics["source_ports"][source_port] += 1
        statistics["destination_ports"][destination_port] += 1

        source = f"{source_ip}:{source_port}"
        destination = f"{destination_ip}:{destination_port}"
        payload_preview = get_payload_preview(packet)

        print(
            f"{timestamp}  "
            f"IPv{ip_version}  "
            f"UDP  "
            f"{source:<22}  ->  "
            f"{destination:<22}  "
            f"{packet_length:>4} bytes"
        )

        if payload_preview:
            print(f"                   Payload: {payload_preview}")

    elif packet.haslayer(ICMP) or has_icmpv6(packet):
        print(
            f"{timestamp}  "
            f"IPv{ip_version}  "
            f"ICMP  "
            f"{source_ip:<22} ->  "
            f"{destination_ip:<22}  "
            f"[{'-':<11}]  "
            f"{packet_length:>4} bytes"
        )

def print_statistics(statistics):
    """
    Display overall capture and traffic distribution statistics.
    """
    total_packets = statistics["total"]
    total_bytes = statistics["bytes"]
    average_packet_size = (total_bytes / total_packets) if total_packets else 0

    print("\n")
    print("=" * 60)
    print("ADVANCED CAPTURE STATISTICS")
    print("=" * 60)

    print(f"Total packets       : {total_packets}")
    print(f"Total bytes         : {total_bytes}")
    print(f"Average packet size : {average_packet_size:.2f} bytes")

    print("\nIP VERSION")
    print("-" * 60)
    print(f"IPv4 packets       : {statistics['ipv4']}")
    print(f"IPv6 packets       : {statistics['ipv6']}")

    print("\nPROTOCOL STATISTICS")
    print("-" * 60)
    print(f"TCP                : {statistics['tcp_packets']:>6} packets  {statistics['tcp_bytes']:>8} bytes")
    print(f"UDP                : {statistics['udp_packets']:>6} packets  {statistics['udp_bytes']:>8} bytes")
    print(f"ICMP               : {statistics['icmp_packets']:>6} packets  {statistics['icmp_bytes']:>8} bytes")
    print(f"Other              : {statistics['other_packets']:>6} packets  {statistics['other_bytes']:>8} bytes")

    print("\nTOP SOURCE IPs")
    print("-" * 60)
    for ip, count in statistics["source_ips"].most_common(5):
        print(f"{ip:<30} {count:>6} packets")

    print("\nTOP DESTINATION IPs")
    print("-" * 60)
    for ip, count in statistics["destination_ips"].most_common(5):
        print(f"{ip:<30} {count:>6} packets")

    print("\nTOP SOURCE PORTS")
    print("-" * 60)
    for port, count in statistics["source_ports"].most_common(5):
        print(f"{port:<30} {count:>6} packets")

    print("\nTOP DESTINATION PORTS")
    print("-" * 60)
    for port, count in statistics["destination_ports"].most_common(5):
        print(f"{port:<30} {count:>6} packets")

    print("=" * 60)

def main():
    args = parse_arguments()

    available_interfaces = get_if_list()
    if args.interface not in available_interfaces:
        raise SystemExit(f"[-] Interface not found: {args.interface}")

    statistics = {
        "total": 0,
        "bytes": 0,

        "ipv4": 0,
        "ipv6": 0,

        "tcp_packets": 0,
        "tcp_bytes": 0,

        "udp_packets": 0,
        "udp_bytes": 0,

        "icmp_packets": 0,
        "icmp_bytes": 0,

        "other_packets": 0,
        "other_bytes": 0,

        "source_ips": Counter(),
        "destination_ips": Counter(),
        
        "source_ports": Counter(),
        "destination_ports": Counter(),
    }

    print(f"[*] Interface   : {args.interface}")
    print(f"[*] Packet limit: {args.count if args.count != 0 else 'unlimited'}")
    print(f"[*] BPF Filter  : {args.bpf if args.bpf else 'none'}")
    print(f"[*] PCAP output : {args.output if args.output else 'none'}")
    print(f"[*] Protocol    : {args.filter}")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        packets = sniff(
            iface=args.interface,
            count=args.count,
            filter=args.bpf,
            prn=lambda packet: process_packet(packet, args.filter, statistics)
        )

        if args.output:
            wrpcap(args.output, packets)
            print(f"[*] PCAP saved to: {args.output}")

    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")

    finally:
        print_statistics(statistics)

if __name__ == "__main__":
    main()