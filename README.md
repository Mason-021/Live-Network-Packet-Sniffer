# Live Network Packet Sniffer

A Python-based live network packet sniffer built with **Scapy** for capturing, inspecting, filtering, and analyzing network traffic directly from the command line.

The project was developed as a practical cybersecurity and network-analysis exercise, progressing from basic packet capture into protocol analysis, packet filtering, PCAP recording, payload inspection, and advanced traffic statistics.

---

## Overview

This tool captures live network traffic from a specified network interface and extracts useful information from IPv4 and IPv6 packets.

It currently supports:

* Live packet capture
* IPv4 and IPv6 traffic
* TCP, UDP, ICMP, and ICMPv6 detection
* TCP flag interpretation
* Source and destination IP extraction
* Source and destination port extraction
* Application-level protocol filtering
* Berkeley Packet Filter (BPF) capture filtering
* Raw payload previews
* Packet-size measurement
* PCAP file recording
* Advanced traffic statistics
* Top source and destination IP analysis
* Top source and destination port analysis
* Command-line configuration
* Graceful interruption with `Ctrl+C`

The implementation uses Scapy's packet-layer inspection capabilities to identify and process individual packets.

---

## Project Objectives

The main objectives of this project are to develop practical understanding of:

1. Live network packet capture
2. Network protocol identification
3. TCP/UDP packet analysis
4. IPv4 and IPv6 packet handling
5. Packet filtering
6. BPF capture filtering
7. Packet payload inspection
8. Traffic statistics and measurement
9. PCAP generation for offline analysis
10. Command-line network-security tooling

The project is intended as a learning and cybersecurity portfolio project rather than a replacement for mature packet-analysis platforms such as Wireshark.

---

## Features

### 1. Live Packet Capture

The program captures packets directly from a selected network interface using Scapy's `sniff()` functionality.

The interface is supplied through the command line:

```bash
sudo ./venv/bin/python3 sniffer.py -i eth0
```

`-i` / `--interface` specifies the network interface from which packets should be captured.

The program validates that the requested interface exists before starting the capture.

> **Note:** Packet capture generally requires elevated privileges because access to raw network traffic is restricted on many Linux systems.

---

### 2. Packet Count Control

The `-c` / `--count` option controls how many packets are captured.

```bash
sudo ./venv/bin/python3 sniffer.py -i eth0 -c 50
```

A positive value limits the capture to that number of packets.

A value of `0` means continuous capture until the user stops the program with `Ctrl+C`.

The program also validates the supplied value and rejects negative numbers.

---

### 3. Protocol Filtering

The `-f` / `--filter` option controls which protocol traffic is displayed.

Supported values:

| Filter | Description                     |
| ------ | ------------------------------- |
| `tcp`  | Display TCP packets             |
| `udp`  | Display UDP packets             |
| `icmp` | Display ICMP and ICMPv6 packets |
| `all`  | Display all supported traffic   |

Example:

```bash
sudo ./venv/bin/python3 sniffer.py -i eth0 -f tcp -c 30
```

The protocol filter is implemented at the application's packet-processing level.

An important design detail is that packet statistics are updated before the application-level filter is applied. This means the tool can maintain statistics about the captured traffic while selectively displaying only the protocol requested by the user.

---

### 4. BPF Capture Filtering

The `-b` / `--bpf` option allows a Berkeley Packet Filter expression to be passed to Scapy.

Example:

```bash
sudo ./venv/bin/python3 sniffer.py -i eth0 -b "tcp port 443" -c 30
```

This differs from the application's `-f` protocol filter.

**Application-level filtering:**

```text
Packet capture
      ↓
Python receives packet
      ↓
Python checks -f
      ↓
Packet displayed or ignored
```

**BPF filtering:**

```text
Network traffic
      ↓
BPF filter
      ↓
Only matching packets reach Python
      ↓
Packet processing
```

This distinction is important when interpreting the resulting statistics.

The BPF expression is passed directly to Scapy's `sniff()` call.

---

### 5. IPv4 and IPv6 Support

The sniffer recognizes both IPv4 and IPv6 packets.

For IPv4:

```text
IPv4 source → IPv4 destination
```

For IPv6:

```text
IPv6 source → IPv6 destination
```

The program identifies the IP version and extracts the corresponding source and destination addresses.

---

### 6. ICMP and ICMPv6 Detection

The project supports both ICMP and ICMPv6.

ICMPv6 is identified using the IPv6 **Next Header value 58** rather than relying on a single generic ICMPv6 Scapy class.

This allows the sniffer to recognize IPv6 ICMP traffic while remaining compatible with the Scapy implementation used by the project.

---

### 7. TCP Analysis

For TCP packets, the program extracts:

* Source IP
* Destination IP
* Source port
* Destination port
* TCP flags
* Packet size
* Payload preview

TCP flags are converted from Scapy's flag representation into human-readable names such as:

```text
SYN
ACK
FIN
RST
PSH
URG
ECE
CWR
```

The implementation maintains separate counters for TCP packets and TCP bytes.

Example output:

```text
13:50:26:592  IPv4  TCP  172.31.11.135:58342  ->  4.225.11.192:443
[ACK        ]  1466 bytes
```

---

### 8. UDP Analysis

UDP packets are analyzed for:

* Source IP
* Destination IP
* Source port
* Destination port
* Packet size
* Payload preview

UDP packet and byte counts are maintained independently from TCP traffic.

---

### 9. Payload Preview

When a packet contains a `Raw` payload, the program extracts a limited hexadecimal preview.

The default preview is limited to **32 bytes**.

Example:

```text
Payload: 17030338522dc432b653936f1d8ad8e3b9d4e90a1191e285d94a94d79617aa3f
```

The payload is displayed in hexadecimal rather than interpreted as plaintext.

For encrypted protocols such as TLS, the sniffer will therefore normally observe encrypted application data rather than decrypted content.

---

### 10. PCAP Recording

The `-o` / `--output` option saves captured packets to a PCAP file.

Example:

```bash
sudo ./venv/bin/python3 sniffer.py -i eth0 -c 100 -o capture.pcap
```

The captured packet collection is written using Scapy's `wrpcap()` functionality.

The resulting PCAP file can subsequently be opened in packet-analysis tools such as Wireshark for deeper offline investigation.

---

# Advanced Statistics

The current version includes an advanced statistics subsystem that records information about the captured traffic.

## Overall Statistics

The program tracks:

* Total packets
* Total bytes
* Average packet size

The average packet size is calculated as:

```text
Average packet size =
Total captured bytes / Total captured packets
```

The implementation protects against division by zero when no packets have been captured.

---

## IP Version Statistics

The program separately counts:

```text
IPv4 packets
IPv6 packets
```

This makes it possible to quickly determine the IP-version distribution of the observed traffic.

---

## Protocol Statistics

Traffic is divided into:

```text
TCP
UDP
ICMP
Other
```

For each category, the program records both:

* Packet count
* Total bytes

Example:

```text
PROTOCOL STATISTICS
------------------------------------------------------------
TCP                :     28 packets     10240 bytes
UDP                :      2 packets       755 bytes
ICMP               :      0 packets         0 bytes
Other              :      0 packets         0 bytes
```

The implementation maintains these values independently for each protocol.

---

## Endpoint Statistics

The sniffer uses Python's `Counter` class to track the frequency of source and destination IP addresses.

It reports the top five source IPs and top five destination IPs.

```text
TOP SOURCE IPs
------------------------------------------------------------
172.31.11.135                         18 packets
192.168.1.10                           7 packets
...
```

This provides a simple way of identifying which endpoints are generating or receiving the largest number of observed packets.

---

## Port Statistics

The program also tracks source and destination ports for TCP and UDP traffic.

The top five source and destination ports are displayed after the capture.

```text
TOP DESTINATION PORTS
------------------------------------------------------------
443                                  24 packets
53                                    4 packets
80                                    2 packets
```

This can provide a quick indication of which network services are most active during a capture.

---

# Example Output

A typical capture may look similar to:

```text
[*] Interface   : eth0
[*] Packet limit: 30
[*] BPF Filter  : none
[*] PCAP output : none
[*] Protocol    : tcp
[*] Press Ctrl+C to stop.

13:50:26:592  IPv4  TCP  172.31.11.135:58342  ->  4.225.11.192:443
[ACK        ]   1466 bytes
                   Payload: 17030338522dc432b653936f1d8ad8e3...

13:50:27:104  IPv4  TCP  4.225.11.192:443     ->  172.31.11.135:58342
[ACK        ]   1466 bytes

============================================================
ADVANCED CAPTURE STATISTICS
============================================================
Total packets       : 30
Total bytes         : 10995
Average packet size : 366.50 bytes

IP VERSION
------------------------------------------------------------
IPv4 packets       : 30
IPv6 packets       : 0

PROTOCOL STATISTICS
------------------------------------------------------------
TCP                :     28 packets     10240 bytes
UDP                :      0 packets         0 bytes
ICMP               :      0 packets         0 bytes
Other              :      2 packets       755 bytes
```

---

# Command-Line Options

| Option | Long Form     | Description                       |
| ------ | ------------- | --------------------------------- |
| `-i`   | `--interface` | Network interface to capture from |
| `-c`   | `--count`     | Number of packets to capture      |
| `-f`   | `--filter`    | Application-level protocol filter |
| `-b`   | `--bpf`       | Berkeley Packet Filter expression |
| `-o`   | `--output`    | PCAP output file                  |

The interface option is required, while the remaining options have defaults.

---

# Usage Examples

## Capture Continuously

```bash
sudo ./venv/bin/python3 sniffer.py -i eth0
```

Captures continuously from `eth0` until `Ctrl+C` is pressed.

---

## Capture 30 TCP Packets

```bash
sudo ./venv/bin/python3 sniffer.py -i eth0 -f tcp -c 30
```

Captures 30 packets while displaying TCP traffic.

---

## Capture UDP Traffic

```bash
sudo ./venv/bin/python3 sniffer.py -i eth0 -f udp -c 50
```

Captures 50 packets and displays UDP traffic.

---

## Capture ICMP Traffic

```bash
sudo ./venv/bin/python3 sniffer.py -i eth0 -f icmp
```

Captures continuously while displaying ICMP and ICMPv6 traffic.

---

## Capture HTTPS Traffic with BPF

```bash
sudo ./venv/bin/python3 sniffer.py -i eth0 -b "tcp port 443" -c 50
```

Uses a BPF expression to capture only TCP traffic associated with port 443.

---

## Capture and Save to PCAP

```bash
sudo ./venv/bin/python3 sniffer.py -i eth0 -c 100 -o capture.pcap
```

Captures 100 packets and saves them to `capture.pcap`.

---

## Combine BPF Filtering and PCAP Recording

```bash
sudo ./venv/bin/python3 sniffer.py -i eth0 -b "tcp port 443" -o https_capture.pcap -c 100
```

Captures TCP port 443 traffic, displays matching packets, and saves the captured packets to a PCAP file.

---

# Installation

## Requirements

* Linux
* Python 3
* Scapy
* A network interface capable of packet capture
* Appropriate privileges for packet capture

Install Scapy inside the project's virtual environment:

```bash
python3 -m venv venv
```

Creates a Python virtual environment named `venv`, isolating the project's Python packages from the system Python installation.

```bash
./venv/bin/pip install scapy
```

Uses the virtual environment's `pip` executable to install Scapy into the project environment.

---

# Project Structure

A recommended project structure is:

```text
live_packet_sniffer/
├── sniffer.py
├── venv/
├── README.md
└── captures/
    └── *.pcap
```

### `sniffer.py`

The main packet-sniffing application.

### `venv/`

Python virtual environment containing the project's dependencies.

### `README.md`

Project documentation and usage instructions.

### `captures/`

Optional directory for PCAP files generated during testing and analysis.

> PCAP files may contain sensitive network information and should be reviewed carefully before being committed to a public repository.

---

# Architecture

The current implementation follows a straightforward processing pipeline:

```text
                Network Interface
                       │
                       ▼
                ┌─────────────┐
                │   Scapy     │
                │   sniff()   │
                └──────┬──────┘
                       │
                       ▼
                 Captured Packet
                       │
             ┌─────────┴─────────┐
             │                   │
             ▼                   ▼
       BPF Filtering       Statistics
             │                   │
             ▼                   │
      Protocol Filtering         │
             │                   │
             ▼                   ▼
       Packet Analysis      Traffic Metrics
             │
       ┌─────┼─────┐
       ▼     ▼     ▼
      TCP   UDP   ICMP
       │     │     │
       └─────┼─────┘
             │
             ▼
       Formatted Output
             │
             └──────────► Optional PCAP
```

---

# Technical Concepts Demonstrated

This project demonstrates practical application of several networking and cybersecurity concepts:

### Packet Capture

Intercepting packets directly from a network interface for analysis.

### Packet Dissection

Examining protocol layers and extracting fields such as IP addresses, ports, TCP flags, and payload data.

### Protocol Identification

Determining whether captured traffic belongs to TCP, UDP, ICMP, ICMPv6, or another category.

### IPv4 / IPv6

Handling both major versions of the Internet Protocol.

### TCP Flags

Interpreting TCP control flags such as SYN, ACK, FIN, RST, and PSH.

### BPF

Using Berkeley Packet Filter expressions to restrict traffic at the capture level.

### Traffic Statistics

Measuring packet counts, byte counts, protocol distribution, endpoint frequency, and port frequency.

### PCAP

Preserving captured packets for subsequent offline analysis.

### Command-Line Interface Design

Using Python's `argparse` module to provide configurable command-line functionality.

---

# Security and Privacy Considerations

A packet sniffer can observe network traffic that may contain sensitive information.

This tool should therefore be used only on networks and systems where you have explicit authorization to perform packet capture.

Captured traffic may potentially contain:

* IP addresses
* Network metadata
* Protocol information
* Application data
* Authentication-related traffic
* Other sensitive information

PCAP files should therefore be treated as potentially sensitive artifacts.

**Do not upload real-world sensitive PCAP captures to a public GitHub repository.**

For demonstrations and testing, use traffic generated in an environment you control.

---

# Limitations

The current version intentionally remains a lightweight command-line packet-analysis tool.

It does **not** currently attempt to provide:

* Full Wireshark-style protocol dissection
* TCP stream reconstruction
* Connection/session tracking
* Automatic port-scan detection
* Intrusion detection
* Persistent database storage
* Graphical visualization
* Full application-layer protocol parsing
* TLS decryption
* Automated threat intelligence
* Advanced anomaly detection

These limitations are deliberate and provide a foundation for future development.

---

# Current Development Stage

The project has progressed beyond basic packet capture and currently includes:

```text
✓ Live packet capture
✓ Command-line interface
✓ Interface validation
✓ Packet-count control
✓ TCP filtering
✓ UDP filtering
✓ ICMP filtering
✓ IPv4 support
✓ IPv6 support
✓ ICMPv6 detection
✓ TCP flag decoding
✓ Packet-size reporting
✓ Raw payload preview
✓ BPF capture filtering
✓ PCAP recording
✓ Advanced packet statistics
✓ Protocol byte statistics
✓ IP-version statistics
✓ Top source IP analysis
✓ Top destination IP analysis
✓ Top source port analysis
✓ Top destination port analysis
```

The current implementation maintains these statistics using `Counter` objects for endpoint and port-frequency analysis.

---

# Learning Outcomes

By completing this project, the developer gains practical experience with:

* Python network programming
* Scapy
* Packet capture
* Network protocol analysis
* TCP/IP fundamentals
* IPv4 and IPv6
* TCP flags
* UDP traffic
* ICMP traffic
* BPF filtering
* PCAP files
* Packet payloads
* Network traffic statistics
* Command-line application development
* Linux packet-capture privileges
* Cybersecurity network monitoring

More importantly, the project demonstrates the progression from **observing packets** to **extracting structured information from network traffic**.

---

# Future Development

Potential future stages of the project include:

* Network flow tracking
* DNS analysis
* Application-layer protocol identification
* TCP session analysis
* Connection tracking
* Port-scan detection
* Traffic anomaly detection
* Rule-based alerts
* JSON logging
* CSV reporting
* Configuration files
* Improved runtime controls
* Modular architecture
* Automated testing
* Performance optimization
* Security hardening

These features are outside the scope of the current implementation and can be introduced incrementally as the project develops.

---

# Disclaimer

This project is intended for **educational, defensive-security, and authorized network-analysis purposes**.

Only capture or inspect network traffic on systems and networks for which you have permission.

The author is not responsible for misuse of this software.

---

## Author

**Mason-021**

Cybersecurity / Network Security Learning Project

Built with:

* Python
* Scapy
* Linux
* Networking and packet-analysis concepts

