# AGONY: Stealthy Network Scanner
AGONY is a stealthy and fast network scanner built using Python and the powerful Scapy library. It allows you to discover all devices on a given network, including laptops, , IoT devices, printers, routers, and cameras. The tool performs an ARP scan and presents the live devices in a clean and organized format. It supports aggressive scanning modes, fast scanning options, and threading for efficiency.

## Features

- **Stealthy ARP Scan**: Discovers devices on the network using ARP requests.
- **Device Detection**: Identifies laptops, IoT devices, printers, routers, and cameras.
- **Threading Support**: Faster scans using multithreading.
- **Custom DNS Resolution**: Resolve hostnames using custom DNS servers.
- **Aggressive Scan Mode**: Floods ARP requests to wake devices for scanning.
- **Fast Scan Mode**: Reduces timeout and retry values for quick scans.
- **Verbose Output**: Detailed scan results, including device detection and resolution status.

## Installation

### Prerequisites

- **Python 3.x**: Ensure you have Python 3 installed.
- **Scapy**: Install Scapy using `pip`.

```bash
pip install scapy
```

### Windows Users

- **Npcap**: Scapy requires Npcap on Windows. Download it from [Npcap](https://npcap.com/).

### Linux/macOS Users

No additional installation is required for Npcap on Linux or macOS.

## Usage

```bash
usage: AGONY.py [-h] -t TARGET [-i INTERFACE] [-d DNS_SERVER] [-f] [-a]
                      [-v] [-th THREADS]

AGONY: A stealthy network scanner for discovering ALL devices

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target IP range in CIDR (e.g., 192.168.1.0/24).
  -i INTERFACE, --interface INTERFACE
                        Network interface (e.g., "eth0" or "Wi-Fi").
  -d DNS_SERVER, --dns DNS_SERVER
                        Custom DNS server IP (e.g., 8.8.8.8).
  -f, --fast            Fast mode: reduces timeout and retries.
  -a, --aggressive      Aggressive mode: floods ARP requests to wake devices.
  -v, --verbose         Verbose output: shows detection and resolution details.
  -th THREADS, --threads THREADS
                        Number of threads for scanning. Default: 10.
```

### Examples

1. **Basic Scan**:  
   Discover devices in the range `192.168.1.0/24`.

   ```bash
   sudo python3 AGONY.py -t 192.168.1.0/24
   ```

2. **Fast Scan**:  
   Perform a quicker scan with reduced timeout and retries.

   ```bash
   sudo python3 AGONY.py -t 192.168.1.0/24 -f
   ```

3. **Aggressive Mode**:  
   Flood ARP requests to wake up devices more quickly.

   ```bash
   sudo python3 arp_scanner.py -t 192.168.1.0/24 -a
   ```

4. **Custom DNS Server**:  
   Use a custom DNS server for hostname resolution.

   ```bash
   sudo python3 AGONY.py -t 192.168.1.0/24 -d 8.8.8.8
   ```

5. **Verbose Output**:  
   Show detailed output for each device.

   ```bash
   sudo python3 AGONY.py -t 192.168.1.0/24 -v
   ```

6. **Custom Threads**:  
   Adjust the number of threads used during scanning.

   ```bash
   sudo python3 AGONY.py -t 192.168.1.0/24 -th 20
   ```

## Example Output

```bash
└── Scanning 254 IPs with 10 threads...
└── Aggressive mode enabled
└── Found 50 live hosts

Discovered Devices with Resolved Hostnames:
┌──────────────────┬────────────────────┬──────────────────────────────┐
│ IP Address      │ MAC Address        │ Hostname                    │
├──────────────────┼────────────────────┼──────────────────────────────┤
│ 192.168.1.1     │ 00:14:22:01:23:45  │ router.local                │
│ 192.168.1.2     │ 00:25:96:FF:12:34  │ laptop1.local               │
│ 192.168.1.3     │ 00:11:22:AA:BB:CC  │ mobilephone.local           │
└──────────────────┴────────────────────┴──────────────────────────────┘

Total devices with resolved hostnames: 3
```

## Contributing

Feel free to open issues, fork the repository, or submit pull requests.

### Development Setup

1. Clone the repository.

```bash
git clone https://github.com/username/AGONY.git
cd AGONY
```

2. Create a virtual environment and activate it.

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

3. Run the scanner.

```bash
sudo python3 AGONY.py -t 192.168.1.0/24
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Scapy](https://scapy.readthedocs.io/en/latest/) for providing the powerful packet manipulation library.
- [Npcap](https://npcap.com/) for Windows packet capture support.
```
