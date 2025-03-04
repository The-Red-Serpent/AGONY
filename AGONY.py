
from scapy.all import ARP, Ether, srp
import time
import random
import argparse
import platform
import sys
import ipaddress
import os
import socket
import threading
from queue import Queue
from scapy.config import conf


def supports_color():
    return sys.stdout.isatty() and platform.system() != "Windows" or "ANSICON" in os.environ

COLOR = supports_color()
BOLD = "\033[1m" if COLOR else ""
GREEN = "\033[92m" if COLOR else ""
BLUE = "\033[94m" if COLOR else ""
YELLOW = "\033[93m" if COLOR else ""
RED = "\033[91m" if COLOR else ""
RESET = "\033[0m" if COLOR else ""

def print_ascii_art():
    
    death_art = '''
  ______    ______    ______   __    __  __      __ 
 /      \  /      \  /      \ /  \  /  |/  \    /  |
/$$$$$$  |/$$$$$$  |/$$$$$$  |$$  \ $$ |$$  \  /$$/ 
$$ |__$$ |$$ | _$$/ $$ |  $$ |$$$  \$$ | $$  \/$$/  
$$    $$ |$$ |/    |$$ |  $$ |$$$$  $$ |  $$  $$/   
$$$$$$$$ |$$ |$$$$ |$$ |  $$ |$$ $$ $$ |   $$$$/    
$$ |  $$ |$$ \__$$ |$$ \__$$ |$$ |$$$$ |    $$ |    
$$ |  $$ |$$    $$/ $$    $$/ $$ | $$$ |    $$ |    
$$/   $$/  $$$$$$/   $$$$$$/  $$/   $$/     $$/     
'''
    # Print ASCII Art
    print(f"{BLUE}{death_art}{RESET}")
    print(f"{RED}{BOLD}Author : The Red Serpent{RESET}")

def get_arguments():
    parser = argparse.ArgumentParser(
        description='ARPScanTool: A stealthy network scanner for discovering ALL devices',
        epilog='''
Examples:
  Basic scan:                 sudo python3 arp_scanner.py -t 192.168.1.0/24
  Fast scan:                  sudo python3 arp_scanner.py -t 192.168.1.0/24 -f
  Aggressive mode:            sudo python3 arp_scanner.py -t 192.168.1.0/24 -a
  Custom DNS and threads:     sudo python3 arp_scanner.py -t 192.168.1.0/24 -d 8.8.8.8 -th 20 -v
  Verbose mode (Windows):     python arp_scanner.py -t 192.168.1.0/24 -i "Wi-Fi" -v

Notes:
  - Detects laptops, mobiles, IoT, printers, routers, cameras, etc., using real MACs via ARP.
  - Prints all live IPs, including those with unresolvable hostnames.
  - Uses threading for faster scanning.
  - Requires root/admin privileges.
  - Install: pip install scapy; Windows needs Npcap (https://npcap.com/).
''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-t', '--target', dest='target', required=True,
                        help='Target IP range in CIDR (e.g., 192.168.1.0/24).')
    parser.add_argument('-i', '--interface', dest='interface',
                        help='Network interface (e.g., "eth0" or "Wi-Fi"). Defaults to auto-detection.')
    parser.add_argument('-d', '--dns', dest='dns_server',
                        help='Custom DNS server IP (e.g., 8.8.8.8). Defaults to system resolver.')
    parser.add_argument('-f', '--fast', action='store_true',
                        help='Fast mode: reduces timeout and retries.')
    parser.add_argument('-a', '--aggressive', action='store_true',
                        help='Aggressive mode: floods ARP requests to wake devices.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output: shows detection and resolution details.')
    parser.add_argument('-th', '--threads', dest='threads', type=int, default=10,
                        help='Number of threads for scanning. Default: 10.')
    return parser.parse_args()

def get_default_interface():
    """Get the default network interface using conf.ifaces"""
    os_name = platform.system().lower()
    try:
        if not conf.ifaces:
            raise Exception("No interfaces detected in Scapy config. Specify with -i.")
        
        
        conf.ifaces.refresh()
        
        if os_name == "windows":
            for iface in conf.ifaces:
                if "Wi-Fi" in iface.description or "Ethernet" in iface.description:
                    return iface.name
            return conf.ifaces[0].name 
        elif os_name == "linux":
            return conf.iface or "eth0"
        else:
            raise Exception("Unsupported OS")
    except Exception as e:
        print(f"{BOLD}[!] Interface error:{RESET} {str(e)}")
        print(f"{BLUE}[*] Available interfaces:{RESET} {[iface.name for iface in conf.ifaces]}")
        return None

def arp_scan_worker(ip_queue, result_queue, interface, fast, aggressive, verbose):
    """Worker function for threaded ARP scanning"""
    timeout = 1 if fast else 4  
    retries = 0 if fast else 3  
    delay_range = (0.01, 0.05) if fast else (0.05, 0.2) 
    
    if aggressive:
        timeout = 5
        retries = 5
        delay_range = (0.005, 0.01) 
    
    while not ip_queue.empty():
        try:
            ip = ip_queue.get_nowait()
            ip_str = str(ip)
            arp_request = ARP(pdst=ip_str)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            answered_list = srp(arp_request_broadcast, timeout=timeout, retry=retries, inter=random.uniform(*delay_range), verbose=0, iface=interface)[0]
            
            if answered_list:
                for sent, received in answered_list:
                    if verbose:
                        print(f"{GREEN}│   └── Live host:{RESET} IP {received.psrc}, MAC {received.hwsrc}")
                    result_queue.put({
                        'ip': received.psrc,
                        'mac': received.hwsrc
                    })
            elif verbose:
                print(f"{YELLOW}│   └── No response from:{RESET} IP {ip_str}")
        except Exception as e:
            if verbose:
                print(f"{BOLD}[!] Thread error for {ip_str}:{RESET} {str(e)}")
        finally:
            ip_queue.task_done()

def arp_scan_live_hosts(target_range, interface=None, fast=False, aggressive=False, verbose=False, num_threads=10):
    """Perform ARP scan to find live hosts with threading"""
    live_hosts = []
    network = ipaddress.ip_network(target_range, strict=False)
    target_ips = list(network.hosts())
    
    if verbose:
        print(f"{BLUE}└── Scanning {len(target_ips)} IPs with {num_threads} threads...{RESET}")
        if aggressive:
            print(f"{BLUE}└── Aggressive mode enabled{RESET}")
    
    ip_queue = Queue()
    result_queue = Queue()
    
    # Fill the queue with IPs
    for ip in target_ips:
        ip_queue.put(ip)
    
    # Start worker threads
    threads = []
    for _ in range(min(num_threads, len(target_ips))):  # Don't exceed number of IPs
        t = threading.Thread(target=arp_scan_worker, args=(ip_queue, result_queue, interface, fast, aggressive, verbose))
        t.daemon = True  # Threads terminate with main program
        t.start()
        threads.append(t)
    
    # Wait for all IPs to be processed
    ip_queue.join()
    
    # Collect results
    while not result_queue.empty():
        live_hosts.append(result_queue.get())
    
    return live_hosts

def stealth_scan(ip_range, interface=None, dns_server=None, fast=False, aggressive=False, verbose=False, num_threads=10):
    """Stealthy ARP scan for all devices"""
    conf.verb = 0
    
    if not interface:
        interface = get_default_interface()
        if not interface:
            print(f"{BOLD}[!] No interface. Use -i.{RESET}")
            return []
    
    devices = []
    unresolved_ips = [] 
    
    try:
        print(f"{BLUE}└── Performing ARP scan...{RESET}")
        live_hosts = arp_scan_live_hosts(ip_range, interface, fast, aggressive, verbose)
        
        if not live_hosts:
            print(f"{BOLD}[!] No live hosts found{RESET}")
            return []

        print(f"{BLUE}└── Found {len(live_hosts)} live hosts{RESET}")
        
        for host in live_hosts:
            ip_addr = host['ip']
            mac_addr = host['mac']
            try:
                hostname = resolve_hostname(ip_addr, dns_server)
                if verbose:
                    print(f"{BLUE}│   └── Resolved:{RESET} IP {ip_addr} to {hostname}")
                devices.append({
                    'ip': ip_addr,
                    'mac': mac_addr,
                    'hostname': hostname
                })
            except Exception as e:
                if verbose:
                    print(f"{RED}│   └── Failed to resolve hostname for:{RESET} IP {ip_addr} - {str(e)}")
                unresolved_ips.append({
                    'ip': ip_addr,
                    'mac': mac_addr
                })
        
    except PermissionError:
        print(f"{BOLD}[!] Run with admin/root privileges{RESET}")
        return []
    except Exception as e:
        print(f"{BOLD}[!] Scan error:{RESET} {str(e)}")
        return []
    
    return devices, unresolved_ips

def resolve_hostname(ip, dns_server=None):
    """Resolve hostname using sockets"""
    socket.setdefaulttimeout(2)
    if dns_server:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((dns_server, 53))
            return socket.gethostbyaddr(ip)[0]
        finally:
            sock.close()
    else:
        return socket.gethostbyaddr(ip)[0]

def print_results(devices, unresolved_ips):
    """Print scan results with a pretty table and unresolved IPs"""
    # Print resolved devices
    print(f"\n{BOLD}Discovered Devices with Resolved Hostnames:{RESET}")
    print("┌──────────────────┬────────────────────┬──────────────────────────────┐")
    print(f"│ {'IP Address':<16} │ {'MAC Address':<18} │ {'Hostname':<28} │")
    print("├──────────────────┼────────────────────┼──────────────────────────────┤")
    
    for device in devices:
        print(f"│ {device['ip']:<16} │ {device['mac']:<18} │ {device['hostname']:<28} │")
    
    print("└──────────────────┴────────────────────┴──────────────────────────────┘")
    print(f"{BLUE}Total devices with resolved hostnames:{RESET} {len(devices)}\n")
    
    # Print unresolved IPs
    if unresolved_ips:
        print(f"{BOLD}Live IPs Unable to Resolve Hostnames:{RESET}")
        print("┌──────────────────┬────────────────────┐")
        print(f"│ {'IP Address':<16} │ {'MAC Address':<18} │")
        print("├──────────────────┼────────────────────┼")
        
        for device in unresolved_ips:
            print(f"│ {device['ip']:<16} │ {device['mac']:<18} │")
        
        print("└──────────────────┴────────────────────┘")
        print(f"{BLUE}Total unresolved IPs:{RESET} {len(unresolved_ips)}")

def main():
    print_ascii_art() 
    
    args = get_arguments()
    target_range = args.target
    interface = args.interface
    dns_server = args.dns_server
    fast = args.fast
    aggressive = args.aggressive
    verbose = args.verbose
    num_threads = args.threads
    
    print(f"{BOLD}AGONY starting...{RESET}")
    print(f"{BLUE}└── Target:{RESET} {target_range}")
    if verbose:
        print(f"{BLUE}├── Platform:{RESET} {platform.system()} {platform.release()}")
        print(f"{BLUE}├── DNS:{RESET} {dns_server or 'System resolver'}")
        print(f"{BLUE}├── Interface:{RESET} {interface or 'Auto-detected'}")
        print(f"{BLUE}├── Threads:{RESET} {num_threads}")
        if fast:
            print(f"{BLUE}├── Mode:{RESET} Fast")
        if aggressive:
            print(f"{BLUE}├── Mode:{RESET} Aggressive")
    
    start_time = time.time()
    try:
        devices, unresolved_ips = stealth_scan(target_range, interface, dns_server, fast, aggressive, verbose, num_threads)
        if devices or unresolved_ips:
            print_results(devices, unresolved_ips)
        else:
            print(f"{BOLD}[!] No devices found or scan failed{RESET}")
    except KeyboardInterrupt:
        print(f"\n{BOLD}[!] Scan interrupted by user. Exiting...{RESET}")
        sys.exit(0)
    
    duration = time.time() - start_time
    print(f"{BOLD}Scan completed in {duration:.2f} seconds{RESET}")

if __name__ == "__main__":
    try:
        import scapy
        if not hasattr(scapy, '__version__'):
            print(f"{BOLD}[!] Scapy not installed or not detected. Use 'pip install scapy'{RESET}")
            sys.exit(1)
        print(f"{BLUE}[*] Scapy version:{RESET} {scapy.__version__}")
        main()
    except ImportError:
        print(f"{BOLD}[!] Scapy import failed. Install with 'pip install scapy'{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{BOLD}[!] Error:{RESET} {str(e)}")
