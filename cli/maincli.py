import socket
from concurrent.futures import ThreadPoolExecutor

import psutil
from scapy.all import ARP, Ether, srp


def get_local_subnets():
    """
    Ermittelt alle lokalen Subnetze des Hosts.

    Returns:
        list: Liste der Subnetze im CIDR-Format (z.B. ['192.168.1.0/24'])
    """
    subnets = []
    # Durch alle Netzwerk-Interfaces iterieren
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            # Nur IPv4-Adressen betrachten
            if addr.family == socket.AF_INET:
                ip = addr.address
                # APIPA und Loopback-Adressen ausschließen
                if not ip.startswith("169.254.") and not ip.startswith("127."):
                    # Netzwerkadresse berechnen
                    ip_parts = map(int, ip.split("."))
                    mask_parts = map(int, addr.netmask.split("."))
                    network_address = ".".join(
                        str(ip & mask) for ip, mask in zip(ip_parts, mask_parts)
                    )
                    # CIDR-Wert berechnen
                    cidr = sum(
                        [bin(int(x)).count("1") for x in addr.netmask.split(".")]
                    )
                    subnets.append(f"{network_address}/{cidr}")
    return subnets


def scan_subnet(target_ip):
    """
    Führt einen ARP-Scan in einem bestimmten Subnetz durch.

    Args:
        target_ip (str): Ziel-IP-Adresse oder Subnetz im CIDR-Format.

    Returns:
        list: Liste von gefundenen Clients als Dictionary mit IP und MAC-Adresse.
    """
    # ARP-Anfrage vorbereiten
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # ARP-Anfrage senden
    result = srp(packet, timeout=10, verbose=0)[0]
    clients = []

    # Antwortpakete verarbeiten
    for sent, received in result:
        clients.append({"ip": received.psrc, "mac": received.hwsrc})

    return clients


def scan_and_print(subnet):
    """
    Führt einen ARP-Scan in einem bestimmten Subnetz durch und gibt die Ergebnisse aus.

    Args:
        subnet (str): Das zu scannende Subnetz im CIDR-Format.
    """
    print(f"Scanning {subnet}...")
    print("IP                 MAC\n" + "-" * 40)
    clients = scan_subnet(subnet)
    for client in clients:
        print("{:16}   {}".format(client["ip"], client["mac"]))
    print("-" * 40)


if __name__ == "__main__":
    # Lokale Subnetze identifizieren
    local_subnets = get_local_subnets()
    print(f"Local Subnets Identified: {local_subnets}")

    # Subnetze parallel scannen
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(scan_and_print, local_subnets)
