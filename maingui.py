import socket
import sys
from concurrent.futures import ThreadPoolExecutor

import psutil
from PyQt6.QtCore import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QColor, QIcon, QPalette
from PyQt6.QtWidgets import QApplication, QPushButton, QTextEdit, QVBoxLayout, QWidget
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
                    cidr = sum(bin(int(x)).count("1") for x in addr.netmask.split("."))
                    subnets.append(f"{network_address}/{cidr}")
    return subnets


def scan_subnet(target_ip):
    """
    Führt einen ARP-Scan in einem bestimmten Subnetz durch.

    Args:
        target_ip (str): Ziel-IP-Adresse oder Subnetz im CIDR-Format.

    Returns:
        list: Liste von gefundenen Clients als Dictionary mit IP, MAC-Adresse und Gerätename.
    """
    # ARP-Anfrage vorbereiten
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # ARP-Anfrage senden
    result = srp(packet, timeout=3, verbose=0)[0]
    return [
        {
            "ip": received.psrc,
            "mac": received.hwsrc,
            "name": socket.gethostbyaddr(received.psrc)[0],
        }
        for sent, received in result
    ]


def apply_github_theme(q_app):
    with open("assets/github.qss", "r") as f:
        q_app.setStyleSheet(f.read())


class NetworkScannerThread(QThread):
    update_text_signal = pyqtSignal(str)

    def run(self):
        local_subnets = get_local_subnets()
        self.update_text_signal.emit(f"Local Subnets Identified: {local_subnets}")
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(self.scan_and_print, local_subnets)

    def scan_and_print(self, subnet):
        clients = scan_subnet(subnet)
        self.update_text_signal.emit("IP" + " " * 24 + "MAC" + " " * 23 + "Hostname")
        for client in clients:
            self.update_text_signal.emit(
                f"{client['ip']:<17}{client['mac']:<20}{client['name']}"
            )


class NetworkScannerApp(QWidget):
    update_text_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Scanner")

        # GUI Layout
        self.layout = QVBoxLayout()

        self.textbox = QTextEdit()
        self.textbox.setReadOnly(True)
        self.layout.addWidget(self.textbox)

        self.scan_button = QPushButton("Scan Network")
        self.layout.addWidget(self.scan_button)

        self.setLayout(self.layout)

        self.scan_button.setStyleSheet("background-color: #5865F2; color: white;")
        self.textbox.setStyleSheet("background-color: #0D1117; color: #C9D1D9;")

        # Signal-Slot Verbindung
        self.scan_button.clicked.connect(self.perform_scan)
        self.update_text_signal.connect(self.update_textbox)

    @pyqtSlot(str)
    def update_textbox(self, text):
        self.textbox.append(text)

    def perform_scan(self):
        self.thread = NetworkScannerThread()
        self.thread.update_text_signal.connect(self.update_text_signal)
        self.thread.start()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    apply_github_theme(app)  # Stil anwenden

    # Set Windows title bar style to dark
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(13, 17, 23))
    palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
    app.setPalette(palette)

    window = NetworkScannerApp()
    window.resize(400, 300)
    # set icon logo.png
    window.setWindowIcon(QIcon("assets/logo.png"))
    # Disable window resizing
    window.setFixedSize(window.size())
    window.show()
    sys.exit(app.exec())
