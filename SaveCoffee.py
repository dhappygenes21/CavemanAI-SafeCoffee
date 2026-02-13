import sys
import threading
import time
import os
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QTextEdit, QPushButton
from PySide6.QtCore import Qt, Signal, QObject
from scapy.all import (sniff, ARP, conf, getmacbyip, Dot11Deauth, IP, 
                       ICMP, sr1, get_if_list, RadioTap, Dot11, sendp)

# --- BRANDING: CAVEMAN AI ---
CAVEMAN_STYLE = """
QMainWindow { background-color: #121826; }
QLabel#Status { font-size: 26px; font-weight: bold; padding: 15px; border-radius: 10px; }
QLabel { color: #E0E0E0; font-family: 'Segoe UI'; }
QTextEdit { 
    background-color: #0D1117; color: #008080; 
    border: 1px solid #8A2BE2; border-radius: 8px; 
    font-family: 'Consolas', monospace; font-size: 11px;
}
QPushButton#PanicBtn {
    background-color: #8A2BE2; color: white; border-radius: 8px;
    padding: 15px; font-weight: bold; font-size: 14px;
}
QPushButton#PanicBtn:hover { background-color: #7022B8; border: 1px solid #008080; }
"""

class SecuritySignals(QObject):
    log = Signal(str)
    alert = Signal(str)
    heartbeat = Signal(bool)
    punish = Signal(str) # Pass the offender MAC to the UI/Defense method

class DeepShieldEngine(threading.Thread):
    def __init__(self, signals):
        super().__init__()
        self.signals = signals
        self.daemon = True
        self.interface = self.detect_interface()
        self.gw_ip = None
        self.gw_mac = None
        self.refresh_gateway()

    def refresh_gateway(self):
        try:
            self.gw_ip = conf.route.route("0.0.0.0")[2]
            self.gw_mac = getmacbyip(self.gw_ip)
        except:
            pass

    def detect_interface(self):
        ifaces = get_if_list()
        for i in ifaces:
            if any(x in i.lower() for x in ["wlan1", "mon", "usb", "mango"]):
                return i
        return conf.iface 

    def run(self):
        self.signals.log.emit(f"🚀 Adapter: {self.interface}")
        if self.gw_mac:
            self.signals.log.emit(f"🛡️ Shield Locked: {self.gw_ip} [{self.gw_mac}]")
        else:
            self.signals.log.emit("⚠️ Warning: Gateway not found. Using passive detection.")
        
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        sniff(iface=self.interface, prn=self.process_packet, store=0)

    def heartbeat_loop(self):
        while True:
            if self.gw_ip and self.gw_mac:
                pkt = IP(dst=self.gw_ip)/ICMP()
                resp = sr1(pkt, timeout=1, verbose=0)
                if resp and resp.src != self.gw_mac:
                    self.signals.alert.emit(f"⚠️ HEARTBEAT FAIL: Gateway spoofed by {resp.src}")
                    self.signals.punish.emit(resp.src)
                else:
                    self.signals.heartbeat.emit(True)
            time.sleep(30)

    def process_packet(self, pkt):
        # ARP Spoof Detection
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            if self.gw_ip and pkt[ARP].psrc == self.gw_ip and pkt[ARP].hwsrc != self.gw_mac:
                offender = pkt[ARP].hwsrc
                self.signals.alert.emit(f"🚨 MITM ALERT: {offender} is mimicking the router!")
                self.signals.punish.emit(offender)
        
        # De-auth Detection
        if pkt.haslayer(Dot11Deauth):
            self.signals.alert.emit("💥 ATTACK: De-auth frames detected. Clearing the air.")

class SafeCoffee(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SafeCoffee V2 | CavemanAI Defender")
        self.resize(500, 700)
        self.setStyleSheet(CAVEMAN_STYLE)
        
        layout = QVBoxLayout()
        self.status = QLabel("PERIMETER SECURE")
        self.status.setObjectName("Status")
        self.status.setAlignment(Qt.AlignCenter)
        self.status.setStyleSheet("color: #008080; background-color: #1B2436;")
        
        self.feed = QTextEdit()
        self.feed.setReadOnly(True)

        self.panic_btn = QPushButton("TERMINAL PANIC (KILL NET)")
        self.panic_btn.setObjectName("PanicBtn")
        self.panic_btn.clicked.connect(self.kill_network)
        
        layout.addWidget(self.status)
        layout.addWidget(QLabel("Live Security Feed:"))
        layout.addWidget(self.feed)
        layout.addWidget(self.panic_btn)
        
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Signals
        self.signals = SecuritySignals()
        self.signals.log.connect(lambda m: self.feed.append(f"<font color='#008080'>[*] {m}</font>"))
        self.signals.alert.connect(self.trigger_alert)
        self.signals.heartbeat.connect(lambda: self.feed.append("<font color='#8A2BE2'>[♡] Heartbeat: Router Verified.</font>"))
        self.signals.punish.connect(self.punish_offender)
        
        self.engine = DeepShieldEngine(self.signals)
        self.engine.start()

    def trigger_alert(self, msg):
        self.status.setText("⚠️ BREACH DETECTED")
        self.status.setStyleSheet("color: #FFFFFF; background-color: #800000;")
        self.feed.append(f"<font color='#FF4500'><b>[!!!] {msg}</b></font>")

    def kill_network(self):
        iface = self.engine.interface
        os.system(f"sudo ip link set {iface} down")
        self.status.setText("OFFLINE / AIR-GAPPED")
        self.status.setStyleSheet("color: #FFFFFF; background-color: #8A2BE2;")
        self.feed.append("<font color='white'><b>[X] Interface dropped. Shield deactivated.</b></font>")

    def punish_offender(self, target_mac):
        """ Retaliatory de-auth pulse """
        iface = self.engine.interface
        gateway_mac = self.engine.gw_mac
        if not gateway_mac: return

        # Packet: Tell Attacker to disconnect from Router
        pkt = RadioTap()/Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)/Dot11Deauth(reason=7)
        
        self.feed.append(f"<font color='#8A2BE2'>[!] Counter-Pulse sent to {target_mac}...</font>")
        try:
            sendp(pkt, iface=iface, count=32, inter=0.1, verbose=0)
        except Exception as e:
            self.feed.append(f"<font color='red'>[!] Punishment failed: {e}</font>")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SafeCoffee()
    window.show()
    sys.exit(app.exec())
