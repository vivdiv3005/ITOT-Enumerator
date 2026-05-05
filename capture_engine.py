import os

# Put this at the top of ALL three files, replacing your current DB_FILE line
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "asset_inventory.db")

from scapy.all import sniff, IP, TCP, UDP, ARP, Ether, Raw
from scapy.contrib.modbus import ModbusADURequest  # pip install scapy-contrib
import sqlite3
import json
import time
import threading
from datetime import datetime

DB_FILE = "asset_inventory.db"

# OT protocol port signatures
OT_PORTS = {
    502:   "Modbus TCP",
    20000: "DNP3",
    44818: "EtherNet/IP",
    102:   "Siemens S7 (ISO-TSAP)",
    2222:  "EtherNet/IP UDP",
    4840:  "OPC-UA",
    1962:  "PCWorx (Phoenix Contact)",
    9600:  "OMRON FINS",
    20547: "ProConOS",
    1089:  "FF Annunciation",
}

IT_PORTS = {
    22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
    445: "SMB", 3389: "RDP", 5900: "VNC", 161: "SNMP",
    53: "DNS", 21: "FTP", 25: "SMTP",
}

# Known OT vendor MAC prefixes (OUI)
OT_VENDORS = {
    "00:0e:8c": "Siemens",
    "00:1b:1b": "Schneider Electric",
    "00:00:bc": "Rockwell / Allen-Bradley",
    "00:80:f4": "Moxa",
    "00:0a:e4": "Hirschmann",
    "00:30:48": "Advantech",
    "00:1d:9c": "GE Automation",
    "00:60:35": "Phoenix Contact",
}

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            vendor TEXT,
            first_seen TEXT,
            last_seen TEXT,
            open_ports TEXT,
            ot_protocols TEXT,
            it_protocols TEXT,
            device_type TEXT,
            purdue_zone TEXT,
            risk_level TEXT,
            llm_classification TEXT,
            packet_count INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

def get_vendor_from_mac(mac: str) -> str:
    if not mac:
        return "Unknown"
    prefix = mac[:8].lower()
    return OT_VENDORS.get(prefix, "Unknown Vendor")

def upsert_asset(ip, mac="", port=None, protocol_type="it", protocol_name=""):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    now = datetime.now().isoformat()
    vendor = get_vendor_from_mac(mac)

    existing = c.execute("SELECT * FROM assets WHERE ip=?", (ip,)).fetchone()

    if not existing:
        ot_p = json.dumps([protocol_name]) if protocol_type == "ot" and protocol_name else json.dumps([])
        it_p = json.dumps([protocol_name]) if protocol_type == "it" and protocol_name else json.dumps([])
        ports = json.dumps([port]) if port else json.dumps([])
        c.execute("""
            INSERT INTO assets (ip, mac, vendor, first_seen, last_seen,
            open_ports, ot_protocols, it_protocols, device_type, purdue_zone,
            risk_level, llm_classification, packet_count)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)
        """, (ip, mac, vendor, now, now, ports, ot_p, it_p,
              "Unknown", "Unclassified", "UNKNOWN", "", ))
    else:
        # Update existing asset
        ot_protocols = json.loads(existing[7] or "[]")
        it_protocols = json.loads(existing[8] or "[]")
        open_ports   = json.loads(existing[5] or "[]")

        if protocol_type == "ot" and protocol_name and protocol_name not in ot_protocols:
            ot_protocols.append(protocol_name)
        if protocol_type == "it" and protocol_name and protocol_name not in it_protocols:
            it_protocols.append(protocol_name)
        if port and port not in open_ports:
            open_ports.append(port)

        c.execute("""
            UPDATE assets SET last_seen=?, mac=?, vendor=?,
            open_ports=?, ot_protocols=?, it_protocols=?,
            packet_count=packet_count+1
            WHERE ip=?
        """, (now, mac or existing[1], vendor if vendor != "Unknown Vendor" else existing[2],
              json.dumps(open_ports), json.dumps(ot_protocols),
              json.dumps(it_protocols), ip))

    conn.commit()
    conn.close()

def process_packet(pkt):
    try:
        if IP not in pkt:
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        mac = pkt[Ether].src if Ether in pkt else ""

        # Skip multicast and broadcast
        if src_ip.startswith("224.") or src_ip.endswith(".255"):
            return

        # Check for OT protocols by destination port
        if TCP in pkt:
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport

            if dport in OT_PORTS:
                upsert_asset(src_ip, mac, dport, "ot", OT_PORTS[dport])
                upsert_asset(dst_ip, "", dport, "ot", OT_PORTS[dport])
            elif sport in OT_PORTS:
                upsert_asset(dst_ip, mac, sport, "ot", OT_PORTS[sport])
            elif dport in IT_PORTS:
                upsert_asset(src_ip, mac, dport, "it", IT_PORTS[dport])
            else:
                upsert_asset(src_ip, mac)

        if UDP in pkt:
            dport = pkt[UDP].dport
            if dport in OT_PORTS:
                upsert_asset(src_ip, mac, dport, "ot", OT_PORTS[dport])

        # ARP reveals devices even if they have no open ports
        if ARP in pkt:
            upsert_asset(pkt[ARP].psrc, pkt[ARP].hwsrc)

    except Exception:
        pass  # Never crash on a bad packet

def start_capture(interface="eth0", duration=None):
    print(f"Starting passive capture on {interface}...")
    print("⚠  PASSIVE MODE — no packets sent to network")
    print("-" * 50)
    sniff(iface=interface, prn=process_packet,
          store=False, timeout=duration)

if __name__ == "__main__":
    init_db()
    start_capture(interface="eth0")  # Change to your interface name
