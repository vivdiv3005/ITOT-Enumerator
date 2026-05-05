import sqlite3
import json
from datetime import datetime, timedelta
import random
import os

DB_FILE = "/home/claude/asset_inventory.db"

# --- Realistic IT/OT asset definitions ---
ASSETS = [

    # ── Level 0 — Field Devices ──────────────────────────────────────────
    {
        "ip": "10.0.0.11", "mac": "00:0e:8c:11:22:01", "vendor": "Siemens",
        "device_type": "Siemens S7-300 PLC",
        "purdue_zone": "Level 0 — Field Devices",
        "ot_protocols": ["Modbus TCP", "Siemens S7 (ISO-TSAP)"],
        "it_protocols": [],
        "open_ports": [102, 502],
        "risk_level": "HIGH",
        "risk_reasons": [
            "PLC directly reachable from Level 2 without firewall",
            "S7 protocol has no authentication by default"
        ],
        "recommended_actions": [
            "Segment PLC behind industrial firewall",
            "Enable S7 communication whitelisting"
        ],
        "packet_count": 4821,
        "days_ago_first": 14
    },
    {
        "ip": "10.0.0.12", "mac": "00:0e:8c:11:22:02", "vendor": "Siemens",
        "device_type": "Siemens S7-400 PLC",
        "purdue_zone": "Level 0 — Field Devices",
        "ot_protocols": ["Siemens S7 (ISO-TSAP)"],
        "it_protocols": [],
        "open_ports": [102],
        "risk_level": "MEDIUM",
        "risk_reasons": ["No recent firmware update observed"],
        "recommended_actions": ["Verify firmware version", "Check patch status with vendor"],
        "packet_count": 2103,
        "days_ago_first": 20
    },
    {
        "ip": "10.0.0.13", "mac": "00:00:bc:aa:bb:01", "vendor": "Rockwell / Allen-Bradley",
        "device_type": "Allen-Bradley ControlLogix PLC",
        "purdue_zone": "Level 0 — Field Devices",
        "ot_protocols": ["EtherNet/IP"],
        "it_protocols": [],
        "open_ports": [44818],
        "risk_level": "MEDIUM",
        "risk_reasons": ["EtherNet/IP has no built-in encryption"],
        "recommended_actions": ["Monitor EtherNet/IP traffic for anomalous write commands"],
        "packet_count": 3670,
        "days_ago_first": 18
    },
    {
        "ip": "10.0.0.14", "mac": "00:60:35:cc:dd:01", "vendor": "Phoenix Contact",
        "device_type": "Phoenix Contact I/O Module (RTU)",
        "purdue_zone": "Level 0 — Field Devices",
        "ot_protocols": ["Modbus TCP"],
        "it_protocols": [],
        "open_ports": [502],
        "risk_level": "LOW",
        "risk_reasons": [],
        "recommended_actions": ["Routine — maintain passive monitoring"],
        "packet_count": 980,
        "days_ago_first": 30
    },
    {
        "ip": "10.0.0.15", "mac": "00:30:48:ee:ff:01", "vendor": "Advantech",
        "device_type": "Advantech ADAM-6150 Remote I/O",
        "purdue_zone": "Level 0 — Field Devices",
        "ot_protocols": ["Modbus TCP"],
        "it_protocols": ["HTTP"],
        "open_ports": [502, 80],
        "risk_level": "CRITICAL",
        "risk_reasons": [
            "Field device with HTTP web interface exposed",
            "Default credentials likely (Advantech ADAM factory default)",
            "HTTP not HTTPS — credentials transmitted in cleartext"
        ],
        "recommended_actions": [
            "Immediately disable HTTP interface or restrict to management VLAN",
            "Change default credentials",
            "Block port 80 at upstream switch ACL"
        ],
        "packet_count": 412,
        "days_ago_first": 3
    },

    # ── Level 1 — Controllers ────────────────────────────────────────────
    {
        "ip": "10.0.1.10", "mac": "00:1b:1b:aa:01:01", "vendor": "Schneider Electric",
        "device_type": "Schneider Modicon M340 DCS Controller",
        "purdue_zone": "Level 1 — Controllers",
        "ot_protocols": ["Modbus TCP", "DNP3"],
        "it_protocols": [],
        "open_ports": [502, 20000],
        "risk_level": "MEDIUM",
        "risk_reasons": ["DNP3 has no authentication enabled (SAv5 not configured)"],
        "recommended_actions": ["Enable DNP3 Secure Authentication v5", "Restrict DNP3 to known master IPs"],
        "packet_count": 7241,
        "days_ago_first": 25
    },
    {
        "ip": "10.0.1.11", "mac": "00:1d:9c:bb:02:01", "vendor": "GE Automation",
        "device_type": "GE Mark VIe Turbine Controller",
        "purdue_zone": "Level 1 — Controllers",
        "ot_protocols": ["DNP3", "OPC-UA"],
        "it_protocols": [],
        "open_ports": [20000, 4840],
        "risk_level": "LOW",
        "risk_reasons": [],
        "recommended_actions": ["OPC-UA security mode — verify certificates are in use"],
        "packet_count": 5890,
        "days_ago_first": 40
    },
    {
        "ip": "10.0.1.12", "mac": "00:1b:1b:aa:01:02", "vendor": "Schneider Electric",
        "device_type": "Schneider Electric Safety Controller (SIS)",
        "purdue_zone": "Level 1 — Controllers",
        "ot_protocols": ["Modbus TCP"],
        "it_protocols": [],
        "open_ports": [502],
        "risk_level": "HIGH",
        "risk_reasons": [
            "Safety Instrumented System (SIS) on same VLAN as basic process control",
            "SIS should be fully isolated per IEC 61511"
        ],
        "recommended_actions": [
            "Physically separate SIS network from BPCS",
            "Implement data diode for one-way monitoring only"
        ],
        "packet_count": 1203,
        "days_ago_first": 10
    },

    # ── Level 2 — Supervisory ────────────────────────────────────────────
    {
        "ip": "10.0.2.10", "mac": "00:0a:e4:cc:01:01", "vendor": "Hirschmann",
        "device_type": "SCADA Server (Wonderware InTouch)",
        "purdue_zone": "Level 2 — Supervisory",
        "ot_protocols": ["Modbus TCP", "OPC-UA"],
        "it_protocols": ["SMB", "RDP"],
        "open_ports": [502, 4840, 445, 3389],
        "risk_level": "CRITICAL",
        "risk_reasons": [
            "RDP (3389) open on SCADA server — remote attack surface",
            "SMB (445) open — vulnerable to lateral movement",
            "SCADA server bridging OT and IT protocols simultaneously"
        ],
        "recommended_actions": [
            "Disable RDP — use jump server with MFA instead",
            "Block SMB at OT zone firewall",
            "Restrict OPC-UA to known historian IP only"
        ],
        "packet_count": 18942,
        "days_ago_first": 60
    },
    {
        "ip": "10.0.2.11", "mac": "00:0a:e4:cc:01:02", "vendor": "Hirschmann",
        "device_type": "HMI Workstation (GE iFIX)",
        "purdue_zone": "Level 2 — Supervisory",
        "ot_protocols": ["EtherNet/IP", "OPC-UA"],
        "it_protocols": ["VNC"],
        "open_ports": [44818, 4840, 5900],
        "risk_level": "CRITICAL",
        "risk_reasons": [
            "VNC (5900) open with no password observed in traffic",
            "HMI directly accessible remotely via VNC"
        ],
        "recommended_actions": [
            "Immediately disable VNC or require VNC authentication",
            "Restrict HMI access to local console only",
            "Alert ICSBit Labs client — potential active exposure"
        ],
        "packet_count": 9320,
        "days_ago_first": 7
    },
    {
        "ip": "10.0.2.12", "mac": "00:80:f4:dd:01:01", "vendor": "Moxa",
        "device_type": "Historian Server (OSIsoft PI)",
        "purdue_zone": "Level 2 — Supervisory",
        "ot_protocols": ["OPC-UA"],
        "it_protocols": ["HTTPS"],
        "open_ports": [4840, 443],
        "risk_level": "LOW",
        "risk_reasons": [],
        "recommended_actions": ["Routine — verify PI Server patch level quarterly"],
        "packet_count": 6741,
        "days_ago_first": 45
    },

    # ── Level 3.5 — DMZ ──────────────────────────────────────────────────
    {
        "ip": "10.0.3.1", "mac": "00:80:f4:dd:02:01", "vendor": "Moxa",
        "device_type": "Industrial Firewall (Moxa EDR-810)",
        "purdue_zone": "Level 3.5 — DMZ",
        "ot_protocols": [],
        "it_protocols": ["HTTPS", "SSH"],
        "open_ports": [443, 22],
        "risk_level": "LOW",
        "risk_reasons": [],
        "recommended_actions": ["Verify firewall ruleset — ensure OT-to-IT traffic is restricted"],
        "packet_count": 52300,
        "days_ago_first": 60
    },
    {
        "ip": "10.0.3.2", "mac": "00:80:f4:dd:02:02", "vendor": "Moxa",
        "device_type": "Jump Server / Bastion Host",
        "purdue_zone": "Level 3.5 — DMZ",
        "ot_protocols": [],
        "it_protocols": ["SSH", "RDP"],
        "open_ports": [22, 3389],
        "risk_level": "MEDIUM",
        "risk_reasons": ["RDP on jump server — should be SSH only for OT access"],
        "recommended_actions": ["Disable RDP on jump server", "Enforce MFA on SSH sessions"],
        "packet_count": 3102,
        "days_ago_first": 30
    },

    # ── Level 4 — Business / IT Network ─────────────────────────────────
    {
        "ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01", "vendor": "Unknown Vendor",
        "device_type": "Engineering Workstation (Windows 10)",
        "purdue_zone": "Level 4 — Business Network",
        "ot_protocols": [],
        "it_protocols": ["SMB", "RDP", "HTTP", "HTTPS"],
        "open_ports": [445, 3389, 80, 443],
        "risk_level": "MEDIUM",
        "risk_reasons": ["Engineering workstation with both OT tool access and internet connectivity"],
        "recommended_actions": ["Ensure workstation has EDR agent", "Restrict direct OT zone access from this host"],
        "packet_count": 22410,
        "days_ago_first": 60
    },
    {
        "ip": "192.168.1.11", "mac": "aa:bb:cc:dd:ee:02", "vendor": "Unknown Vendor",
        "device_type": "Corporate Laptop (Windows 11)",
        "purdue_zone": "Level 4 — Business Network",
        "ot_protocols": [],
        "it_protocols": ["HTTPS", "DNS", "SMTP"],
        "open_ports": [443, 53, 25],
        "risk_level": "LOW",
        "risk_reasons": [],
        "recommended_actions": ["Standard IT asset — maintain EDR and patch cycle"],
        "packet_count": 8901,
        "days_ago_first": 45
    },
    {
        "ip": "192.168.1.99", "mac": "de:ad:be:ef:00:01", "vendor": "Unknown Vendor",
        "device_type": "Unidentified Device — Rogue?",
        "purdue_zone": "Level 4 — Business Network",
        "ot_protocols": ["Modbus TCP"],
        "it_protocols": ["HTTP"],
        "open_ports": [502, 80],
        "risk_level": "CRITICAL",
        "risk_reasons": [
            "Unknown MAC vendor — device not in asset register",
            "Modbus TCP traffic from IT network segment — unexpected",
            "Could indicate attacker pivot from IT to OT network"
        ],
        "recommended_actions": [
            "IMMEDIATELY isolate this IP at switch port level",
            "Capture full packet trace for forensic analysis",
            "Escalate to ICSBit Labs incident response team"
        ],
        "packet_count": 143,
        "days_ago_first": 1
    },
]

def generate_timestamps(days_ago_first):
    first = datetime.now() - timedelta(days=days_ago_first)
    last  = datetime.now() - timedelta(minutes=random.randint(1, 120))
    return first.isoformat(), last.isoformat()

def populate_db():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            ip TEXT PRIMARY KEY,
            mac TEXT, vendor TEXT,
            first_seen TEXT, last_seen TEXT,
            open_ports TEXT, ot_protocols TEXT, it_protocols TEXT,
            device_type TEXT, purdue_zone TEXT,
            risk_level TEXT, llm_classification TEXT,
            packet_count INTEGER DEFAULT 0
        )
    """)

    for a in ASSETS:
        first_seen, last_seen = generate_timestamps(a["days_ago_first"])
        llm = json.dumps({
            "device_type":          a["device_type"],
            "purdue_zone":          a["purdue_zone"],
            "risk_level":           a["risk_level"],
            "risk_reasons":         a["risk_reasons"],
            "recommended_actions":  a["recommended_actions"],
            "confidence":           "HIGH"
        })
        c.execute("""
            INSERT INTO assets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            a["ip"], a["mac"], a["vendor"],
            first_seen, last_seen,
            json.dumps(a["open_ports"]),
            json.dumps(a["ot_protocols"]),
            json.dumps(a["it_protocols"]),
            a["device_type"], a["purdue_zone"],
            a["risk_level"], llm,
            a["packet_count"]
        ))

    conn.commit()
    conn.close()
    print(f"✅ Populated {len(ASSETS)} assets into {DB_FILE}")
    print("\nBreakdown:")
    from collections import Counter
    zones = Counter(a["purdue_zone"] for a in ASSETS)
    risks = Counter(a["risk_level"] for a in ASSETS)
    for z,n in sorted(zones.items()): print(f"  {z}: {n} devices")
    print()
    for r,n in risks.most_common():   print(f"  {r}: {n} devices")

if __name__ == "__main__":
    populate_db()
