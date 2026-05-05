import sqlite3
import json
import requests
from datetime import datetime

DB_FILE = "asset_inventory.db"
OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "llama3.1:70b"

# Purdue Model zone definitions
PURDUE_ZONES = {
    "Level 0 — Field Devices":    "PLCs, RTUs, sensors, actuators, field instruments",
    "Level 1 — Controllers":      "DCS, PLC control systems, safety systems (SIS)",
    "Level 2 — Supervisory":      "SCADA servers, HMI workstations, historian servers",
    "Level 3 — Operations":       "MES, batch management, OT DMZ systems",
    "Level 3.5 — DMZ":            "Firewalls, jump servers, data diodes between IT and OT",
    "Level 4 — Business Network": "ERP, corporate IT, engineering workstations",
}

SYSTEM_PROMPT = """You are an expert OT/ICS network security analyst specializing in 
asset identification and Purdue Model network segmentation.

Given information about a network device (IP, MAC, vendor, observed protocols and ports),
classify it and respond ONLY with valid JSON — no other text:

{
  "device_type": "specific device type (e.g. Siemens S7-300 PLC, Modbus RTU Gateway, Engineering Workstation, Historian Server, HMI, DCS Controller, IP Camera, Network Switch, Unknown IT Device)",
  "purdue_zone": "Level 0 — Field Devices | Level 1 — Controllers | Level 2 — Supervisory | Level 3 — Operations | Level 3.5 — DMZ | Level 4 — Business Network",
  "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
  "risk_reasons": ["list of specific risk factors observed"],
  "recommended_actions": ["list of security recommendations"],
  "confidence": "HIGH | MEDIUM | LOW"
}

Risk assessment guidelines:
- CRITICAL: OT device with IT-facing ports (Telnet, RDP, VNC) or unknown device in OT zone
- HIGH: OT device using insecure protocols, or device in wrong Purdue zone
- MEDIUM: IT device with unusual ports, or OT device with limited visibility
- LOW: Well-known IT device with standard ports in correct zone"""

def classify_asset(asset: dict) -> dict:
    prompt = f"""Classify this network device:

IP Address: {asset['ip']}
MAC Address: {asset['mac']}
Vendor (from MAC OUI): {asset['vendor']}
OT Protocols observed: {asset['ot_protocols']}
IT Protocols observed: {asset['it_protocols']}
Open Ports: {asset['open_ports']}
First seen: {asset['first_seen']}
Packet count: {asset['packet_count']}"""

    try:
        response = requests.post(OLLAMA_URL, json={
            "model": MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "stream": False,
            "options": {"temperature": 0.1}
        }, timeout=90)

        content = response.json()["message"]["content"].strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]

        return json.loads(content)

    except Exception as e:
        return {
            "device_type": "Classification failed",
            "purdue_zone": "Unclassified",
            "risk_level": "UNKNOWN",
            "risk_reasons": [str(e)],
            "recommended_actions": [],
            "confidence": "LOW"
        }

def classify_all_unclassified():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Only classify assets not yet classified or seen recently
    assets = c.execute("""
        SELECT ip, mac, vendor, open_ports, ot_protocols,
               it_protocols, first_seen, packet_count
        FROM assets
        WHERE llm_classification = '' OR device_type = 'Unknown'
    """).fetchall()
    conn.close()

    print(f"Classifying {len(assets)} assets with Llama 70B on DGX Spark...")

    for row in assets:
        asset = {
            "ip": row[0], "mac": row[1], "vendor": row[2],
            "open_ports": row[3], "ot_protocols": row[4],
            "it_protocols": row[5], "first_seen": row[6],
            "packet_count": row[7]
        }

        print(f"  Classifying {asset['ip']}...")
        result = classify_asset(asset)

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("""
            UPDATE assets SET
                device_type=?, purdue_zone=?,
                risk_level=?, llm_classification=?
            WHERE ip=?
        """, (
            result.get("device_type", "Unknown"),
            result.get("purdue_zone", "Unclassified"),
            result.get("risk_level", "UNKNOWN"),
            json.dumps(result),
            asset["ip"]
        ))
        conn.commit()
        conn.close()
        print(f"  → {result.get('device_type')} | {result.get('purdue_zone')} | {result.get('risk_level')}")

if __name__ == "__main__":
    classify_all_unclassified()
