import os

# Put this at the top of ALL three files, replacing your current DB_FILE line
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "asset_inventory.db")
import streamlit as st
import sqlite3
import pandas as pd
import json
import time

DB_FILE = "asset_inventory.db"

st.set_page_config(page_title="IT/OT Asset Enumerator",
                   page_icon="🗺️", layout="wide")

st.title("🗺️ IT/OT Network Enumerator")
st.caption("Passive asset discovery powered by local Llama on NVIDIA DGX Spark")

RISK_ICON = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","UNKNOWN":"⚪"}
ZONE_ORDER = [
    "Level 0 — Field Devices", "Level 1 — Controllers",
    "Level 2 — Supervisory",   "Level 3 — Operations",
    "Level 3.5 — DMZ",         "Level 4 — Business Network",
    "Unclassified"
]

def load_assets():
    # Create DB and table if they don't exist yet
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
    
    df = pd.read_sql_query(
        "SELECT * FROM assets ORDER BY risk_level DESC", conn
    )
    conn.close()
    return df
df = load_assets()

if df.empty:
    st.info("⏳ Waiting for assets... Make sure capture_engine.py is running.")
    time.sleep(5)
    st.rerun()
  
def parse_json_col(val):
    try:
        v = json.loads(val)
        return ", ".join(v) if v else "—"
    except:
        return val or "—"

placeholder = st.empty()

while True:
    df = load_assets()

    with placeholder.container():
        # Summary metrics
        c1,c2,c3,c4,c5 = st.columns(5)
        c1.metric("Total Assets", len(df))
        c2.metric("🔴 Critical", len(df[df.risk_level=="CRITICAL"]))
        c3.metric("🟠 High Risk", len(df[df.risk_level=="HIGH"]))
        ot = df[df.ot_protocols.apply(lambda x: len(json.loads(x or "[]"))>0)]
        c4.metric("⚙️ OT Devices", len(ot))
        c5.metric("💻 IT Devices", len(df)-len(ot))

        st.divider()
        tab1, tab2, tab3 = st.tabs(["🗂️ Asset Inventory", "🏗️ Purdue Zone View", "🚨 Risk Summary"])

        with tab1:
            display = df.copy()
            display["OT Protocols"] = display["ot_protocols"].apply(parse_json_col)
            display["IT Protocols"] = display["it_protocols"].apply(parse_json_col)
            display["Risk"] = display["risk_level"].apply(lambda r: f"{RISK_ICON.get(r,'')} {r}")
            st.dataframe(
                display[["ip","mac","vendor","device_type","purdue_zone","Risk",
                          "OT Protocols","IT Protocols","packet_count","last_seen"]],
                use_container_width=True, hide_index=True
            )

        with tab2:
            for zone in ZONE_ORDER:
                zone_df = df[df.purdue_zone == zone]
                if len(zone_df) == 0:
                    continue
                st.subheader(f"{zone} — {len(zone_df)} devices")
                for _, row in zone_df.iterrows():
                    risk = row["risk_level"]
                    icon = RISK_ICON.get(risk, "⚪")
                    llm = {}
                    try: llm = json.loads(row["llm_classification"] or "{}")
                    except: pass
                    with st.expander(f"{icon} {row['ip']} — {row['device_type']}"):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown(f"**MAC:** {row['mac'] or '—'}")
                            st.markdown(f"**Vendor:** {row['vendor'] or '—'}")
                            st.markdown(f"**OT Protocols:** {parse_json_col(row['ot_protocols'])}")
                            st.markdown(f"**IT Protocols:** {parse_json_col(row['it_protocols'])}")
                        with col2:
                            reasons = llm.get("risk_reasons", [])
                            actions = llm.get("recommended_actions", [])
                            if reasons:
                                st.markdown("**Risk factors:**")
                                for r in reasons: st.markdown(f"- {r}")
                            if actions:
                                st.markdown("**Recommended actions:**")
                                for a in actions: st.markdown(f"- {a}")

        with tab3:
            critical_df = df[df.risk_level.isin(["CRITICAL","HIGH"])]
            if len(critical_df) == 0:
                st.success("No critical or high risk devices detected.")
            else:
                st.warning(f"{len(critical_df)} devices need immediate attention")
                for _, row in critical_df.iterrows():
                    llm = {}
                    try: llm = json.loads(row["llm_classification"] or "{}")
                    except: pass
                    with st.expander(
                        f"{RISK_ICON.get(row['risk_level'],'')} {row['ip']} — {row['device_type']}"
                    ):
                        st.markdown(f"**Zone:** {row['purdue_zone']}")
                        st.markdown(f"**Reason:** {', '.join(llm.get('risk_reasons', ['N/A']))}")
                        st.markdown(f"**Action:** {', '.join(llm.get('recommended_actions', ['N/A']))}")

    time.sleep(10)
    st.rerun()
