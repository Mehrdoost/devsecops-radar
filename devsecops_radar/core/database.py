import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any

DB_PATH = "scan_history.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            findings_json TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def save_scan(findings: List[Dict[str, Any]]):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO scans (timestamp, findings_json) VALUES (?, ?)',
              (datetime.utcnow().isoformat(), json.dumps(findings)))
    conn.commit()
    conn.close()

def get_all_scans() -> List[Dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT id, timestamp, findings_json FROM scans ORDER BY timestamp ASC')
    rows = c.fetchall()
    scans = []
    for row in rows:
        findings = json.loads(row['findings_json'])
        criticals = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        highs = sum(1 for f in findings if f.get('severity') == 'HIGH')
        mediums = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
        lows = sum(1 for f in findings if f.get('severity') == 'LOW')
        scans.append({
            'id': row['id'],
            'timestamp': row['timestamp'],
            'total': len(findings),
            'critical': criticals,
            'high': highs,
            'medium': mediums,
            'low': lows
        })
    conn.close()
    return scans