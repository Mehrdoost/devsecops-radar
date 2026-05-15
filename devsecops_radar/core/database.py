import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

DB_PATH = os.environ.get("PIPELINE_DB_PATH", "scan_history.db")

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
    c.execute('CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)')
    conn.commit()
    conn.close()

def save_scan(findings: List[Dict[str, Any]]):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        'INSERT INTO scans (timestamp, findings_json) VALUES (?, ?)',
        (datetime.now(timezone.utc).isoformat(), json.dumps(findings))
    )
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
        scans.append({
            'id': row['id'],
            'timestamp': row['timestamp'],
            'total': len(findings),
            'critical': sum(1 for f in findings if f.get('severity') == 'CRITICAL'),
            'high': sum(1 for f in findings if f.get('severity') == 'HIGH'),
            'medium': sum(1 for f in findings if f.get('severity') == 'MEDIUM'),
            'low': sum(1 for f in findings if f.get('severity') == 'LOW'),
        })
    conn.close()
    return scans

def get_findings_by_severity(severity: str, limit: int = 100) -> List[Dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT findings_json FROM scans ORDER BY timestamp DESC LIMIT ?', (limit * 2,))
    rows = c.fetchall()
    results = []
    for row in rows:
        findings = json.loads(row['findings_json'])
        for f in findings:
            if f.get('severity') == severity.upper():
                results.append(f)
                if len(results) >= limit:
                    break
        if len(results) >= limit:
            break
    conn.close()
    return results

def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT id, timestamp, findings_json FROM scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    if row is None:
        return None
    findings = json.loads(row['findings_json'])
    return {
        'id': row['id'],
        'timestamp': row['timestamp'],
        'findings': findings,
        'total': len(findings),
        'critical': sum(1 for f in findings if f.get('severity') == 'CRITICAL'),
        'high': sum(1 for f in findings if f.get('severity') == 'HIGH'),
        'medium': sum(1 for f in findings if f.get('severity') == 'MEDIUM'),
        'low': sum(1 for f in findings if f.get('severity') == 'LOW'),
    }

def compare_scans(scan_id_1: int, scan_id_2: int) -> Dict[str, Any]:
    scan1 = get_scan_by_id(scan_id_1)
    scan2 = get_scan_by_id(scan_id_2)
    if not scan1 or not scan2:
        return {"error": "One or both scans not found"}

    ids1 = {f.get('id') for f in scan1['findings']}
    ids2 = {f.get('id') for f in scan2['findings']}

    added = [f for f in scan2['findings'] if f.get('id') not in ids1]
    removed = [f for f in scan1['findings'] if f.get('id') not in ids2]

    return {
        'scan1': {'id': scan1['id'], 'timestamp': scan1['timestamp'], 'total': scan1['total']},
        'scan2': {'id': scan2['id'], 'timestamp': scan2['timestamp'], 'total': scan2['total']},
        'added': len(added),
        'removed': len(removed),
        'unchanged': len(scan1['findings']) - len(removed),
        'added_findings': added,
        'removed_findings': removed,
    }