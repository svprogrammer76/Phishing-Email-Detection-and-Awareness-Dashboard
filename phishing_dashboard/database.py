"""Small local SQLite store for user-submitted analysis metadata and results."""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "data" / "history.sqlite3"

def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection

def init_db():
    with _connect() as db:
        db.execute("CREATE TABLE IF NOT EXISTS analyses (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, sender TEXT, subject TEXT, risk_score INTEGER NOT NULL, classification TEXT NOT NULL, findings TEXT NOT NULL)")

def save_analysis(sender, subject, result):
    with _connect() as db:
        db.execute("INSERT INTO analyses(sender,subject,risk_score,classification,findings) VALUES(?,?,?,?,?)", (sender[:320], subject[:998], result["risk_score"], result["classification"], json.dumps(result["findings"])))

def list_analyses(limit=500):
    with _connect() as db:
        return [dict(row) for row in db.execute("SELECT id, created_at, sender, subject, risk_score, classification FROM analyses ORDER BY id DESC LIMIT ?", (limit,))]
