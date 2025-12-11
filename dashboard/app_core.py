# app_core.py
import os
import json
import time
import socket
import queue
import random
import sqlite3
import threading
import traceback
from datetime import datetime
from typing import Dict, Any, List

import pandas as pd
import numpy as np
import pytz

# Optional: elasticsearch
try:
    from elasticsearch import Elasticsearch
    ELASTICSEARCH_AVAILABLE = True
except Exception:
    ELASTICSEARCH_AVAILABLE = False

# SSE queue for API <-> Streamlit
SSE_QUEUE = queue.Queue(maxsize=400)

# Config defaults (override via env)
CSV_PATH = os.getenv("SYS_MON_CSV", "sysmon_users.csv")
DB_PATH = os.getenv("THREAT_DB", "insider_threats.db")
API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", 8001))
ELK_HOST = os.getenv("ELK_HOST", "http://localhost:9200")

# MITRE sample rules
MITRE_RULES = [
    {"id":"T1005","name":"Data from Local System","conditions":{"process_count_gt":50},"score":50},
    {"id":"T1078","name":"Valid Accounts","conditions":{"is_service_account":True,"process_count_gt":20},"score":60},
    {"id":"CUSTOM-1","name":"High Risk Score","conditions":{"risk_score_gt":0.9},"score":80}
]

# ---------------- DB ----------------
def init_db(path=DB_PATH):
    conn = sqlite3.connect(path, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id TEXT PRIMARY KEY, username TEXT, domain TEXT, full_name TEXT,
        department TEXT, role TEXT, risk_level TEXT, risk_score REAL,
        threat_count INTEGER, is_service_account INTEGER, process_count INTEGER,
        last_seen TEXT
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS threats(
        id TEXT PRIMARY KEY, timestamp TEXT, type TEXT, severity TEXT,
        user_id TEXT, department TEXT, description TEXT, status TEXT, risk_score INTEGER
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS mitre_hits(
        id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id TEXT, mitre_id TEXT,
        mitre_name TEXT, score INTEGER, details TEXT
    )""")
    conn.commit()
    return conn

DB = init_db()
DB_LOCK = threading.Lock()

# ---------------- Utilities ----------------
def now_iso():
    return datetime.utcnow().replace(tzinfo=pytz.UTC).isoformat()

def port_in_use(port:int, host:str="127.0.0.1") -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0

# ---------------- SSE ----------------
def push_sse(event_type: str, payload: Dict[str, Any]):
    msg = {"ts": now_iso(), "type": event_type, "payload": payload}
    try:
        SSE_QUEUE.put_nowait(msg)
    except queue.Full:
        try:
            _ = SSE_QUEUE.get_nowait()
            SSE_QUEUE.put_nowait(msg)
        except Exception:
            pass

# ---------------- CRUD helpers ----------------
def upsert_user(u: Dict[str, Any]):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute(
            """
            INSERT INTO users(id,username,domain,full_name,department,role,risk_level,risk_score,threat_count,is_service_account,process_count,last_seen)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                username=excluded.username, domain=excluded.domain, full_name=excluded.full_name,
                department=excluded.department, role=excluded.role, risk_level=excluded.risk_level,
                risk_score=excluded.risk_score, threat_count=excluded.threat_count, is_service_account=excluded.is_service_account,
                process_count=excluded.process_count, last_seen=excluded.last_seen
            """,
            (
                u.get('id'), u.get('username'), u.get('domain'), u.get('full_name'), u.get('department'), u.get('role'),
                u.get('risk_level'), float(u.get('risk_score') or 0.0), int(u.get('threat_count') or 0),
                1 if u.get('is_service_account') else 0, int(u.get('process_count') or 0), u.get('last_seen')
            )
        )
        DB.commit()

def insert_threat(t: Dict[str, Any]):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO threats(id,timestamp,type,severity,user_id,department,description,status,risk_score) VALUES(?,?,?,?,?,?,?,?,?)",
            (t.get('id'), t.get('timestamp'), t.get('type'), t.get('severity'), t.get('user_id'), t.get('department'), t.get('description'), t.get('status'), int(t.get('risk_score') or 0))
        )
        DB.commit()

def insert_mitre_hit(threat_id, mitre_id, mitre_name, score, details):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("INSERT INTO mitre_hits(threat_id,mitre_id,mitre_name,score,details) VALUES(?,?,?,?,?)", (threat_id, mitre_id, mitre_name, score, json.dumps(details)))
        DB.commit()

def list_users() -> List[Dict[str,Any]]:
    with DB_LOCK:
        cur = DB.cursor()
        rows = cur.execute("SELECT id,username,domain,full_name,department,role,risk_level,risk_score,threat_count,is_service_account,process_count,last_seen FROM users").fetchall()
    cols = ['id','username','domain','full_name','department','role','risk_level','risk_score','threat_count','is_service_account','process_count','last_seen']
    out = []
    for r in rows:
        d = dict(zip(cols,r))
        d['is_service_account'] = bool(d['is_service_account'])
        out.append(d)
    return out

def list_threats(limit=200) -> List[Dict[str,Any]]:
    with DB_LOCK:
        cur = DB.cursor()
        rows = cur.execute("SELECT id,timestamp,type,severity,user_id,department,description,status,risk_score FROM threats ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    cols = ['id','timestamp','type','severity','user_id','department','description','status','risk_score']
    return [dict(zip(cols,r)) for r in rows]

# ---------------- CSV ingestion ----------------
def ingest_csv(path=CSV_PATH) -> Dict[str,Any]:
    if not os.path.exists(path):
        return {"error": f"CSV not found: {path}"}
    try:
        df = pd.read_csv(path)
    except Exception as e:
        return {"error": str(e)}
    expected = ["id","username","domain","full_name","department","role","risk_level","risk_score","threat_count","is_service_account","process_count","last_seen"]
    for c in expected:
        if c not in df.columns:
            df[c] = None
    count = 0
    for _, row in df.iterrows():
        u = {k: row.get(k) for k in expected}
        # normalize booleans/numbers
        try:
            u['risk_score'] = float(u.get('risk_score') or 0.0)
        except:
            u['risk_score'] = 0.0
        try:
            u['threat_count'] = int(u.get('threat_count') or 0)
        except:
            u['threat_count'] = 0
        u['is_service_account'] = bool(u.get('is_service_account')) if u.get('is_service_account') not in [None, np.nan] else False
        try:
            u['process_count'] = int(u.get('process_count') or 0)
        except:
            u['process_count'] = 0
        upsert_user(u)
        count += 1
    push_sse('ingest_complete', {'source': path, 'count': count})
    return {'status':'ok','ingested':count}

# ---------------- MITRE engine ----------------
def run_mitre_rules_on_user(user: Dict[str,Any]) -> List[Dict[str,Any]]:
    matches = []
    role = (user.get('role') or '').lower()
    rscore = float(user.get('risk_score') or 0.0)
    pcount = int(user.get('process_count') or 0)
    is_svc = bool(user.get('is_service_account'))
    for rule in MITRE_RULES:
        cond = rule.get('conditions', {})
        hit = True
        details = {}
        if 'process_count_gt' in cond:
            if pcount <= cond['process_count_gt']:
                hit = False
            else:
                details['process_count'] = pcount
        if 'risk_score_gt' in cond:
            if rscore <= cond['risk_score_gt']:
                hit = False
            else:
                details['risk_score'] = rscore
        if 'is_service_account' in cond:
            if cond['is_service_account'] != is_svc:
                hit = False
            else:
                details['is_service_account'] = is_svc
        if 'role_contains' in cond:
            found = any(s in role for s in cond['role_contains'])
            if not found:
                hit = False
            else:
                details['role'] = role
        if hit:
            matches.append({'mitre_id': rule['id'], 'mitre_name': rule['name'], 'score': rule['score'], 'details': details})
    return matches

def analyze_user_and_create_threat(user_id: str) -> Dict[str,Any]:
    users = list_users()
    user = next((u for u in users if u['id'] == user_id), None)
    if not user:
        return {'error':'user not found'}
    matches = run_mitre_rules_on_user(user)
    if not matches:
        return {'status':'no_matches'}
    th = {
        'id': f"TH-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{random.randint(100,999)}",
        'timestamp': now_iso(),
        'type': ','.join(set(m['mitre_name'] for m in matches)),
        'severity': 'Critical' if any(m['score']>=60 for m in matches) else 'High',
        'user_id': user_id,
        'department': user.get('department'),
        'description': 'Automated MITRE hits: ' + ','.join(m['mitre_id'] for m in matches),
        'status': 'Active',
        'risk_score': int(sum(m['score'] for m in matches))
    }
    insert_threat(th)
    for m in matches:
        insert_mitre_hit(th['id'], m['mitre_id'], m['mitre_name'], m['score'], m['details'])
    push_sse('automated_threat', {'threat': th, 'matches': matches})
    return {'threat': th, 'matches': matches}

# ---------------- ELK adapter (optional) ----------------
class ELKAdapter:
    def __init__(self, host=ELK_HOST):
        self.connected = False
        self.es = None
        if ELASTICSEARCH_AVAILABLE:
            try:
                # use request_timeout to avoid deprecation warning
                self.es = Elasticsearch([host], verify_certs=False, request_timeout=10)
                self.connected = self.es.ping()
            except Exception:
                self.connected = False
    def index(self, index_name, doc):
        if not self.connected:
            return False, 'ELK not connected'
        try:
            self.es.index(index=index_name, document=doc)
            return True, 'ok'
        except Exception as e:
            return False, str(e)

ELK = ELKAdapter()

# ---------------- API (fastapi) starter helper ----------------
from fastapi import FastAPI, Body
from fastapi.responses import StreamingResponse, JSONResponse
import uvicorn

api_app = FastAPI(title='insider-core-api')

@api_app.get('/health')
def _health():
    return {'ok':True, 'time': now_iso(), 'elk': ELK.connected}

@api_app.get('/threats')
def _threats(limit:int=200):
    return {'count': limit, 'threats': list_threats(limit)}

@api_app.post('/analyze')
def _analyze(payload: Dict[str,Any] = Body(...)):
    if payload.get('run_ingest'):
        return ingest_csv()
    if payload.get('user_id'):
        return analyze_user_and_create_threat(payload.get('user_id'))
    return JSONResponse({'error':'invalid payload'}, status_code=400)

# SSE generator
def sse_generator():
    yield f"event: heartbeat\ndata: {json.dumps({'ts': now_iso()})}\n\n"
    while True:
        try:
            msg = SSE_QUEUE.get(timeout=12)
            etype = msg.get('type','message')
            payload = msg.get('payload',{})
            payload['ts'] = msg.get('ts')
            yield f"event: {etype}\n" + "data: " + json.dumps(payload) + "\n\n"
        except queue.Empty:
            yield f"event: heartbeat\ndata: {json.dumps({'ts': now_iso()})}\n\n"
        except GeneratorExit:
            break
        except Exception:
            traceback.print_exc()
            break

@api_app.get('/events')
def _events():
    return StreamingResponse(sse_generator(), media_type='text/event-stream')

# Safe starter that avoids port conflict
_api_thread = None
def start_api_once(host='127.0.0.1', port=8001):
    global _api_thread
    if _api_thread and _api_thread.is_alive():
        return
    if port_in_use(port, host):
        print(f"API already running on {host}:{port}")
        return
    def _run():
        uvicorn.run(api_app, host=host, port=port, log_level='info')
    _api_thread = threading.Thread(target=_run, daemon=True)
    _api_thread.start()
    time.sleep(0.4)

# EOF app_core.py
