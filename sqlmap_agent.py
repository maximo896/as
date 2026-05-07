from flask import Flask, request, jsonify
import requests, os, json, threading, time, secrets, random, argparse

parser = argparse.ArgumentParser()
parser.add_argument('--sqlmapapi-port', type=int, default=None)
parser.add_argument('--flask-port', type=int, default=5000)
parser.add_argument('--api-token', default=None)
parser.add_argument('--max-concurrent', type=int, default=10)
args, _ = parser.parse_known_args()

app = Flask(__name__)

SQLMAPAPI_PORT = args.sqlmapapi_port or int(os.getenv("SQLMAPAPI_PORT", "30000"))
SQLMAPAPI_HOST = os.getenv("SQLMAPAPI_HOST", "127.0.0.1")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/app/output")
MAX_CONCURRENT_SCANS = args.max_concurrent or int(os.getenv("MAX_CONCURRENT_SCANS", "10"))
API_TOKEN = args.api_token or os.getenv("API_TOKEN", secrets.token_hex(16))
FLASK_PORT = args.flask_port or int(os.getenv("FLASK_PORT", "5000"))

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

task_queue = []
running_tasks = {}
queue_lock = threading.Lock()
sqlmapapi_base = ""

def get_sqlmapapi_base():
    global sqlmapapi_base
    if sqlmapapi_base:
        return sqlmapapi_base
    sqlmapapi_base = f"http://{SQLMAPAPI_HOST}:{SQLMAPAPI_PORT}"
    return sqlmapapi_base

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Api-Token")
        if token and token == API_TOKEN:
            return f(*args, **kwargs)
        return jsonify({"error": "Unauthorized"}), 401
    return decorated

def start_sqlmap_task(task_id, filename, scan_data):
    headers = {'Content-Type': 'application/json'}
    try:
        start_res = requests.post(f"{get_sqlmapapi_base()}/scan/{task_id}/start", data=json.dumps(scan_data), headers=headers, timeout=10)
        if start_res.status_code != 200:
            cleanup_task(task_id)
            return
        while True:
            try:
                status_res = requests.get(f"{get_sqlmapapi_base()}/scan/{task_id}/status", timeout=10)
                status = status_res.json().get("status", "unknown")
                running_tasks[task_id]["status"] = status
                if status in ("terminated", "completed"):
                    running_tasks[task_id]["finished"] = True
                    break
                time.sleep(10)
            except:
                time.sleep(10)
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        cleanup_task(task_id)
        process_next_in_queue()

def cleanup_task(task_id):
    with queue_lock:
        if task_id in running_tasks:
            del running_tasks[task_id]

def process_next_in_queue():
    with queue_lock:
        if len(running_tasks) >= MAX_CONCURRENT_SCANS or not task_queue:
            return
        task_info = task_queue.pop(0)
        running_tasks[task_info["task_id"]] = {"status": "running", "finished": False}
        t = threading.Thread(target=start_sqlmap_task, args=(task_info["task_id"], task_info["filename"], task_info["scan_data"]))
        t.daemon = True
        t.start()

@app.route('/info', methods=['GET'])
def get_info():
    return jsonify({
        "api_token": API_TOKEN,
        "max_concurrent": MAX_CONCURRENT_SCANS,
        "sqlmapapi_url": get_sqlmapapi_base(),
        "agent_port": FLASK_PORT,
        "version": "1.0"
    })

@app.route('/status', methods=['GET'])
@require_auth
def get_status():
    with queue_lock:
        return jsonify({
            "running_count": len(running_tasks),
            "max_concurrent": MAX_CONCURRENT_SCANS,
            "queued_count": len(task_queue)
        })

@app.route('/scan', methods=['POST'])
@require_auth
def start_scan():
    data = request.json
    domain = data.get("domain")
    vuln_id = data.get("vuln_id")
    request_data = data.get("request_data")
    force_ssl = data.get("force_ssl", False)

    if not all([domain, vuln_id, request_data]):
        return jsonify({"error": "Missing required fields"}), 400

    ssl_prefix = "force-ssl=" if force_ssl else ""
    filename = os.path.join(OUTPUT_DIR, f"{ssl_prefix}{domain}.{vuln_id}")

    with open(filename, 'wt', encoding='utf8', newline='') as f:
        f.write(request_data)

    new_task_res = requests.get(f"{get_sqlmapapi_base()}/task/new", timeout=10)
    task_id = new_task_res.json().get("taskid")

    scan_data = {
        "requestFile": os.path.abspath(filename),
        "level": 5,
        "risk": 3,
        "tamper": "between",
        "batch": True,
        "forceSSL": force_ssl,
        "osShell": True,
    }

    task_info = {"task_id": task_id, "filename": filename, "scan_data": scan_data}

    with queue_lock:
        if len(running_tasks) >= MAX_CONCURRENT_SCANS:
            task_queue.append(task_info)
            return jsonify({"message": "Task queued", "task_id": task_id}), 202
        else:
            running_tasks[task_id] = {"status": "running", "finished": False}
            t = threading.Thread(target=start_sqlmap_task, args=(task_id, filename, scan_data))
            t.daemon = True
            t.start()
            return jsonify({"message": "Scan started", "task_id": task_id}), 200

if __name__ == '__main__':
    print(f"[*] Sqlmap Agent started")
    print(f"[*] API_TOKEN: {API_TOKEN}")
    print(f"[*] SQLMAPAPI_PORT: {SQLMAPAPI_PORT}")
    print(f"[*] FLASK_PORT: {FLASK_PORT}")
    app.run(host='0.0.0.0', port=FLASK_PORT)
