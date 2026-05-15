import argparse
import base64
import json
import os
import queue
import re
import secrets
import subprocess
import sys
import threading
import time
import uuid
from functools import wraps
from html import unescape
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, request
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument("--flask-port", type=int, default=5000)
parser.add_argument("--api-token", default=None)
parser.add_argument("--max-concurrent", type=int, default=5)
args, _ = parser.parse_known_args()

app = Flask(__name__)

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/app/output")
API_TOKEN = args.api_token or os.getenv("API_TOKEN", secrets.token_hex(16))
FLASK_PORT = args.flask_port or int(os.getenv("FLASK_PORT", "5000"))
MAX_CONCURRENT_SCANS = args.max_concurrent or int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
REQUEST_TIMEOUT = 12
MAX_FETCH_URLS = 200
LOG_RETENTION_LINES = 2000
LOG_RESPONSE_LIMIT = 200
DEFAULT_DIRSEARCH_WORDLIST = "/opt/wordlists/path-default.txt"
CUSTOM_PATH_LIMIT = 500
CUSTOM_PATH_LENGTH_LIMIT = 256
DEFAULT_KATANA_SEED_MODE = "auto"
KATANA_SEED_MODE_LIMITS = {
    "auto": 0,
    "20": 20,
    "50": 50,
    "100": 100,
    "unlimited": 0,
}
KATANA_MAX_DEPTH = 3
KATANA_TARGETED_SEED_LIMIT = 10
KATANA_PRIORITY_KEYWORDS = [
    "admin",
    "administrator",
    "root",
    "manager",
    "adm",
    "panel",
    "login",
    "dashboard",
    "backend",
    "console",
    "control",
    "manage",
]
AGENT_VERSION = "2.4.6"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
PYTHON_BIN = os.getenv("PATH_AGENT_PYTHON", sys.executable or "python3")

http_session = requests.Session()
http_session.headers.update({"User-Agent": USER_AGENT})
task_queue = queue.Queue()
scan_records = {}
running_tasks = {}
record_lock = threading.Lock()


def now_ts():
    return int(time.time())


def strip_wrapping_quotes(value):
    text = str(value or "").strip()
    while len(text) >= 2 and text[0] == text[-1] and text[0] in {"`", '"', "'"}:
        text = text[1:-1].strip()
    return text


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(os.path.join(OUTPUT_DIR, "scans"), exist_ok=True)


def require_auth(func):
    @wraps(func)
    def decorated(*args_, **kwargs_):
        token = request.headers.get("X-Api-Token")
        if token != API_TOKEN:
            return jsonify({"error": "Unauthorized"}), 401
        return func(*args_, **kwargs_)

    return decorated


def normalize_target_url(raw_url):
    raw_url = strip_wrapping_quotes(raw_url)
    if not raw_url:
        raise ValueError("target_url is required")
    parsed = urlparse(raw_url if "://" in raw_url else "http://" + raw_url)
    if not parsed.hostname:
        raise ValueError("target_url host is empty")
    scheme = parsed.scheme or "http"
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{parsed.netloc}{path}{query}"


def normalize_site_root(raw_url):
    raw_url = strip_wrapping_quotes(raw_url)
    parsed = urlparse(raw_url if "://" in raw_url else "http://" + raw_url)
    if not parsed.hostname:
        raise ValueError("target_url host is empty")
    scheme = parsed.scheme or "http"
    return f"{scheme}://{parsed.netloc}/"


def normalize_katana_seed_mode(value):
    normalized = str(value or "").strip().lower()
    return normalized if normalized in KATANA_SEED_MODE_LIMITS else DEFAULT_KATANA_SEED_MODE


def normalize_custom_paths(values):
    if not isinstance(values, list):
        return []
    normalized = []
    seen = set()
    for raw_value in values:
        value = str(raw_value or "").strip().replace("\\", "/")
        value = value.split("?", 1)[0].split("#", 1)[0].lstrip("/")
        value = "/".join(part for part in value.split("/") if part not in {"", ".", ".."})
        if not value:
            continue
        if len(value) > CUSTOM_PATH_LENGTH_LIMIT:
            value = value[:CUSTOM_PATH_LENGTH_LIMIT]
        if value in seen:
            continue
        seen.add(value)
        normalized.append(value)
        if len(normalized) >= CUSTOM_PATH_LIMIT:
            break
    return normalized


def make_scan_snapshot(record):
    if not record:
        return {"error": "Task not found"}
    return {
        "task_id": record["task_id"],
        "panel_task_id": record.get("panel_task_id"),
        "target_url": record.get("target_url"),
        "status": record.get("status"),
        "paths_count": int(record.get("paths_count") or 0),
        "forms_count": int(record.get("forms_count") or 0),
        "last_error": record.get("last_error", ""),
        "created_at": int(record.get("created_at") or 0),
        "updated_at": int(record.get("updated_at") or 0),
        "completed_at": int(record.get("completed_at") or 0),
        "log_count": int(record.get("log_cursor") or 0),
        "katana_seed_mode": record.get("katana_seed_mode", DEFAULT_KATANA_SEED_MODE),
        "custom_paths": list(record.get("custom_paths") or []),
        "queued": record["task_id"] not in running_tasks and any(item == record["task_id"] for item in list(task_queue.queue)),
        "running": record["task_id"] in running_tasks,
        "result": record.get("result"),
    }


def make_log_snapshot(record, offset=0, limit=LOG_RESPONSE_LIMIT):
    if not record:
        return {"error": "Task not found"}
    safe_offset = max(0, int(offset or 0))
    safe_limit = max(1, min(int(limit or LOG_RESPONSE_LIMIT), 1000))
    logs = list(record.get("logs") or [])
    total = int(record.get("log_cursor") or 0)
    first_offset = logs[0]["offset"] if logs else total + 1
    truncated = bool(logs) and safe_offset < first_offset - 1
    entries = [entry for entry in logs if int(entry.get("offset") or 0) > safe_offset]
    entries = entries[:safe_limit]
    next_offset = safe_offset
    if entries:
        next_offset = int(entries[-1].get("offset") or safe_offset)
    return {
        "task_id": record["task_id"],
        "status": record.get("status"),
        "running": record["task_id"] in running_tasks,
        "queued": record["task_id"] not in running_tasks and any(item == record["task_id"] for item in list(task_queue.queue)),
        "entries": entries,
        "next_offset": next_offset,
        "total": total,
        "truncated": truncated,
        "completed_at": int(record.get("completed_at") or 0),
    }


def create_record(target_url, panel_task_id, katana_seed_mode=DEFAULT_KATANA_SEED_MODE, custom_paths=None):
    task_id = uuid.uuid4().hex
    scan_root = os.path.join(OUTPUT_DIR, "scans", task_id)
    os.makedirs(scan_root, exist_ok=True)
    record = {
        "task_id": task_id,
        "panel_task_id": panel_task_id,
        "target_url": target_url,
        "katana_seed_mode": normalize_katana_seed_mode(katana_seed_mode),
        "custom_paths": normalize_custom_paths(custom_paths or []),
        "scan_root": scan_root,
        "status": "queued",
        "paths_count": 0,
        "forms_count": 0,
        "last_error": "",
        "created_at": now_ts(),
        "updated_at": now_ts(),
        "completed_at": 0,
        "log_cursor": 0,
        "logs": [],
        "result": {
            "target_url": target_url,
            "paths": [],
        },
    }
    with record_lock:
        scan_records[task_id] = record
    return record


def append_log(record, message):
    text = " ".join(str(message or "").strip().split())
    if not text:
        return
    with record_lock:
        next_offset = int(record.get("log_cursor") or 0) + 1
        logs = record.setdefault("logs", [])
        logs.append(
            {
                "offset": next_offset,
                "timestamp": now_ts(),
                "message": text,
            }
        )
        record["log_cursor"] = next_offset
        if len(logs) > LOG_RETENTION_LINES:
            del logs[: len(logs) - LOG_RETENTION_LINES]
        record["updated_at"] = now_ts()


def write_json(path, payload):
    with open(path, "wt", encoding="utf8", newline="\n") as file_handle:
        json.dump(payload, file_handle, ensure_ascii=False, indent=2)


def run_command(cmd, cwd, stdout_path, timeout, record, stage_name):
    append_log(record, f"[{stage_name}] start: {' '.join(cmd)}")
    started_at = time.time()
    with open(stdout_path, "wt", encoding="utf8", newline="\n") as output_handle:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        try:
            while True:
                if timeout and (time.time() - started_at) > timeout:
                    proc.kill()
                    append_log(record, f"[{stage_name}] timeout after {timeout}s")
                    raise TimeoutError(f"{stage_name} timed out after {timeout}s")
                line = proc.stdout.readline()
                if line:
                    output_handle.write(line)
                    output_handle.flush()
                    append_log(record, f"[{stage_name}] {line.rstrip()}")
                    continue
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
            tail = proc.stdout.read() if proc.stdout else ""
            if tail:
                output_handle.write(tail)
                output_handle.flush()
                for line in tail.splitlines():
                    append_log(record, f"[{stage_name}] {line.rstrip()}")
        finally:
            if proc.stdout:
                proc.stdout.close()
        return_code = proc.wait()
    append_log(record, f"[{stage_name}] exit code: {return_code}")
    return return_code


def parse_dirsearch_results(result_path, target_url):
    results = []
    if not os.path.isfile(result_path):
        return results
    try:
        with open(result_path, "rt", encoding="utf8") as file_handle:
            payload = json.load(file_handle)
    except Exception:
        return results

    entries = []
    stack = [payload]
    while stack:
        current = stack.pop()
        if isinstance(current, list):
            stack.extend(current)
            continue
        if not isinstance(current, dict):
            continue
        status_value = current.get("status")
        if status_value is None:
            status_value = current.get("status_code")
        if status_value is None:
            status_value = current.get("response-status")
        if (current.get("url") or current.get("path")) and status_value is not None:
            entries.append(current)
        for value in current.values():
            if isinstance(value, (list, dict)):
                stack.append(value)

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        url_value = strip_wrapping_quotes(entry.get("url") or "")
        path_value = strip_wrapping_quotes(entry.get("path") or "")
        if not url_value and path_value:
            url_value = urljoin(target_url, path_value)
        if not url_value:
            continue
        status_value = entry.get("status")
        if status_value is None:
            status_value = entry.get("status_code")
        if status_value is None:
            status_value = entry.get("response-status")
        results.append(
            {
                "url": url_value,
                "status_code": int(status_value or 0),
                "source": "dirsearch",
            }
        )
    return results


def parse_dirsearch_log(log_path, target_url):
    results = []
    if not os.path.isfile(log_path):
        return results
    line_re = re.compile(r"\[(?:\d{2}:\d{2}:\d{2})\]\s+(?P<status>\d{3})\s+-.*?-\s+`(?P<url>https?://[^`]+)`(?:\s*->\s*`(?P<redirect>https?://[^`]+)`)?", re.I)
    try:
        with open(log_path, "rt", encoding="utf8", errors="ignore") as file_handle:
            for raw_line in file_handle:
                line = str(raw_line or "").strip()
                match = line_re.search(line)
                if not match:
                    continue
                preferred_url = (match.group("redirect") or match.group("url") or "").strip()
                normalized_url = normalize_same_host_url(target_url, preferred_url)
                if not normalized_url:
                    normalized_url = normalize_same_host_url(target_url, match.group("url") or "")
                if not normalized_url:
                    continue
                results.append(
                    {
                        "url": normalized_url,
                        "status_code": int(match.group("status") or 0),
                        "source": "dirsearch-log",
                    }
                )
    except Exception:
        return []
    return results


def build_dirsearch_wordlist(scan_root, custom_paths):
    normalized_custom_paths = normalize_custom_paths(custom_paths)
    if not normalized_custom_paths:
        return DEFAULT_DIRSEARCH_WORDLIST, 0
    merged_lines = []
    seen = set()
    for path_value in normalized_custom_paths:
        if path_value not in seen:
            seen.add(path_value)
            merged_lines.append(path_value)
    if os.path.isfile(DEFAULT_DIRSEARCH_WORDLIST):
        with open(DEFAULT_DIRSEARCH_WORDLIST, "rt", encoding="utf8", errors="ignore") as file_handle:
            for line in file_handle:
                candidate = str(line or "").strip()
                if not candidate or candidate.startswith("#") or candidate in seen:
                    continue
                seen.add(candidate)
                merged_lines.append(candidate)
    custom_wordlist_path = os.path.join(scan_root, "dirsearch-wordlist.txt")
    with open(custom_wordlist_path, "wt", encoding="utf8", newline="\n") as file_handle:
        file_handle.write("\n".join(merged_lines) + "\n")
    return custom_wordlist_path, len(normalized_custom_paths)


def run_dirsearch(target_url, scan_root, record):
    output_path = os.path.join(scan_root, "dirsearch.json")
    log_path = os.path.join(scan_root, "dirsearch.log")
    wordlist_path, custom_count = build_dirsearch_wordlist(scan_root, record.get("custom_paths"))
    append_log(record, f"[dirsearch] wordlist={wordlist_path} custom_paths={custom_count}")
    cmd = [
        PYTHON_BIN,
        "/opt/dirsearch/dirsearch.py",
        "-u",
        target_url,
        "-w",
        wordlist_path,
        "-O",
        "json",
        "-o",
        output_path,
        "--quiet-mode",
        "--random-agent",
    ]
    try:
        run_command(cmd, "/opt/dirsearch", log_path, 900, record, "dirsearch")
    except Exception as exc:
        append_log(record, f"[dirsearch] failed: {exc}")
        return []
    results = parse_dirsearch_results(output_path, target_url)
    if not results:
        results = parse_dirsearch_log(log_path, target_url)
        if results:
            append_log(record, f"[dirsearch] fallback parsed {len(results)} candidate paths from stdout log")
    append_log(record, f"[dirsearch] discovered {len(results)} candidate paths")
    return results


def run_katana(target_urls, scan_root, record, output_name="katana.txt", stage_name="katana"):
    output_path = os.path.join(scan_root, output_name)
    normalized_targets = []
    seen_targets = set()
    for target_url in target_urls if isinstance(target_urls, (list, tuple, set)) else [target_urls]:
        value = str(target_url or "").strip()
        if not value or value in seen_targets:
            continue
        seen_targets.add(value)
        normalized_targets.append(value)
    if not normalized_targets:
        return []
    scope_host = (urlparse(normalized_targets[0]).hostname or "").strip().lower()
    cmd = ["/usr/local/bin/katana", "-silent", "-d", str(KATANA_MAX_DEPTH), "-fs", "fqdn"]
    if scope_host:
        append_log(record, f"[{stage_name}] scope=fqdn host={scope_host}")
    seed_file_path = ""
    if len(normalized_targets) == 1:
        append_log(record, f"[{stage_name}] mode=single seed_count=1 target={normalized_targets[0]}")
        cmd.extend(["-u", normalized_targets[0]])
    else:
        seed_file_path = os.path.join(scan_root, output_name + ".seeds.txt")
        with open(seed_file_path, "wt", encoding="utf8", newline="\n") as seed_file:
            seed_file.write("\n".join(normalized_targets) + "\n")
        append_log(
            record,
            f"[{stage_name}] mode=list seed_count={len(normalized_targets)} seed_file={os.path.basename(seed_file_path)}",
        )
        cmd.extend(["-list", seed_file_path])
    try:
        run_command(cmd, scan_root, output_path, 600, record, stage_name)
    except Exception as exc:
        append_log(record, f"[{stage_name}] failed: {exc}")
        return []
    results = []
    if not os.path.isfile(output_path):
        return results
    try:
        with open(output_path, "rt", encoding="utf8") as file_handle:
            for line in file_handle:
                candidate = line.strip()
                if candidate.startswith("http://") or candidate.startswith("https://"):
                    results.append({"url": candidate, "source": "katana"})
    except Exception as exc:
        append_log(record, f"[{stage_name}] parse failed: {exc}")
        return []
    append_log(record, f"[{stage_name}] depth={KATANA_MAX_DEPTH} discovered {len(results)} candidate URLs from {len(normalized_targets)} seed URLs")
    return results


def normalize_same_host_url(base_target, candidate):
    candidate = strip_wrapping_quotes(candidate)
    if not candidate:
        return ""
    if candidate.startswith("javascript:") or candidate.startswith("mailto:") or candidate.startswith("tel:"):
        return ""
    absolute = urljoin(base_target, candidate)
    base_parsed = urlparse(base_target)
    parsed = urlparse(absolute)
    if not parsed.scheme.startswith("http"):
        return ""
    if parsed.hostname != base_parsed.hostname:
        return ""
    base_scheme = base_parsed.scheme or parsed.scheme
    base_netloc = base_parsed.netloc or parsed.netloc
    path = parsed.path or "/"
    query = ("?" + parsed.query) if parsed.query else ""
    return f"{base_scheme}://{base_netloc}{path}{query}"


def extract_title(soup):
    title_tag = soup.find("title")
    if not title_tag:
        return ""
    return " ".join(title_tag.get_text(" ", strip=True).split())


def extract_form_inputs(form):
    fields = []
    for element in form.find_all(["input", "select", "textarea"]):
        name = (element.get("name") or "").strip()
        field_type = (element.get("type") or element.name or "").strip().lower()
        default_value = ""
        if element.name == "textarea":
            default_value = element.get_text(" ", strip=True)
        else:
            default_value = (element.get("value") or "").strip()
        fields.append(
            {
                "name": name,
                "type": field_type,
                "tag": element.name,
                "default_value": default_value,
            }
        )
    return fields


def extract_forms(html_text, page_url):
    soup = BeautifulSoup(html_text, "html.parser")
    forms = []
    for index, form in enumerate(soup.find_all("form"), start=1):
        action = normalize_same_host_url(page_url, form.get("action") or page_url)
        forms.append(
            {
                "form_index": index,
                "page_url": page_url,
                "action": action or page_url,
                "method": (form.get("method") or "GET").upper(),
                "enctype": (form.get("enctype") or "").strip(),
                "fields": extract_form_inputs(form),
            }
        )
    return forms, soup


ABSOLUTE_URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.I)
RELATIVE_URL_RE = re.compile(r"(?P<quote>[\"'])(?P<value>/(?:[^\"'<>\\]|\\.){1,300})(?P=quote)")


def extract_js_urls(text, base_url):
    found = set()
    for match in ABSOLUTE_URL_RE.findall(text or ""):
        normalized = normalize_same_host_url(base_url, unescape(match))
        if normalized:
            found.add(normalized)
    for match in RELATIVE_URL_RE.finditer(text or ""):
        normalized = normalize_same_host_url(base_url, unescape(match.group("value")))
        if normalized:
            found.add(normalized)
    return sorted(found)


def fetch_url_details(url_value):
    response = http_session.get(url_value, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True)
    content_type = (response.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    final_url = normalize_same_host_url(url_value, response.url or url_value) or url_value
    html_text = ""
    forms = []
    title = ""
    js_urls = []
    if "html" in content_type:
        html_text = response.text
        forms, soup = extract_forms(html_text, final_url)
        title = extract_title(soup)
        for script in soup.find_all("script"):
            src = normalize_same_host_url(final_url, script.get("src") or "")
            if src:
                js_urls.append(src)
            inline_text = script.get_text(" ", strip=True)
            if inline_text:
                js_urls.extend(extract_js_urls(inline_text, final_url))
    elif "javascript" in content_type or final_url.endswith(".js"):
        js_urls.extend(extract_js_urls(response.text, final_url))
    return {
        "url": final_url,
        "status_code": int(response.status_code),
        "content_type": content_type,
        "title": title,
        "forms": forms,
        "js_urls": sorted(set(js_urls)),
    }


def merge_path_item(existing, details, source):
    item = existing or {
        "url": details.get("url"),
        "path": urlparse(details.get("url") or "").path or "/",
        "status_code": 0,
        "title": "",
        "content_type": "",
        "sources": [],
        "forms": [],
    }
    if source and source not in item["sources"]:
        item["sources"].append(source)
    if details.get("status_code"):
        item["status_code"] = details.get("status_code")
    if details.get("title"):
        item["title"] = details.get("title")
    if details.get("content_type"):
        item["content_type"] = details.get("content_type")
    if details.get("forms"):
        item["forms"] = details.get("forms")
    return item


def katana_seed_status_priority(status_code):
    status = int(status_code or 0)
    if status == 200:
        return 40
    if status in {201, 202, 204}:
        return 32
    if status in {301, 302, 307, 308}:
        return 28
    if status in {401, 403}:
        return 20
    return 0


def katana_seed_keyword_score(candidate_url):
    parsed = urlparse(candidate_url or "")
    haystack = f"{parsed.path or '/'} {parsed.query or ''}".lower()
    score = 0
    for keyword in KATANA_PRIORITY_KEYWORDS:
        if f"/{keyword}" in haystack or f"-{keyword}" in haystack or f"_{keyword}" in haystack:
            score += 120
        elif keyword in haystack:
            score += 60
    return score


def build_katana_seed_list(target_url, dirsearch_results, record=None):
    deduped = []
    seen_seed_urls = set()
    skipped_host_mismatch = 0
    skipped_dedup = 0
    for item in dirsearch_results:
        raw_url = item.get("url")
        candidate_url = normalize_same_host_url(target_url, raw_url)
        if not candidate_url:
            skipped_host_mismatch += 1
            if record:
                append_log(record, f"[katana-seed][skip][host-mismatch] {raw_url!r} does not match target host {target_url!r}")
            continue
        status_code = int(item.get("status_code") or 0)
        if candidate_url in seen_seed_urls:
            skipped_dedup += 1
            continue
        seen_seed_urls.add(candidate_url)
        deduped.append(item)
        if record:
            kw_score = katana_seed_keyword_score(item.get("url"))
            append_log(record, f"[katana-seed][accept][status={status_code}][kw_score={kw_score}] {candidate_url}")
    if record and (skipped_host_mismatch or skipped_dedup):
        append_log(
            record,
            f"[katana-seed] dirsearch total={len(dirsearch_results)} accepted={len(deduped)}"
            f" skipped_host_mismatch={skipped_host_mismatch}"
            f" skipped_dedup={skipped_dedup}",
        )
    ranked = sorted(
        deduped,
        key=lambda item: (
            -katana_seed_keyword_score(item.get("url")),
            -katana_seed_status_priority(item.get("status_code")),
            item.get("url") or "",
        ),
    )
    return [
        normalize_same_host_url(target_url, item.get("url"))
        for item in ranked
        if normalize_same_host_url(target_url, item.get("url"))
    ]


def run_scan_pipeline(record):
    target_url = record["target_url"]
    site_root = normalize_site_root(target_url)
    scan_root = record["scan_root"]
    katana_seed_mode = normalize_katana_seed_mode(record.get("katana_seed_mode"))
    candidates = {}
    pending = queue.Queue()
    processed = set()
    path_map = {}
    dirsearch_results = []

    def push_candidate(url_value, source):
        normalized = normalize_same_host_url(target_url, url_value)
        if not normalized:
            return
        entry = candidates.setdefault(normalized, {"sources": set()})
        entry["sources"].add(source)
        if normalized not in processed:
            pending.put(normalized)

    append_log(record, f"[scan] start target={target_url}")
    push_candidate(site_root, "root")
    if target_url != site_root:
        push_candidate(target_url, "seed")
        append_log(record, f"[scan] root URL queued: {site_root}")
        append_log(record, f"[scan] target seed queued: {target_url}")
    else:
        append_log(record, "[scan] root URL queued")
    for item in run_dirsearch(site_root, scan_root, record):
        normalized_item_url = normalize_same_host_url(target_url, item.get("url"))
        dirsearch_results.append(item)
        push_candidate(normalized_item_url, item.get("source") or "dirsearch")
        if normalized_item_url:
            item = dict(item)
            item["url"] = normalized_item_url
            existing = path_map.get(normalized_item_url)
            path_map[normalized_item_url] = merge_path_item(existing, item, item.get("source") or "dirsearch")
    initial_katana_targets = [site_root]
    if target_url != site_root:
        initial_katana_targets.append(target_url)
    for item in run_katana(initial_katana_targets, scan_root, record, output_name="katana-initial.txt", stage_name="katana-initial"):
        push_candidate(item.get("url"), item.get("source") or "katana")
    all_katana_seeds = build_katana_seed_list(target_url, dirsearch_results, record=record)
    katana_seed_limit = int(KATANA_SEED_MODE_LIMITS.get(katana_seed_mode, KATANA_SEED_MODE_LIMITS[DEFAULT_KATANA_SEED_MODE]))
    katana_seeds = all_katana_seeds if katana_seed_limit <= 0 else all_katana_seeds[:katana_seed_limit]
    if katana_seeds:
        append_log(record, f"[katana-seed] mode={katana_seed_mode} queued {len(katana_seeds)} of {len(all_katana_seeds)} dirsearch-discovered seeds as a url list")
    if katana_seed_limit > 0 and len(all_katana_seeds) > len(katana_seeds):
        append_log(record, f"[katana-seed] truncated {len(all_katana_seeds) - len(katana_seeds)} lower-priority seeds (mode limit={katana_seed_limit})")
    if katana_seeds:
        append_log(record, f"[katana-seed] running depth={KATANA_MAX_DEPTH} on full dirsearch seed list")
        for item in run_katana(katana_seeds, scan_root, record, output_name="katana.txt", stage_name="katana-seeds"):
            push_candidate(item.get("url"), "katana-seed")
        targeted_seeds = katana_seeds[:KATANA_TARGETED_SEED_LIMIT]
        if targeted_seeds:
            append_log(
                record,
                f"[katana-seed] running targeted per-seed crawl for top {len(targeted_seeds)} high-priority seeds",
            )
        for index, seed_url in enumerate(targeted_seeds, start=1):
            stage_name = f"katana-seed-{index}"
            output_name = f"katana-seed-{index}.txt"
            for item in run_katana(seed_url, scan_root, record, output_name=output_name, stage_name=stage_name):
                push_candidate(item.get("url"), "katana-seed")

    while not pending.empty() and len(processed) < MAX_FETCH_URLS:
        current = pending.get()
        if current in processed:
            continue
        processed.add(current)
        try:
            append_log(record, f"[fetch] {len(processed)}/{MAX_FETCH_URLS} {current}")
            details = fetch_url_details(current)
        except Exception:
            details = {
                "url": current,
                "status_code": 0,
                "content_type": "",
                "title": "",
                "forms": [],
                "js_urls": [],
            }
        sources = sorted(candidates.get(current, {}).get("sources", []))
        merged = path_map.get(current)
        for source in sources:
            merged = merge_path_item(merged, details, source)
        path_map[current] = merged
        final_url = normalize_same_host_url(target_url, details.get("url"))
        if final_url and final_url != current:
            push_candidate(final_url, "redirect")
            redirected = path_map.get(final_url)
            redirected = merge_path_item(redirected, details, "redirect")
            path_map[final_url] = redirected
        for js_url in details.get("js_urls", []):
            push_candidate(js_url, "js")

    paths = sorted(path_map.values(), key=lambda item: item.get("url") or "")
    forms_count = sum(len(item.get("forms") or []) for item in paths)
    result = {
        "target_url": target_url,
        "paths": paths,
    }
    record["result"] = result
    record["paths_count"] = len(paths)
    record["forms_count"] = forms_count
    append_log(record, f"[scan] completed with {len(paths)} paths and {forms_count} forms")
    write_json(os.path.join(scan_root, "result.json"), make_scan_snapshot(record))


def worker_loop():
    while True:
        task_id = task_queue.get()
        record = None
        with record_lock:
            record = scan_records.get(task_id)
            if record:
                record["status"] = "running"
                record["updated_at"] = now_ts()
                running_tasks[task_id] = True
        if not record:
            task_queue.task_done()
            continue
        append_log(record, "[queue] dequeued and running")
        try:
            run_scan_pipeline(record)
            record["status"] = "completed"
            record["last_error"] = ""
            record["completed_at"] = now_ts()
            append_log(record, "[queue] task completed")
        except Exception as exc:
            record["status"] = "failed"
            record["last_error"] = str(exc)
            record["completed_at"] = now_ts()
            append_log(record, f"[queue] task failed: {exc}")
        finally:
            record["updated_at"] = now_ts()
            write_json(os.path.join(record["scan_root"], "snapshot.json"), make_scan_snapshot(record))
            with record_lock:
                running_tasks.pop(task_id, None)
            task_queue.task_done()


@app.route("/status", methods=["GET"])
@require_auth
def get_status():
    return jsonify(
        {
            "running_count": len(running_tasks),
            "queued_count": task_queue.qsize(),
            "max_concurrent": MAX_CONCURRENT_SCANS,
            "version": AGENT_VERSION,
        }
    )


@app.route("/scan", methods=["POST"])
@require_auth
def start_scan():
    data = request.json or {}
    try:
        target_url = normalize_target_url(data.get("target_url"))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    panel_task_id = data.get("task_id")
    katana_seed_mode = normalize_katana_seed_mode(data.get("katana_seed_mode"))
    custom_paths = normalize_custom_paths(data.get("custom_paths"))
    record = create_record(target_url, panel_task_id, katana_seed_mode, custom_paths)
    append_log(record, f"[queue] task created for {target_url}")
    append_log(record, f"[queue] katana seed mode: {katana_seed_mode}")
    append_log(record, f"[queue] custom path count: {len(custom_paths)}")
    task_queue.put(record["task_id"])
    append_log(record, "[queue] task queued")
    return jsonify({"message": "Task queued", "task_id": record["task_id"]}), 202


@app.route("/scan/<task_id>", methods=["GET"])
@require_auth
def get_scan(task_id):
    with record_lock:
        record = scan_records.get(task_id)
    snapshot = make_scan_snapshot(record)
    if snapshot.get("error"):
        return jsonify(snapshot), 404
    return jsonify(snapshot)


@app.route("/scan/<task_id>/log", methods=["GET"])
@require_auth
def get_scan_log(task_id):
    offset = request.args.get("offset", default=0, type=int)
    limit = request.args.get("limit", default=LOG_RESPONSE_LIMIT, type=int)
    with record_lock:
        record = scan_records.get(task_id)
        payload = make_log_snapshot(record, offset=offset, limit=limit)
    if payload.get("error"):
        return jsonify(payload), 404
    return jsonify(payload)


def start_workers():
    worker_count = max(1, MAX_CONCURRENT_SCANS)
    for _ in range(worker_count):
        worker = threading.Thread(target=worker_loop, daemon=True)
        worker.start()


def emit_protocol_link():
    public_host = os.getenv("PUBLIC_HOST") or ""
    host_port = os.getenv("HOST_PORT") or str(FLASK_PORT)
    if not public_host:
        try:
            public_host = requests.get("https://api.ipify.org", timeout=5).text.strip()
        except Exception:
            public_host = "127.0.0.1"
    payload = {
        "name": os.getenv("AGENT_NAME", "path-agent"),
        "url": f"http://{public_host}:{host_port}",
        "api_key": API_TOKEN,
        "max_concurrency": int(MAX_CONCURRENT_SCANS),
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    print(f"pathagent://{encoded}", flush=True)


ensure_output_dir()
start_workers()
emit_protocol_link()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=FLASK_PORT)
