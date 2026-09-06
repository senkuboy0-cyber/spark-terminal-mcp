"""Gemini Spark Terminal MCP Server

A complete MCP server with:
  - 30+ terminal tools (execute commands, files, web, git, etc.)
  - OAuth 2.1 discovery chain (RFC 9728 / 8414 / 7591 / 7636)
    that Gemini Spark requires for custom Connected Apps
  - Streamable HTTP transport (what Spark uses)
  - SSE transport (legacy clients)
  - Optional AUTH_BYPASS=true for local dev

Deploy to Render, paste the URL into:
  Gemini Spark → Connected Apps → Add a custom app
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import tarfile
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil
import requests
import uvicorn
from bs4 import BeautifulSoup
from ddgs import DDGS
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http import StreamableHTTPServerTransport
import mcp.types as types

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

PORT = int(os.environ.get("PORT", 8080))
AUTH_BYPASS = os.environ.get("AUTH_BYPASS", "").lower() in ("true", "1", "yes")
JWT_SIGNING_KEY = os.environ.get("JWT_SIGNING_KEY") or secrets.token_hex(32)
SERVER_NAME = "Spark Terminal MCP"
SERVER_DOC_URI = "https://github.com/senkuboy0-cyber/spark-terminal-mcp"

DOWNLOADS_DIR = "/app/downloads"
TEMP_DIR = "/app/temp"
os.makedirs(DOWNLOADS_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# In-memory OAuth stores
# ─────────────────────────────────────────────────────────────────────────────
_clients: dict[str, dict] = {}   # client_id -> {client_secret, redirect_uris, ...}
_codes: dict[str, dict] = {}     # auth_code -> {client_id, redirect_uri, code_challenge, sub}

# ─────────────────────────────────────────────────────────────────────────────
# Process tracking
# ─────────────────────────────────────────────────────────────────────────────
process_buffer: dict[str, list[str]] = {}
process_status: dict[str, str] = {}
process_read_index: dict[str, int] = {}
active_processes: dict[str, subprocess.Popen] = {}

# ─────────────────────────────────────────────────────────────────────────────
# JWT helpers
# ─────────────────────────────────────────────────────────────────────────────
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (padding % 4))

def _issue_jwt(sub: str, client_id: str, base_url: str) -> str:
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "iss": base_url, "sub": sub, "aud": client_id,
        "iat": now, "exp": now + 3600,
    }).encode())
    sig = _b64url(hmac.new(
        JWT_SIGNING_KEY.encode(), f"{header}.{payload}".encode(), hashlib.sha256
    ).digest())
    return f"{header}.{payload}.{sig}"

def _verify_jwt(token: str, base_url: str) -> dict | None:
    try:
        header, payload, sig = token.split(".")
        expected = _b64url(hmac.new(
            JWT_SIGNING_KEY.encode(), f"{header}.{payload}".encode(), hashlib.sha256
        ).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(_b64url_decode(payload))
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────────────────────
# Request base URL
# ─────────────────────────────────────────────────────────────────────────────
def _base_url(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", f"localhost:{PORT}"))
    return f"{proto}://{host}"

# ─────────────────────────────────────────────────────────────────────────────
# MCP Server + tools
# ─────────────────────────────────────────────────────────────────────────────
mcp_server = Server("spark-terminal")

@mcp_server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(name="execute_command",
            description="Execute any bash shell command and return stdout+stderr. Use for ls, cat, python3, node, compile, etc. Default timeout 60s. For long commands use stream_output.",
            inputSchema={"type":"object","properties":{"command":{"type":"string","description":"Bash command to run"},"timeout":{"type":"integer","description":"Timeout seconds (default 60)","default":60}},"required":["command"]}),
        types.Tool(name="run_python_code",
            description="Execute Python 3 code block directly (no file needed). Returns stdout, stderr, exceptions.",
            inputSchema={"type":"object","properties":{"code":{"type":"string","description":"Python 3 code to execute"}},"required":["code"]}),
        types.Tool(name="stream_output",
            description="Start a long-running command in background. Returns process_id. Poll with get_process_output until status is finished/error.",
            inputSchema={"type":"object","properties":{"command":{"type":"string","description":"Bash command to run in background"}},"required":["command"]}),
        types.Tool(name="get_process_output",
            description="Get output of a background process started by stream_output. Status: running/finished/error.",
            inputSchema={"type":"object","properties":{"process_id":{"type":"string"},"get_new_only":{"type":"boolean","default":False}},"required":["process_id"]}),
        types.Tool(name="kill_process",
            description="Kill a process by PID or process_id from stream_output.",
            inputSchema={"type":"object","properties":{"process_id":{"type":"string"},"force":{"type":"boolean","default":False}},"required":["process_id"]}),
        types.Tool(name="read_file",
            description="Read contents of any text file. Optionally specify line range.",
            inputSchema={"type":"object","properties":{"file_path":{"type":"string"},"line_start":{"type":"integer"},"line_end":{"type":"integer"}},"required":["file_path"]}),
        types.Tool(name="write_file",
            description="Create or overwrite a file with given content. Use append=true to add to end.",
            inputSchema={"type":"object","properties":{"file_path":{"type":"string"},"content":{"type":"string"},"append":{"type":"boolean","default":False}},"required":["file_path","content"]}),
        types.Tool(name="delete_file",
            description="Delete a file or directory. Use recursive=true for non-empty directories.",
            inputSchema={"type":"object","properties":{"file_path":{"type":"string"},"recursive":{"type":"boolean","default":False}},"required":["file_path"]}),
        types.Tool(name="move_file",
            description="Move or rename a file/directory.",
            inputSchema={"type":"object","properties":{"source_path":{"type":"string"},"destination_path":{"type":"string"}},"required":["source_path","destination_path"]}),
        types.Tool(name="copy_file",
            description="Copy a file or directory. Use recursive=true for directories.",
            inputSchema={"type":"object","properties":{"source_path":{"type":"string"},"destination_path":{"type":"string"},"recursive":{"type":"boolean","default":False}},"required":["source_path","destination_path"]}),
        types.Tool(name="list_directory",
            description="List directory contents with type, size, permissions.",
            inputSchema={"type":"object","properties":{"directory_path":{"type":"string"},"show_hidden":{"type":"boolean","default":False}},"required":["directory_path"]}),
        types.Tool(name="create_directory",
            description="Create a new directory (with parents by default).",
            inputSchema={"type":"object","properties":{"directory_path":{"type":"string"},"parents":{"type":"boolean","default":True}},"required":["directory_path"]}),
        types.Tool(name="fetch_url",
            description="Fetch webpage content. extract_text=true returns clean text (default). extract_text=false returns raw HTML.",
            inputSchema={"type":"object","properties":{"url":{"type":"string"},"extract_text":{"type":"boolean","default":True},"timeout":{"type":"integer","default":30}},"required":["url"]}),
        types.Tool(name="download_file_from_url",
            description="Download a file from a URL to /app/downloads.",
            inputSchema={"type":"object","properties":{"url":{"type":"string"},"filename":{"type":"string"}},"required":["url"]}),
        types.Tool(name="search_web",
            description="Search the web via DuckDuckGo. Returns title, URL, description for each result.",
            inputSchema={"type":"object","properties":{"query":{"type":"string"},"max_results":{"type":"integer","default":10}},"required":["query"]}),
        types.Tool(name="http_request",
            description="Send a custom HTTP request (GET/POST/PUT/DELETE/PATCH) with headers and body.",
            inputSchema={"type":"object","properties":{"url":{"type":"string"},"method":{"type":"string","enum":["GET","POST","PUT","DELETE","PATCH"],"default":"GET"},"headers":{"type":"object"},"body":{"type":"string"},"timeout":{"type":"integer","default":30}},"required":["url"]}),
        types.Tool(name="install_package",
            description="Install a package via pip, apt, or npm.",
            inputSchema={"type":"object","properties":{"package_name":{"type":"string"},"manager":{"type":"string","enum":["pip","apt","npm"]}},"required":["package_name","manager"]}),
        types.Tool(name="get_system_info",
            description="Get CPU, RAM, disk, Python/Node versions, hostname.",
            inputSchema={"type":"object","properties":{}}),
        types.Tool(name="list_processes",
            description="List running processes. Optionally filter by name.",
            inputSchema={"type":"object","properties":{"filter_name":{"type":"string"}}}),
        types.Tool(name="check_disk_space",
            description="Check disk usage for a path.",
            inputSchema={"type":"object","properties":{"path":{"type":"string","default":"/"}}}),
        types.Tool(name="view_logs",
            description="Read last N lines from a log file.",
            inputSchema={"type":"object","properties":{"log_file":{"type":"string","default":"/var/log/syslog"},"lines":{"type":"integer","default":50}}}),
        types.Tool(name="grep_file",
            description="Search for a text pattern in a file or directory.",
            inputSchema={"type":"object","properties":{"pattern":{"type":"string"},"path":{"type":"string"},"case_sensitive":{"type":"boolean","default":True},"recursive":{"type":"boolean","default":False}},"required":["pattern","path"]}),
        types.Tool(name="find_files",
            description="Find files by glob pattern inside a directory.",
            inputSchema={"type":"object","properties":{"directory":{"type":"string"},"pattern":{"type":"string"},"file_type":{"type":"string","enum":["file","directory","both"],"default":"both"}},"required":["directory","pattern"]}),
        types.Tool(name="replace_in_file",
            description="Find and replace text in a file. Supports regex.",
            inputSchema={"type":"object","properties":{"file_path":{"type":"string"},"search_text":{"type":"string"},"replacement_text":{"type":"string"},"use_regex":{"type":"boolean","default":False}},"required":["file_path","search_text","replacement_text"]}),
        types.Tool(name="git_clone",
            description="Clone a git repository.",
            inputSchema={"type":"object","properties":{"repo_url":{"type":"string"},"destination":{"type":"string"},"branch":{"type":"string"}},"required":["repo_url"]}),
        types.Tool(name="git_status",
            description="Show git working tree status.",
            inputSchema={"type":"object","properties":{"repo_path":{"type":"string","default":"/app"}}}),
        types.Tool(name="git_commit",
            description="Stage all changes and commit with a message.",
            inputSchema={"type":"object","properties":{"message":{"type":"string"},"repo_path":{"type":"string","default":"/app"}},"required":["message"]}),
        types.Tool(name="git_push",
            description="Push commits to remote repository.",
            inputSchema={"type":"object","properties":{"repo_path":{"type":"string","default":"/app"},"remote":{"type":"string","default":"origin"},"branch":{"type":"string"}}}),
        types.Tool(name="git_pull",
            description="Pull latest changes from remote.",
            inputSchema={"type":"object","properties":{"repo_path":{"type":"string","default":"/app"},"remote":{"type":"string","default":"origin"}}}),
        types.Tool(name="compress_files",
            description="Compress a file/directory into zip or tar.gz. Output saved to /app/downloads.",
            inputSchema={"type":"object","properties":{"source_path":{"type":"string"},"output_filename":{"type":"string"},"format":{"type":"string","enum":["zip","tar.gz"],"default":"zip"}},"required":["source_path","output_filename"]}),
        types.Tool(name="extract_archive",
            description="Extract a zip or tar.gz archive.",
            inputSchema={"type":"object","properties":{"archive_path":{"type":"string"},"destination":{"type":"string"}},"required":["archive_path"]}),
        types.Tool(name="ping_host",
            description="Ping a host to check reachability.",
            inputSchema={"type":"object","properties":{"host":{"type":"string"},"count":{"type":"integer","default":4}},"required":["host"]}),
        types.Tool(name="check_port",
            description="Check if a TCP port is open on a host.",
            inputSchema={"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer"},"timeout":{"type":"integer","default":5}},"required":["host","port"]}),
        types.Tool(name="get_ip_info",
            description="Get geolocation info for an IP or domain. Leave empty for own public IP.",
            inputSchema={"type":"object","properties":{"ip_or_domain":{"type":"string"}}}),
        types.Tool(name="change_permissions",
            description="Change file permissions (chmod). Accepts octal (755) or symbolic (+x).",
            inputSchema={"type":"object","properties":{"file_path":{"type":"string"},"permissions":{"type":"string"},"recursive":{"type":"boolean","default":False}},"required":["file_path","permissions"]}),
        types.Tool(name="get_env_variable",
            description="Read an environment variable. Leave name empty to list all.",
            inputSchema={"type":"object","properties":{"variable_name":{"type":"string"}}}),
        types.Tool(name="set_env_variable",
            description="Set an environment variable for this session.",
            inputSchema={"type":"object","properties":{"variable_name":{"type":"string"},"value":{"type":"string"}},"required":["variable_name","value"]}),
        types.Tool(name="get_download_url",
            description="Generate a public download URL for a file in /app/downloads.",
            inputSchema={"type":"object","properties":{"filename":{"type":"string"}},"required":["filename"]}),
        types.Tool(name="clear_terminal",
            description="Clear process buffers and temp files.",
            inputSchema={"type":"object","properties":{}}),
    ]

def _run_background(pid: str, command: str) -> None:
    try:
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
        active_processes[pid] = proc
        for line in iter(proc.stdout.readline, ""):
            process_buffer[pid].append(line.rstrip("\n"))
        proc.wait()
        process_status[pid] = "finished" if proc.returncode == 0 else "error"
        active_processes.pop(pid, None)
    except Exception as exc:
        process_buffer.setdefault(pid, []).append(f"Exception: {exc}")
        process_status[pid] = "error"

@mcp_server.call_tool()
async def call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    args = arguments or {}
    def ok(text: str) -> list[types.TextContent]:
        return [types.TextContent(type="text", text=str(text))]
    try:
        if name == "execute_command":
            r = subprocess.run(args["command"], shell=True, capture_output=True, text=True,
                               timeout=int(args.get("timeout", 60)))
            out = r.stdout + ("\n[stderr]\n" + r.stderr if r.stderr else "")
            return ok(out or f"[Exit code {r.returncode}]")

        elif name == "run_python_code":
            tmp = os.path.join(TEMP_DIR, f"s_{uuid.uuid4().hex[:8]}.py")
            Path(tmp).write_text(args["code"])
            r = subprocess.run(["python3", tmp], capture_output=True, text=True, timeout=60)
            os.remove(tmp)
            return ok(r.stdout + ("\n[stderr]\n" + r.stderr if r.stderr else "") or "[No output]")

        elif name == "stream_output":
            pid = f"proc_{uuid.uuid4().hex[:8]}"
            process_buffer[pid] = []
            process_status[pid] = "running"
            process_read_index[pid] = 0
            threading.Thread(target=_run_background, args=(pid, args["command"]), daemon=True).start()
            return ok(f"Started.\nprocess_id: {pid}\nUse get_process_output to read output.")

        elif name == "get_process_output":
            pid = args["process_id"]
            if pid not in process_buffer:
                return ok(f"No process: {pid}")
            status = process_status.get(pid, "unknown")
            if args.get("get_new_only"):
                last = process_read_index.get(pid, 0)
                lines = process_buffer[pid][last:]
                process_read_index[pid] = len(process_buffer[pid])
            else:
                lines = process_buffer[pid]
            return ok(f"process_id: {pid}\nstatus: {status}\n\n" + ("\n".join(lines) or "[No output yet]"))

        elif name == "kill_process":
            pid = args["process_id"]
            force = args.get("force", False)
            if pid in active_processes:
                (active_processes[pid].kill if force else active_processes[pid].terminate)()
                process_status[pid] = "error"
                active_processes.pop(pid, None)
                return ok(f"Process '{pid}' terminated.")
            r = subprocess.run(f"kill {'-9' if force else '-15'} {pid}", shell=True, capture_output=True, text=True)
            return ok(f"Process {pid} killed." if r.returncode == 0 else f"Failed: {r.stderr.strip()}")

        elif name == "read_file":
            fp = args["file_path"]
            if not os.path.exists(fp):
                return ok(f"Error: File not found: {fp}")
            with open(fp, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            s, e = args.get("line_start"), args.get("line_end")
            if s or e:
                lines = lines[(s or 1) - 1:(e or len(lines))]
            return ok("".join(lines))

        elif name == "write_file":
            fp = args["file_path"]
            Path(fp).parent.mkdir(parents=True, exist_ok=True)
            with open(fp, "a" if args.get("append") else "w", encoding="utf-8") as f:
                f.write(args["content"])
            return ok(f"Written: {fp} ({os.path.getsize(fp)} bytes)")

        elif name == "delete_file":
            fp = args["file_path"]
            if not os.path.exists(fp):
                return ok(f"Error: Not found: {fp}")
            if os.path.isfile(fp) or os.path.islink(fp):
                os.remove(fp)
                return ok(f"Deleted: {fp}")
            if args.get("recursive"):
                shutil.rmtree(fp)
                return ok(f"Directory deleted: {fp}")
            try:
                os.rmdir(fp)
                return ok(f"Empty dir deleted: {fp}")
            except OSError:
                return ok("Directory not empty. Use recursive=true.")

        elif name == "move_file":
            src, dst = args["source_path"], args["destination_path"]
            if not os.path.exists(src):
                return ok(f"Error: Not found: {src}")
            Path(dst).parent.mkdir(parents=True, exist_ok=True)
            shutil.move(src, dst)
            return ok(f"Moved: {src} -> {dst}")

        elif name == "copy_file":
            src, dst = args["source_path"], args["destination_path"]
            if not os.path.exists(src):
                return ok(f"Error: Not found: {src}")
            Path(dst).parent.mkdir(parents=True, exist_ok=True)
            if os.path.isdir(src):
                if not args.get("recursive"):
                    return ok("Source is directory. Use recursive=true.")
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
            return ok(f"Copied: {src} -> {dst}")

        elif name == "list_directory":
            dp = args["directory_path"]
            if not os.path.exists(dp):
                return ok(f"Error: Not found: {dp}")
            rows = []
            for entry in sorted(os.scandir(dp), key=lambda e: (not e.is_dir(), e.name)):
                if not args.get("show_hidden") and entry.name.startswith("."):
                    continue
                kind = "DIR " if entry.is_dir() else "FILE"
                st = entry.stat()
                sz = st.st_size
                size_str = f"{sz}B" if sz < 1024 else (f"{sz//1024}KB" if sz < 1024**2 else f"{sz//1024**2}MB")
                rows.append(f"[{kind}] {entry.name:<45} {size_str:<10} {oct(stat.S_IMODE(st.st_mode))[2:]}")
            return ok(f"Contents of {dp}:\n" + "\n".join(rows) if rows else f"Empty: {dp}")

        elif name == "create_directory":
            Path(args["directory_path"]).mkdir(parents=args.get("parents", True), exist_ok=True)
            return ok(f"Created: {args['directory_path']}")

        elif name == "fetch_url":
            headers = {"User-Agent": "Mozilla/5.0 (SparkTerminalMCP/1.0)"}
            resp = requests.get(args["url"], headers=headers, timeout=int(args.get("timeout", 30)))
            resp.raise_for_status()
            if args.get("extract_text", True):
                soup = BeautifulSoup(resp.text, "lxml")
                for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
                    tag.decompose()
                lines = [l for l in soup.get_text(separator="\n", strip=True).splitlines() if l.strip()]
                return ok("\n".join(lines[:600]))
            return ok(resp.text[:60000])

        elif name == "download_file_from_url":
            url = args["url"]
            filename = args.get("filename") or url.split("/")[-1].split("?")[0] or "file"
            dest = os.path.join(DOWNLOADS_DIR, filename)
            resp = requests.get(url, stream=True, timeout=60)
            resp.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in resp.iter_content(8192):
                    f.write(chunk)
            return ok(f"Downloaded: {filename} ({os.path.getsize(dest)} bytes)")

        elif name == "search_web":
            results = list(DDGS().text(args["query"], max_results=int(args.get("max_results", 10))))
            if not results:
                return ok("No results found.")
            lines = [f"Results for: {args['query']}\n" + "="*60]
            for r in results:
                lines.append(f"Title: {r.get('title','')}\nURL:   {r.get('href','')}\nDesc:  {r.get('body','')}\n" + "-"*50)
            return ok("\n".join(lines))

        elif name == "http_request":
            resp = requests.request(
                args.get("method", "GET"), args["url"],
                headers=args.get("headers") or {},
                data=args.get("body"),
                timeout=int(args.get("timeout", 30))
            )
            return ok(f"Status: {resp.status_code}\nHeaders: {dict(resp.headers)}\nBody:\n{resp.text[:10000]}")

        elif name == "install_package":
            pkg, mgr = args["package_name"], args["manager"]
            cmds = {"pip": f"pip3 install {pkg}", "apt": f"apt-get install -y {pkg}", "npm": f"npm install -g {pkg}"}
            if mgr not in cmds:
                return ok(f"Unknown manager: {mgr}")
            r = subprocess.run(cmds[mgr], shell=True, capture_output=True, text=True, timeout=180)
            return ok(r.stdout + r.stderr or "Done.")

        elif name == "get_system_info":
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            py_v = subprocess.run(["python3", "--version"], capture_output=True, text=True).stdout.strip()
            nd_v = subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip()
            npm_v = subprocess.run(["npm", "--version"], capture_output=True, text=True).stdout.strip()
            return ok(f"System Info\n{'='*40}\nCPU: {cpu}%\nRAM: {mem.used//1024**2}/{mem.total//1024**2} MB\nDisk: {disk.used//1024**3}/{disk.total//1024**3} GB\nPython: {py_v}\nNode: {nd_v}\nnpm: {npm_v}\nHost: {socket.gethostname()}")

        elif name == "list_processes":
            fn = args.get("filter_name", "").lower()
            rows = []
            for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
                try:
                    info = p.info
                    if fn and fn not in info["name"].lower():
                        continue
                    rows.append(f"PID:{info['pid']:<7} {info['name']:<22} CPU:{info['cpu_percent']:<6} MEM:{info['memory_percent']:.1f}% {info['status']}")
                except Exception:
                    pass
            return ok("Processes:\n" + "\n".join(rows) if rows else "No processes.")

        elif name == "check_disk_space":
            d = psutil.disk_usage(args.get("path", "/"))
            return ok(f"Total: {d.total//1024**3}GB  Used: {d.used//1024**3}GB  Free: {d.free//1024**3}GB  ({d.percent}% used)")

        elif name == "view_logs":
            r = subprocess.run(f"tail -n {args.get('lines', 50)} {args.get('log_file', '/var/log/syslog')}",
                               shell=True, capture_output=True, text=True)
            return ok(r.stdout or "[Empty]")

        elif name == "grep_file":
            ci = "" if args.get("case_sensitive", True) else "-i"
            rec = "-r" if args.get("recursive") else ""
            r = subprocess.run(f"grep -n {ci} {rec} '{args['pattern']}' '{args['path']}'",
                               shell=True, capture_output=True, text=True)
            return ok(r.stdout or f"No matches for '{args['pattern']}'")

        elif name == "find_files":
            tf = {"file": "-type f", "directory": "-type d", "both": ""}.get(args.get("file_type", "both"), "")
            r = subprocess.run(f"find '{args['directory']}' {tf} -name '{args['pattern']}'",
                               shell=True, capture_output=True, text=True)
            return ok(r.stdout.strip() or "No files found.")

        elif name == "replace_in_file":
            fp = args["file_path"]
            if not os.path.exists(fp):
                return ok(f"Not found: {fp}")
            content = Path(fp).read_text(encoding="utf-8")
            if args.get("use_regex"):
                new, count = re.subn(args["search_text"], args["replacement_text"], content)
            else:
                count = content.count(args["search_text"])
                new = content.replace(args["search_text"], args["replacement_text"])
            Path(fp).write_text(new, encoding="utf-8")
            return ok(f"Replaced {count} occurrence(s) in {fp}")

        elif name == "git_clone":
            b = f"--branch {args['branch']}" if args.get("branch") else ""
            r = subprocess.run(f"git clone {b} {args['repo_url']} {args.get('destination', '/app')}",
                               shell=True, capture_output=True, text=True, timeout=180)
            return ok(r.stdout + r.stderr)

        elif name == "git_status":
            r = subprocess.run("git status", shell=True, capture_output=True, text=True, cwd=args.get("repo_path", "/app"))
            return ok(r.stdout + r.stderr)

        elif name == "git_commit":
            path = args.get("repo_path", "/app")
            add = subprocess.run("git add -A", shell=True, capture_output=True, text=True, cwd=path)
            commit = subprocess.run(f'git commit -m "{args["message"]}"', shell=True, capture_output=True, text=True, cwd=path)
            return ok(add.stdout + commit.stdout + commit.stderr)

        elif name == "git_push":
            r = subprocess.run(f"git push {args.get('remote','origin')} {args.get('branch','')}".strip(),
                               shell=True, capture_output=True, text=True, cwd=args.get("repo_path", "/app"), timeout=60)
            return ok(r.stdout + r.stderr)

        elif name == "git_pull":
            r = subprocess.run(f"git pull {args.get('remote','origin')}",
                               shell=True, capture_output=True, text=True, cwd=args.get("repo_path", "/app"), timeout=60)
            return ok(r.stdout + r.stderr)

        elif name == "compress_files":
            src, out = args["source_path"], os.path.join(DOWNLOADS_DIR, args["output_filename"])
            if not os.path.exists(src):
                return ok(f"Not found: {src}")
            if args.get("format", "zip") == "zip":
                with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
                    if os.path.isdir(src):
                        for root, _, files in os.walk(src):
                            for file in files:
                                full = os.path.join(root, file)
                                zf.write(full, os.path.relpath(full, os.path.dirname(src)))
                    else:
                        zf.write(src, os.path.basename(src))
            else:
                with tarfile.open(out, "w:gz") as tf:
                    tf.add(src, arcname=os.path.basename(src))
            return ok(f"Archive: {out} ({os.path.getsize(out)} bytes)")

        elif name == "extract_archive":
            arc = args["archive_path"]
            dst = args.get("destination", os.path.dirname(arc))
            if not os.path.exists(arc):
                return ok(f"Not found: {arc}")
            os.makedirs(dst, exist_ok=True)
            if arc.endswith(".zip"):
                with zipfile.ZipFile(arc) as zf:
                    zf.extractall(dst)
                    count = len(zf.namelist())
            else:
                with tarfile.open(arc, "r:*") as tf:
                    tf.extractall(dst)
                    count = len(tf.getnames())
            return ok(f"Extracted {count} files to {dst}")

        elif name == "ping_host":
            r = subprocess.run(f"ping -c {args.get('count', 4)} {args['host']}",
                               shell=True, capture_output=True, text=True, timeout=30)
            return ok(r.stdout + r.stderr)

        elif name == "check_port":
            host, port = args["host"], int(args["port"])
            t0 = time.time()
            try:
                s = socket.socket()
                s.settimeout(int(args.get("timeout", 5)))
                r = s.connect_ex((host, port))
                s.close()
                ms = round((time.time() - t0) * 1000, 2)
                return ok(f"Port {port} on {host}: {'OPEN' if r == 0 else 'CLOSED'} ({ms}ms)")
            except Exception as e:
                return ok(f"Error: {e}")

        elif name == "get_ip_info":
            target = args.get("ip_or_domain", "")
            resp = requests.get(f"https://ipinfo.io/{target}/json" if target else "https://ipinfo.io/json", timeout=10)
            return ok("\n".join(f"{k}: {v}" for k, v in resp.json().items()))

        elif name == "change_permissions":
            r = subprocess.run(f"chmod {'-R ' if args.get('recursive') else ''}{args['permissions']} '{args['file_path']}'",
                               shell=True, capture_output=True, text=True)
            return ok(f"Done." if r.returncode == 0 else f"Error: {r.stderr.strip()}")

        elif name == "get_env_variable":
            var = args.get("variable_name")
            if var:
                val = os.environ.get(var)
                return ok(f"{var}={val}" if val is not None else f"'{var}' not set.")
            return ok("\n".join(f"{k}={v}" for k, v in sorted(os.environ.items())))

        elif name == "set_env_variable":
            os.environ[args["variable_name"]] = args["value"]
            return ok(f"Set: {args['variable_name']}={args['value']}")

        elif name == "get_download_url":
            fp = os.path.join(DOWNLOADS_DIR, args["filename"])
            if not os.path.exists(fp):
                return ok(f"File not found in /app/downloads: {args['filename']}")
            base = os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("BASE_URL", "https://your-service.onrender.com"))
            return ok(f"Download URL: {base}/download/{args['filename']}\nSize: {os.path.getsize(fp)} bytes")

        elif name == "clear_terminal":
            process_buffer.clear()
            process_status.clear()
            process_read_index.clear()
            for item in Path(TEMP_DIR).glob("*"):
                try:
                    item.unlink() if item.is_file() else shutil.rmtree(item)
                except Exception:
                    pass
            return ok("Terminal cleared.")

        else:
            return ok(f"Unknown tool: {name}")

    except Exception as exc:
        return ok(f"[Error in '{name}']: {exc}")

# ─────────────────────────────────────────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title=SERVER_NAME)

# SSE transport (legacy)
sse_transport = SseServerTransport("/messages/")

# ─────────────────────────────────────────────────────────────────────────────
# Bearer auth dependency
# ─────────────────────────────────────────────────────────────────────────────
async def require_bearer(request: Request):
    if AUTH_BYPASS:
        return {"sub": "dev", "bypass": True}
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token",
                            headers={"WWW-Authenticate": "Bearer"})
    token = auth[7:]
    base = _base_url(request)
    claims = _verify_jwt(token, base)
    if not claims:
        raise HTTPException(status_code=401, detail="Invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"})
    return claims

# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/healthz")
async def healthz():
    return PlainTextResponse("ok")

@app.get("/")
async def root():
    return PlainTextResponse(f"{SERVER_NAME} is running. MCP endpoint: /mcp")

# ─────────────────────────────────────────────────────────────────────────────
# File downloads
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/download/{filename:path}")
async def download_file(filename: str):
    from fastapi.responses import FileResponse
    fp = os.path.join(DOWNLOADS_DIR, filename)
    if os.path.exists(fp) and os.path.isfile(fp):
        return FileResponse(fp, headers={"Content-Disposition": f'attachment; filename="{os.path.basename(filename)}"}')  
    raise HTTPException(status_code=404, detail="File not found")

# ─────────────────────────────────────────────────────────────────────────────
# RFC 9728 — Protected Resource Metadata
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata(request: Request):
    base = _base_url(request)
    return JSONResponse({
        "resource": base,
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "resource_documentation": SERVER_DOC_URI,
    })

# ─────────────────────────────────────────────────────────────────────────────
# RFC 8414 — Authorization Server Metadata
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/.well-known/oauth-authorization-server")
async def as_metadata(request: Request):
    base = _base_url(request)
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/api/oauth/token",
        "registration_endpoint": f"{base}/api/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "service_documentation": SERVER_DOC_URI,
    })

# ─────────────────────────────────────────────────────────────────────────────
# RFC 7591 — Dynamic Client Registration
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/oauth/register")
async def register_client(request: Request):
    body = await request.json()
    client_id = f"client_{secrets.token_hex(16)}"
    client_secret = secrets.token_hex(32)
    _clients[client_id] = {
        "client_secret": client_secret,
        "redirect_uris": body.get("redirect_uris", []),
        "client_name": body.get("client_name", "Unknown"),
        "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "none"),
    }
    log.info(f"DCR: registered client {client_id} ('{_clients[client_id]['client_name']}')")
    base = _base_url(request)
    return JSONResponse({
        "client_id": client_id,
        "client_secret": client_secret,
        "client_id_issued_at": int(time.time()),
        "client_secret_expires_at": 0,
        "redirect_uris": _clients[client_id]["redirect_uris"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "registration_client_uri": f"{base}/api/oauth/register/{client_id}",
    }, status_code=201)

# ─────────────────────────────────────────────────────────────────────────────
# RFC 7636 — Authorization endpoint (PKCE)
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/authorize")
async def authorize(request: Request):
    p = dict(request.query_params)
    client_id = p.get("client_id", "")
    redirect_uri = p.get("redirect_uri", "")
    state = p.get("state", "")
    code_challenge = p.get("code_challenge", "")
    code_challenge_method = p.get("code_challenge_method", "S256")

    # Auto-approve (demo). In production: show a real login/consent page.
    code = secrets.token_hex(24)
    _codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "sub": "spark-user",
        "expires_at": time.time() + 300,
    }
    log.info(f"Authorize: issued code for client {client_id}")
    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}&state={state}"
    return RedirectResponse(location, status_code=302)

# ─────────────────────────────────────────────────────────────────────────────
# RFC 7636 — Token endpoint
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/oauth/token")
async def token_endpoint(request: Request):
    ct = request.headers.get("content-type", "")
    if "application/json" in ct:
        body = await request.json()
    else:
        form = await request.form()
        body = dict(form)

    grant_type = body.get("grant_type", "")
    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    code = body.get("code", "")
    code_verifier = body.get("code_verifier", "")
    client_id = body.get("client_id", "")

    code_data = _codes.get(code)
    if not code_data or code_data.get("expires_at", 0) < time.time():
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if code_data["client_id"] != client_id:
        return JSONResponse({"error": "invalid_client"}, status_code=400)

    # Verify PKCE S256
    expected = _b64url(hashlib.sha256(code_verifier.encode()).digest())
    if not hmac.compare_digest(expected, code_data.get("code_challenge", "")):
        return JSONResponse({"error": "invalid_grant", "error_description": "PKCE mismatch"}, status_code=400)

    del _codes[code]
    base = _base_url(request)
    access_token = _issue_jwt(code_data["sub"], client_id, base)
    log.info(f"Token: issued JWT for sub={code_data['sub']} client={client_id}")
    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "mcp",
    })

# ─────────────────────────────────────────────────────────────────────────────
# MCP endpoint — Streamable HTTP (Gemini Spark) + SSE (legacy)
# ─────────────────────────────────────────────────────────────────────────────
@app.api_route("/mcp", methods=["GET", "POST", "DELETE"])
@app.api_route("/", methods=["GET", "POST", "DELETE"])
async def mcp_endpoint(request: Request, _claims=Depends(require_bearer)):
    # Streamable HTTP detection: session-id header, DELETE, or non-SSE POST
    session_id = request.headers.get("mcp-session-id", "")
    has_session_param = "sessionid" in {k.lower() for k in request.query_params}

    if session_id or request.method == "DELETE" or (
        request.method == "POST" and not has_session_param
    ):
        # Streamable HTTP transport
        transport = StreamableHTTPServerTransport(mcp_endpoint="/mcp")
        async with transport.connect() as streams:
            await mcp_server.run(
                streams[0], streams[1],
                mcp_server.create_initialization_options(),
            )
        return transport.response(request)
    else:
        # SSE transport (legacy)
        async with sse_transport.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await mcp_server.run(
                streams[0], streams[1],
                mcp_server.create_initialization_options(),
            )

@app.post("/messages/")
async def messages_endpoint(request: Request):
    await sse_transport.handle_post_message(request.scope, request.receive, request._send)

@app.get("/sse")
async def sse_endpoint(request: Request, _claims=Depends(require_bearer)):
    async with sse_transport.connect_sse(
        request.scope, request.receive, request._send
    ) as streams:
        await mcp_server.run(
            streams[0], streams[1],
            mcp_server.create_initialization_options(),
        )

# ─────────────────────────────────────────────────────────────────────────────
# Entry
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info(f"Starting {SERVER_NAME} on port {PORT}")
    log.info(f"Auth bypass: {AUTH_BYPASS}")
    log.info(f"MCP endpoint: /mcp")
    log.info(f"OAuth discovery: /.well-known/oauth-protected-resource")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
