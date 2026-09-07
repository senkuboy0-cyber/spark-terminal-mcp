"""Gemini Spark Terminal MCP Server

OAuth 2.1 (RFC 9728/8414/7591/7636) + Streamable HTTP MCP transport.
Deploy on Render → paste URL into Gemini Spark → Connected Apps.
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
from contextlib import asynccontextmanager
from pathlib import Path

import psutil
import requests
import uvicorn
from bs4 import BeautifulSoup
from ddgs import DDGS
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http import StreamableHTTPServerTransport
from mcp.shared.exceptions import McpError
import mcp.types as types

# ──────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────
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

# ──────────────────────────────────────────────────────────────
# In-memory OAuth stores
# ──────────────────────────────────────────────────────────────
_clients: dict[str, dict] = {}
_codes: dict[str, dict] = {}

# ──────────────────────────────────────────────────────────────
# Process tracking
# ──────────────────────────────────────────────────────────────
process_buffer: dict[str, list[str]] = {}
process_status: dict[str, str] = {}
process_read_index: dict[str, int] = {}
active_processes: dict[str, subprocess.Popen] = {}


# ──────────────────────────────────────────────────────────────
# JWT helpers
# ──────────────────────────────────────────────────────────────
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (4 - len(s) % 4) % 4)

def _issue_jwt(sub: str, client_id: str, base_url: str) -> str:
    now = int(time.time())
    h = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64url(json.dumps({"iss": base_url, "sub": sub, "aud": client_id,
                             "iat": now, "exp": now + 3600}).encode())
    s = _b64url(hmac.new(JWT_SIGNING_KEY.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{s}"

def _verify_jwt(token: str, base_url: str) -> dict | None:
    try:
        h, p, s = token.split(".")
        exp = _b64url(hmac.new(JWT_SIGNING_KEY.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(s, exp):
            return None
        data = json.loads(_b64url_decode(p))
        return data if data.get("exp", 0) >= time.time() else None
    except Exception:
        return None

def _base_url(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", f"localhost:{PORT}"))
    return f"{proto}://{host}"


# ──────────────────────────────────────────────────────────────
# MCP Server
# ──────────────────────────────────────────────────────────────
mcp_server = Server("spark-terminal")

@mcp_server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(name="execute_command",
            description="Execute any bash shell command. Returns stdout+stderr. Default timeout 60s.",
            inputSchema={"type":"object","properties":{"command":{"type":"string"},"timeout":{"type":"integer","default":60}},"required":["command"]}),
        types.Tool(name="run_python_code",
            description="Execute Python 3 code directly. Returns stdout, stderr, exceptions.",
            inputSchema={"type":"object","properties":{"code":{"type":"string"}},"required":["code"]}),
        types.Tool(name="stream_output",
            description="Start a long-running command in background. Returns process_id. Poll with get_process_output.",
            inputSchema={"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}),
        types.Tool(name="get_process_output",
            description="Get output of a background process. Status: running/finished/error.",
            inputSchema={"type":"object","properties":{"process_id":{"type":"string"},"get_new_only":{"type":"boolean","default":False}},"required":["process_id"]}),
        types.Tool(name="kill_process",
            description="Kill a process by PID or process_id.",
            inputSchema={"type":"object","properties":{"process_id":{"type":"string"},"force":{"type":"boolean","default":False}},"required":["process_id"]}),
        types.Tool(name="read_file",
            description="Read a file. Optionally specify line_start and line_end.",
            inputSchema={"type":"object","properties":{"file_path":{"type":"string"},"line_start":{"type":"integer"},"line_end":{"type":"integer"}},"required":["file_path"]}),
        types.Tool(name="write_file",
            description="Create or overwrite a file. Set append=true to add to end.",
            inputSchema={"type":"object","properties":{"file_path":{"type":"string"},"content":{"type":"string"},"append":{"type":"boolean","default":False}},"required":["file_path","content"]}),
        types.Tool(name="delete_file",
            description="Delete file or directory. recursive=true for non-empty dirs.",
            inputSchema={"type":"object","properties":{"file_path":{"type":"string"},"recursive":{"type":"boolean","default":False}},"required":["file_path"]}),
        types.Tool(name="move_file",
            description="Move or rename a file/directory.",
            inputSchema={"type":"object","properties":{"source_path":{"type":"string"},"destination_path":{"type":"string"}},"required":["source_path","destination_path"]}),
        types.Tool(name="copy_file",
            description="Copy a file or directory. recursive=true for directories.",
            inputSchema={"type":"object","properties":{"source_path":{"type":"string"},"destination_path":{"type":"string"},"recursive":{"type":"boolean","default":False}},"required":["source_path","destination_path"]}),
        types.Tool(name="list_directory",
            description="List directory contents.",
            inputSchema={"type":"object","properties":{"directory_path":{"type":"string"},"show_hidden":{"type":"boolean","default":False}},"required":["directory_path"]}),
        types.Tool(name="create_directory",
            description="Create a new directory (with parents by default).",
            inputSchema={"type":"object","properties":{"directory_path":{"type":"string"},"parents":{"type":"boolean","default":True}},"required":["directory_path"]}),
        types.Tool(name="fetch_url",
            description="Fetch webpage as clean text (default) or raw HTML.",
            inputSchema={"type":"object","properties":{"url":{"type":"string"},"extract_text":{"type":"boolean","default":True},"timeout":{"type":"integer","default":30}},"required":["url"]}),
        types.Tool(name="download_file_from_url",
            description="Download a file from URL to /app/downloads.",
            inputSchema={"type":"object","properties":{"url":{"type":"string"},"filename":{"type":"string"}},"required":["url"]}),
        types.Tool(name="search_web",
            description="Search the web with DuckDuckGo. Returns title, URL, description.",
            inputSchema={"type":"object","properties":{"query":{"type":"string"},"max_results":{"type":"integer","default":10}},"required":["query"]}),
        types.Tool(name="http_request",
            description="Send HTTP request (GET/POST/PUT/DELETE/PATCH) with headers/body.",
            inputSchema={"type":"object","properties":{"url":{"type":"string"},"method":{"type":"string","enum":["GET","POST","PUT","DELETE","PATCH"],"default":"GET"},"headers":{"type":"object"},"body":{"type":"string"},"timeout":{"type":"integer","default":30}},"required":["url"]}),
        types.Tool(name="install_package",
            description="Install a package via pip, apt, or npm.",
            inputSchema={"type":"object","properties":{"package_name":{"type":"string"},"manager":{"type":"string","enum":["pip","apt","npm"]}},"required":["package_name","manager"]}),
        types.Tool(name="get_system_info",
            description="Get CPU, RAM, disk, Python/Node versions.",
            inputSchema={"type":"object","properties":{}}),
        types.Tool(name="list_processes",
            description="List running processes. Optional filter by name.",
            inputSchema={"type":"object","properties":{"filter_name":{"type":"string"}}}),
        types.Tool(name="check_disk_space",
            description="Check disk usage for a path.",
            inputSchema={"type":"object","properties":{"path":{"type":"string","default":"/"}}}),
        types.Tool(name="view_logs",
            description="Read last N lines from a log file.",
            inputSchema={"type":"object","properties":{"log_file":{"type":"string","default":"/var/log/syslog"},"lines":{"type":"integer","default":50}}}),
        types.Tool(name="grep_file",
            description="Search for a pattern in a file or directory.",
            inputSchema={"type":"object","properties":{"pattern":{"type":"string"},"path":{"type":"string"},"case_sensitive":{"type":"boolean","default":True},"recursive":{"type":"boolean","default":False}},"required":["pattern","path"]}),
        types.Tool(name="find_files",
            description="Find files by glob pattern.",
            inputSchema={"type":"object","properties":{"directory":{"type":"string"},"pattern":{"type":"string"},"file_type":{"type":"string","enum":["file","directory","both"],"default":"both"}},"required":["directory","pattern"]}),
        types.Tool(name="replace_in_file",
            description="Find and replace text in a file. Supports regex.",
            inputSchema={"type":"object","properties":{"file_path":{"type":"string"},"search_text":{"type":"string"},"replacement_text":{"type":"string"},"use_regex":{"type":"boolean","default":False}},"required":["file_path","search_text","replacement_text"]}),
        types.Tool(name="git_clone",
            description="Clone a git repository.",
            inputSchema={"type":"object","properties":{"repo_url":{"type":"string"},"destination":{"type":"string"},"branch":{"type":"string"}},"required":["repo_url"]}),
        types.Tool(name="git_status",
            description="Show git status.",
            inputSchema={"type":"object","properties":{"repo_path":{"type":"string","default":"/app"}}}),
        types.Tool(name="git_commit",
            description="Stage all and commit.",
            inputSchema={"type":"object","properties":{"message":{"type":"string"},"repo_path":{"type":"string","default":"/app"}},"required":["message"]}),
        types.Tool(name="git_push",
            description="Push to remote.",
            inputSchema={"type":"object","properties":{"repo_path":{"type":"string","default":"/app"},"remote":{"type":"string","default":"origin"},"branch":{"type":"string"}}}),
        types.Tool(name="git_pull",
            description="Pull from remote.",
            inputSchema={"type":"object","properties":{"repo_path":{"type":"string","default":"/app"},"remote":{"type":"string","default":"origin"}}}),
        types.Tool(name="compress_files",
            description="Compress file/directory to zip or tar.gz in /app/downloads.",
            inputSchema={"type":"object","properties":{"source_path":{"type":"string"},"output_filename":{"type":"string"},"format":{"type":"string","enum":["zip","tar.gz"],"default":"zip"}},"required":["source_path","output_filename"]}),
        types.Tool(name="extract_archive",
            description="Extract a zip or tar.gz archive.",
            inputSchema={"type":"object","properties":{"archive_path":{"type":"string"},"destination":{"type":"string"}},"required":["archive_path"]}),
        types.Tool(name="ping_host",
            description="Ping a host.",
            inputSchema={"type":"object","properties":{"host":{"type":"string"},"count":{"type":"integer","default":4}},"required":["host"]}),
        types.Tool(name="check_port",
            description="Check if a TCP port is open.",
            inputSchema={"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer"},"timeout":{"type":"integer","default":5}},"required":["host","port"]}),
        types.Tool(name="get_ip_info",
            description="Geolocation info for IP/domain. Empty = own IP.",
            inputSchema={"type":"object","properties":{"ip_or_domain":{"type":"string"}}}),
        types.Tool(name="change_permissions",
            description="chmod a file/directory.",
            inputSchema={"type":"object","properties":{"file_path":{"type":"string"},"permissions":{"type":"string"},"recursive":{"type":"boolean","default":False}},"required":["file_path","permissions"]}),
        types.Tool(name="get_env_variable",
            description="Read env var. Empty name = list all.",
            inputSchema={"type":"object","properties":{"variable_name":{"type":"string"}}}),
        types.Tool(name="set_env_variable",
            description="Set an env var for this session.",
            inputSchema={"type":"object","properties":{"variable_name":{"type":"string"},"value":{"type":"string"}},"required":["variable_name","value"]}),
        types.Tool(name="get_download_url",
            description="Get a public download URL for a file in /app/downloads.",
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
            return ok(out or f"[Exit {r.returncode}]")

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
            return ok(f"Started.\nprocess_id: {pid}\nCall get_process_output to read output.")

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
            return ok(f"id: {pid}\nstatus: {status}\n\n" + ("\n".join(lines) or "[no output yet]"))

        elif name == "kill_process":
            pid = args["process_id"]
            force = args.get("force", False)
            if pid in active_processes:
                (active_processes[pid].kill if force else active_processes[pid].terminate)()
                process_status[pid] = "error"
                active_processes.pop(pid, None)
                return ok(f"Terminated: {pid}")
            r = subprocess.run(f"kill {'-9' if force else '-15'} {pid}", shell=True, capture_output=True, text=True)
            return ok("Killed." if r.returncode == 0 else f"Failed: {r.stderr.strip()}")

        elif name == "read_file":
            fp = args["file_path"]
            if not os.path.exists(fp):
                return ok(f"Not found: {fp}")
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
                return ok(f"Not found: {fp}")
            if os.path.isfile(fp) or os.path.islink(fp):
                os.remove(fp)
                return ok(f"Deleted: {fp}")
            if args.get("recursive"):
                shutil.rmtree(fp)
                return ok(f"Dir deleted: {fp}")
            try:
                os.rmdir(fp)
                return ok(f"Empty dir deleted: {fp}")
            except OSError:
                return ok("Not empty. Use recursive=true.")

        elif name == "move_file":
            src, dst = args["source_path"], args["destination_path"]
            if not os.path.exists(src):
                return ok(f"Not found: {src}")
            Path(dst).parent.mkdir(parents=True, exist_ok=True)
            shutil.move(src, dst)
            return ok(f"Moved: {src} to {dst}")

        elif name == "copy_file":
            src, dst = args["source_path"], args["destination_path"]
            if not os.path.exists(src):
                return ok(f"Not found: {src}")
            Path(dst).parent.mkdir(parents=True, exist_ok=True)
            if os.path.isdir(src):
                if not args.get("recursive"):
                    return ok("Use recursive=true for dirs.")
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
            return ok(f"Copied: {src} to {dst}")

        elif name == "list_directory":
            dp = args["directory_path"]
            if not os.path.exists(dp):
                return ok(f"Not found: {dp}")
            rows = []
            for entry in sorted(os.scandir(dp), key=lambda e: (not e.is_dir(), e.name)):
                if not args.get("show_hidden") and entry.name.startswith("."):
                    continue
                st = entry.stat()
                sz = st.st_size
                size_str = f"{sz}B" if sz < 1024 else (f"{sz//1024}KB" if sz < 1048576 else f"{sz//1048576}MB")
                rows.append(f"[{'DIR ' if entry.is_dir() else 'FILE'}] {entry.name:<40} {size_str:<10} {oct(stat.S_IMODE(st.st_mode))[2:]}")
            return ok(f"Contents of {dp}:\n" + "\n".join(rows) if rows else f"Empty: {dp}")

        elif name == "create_directory":
            Path(args["directory_path"]).mkdir(parents=args.get("parents", True), exist_ok=True)
            return ok(f"Created: {args['directory_path']}")

        elif name == "fetch_url":
            hdrs = {"User-Agent": "Mozilla/5.0 (SparkTerminalMCP/1.0)"}
            resp = requests.get(args["url"], headers=hdrs, timeout=int(args.get("timeout", 30)))
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
                return ok("No results.")
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
            return ok(
                f"CPU: {cpu}%\nRAM: {mem.used//1048576}/{mem.total//1048576} MB\n"
                f"Disk: {disk.used//1073741824}/{disk.total//1073741824} GB\n"
                f"Python: {py_v}\nNode: {nd_v}\nnpm: {npm_v}\nHost: {socket.gethostname()}"
            )

        elif name == "list_processes":
            fn = args.get("filter_name", "").lower()
            rows = []
            for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
                try:
                    i = p.info
                    if fn and fn not in i["name"].lower():
                        continue
                    rows.append(f"PID:{i['pid']:<7} {i['name']:<22} CPU:{i['cpu_percent']:<5} MEM:{i['memory_percent']:.1f}% {i['status']}")
                except Exception:
                    pass
            return ok("Processes:\n" + "\n".join(rows) if rows else "None.")

        elif name == "check_disk_space":
            d = psutil.disk_usage(args.get("path", "/"))
            return ok(f"Total:{d.total//1073741824}GB Used:{d.used//1073741824}GB Free:{d.free//1073741824}GB ({d.percent}%)")

        elif name == "view_logs":
            r = subprocess.run(
                f"tail -n {args.get('lines', 50)} {args.get('log_file', '/var/log/syslog')}",
                shell=True, capture_output=True, text=True
            )
            return ok(r.stdout or "[Empty]")

        elif name == "grep_file":
            ci = "" if args.get("case_sensitive", True) else "-i"
            rec = "-r" if args.get("recursive") else ""
            r = subprocess.run(
                f"grep -n {ci} {rec} '{args['pattern']}' '{args['path']}'",
                shell=True, capture_output=True, text=True
            )
            return ok(r.stdout or f"No matches for '{args['pattern']}'")

        elif name == "find_files":
            tf = {"file": "-type f", "directory": "-type d", "both": ""}.get(args.get("file_type", "both"), "")
            r = subprocess.run(
                f"find '{args['directory']}' {tf} -name '{args['pattern']}'",
                shell=True, capture_output=True, text=True
            )
            return ok(r.stdout.strip() or "None found.")

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
            r = subprocess.run(
                f"git clone {b} {args['repo_url']} {args.get('destination', '/app')}",
                shell=True, capture_output=True, text=True, timeout=180
            )
            return ok(r.stdout + r.stderr)

        elif name == "git_status":
            r = subprocess.run("git status", shell=True, capture_output=True, text=True,
                               cwd=args.get("repo_path", "/app"))
            return ok(r.stdout + r.stderr)

        elif name == "git_commit":
            path = args.get("repo_path", "/app")
            add = subprocess.run("git add -A", shell=True, capture_output=True, text=True, cwd=path)
            commit = subprocess.run(
                f'git commit -m "{args["message"]}"',
                shell=True, capture_output=True, text=True, cwd=path
            )
            return ok(add.stdout + commit.stdout + commit.stderr)

        elif name == "git_push":
            r = subprocess.run(
                f"git push {args.get('remote', 'origin')} {args.get('branch', '')}".strip(),
                shell=True, capture_output=True, text=True,
                cwd=args.get("repo_path", "/app"), timeout=60
            )
            return ok(r.stdout + r.stderr)

        elif name == "git_pull":
            r = subprocess.run(
                f"git pull {args.get('remote', 'origin')}",
                shell=True, capture_output=True, text=True,
                cwd=args.get("repo_path", "/app"), timeout=60
            )
            return ok(r.stdout + r.stderr)

        elif name == "compress_files":
            src = args["source_path"]
            out = os.path.join(DOWNLOADS_DIR, args["output_filename"])
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
            r = subprocess.run(
                f"ping -c {args.get('count', 4)} {args['host']}",
                shell=True, capture_output=True, text=True, timeout=30
            )
            return ok(r.stdout + r.stderr)

        elif name == "check_port":
            host, port = args["host"], int(args["port"])
            t0 = time.time()
            try:
                s = socket.socket()
                s.settimeout(int(args.get("timeout", 5)))
                result = s.connect_ex((host, port))
                s.close()
                ms = round((time.time() - t0) * 1000, 2)
                return ok(f"Port {port} on {host}: {'OPEN' if result == 0 else 'CLOSED'} ({ms}ms)")
            except Exception as e:
                return ok(f"Error: {e}")

        elif name == "get_ip_info":
            target = args.get("ip_or_domain", "")
            url = f"https://ipinfo.io/{target}/json" if target else "https://ipinfo.io/json"
            resp = requests.get(url, timeout=10)
            return ok("\n".join(f"{k}: {v}" for k, v in resp.json().items()))

        elif name == "change_permissions":
            rec = "-R " if args.get("recursive") else ""
            r = subprocess.run(
                f"chmod {rec}{args['permissions']} '{args['file_path']}'",
                shell=True, capture_output=True, text=True
            )
            return ok("Done." if r.returncode == 0 else f"Error: {r.stderr.strip()}")

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
                return ok(f"Not in /app/downloads: {args['filename']}")
            base = os.environ.get("RENDER_EXTERNAL_URL", "https://spark-terminal-mcp.onrender.com")
            return ok(f"URL: {base}/download/{args['filename']}\nSize: {os.path.getsize(fp)} bytes")

        elif name == "clear_terminal":
            process_buffer.clear()
            process_status.clear()
            process_read_index.clear()
            for item in Path(TEMP_DIR).glob("*"):
                try:
                    item.unlink() if item.is_file() else shutil.rmtree(item)
                except Exception:
                    pass
            return ok("Cleared.")

        else:
            return ok(f"Unknown tool: {name}")

    except Exception as exc:
        return ok(f"[Error in '{name}']: {exc}")


# ──────────────────────────────────────────────────────────────
# FastAPI app
# ──────────────────────────────────────────────────────────────
app = FastAPI(title=SERVER_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

sse_transport = SseServerTransport("/messages/")


async def require_bearer(request: Request):
    if AUTH_BYPASS:
        return {"sub": "dev"}
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=401, detail="Missing Bearer token",
            headers={"WWW-Authenticate": 'Bearer realm="spark-terminal-mcp"'})
    claims = _verify_jwt(auth[7:], _base_url(request))
    if not claims:
        raise HTTPException(
            status_code=401, detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"})
    return claims


# ── Health / root ─────────────────────────────────────────────
@app.get("/healthz")
async def healthz():
    return PlainTextResponse("ok")

@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return PlainTextResponse(f"{SERVER_NAME} running. MCP: /mcp")


# ── File downloads ────────────────────────────────────────────
@app.get("/download/{filename:path}")
async def download_file(filename: str):
    fp = os.path.join(DOWNLOADS_DIR, filename)
    if os.path.exists(fp) and os.path.isfile(fp):
        fname = os.path.basename(filename)
        return FileResponse(fp, headers={"Content-Disposition": 'attachment; filename="' + fname + '"'})
    raise HTTPException(status_code=404, detail="File not found")


# ── RFC 9728 — Protected Resource Metadata ────────────────────
@app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata(request: Request):
    base = _base_url(request)
    return JSONResponse({
        "resource": base,
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "resource_documentation": SERVER_DOC_URI,
    })


# ── RFC 8414 — Authorization Server Metadata ──────────────────
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


# ── RFC 7591 — Dynamic Client Registration ────────────────────
@app.post("/api/oauth/register")
async def register_client(request: Request):
    body = await request.json()
    client_id = f"client_{secrets.token_hex(16)}"
    client_secret = secrets.token_hex(32)
    _clients[client_id] = {
        "client_secret": client_secret,
        "redirect_uris": body.get("redirect_uris", []),
        "client_name": body.get("client_name", "Unknown"),
    }
    log.info(f"DCR: registered {client_id} name={_clients[client_id]['client_name']}")
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


# ── RFC 7636 — Authorization endpoint (PKCE) ──────────────────
@app.get("/authorize")
async def authorize(request: Request):
    p = dict(request.query_params)
    code = secrets.token_hex(24)
    _codes[code] = {
        "client_id": p.get("client_id", ""),
        "redirect_uri": p.get("redirect_uri", ""),
        "code_challenge": p.get("code_challenge", ""),
        "code_challenge_method": p.get("code_challenge_method", "S256"),
        "sub": "spark-user",
        "expires_at": time.time() + 300,
    }
    redirect_uri = p.get("redirect_uri", "")
    state = p.get("state", "")
    sep = "&" if "?" in redirect_uri else "?"
    log.info(f"Authorize: code issued for client={p.get('client_id', '')}")
    return RedirectResponse(f"{redirect_uri}{sep}code={code}&state={state}", status_code=302)


# ── Token endpoint ────────────────────────────────────────────
@app.post("/api/oauth/token")
async def token_endpoint(request: Request):
    ct = request.headers.get("content-type", "")
    body = await request.json() if "application/json" in ct else dict(await request.form())

    if body.get("grant_type") != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    code = body.get("code", "")
    code_data = _codes.get(code)
    if not code_data or code_data.get("expires_at", 0) < time.time():
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if code_data["client_id"] != body.get("client_id", ""):
        return JSONResponse({"error": "invalid_client"}, status_code=400)

    verifier = body.get("code_verifier", "")
    expected = _b64url(hashlib.sha256(verifier.encode()).digest())
    if not hmac.compare_digest(expected, code_data.get("code_challenge", "")):
        return JSONResponse({"error": "invalid_grant", "error_description": "PKCE mismatch"}, status_code=400)

    del _codes[code]
    access_token = _issue_jwt(code_data["sub"], code_data["client_id"], _base_url(request))
    log.info(f"Token: issued for sub={code_data['sub']} client={code_data['client_id']}")
    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "mcp",
    })


# ── MCP endpoint — Streamable HTTP (Gemini Spark) ─────────────
@app.api_route("/mcp", methods=["GET", "POST", "DELETE"])
async def mcp_streamable(request: Request, _claims=Depends(require_bearer)):
    transport = StreamableHTTPServerTransport(
        mcp_endpoint="/mcp",
        is_resumable=False,
        json_response=False,
    )
    async with transport.connect() as (read_stream, write_stream):
        await mcp_server.run(
            read_stream,
            write_stream,
            mcp_server.create_initialization_options(),
        )
    return await transport.handle_request(request)


# ── SSE endpoint (legacy) ───────────────────────────────────
@app.get("/sse")
async def sse_endpoint(request: Request, _claims=Depends(require_bearer)):
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


# ── Entry ─────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info(f"Starting {SERVER_NAME} on :{PORT}  auth_bypass={AUTH_BYPASS}")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
