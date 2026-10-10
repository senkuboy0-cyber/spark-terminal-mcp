import os
import sys
import json
import asyncio
import subprocess
import platform
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from queue import Queue
import threading

# A simple zero-dependency MCP server for Render Ubuntu
# Exposes an SSE endpoint at /sse and handles tool calls.

events_queue = Queue()

def execute_command_sync(command, cwd=None):
    try:
        result = subprocess.run(
            command,
            shell=True,
            cwd=cwd or os.getcwd(),
            capture_output=True,
            text=True
        )
        out = result.stdout.strip()
        err = result.stderr.strip()
        
        if result.returncode == 0:
            return out if out else f"Command executed successfully. Exit code: 0"
        else:
            return f"Error [{result.returncode}]:\n{err}"
    except Exception as e:
        return f"Failed to execute command: {str(e)}"

class MCPRequestHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        if self.path == '/sse':
            self.send_response(200)
            self.send_header('Content-type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            # Send initial connection event
            init_msg = {"type": "connected", "message": "Ubuntu Terminal MCP Server connected"}
            self.wfile.write(f"data: {json.dumps(init_msg)}\n\n".encode('utf-8'))
            self.wfile.flush()
            
            # Keep connection open and listen for events
            while True:
                try:
                    event = events_queue.get(timeout=30)
                    self.wfile.write(f"data: {json.dumps(event)}\n\n".encode('utf-8'))
                    self.wfile.flush()
                    events_queue.task_done()
                except Exception:
                    # Send a ping to keep connection alive
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    
        elif self.path == '/tools':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            tools = [
                {
                    "name": "execute_command",
                    "description": "Execute a terminal command on the Render Ubuntu instance.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string"},
                            "cwd": {"type": "string"}
                        },
                        "required": ["command"]
                    }
                },
                {
                    "name": "get_system_info",
                    "description": "Get information about the Render Ubuntu instance.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                }
            ]
            self.wfile.write(json.dumps(tools).encode('utf-8'))
            
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/execute':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request = json.loads(post_data.decode('utf-8'))
            
            tool_name = request.get("name")
            arguments = request.get("arguments", {})
            
            response = {"status": "error", "message": "Unknown tool"}
            
            if tool_name == "execute_command":
                command = arguments.get("command")
                cwd = arguments.get("cwd")
                if command:
                    result = execute_command_sync(command, cwd)
                    response = {"status": "success", "result": result}
                else:
                    response = {"status": "error", "message": "Command is required"}
                    
            elif tool_name == "get_system_info":
                info = (
                    f"OS: {platform.system()} {platform.release()}\n"
                    f"Architecture: {platform.machine()}\n"
                    f"Current Directory: {os.getcwd()}"
                )
                response = {"status": "success", "result": info}
                
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
            # Broadcast execution event to SSE clients
            events_queue.put({"type": "tool_executed", "tool": tool_name})
            
        else:
            self.send_response(404)
            self.end_headers()

def run_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MCPRequestHandler)
    print(f"Starting custom Zero-Dependency SSE MCP server on port {port}...", flush=True)
    httpd.serve_forever()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", "8080"))
    run_server(port)