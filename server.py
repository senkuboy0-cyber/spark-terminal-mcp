import asyncio
import os
import platform
import subprocess
import sys
from typing import Optional
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# Initialize FastMCP Server
mcp = FastMCP("Ubuntu Terminal MCP")

@mcp.tool()
async def execute_command(command: str, cwd: str = None) -> str:
    """
    Execute a terminal command on the Render Ubuntu instance.
    """
    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd if cwd else os.getcwd()
        )
        
        stdout, stderr = await process.communicate()
        out = stdout.decode('utf-8').strip()
        err = stderr.decode('utf-8').strip()
        
        if process.returncode == 0:
            return out if out else f"Command executed successfully. Exit code: 0"
        else:
            return f"Error [{process.returncode}]:\n{err}"
            
    except Exception as e:
        return f"Failed to execute command: {str(e)}"

@mcp.tool()
def get_system_info() -> str:
    """Get information about the Render Ubuntu instance."""
    info = {
        "OS": platform.system(),
        "Release": platform.release(),
        "Architecture": platform.machine(),
        "Current Directory": os.getcwd()
    }
    result = "System Information:\n"
    for key, value in info.items():
        result += f"- {key}: {value}\n"
    return result

def main():
    """Start the MCP server using SSE for Render."""
    port = int(os.environ.get("PORT", "8080"))
    print(f"Starting Ubuntu Terminal MCP Server on Render (Port: {port})...", flush=True)
    
    # We must use uvicorn to run the SSE app manually because FastMCP < 2 
    # doesn't handle port binding through run() directly.
    import uvicorn
    from mcp.server.fastmcp.sse import create_sse_app
    
    app = create_sse_app(mcp)
    uvicorn.run(app, host="0.0.0.0", port=port)

if __name__ == "__main__":
    main()