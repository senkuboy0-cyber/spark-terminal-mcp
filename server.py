import asyncio
import subprocess
import os
import platform
from typing import Optional
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# Initialize FastMCP Server
mcp = FastMCP(
    "Google Spark Terminal MCP",
    dependencies=["pydantic", "fastmcp"]
)

# Request Models
class CommandRequest(BaseModel):
    command: str = Field(description="The terminal command to execute")
    cwd: Optional[str] = Field(None, description="Working directory to run the command in")

class SystemInfoResponse(BaseModel):
    os: str
    release: str
    architecture: str
    current_directory: str

@mcp.tool()
async def execute_command(command: str, cwd: str = None) -> str:
    """
    Execute a terminal command on the host machine and return the output.
    
    Args:
        command (str): The command to run (e.g., 'ls -la', 'dir', 'echo hello').
        cwd (str, optional): The directory where the command should be executed.
        
    Returns:
        str: The standard output or error message from the command.
    """
    try:
        # Use shell=True for complex commands (pipes, redirects)
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd if cwd else os.getcwd()
        )
        
        stdout, stderr = await process.communicate()
        
        # Decode output
        out = stdout.decode('utf-8').strip()
        err = stderr.decode('utf-8').strip()
        
        if process.returncode == 0:
            return out if out else "Command executed successfully with no output."
        else:
            return f"Error [{process.returncode}]:\n{err}"
            
    except Exception as e:
        return f"Failed to execute command: {str(e)}"

@mcp.tool()
def get_system_info() -> str:
    """
    Get information about the host operating system.
    
    Returns:
        str: Basic system information.
    """
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

@mcp.tool()
def change_directory(path: str) -> str:
    """
    Change the current working directory of the MCP server.
    
    Args:
        path (str): The path to navigate to.
        
    Returns:
        str: Success or error message.
    """
    try:
        os.chdir(path)
        return f"Successfully changed directory to: {os.getcwd()}"
    except FileNotFoundError:
        return f"Error: Directory not found: {path}"
    except Exception as e:
        return f"Error changing directory: {str(e)}"

def main():
    """Start the MCP server"""
    print("Starting Google Spark Terminal MCP Server...", flush=True)
    
    # Check if running on a cloud service like Render (they provide a PORT environment variable)
    port = os.environ.get("PORT")
    
    if port:
        print(f"Running on cloud (SSE transport) on port {port}...", flush=True)
        # Cloud deployments require a web server (SSE) binding to a port
        mcp.run(transport="sse", host="0.0.0.0", port=int(port))
    else:
        print("Running locally (STDIO transport)...", flush=True)
        # Local deployments use standard input/output
        mcp.run(transport="stdio")

if __name__ == "__main__":
    main()