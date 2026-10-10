import asyncio
import os
import platform
import subprocess
import sys
from typing import Optional, Dict, Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, CallToolRequest

# Create standard MCP Server exactly like the antigravity bridge
app = Server("spark-terminal")

@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available terminal tools."""
    return [
        Tool(
            name="execute_terminal_command",
            description="Execute a terminal command on the host machine. Use this to run scripts, manage files, or get system information.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The command to execute (e.g., 'dir', 'ls', 'echo hello')"
                    },
                    "directory": {
                        "type": "string",
                        "description": "Optional: Working directory to run the command in. If not provided, runs in current directory."
                    }
                },
                "required": ["command"]
            }
        ),
        Tool(
            name="get_system_info",
            description="Get information about the operating system and current environment.",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool execution requests."""
    
    if name == "execute_terminal_command":
        command = arguments.get("command")
        directory = arguments.get("directory", os.getcwd())
        
        if not command:
            return [TextContent(type="text", text="Error: Command is required")]
            
        try:
            # Change directory if specified
            if directory and directory != os.getcwd():
                try:
                    os.chdir(directory)
                except Exception as e:
                    return [TextContent(type="text", text=f"Failed to change directory to {directory}: {str(e)}")]

            # Create process
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                shell=True
            )
            
            stdout, stderr = await process.communicate()
            
            out_str = stdout.decode('utf-8', errors='replace').strip()
            err_str = stderr.decode('utf-8', errors='replace').strip()
            
            result = ""
            if out_str:
                result += f"Output:\n{out_str}\n"
            if err_str:
                result += f"Error:\n{err_str}\n"
                
            if not result:
                result = f"Command executed successfully with return code {process.returncode} (No output)"
                
            return [TextContent(type="text", text=result)]
            
        except Exception as e:
            return [TextContent(type="text", text=f"Failed to execute command: {str(e)}")]
            
    elif name == "get_system_info":
        info = (
            f"OS: {platform.system()} {platform.release()}\n"
            f"Architecture: {platform.machine()}\n"
            f"Current Directory: {os.getcwd()}\n"
            f"Python Version: {sys.version.split()[0]}"
        )
        return [TextContent(type="text", text=info)]
        
    else:
        raise ValueError(f"Unknown tool: {name}")

async def main():
    """Run the server using stdio transport (required for standard Google Spark local connection)."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    # Windows event loop policy fix
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    asyncio.run(main())