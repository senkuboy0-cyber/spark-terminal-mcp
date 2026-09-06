# Spark Terminal MCP

A **Gemini Spark**-compatible MCP server with 30+ terminal tools — deployed on Render.

## What this is

Gemini Spark requires custom Connected Apps to expose a full **OAuth 2.1** discovery chain before it will call any tools:

| Spec | Endpoint | Purpose |
|---|---|---|
| RFC 9728 | `/.well-known/oauth-protected-resource` | Discover which auth server protects the tools |
| RFC 8414 | `/.well-known/oauth-authorization-server` | Find token/registration/authorize endpoints |
| RFC 7591 | `/api/oauth/register` | Dynamic Client Registration (auto-register) |
| RFC 7636 | `/authorize` + `/api/oauth/token` | PKCE authorization-code flow |

This server implements all four, plus the **Streamable HTTP MCP transport** that Spark uses.

## Tools (30+)

| Group | Tools |
|---|---|
| Command Execution | `execute_command`, `run_python_code`, `stream_output`, `get_process_output`, `kill_process` |
| File Management | `read_file`, `write_file`, `delete_file`, `move_file`, `copy_file`, `list_directory`, `create_directory` |
| Web & Internet | `fetch_url`, `download_file_from_url`, `search_web`, `http_request` |
| Package & System | `install_package`, `get_system_info`, `list_processes`, `check_disk_space`, `view_logs` |
| Text Processing | `grep_file`, `find_files`, `replace_in_file` |
| Git | `git_clone`, `git_status`, `git_commit`, `git_push`, `git_pull` |
| Archive | `compress_files`, `extract_archive` |
| Network | `ping_host`, `check_port`, `get_ip_info` |
| System | `change_permissions`, `get_env_variable`, `set_env_variable` |
| Downloads | `get_download_url`, `clear_terminal` |

## Deploy to Render

1. Fork / clone this repo
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect this repo, select **Docker** runtime
4. Set env var `JWT_SIGNING_KEY` to a random 64-char hex string
5. Deploy — get your `https://spark-terminal-mcp.onrender.com` URL

## Connect to Gemini Spark

1. Go to [gemini.google.com](https://gemini.google.com)
2. Switch to **Spark** mode
3. Settings & help → Connected Apps → **Add a custom app**
4. Enter your Render URL: `https://spark-terminal-mcp.onrender.com`
5. Follow OAuth flow — click Connect

## Local dev

```bash
pip install -r requirements.txt
AUTH_BYPASS=true python3 server.py
# Server on http://localhost:8080
# MCP endpoint: http://localhost:8080/mcp
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP port |
| `AUTH_BYPASS` | `false` | Set `true` to skip auth (local dev only) |
| `JWT_SIGNING_KEY` | auto-generated | Secret for signing JWT tokens |
