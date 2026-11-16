import hmac
import json
import os
from urllib import error, parse, request

import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings


API_URL = os.environ.get("API_URL", "http://app:8000")
API_TOKEN = os.environ["API_TOKEN"]
MCP_TOKEN = os.environ["MCP_TOKEN"]
if len(MCP_TOKEN) < 16 or MCP_TOKEN.startswith("replace-with-"):
    raise ValueError("MCP_TOKEN must be a non-placeholder secret of at least 16 characters")

mcp = MCPServer("proxprox")
opener = request.build_opener(request.ProxyHandler({}))


def api_call(method: str, path: str, payload: dict | None = None) -> dict | list:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = request.Request(f"{API_URL}{path}", data=body, headers=headers, method=method)
    try:
        with opener.open(req, timeout=30) as response:
            if response.status == 204:
                return {"deleted": True}
            return json.load(response)
    except error.HTTPError as exc:
        details = exc.read(4096).decode("utf-8", errors="replace")
        raise RuntimeError(f"API {method} {path} failed with HTTP {exc.code}: {details}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"API {method} {path} could not reach {API_URL}: {exc.reason}") from exc


@mcp.tool()
def add_scope(program_slug: str, pattern: str, upstream: str = "", vpn: str = "") -> dict:
    """Register a scope. upstream and vpn are registered names, not URLs; administrators create them through the API."""
    return api_call("POST", "/v1/rules", {
        "program_slug": program_slug,
        "pattern": pattern,
        "upstream": upstream,
        "vpn": vpn,
    })


@mcp.tool()
def update_scope(rule_id: str, program_slug: str, pattern: str, upstream: str = "", vpn: str = "") -> dict:
    """Replace a scope by ID. Supply all route fields; upstream and vpn are registered names, not URLs."""
    path = f"/v1/rules/{parse.quote(rule_id, safe='')}"
    return api_call("PUT", path, {
        "program_slug": program_slug,
        "pattern": pattern,
        "upstream": upstream,
        "vpn": vpn,
    })


@mcp.tool()
def remove_scope(rule_id: str) -> dict:
    """Remove a scope rule by ID."""
    return api_call("DELETE", f"/v1/rules/{parse.quote(rule_id, safe='')}")


@mcp.tool()
def list_scopes(program_slug: str = "") -> list:
    """List scope rules, optionally filtered by program slug."""
    query = f"?{parse.urlencode({'program_slug': program_slug})}" if program_slug else ""
    return api_call("GET", f"/v1/rules{query}")


@mcp.tool()
def resolve_scope(host: str) -> dict:
    """Show the winning rule and route for a target host, including its program slug."""
    return api_call("GET", f"/v1/resolve?{parse.urlencode({'host': host})}")


@mcp.tool()
def get_configuration() -> dict:
    """List rules, upstream proxies and VPN gateways without upstream credentials."""
    return api_call("GET", "/v1/config")


transport_security = TransportSecuritySettings(
    allowed_hosts=["localhost:*", "127.0.0.1:*", "[::1]:*"] + [
        host.strip() for host in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if host.strip()
    ],
    allowed_origins=[
        origin.strip() for origin in os.environ.get("MCP_ALLOWED_ORIGINS", "").split(",") if origin.strip()
    ],
)
mcp_app = mcp.streamable_http_app(
    json_response=True,
    stateless_http=True,
    transport_security=transport_security,
)


async def app(scope: dict, receive, send) -> None:
    if scope["type"] == "http":
        headers = {key.lower(): value for key, value in scope["headers"]}
        supplied = headers.get(b"authorization", b"")
        expected = f"Bearer {MCP_TOKEN}".encode("utf-8")
        if not hmac.compare_digest(supplied, expected):
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"www-authenticate", b"Bearer"), (b"content-type", b"text/plain")],
            })
            await send({"type": "http.response.body", "body": b"Unauthorized"})
            return
    await mcp_app(scope, receive, send)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
