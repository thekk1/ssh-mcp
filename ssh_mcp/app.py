"""ssh-mcp: per-user SSH command execution for LibreChat.

One tool, ssh_exec(host, port, username, command) -- no host allowlist, no
command whitelist. That's a deliberate trade-off, not an oversight: unlike
jenkins-mcp ("alles ausser Groovy-Konsole"), there's no equivalent of
Jenkins' own permission matrix to lean on here, because every target host
is an arbitrary, un-enrolled machine. The only two boundaries are (1)
which LibreChat users even see this server at all -- enforced outside this
process, via LibreChat's group/role config-override fed by a Keycloak
group/role sync, not by anything in here -- and (2) the real Unix
permissions of whichever personal key a user brings. If (1) or (2) isn't
in place for a given deployment, this tool is exactly as dangerous as
handing that user a bare terminal.

Multi-user via LibreChat customUserVars -> per-request headers, same shape
as ews-mcp/jenkins-mcp: no MCP_API_KEY, no auth gate on the MCP connection
itself -- a 401 from any such gate makes LibreChat's non-OAuth MCP client
try (and get stuck on) OAuth. Docker network isolation is the only
transport-level boundary; everything else is (1) and (2) above.

Host key handling is genuine TOFU (see hostkeys.HostKeyStore) -- first
contact to a host:port pins its key fingerprint, every later connection
must match it exactly or gets refused, rather than trusting every
handshake unconditionally.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
from typing import Any, Optional

import asyncssh
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route, Router

from .hostkeys import HostKeyStore

logger = logging.getLogger(__name__)

PORT = int(os.environ.get("PORT", "8080"))
HOST_KEY_STORE_PATH = os.environ.get("HOST_KEY_STORE_PATH", "/data/host_keys.json")
DEFAULT_TIMEOUT_SECONDS = 30
CONNECT_TIMEOUT_SECONDS = 10

# Header names the LibreChat customUserVars -> headers mapping targets (see
# README for the librechat.yaml block). Lowercased: Starlette's Headers
# lookup is case-insensitive, but the constant is written the way it's
# actually sent so a grep for the real wire value finds this too.
PRIVATE_KEY_HEADER = "x-ssh-private-key"
PASSPHRASE_HEADER = "x-ssh-key-passphrase"

_INSTRUCTIONS = (
    "Fuehrt Shell-Befehle per SSH auf einem beliebigen Zielserver aus, mit "
    "dem persoenlichen SSH-Key des aktuellen Chat-Nutzers -- kein "
    "geteilter Account. Es gibt keine Server- oder Kommando-Einschraenkung "
    "durch dieses Tool selbst: die tatsaechlichen Rechte kommen "
    "ausschliesslich vom Unix-Account, zu dem der hinterlegte Key gehoert. "
    "Host-Keys werden per Trust-On-First-Use gepinnt -- bei einer "
    "Aenderung gegenueber dem ersten Kontakt schlaegt die Verbindung fehl, "
    "statt sie stillschweigend zu akzeptieren."
)

TOOL = types.Tool(
    name="ssh_exec",
    description=(
        "Fuehrt einen Shell-Befehl per SSH auf einem Zielserver aus, "
        "authentifiziert mit dem persoenlichen SSH-Key des aktuellen "
        "Chat-Nutzers. Kein Host- oder Kommando-Filter -- die Rechte "
        "ergeben sich allein aus dem Ziel-Account des Keys."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Hostname oder IP des Zielservers"},
            "port": {"type": "integer", "description": "SSH-Port", "default": 22},
            "username": {"type": "string", "description": "Login-Benutzername auf dem Zielserver"},
            "command": {"type": "string", "description": "Auszufuehrender Shell-Befehl"},
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout in Sekunden fuer die Befehlsausfuehrung",
                "default": DEFAULT_TIMEOUT_SECONDS,
            },
        },
        "required": ["host", "username", "command"],
    },
    annotations=types.ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True,
    ),
)


class CredentialError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def extract_credentials(request: Optional[Request]) -> tuple[bytes, Optional[str]]:
    if request is None:
        raise CredentialError(
            "No request context available -- ssh-mcp only works over the "
            "streamable-http transport, which carries the per-request "
            "credential headers."
        )
    raw_key = request.headers.get(PRIVATE_KEY_HEADER)
    if not raw_key:
        raise CredentialError(
            f"Missing '{PRIVATE_KEY_HEADER}' header -- configure "
            "SSH_PRIVATE_KEY (base64-encoded private key) in LibreChat's "
            "customUserVars for this server."
        )
    try:
        key_bytes = base64.b64decode(raw_key, validate=True)
    except Exception as exc:
        raise CredentialError(
            f"'{PRIVATE_KEY_HEADER}' is not valid base64: {exc}"
        ) from None
    passphrase = request.headers.get(PASSPHRASE_HEADER) or None
    return key_bytes, passphrase


class _TofuClient(asyncssh.SSHClient):
    """Pins the first host key seen for (host, port); rejects any later
    connection whose presented key doesn't match that pin exactly.

    validate_host_public_key is synchronous and only gets called at all
    when known_hosts isn't None (see asyncssh.connection: known_hosts=None
    skips host key checking entirely) -- app.py passes known_hosts=b"" for
    exactly that reason, so every connection actually reaches this.
    """

    def __init__(self, store: HostKeyStore, host: str, port: int) -> None:
        self._store = store
        self._host = host
        self._port = port

    def validate_host_public_key(
        self, host: str, addr: str, port: int, key: asyncssh.SSHKey,
    ) -> bool:
        fingerprint = key.get_fingerprint("sha256")
        known = self._store.get(self._host, self._port)
        if known is None:
            self._store.put(self._host, self._port, fingerprint)
            logger.info("ssh-mcp: pinned new host key for %s:%s", self._host, self._port)
            return True
        return known == fingerprint


async def run_ssh_command(
    store: HostKeyStore,
    key_bytes: bytes,
    passphrase: Optional[str],
    host: str,
    port: int,
    username: str,
    command: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    try:
        client_key = asyncssh.import_private_key(key_bytes, passphrase=passphrase)
    except asyncssh.KeyImportError as exc:
        return {"ok": False, "error": {"code": "invalid_key", "message": str(exc)}}

    try:
        conn, _client = await asyncssh.create_connection(
            lambda: _TofuClient(store, host, port),
            host,
            port=port,
            username=username,
            client_keys=[client_key],
            known_hosts=b"",  # disables asyncssh's own file-based known_hosts
            # matching (there is none in this container) so every
            # connection falls through to _TofuClient.validate_host_public_key
            # above instead.
            connect_timeout=CONNECT_TIMEOUT_SECONDS,
        )
    except asyncssh.HostKeyNotVerifiable as exc:
        return {
            "ok": False,
            "error": {
                "code": "host_key_mismatch",
                "message": (
                    f"Host key for {host}:{port} does not match the key "
                    f"pinned on first contact ({exc}). Possible MITM, or a "
                    "legitimate host key rotation -- needs a manual review "
                    "of the pinned entry before retrying."
                ),
            },
        }
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        return {"ok": False, "error": {"code": "connection_failed", "message": str(exc)}}

    try:
        result = await conn.run(command, check=False, timeout=timeout_seconds)
        return {
            "ok": True,
            "exit_code": result.exit_status,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except TimeoutError:
        return {
            "ok": False,
            "error": {
                "code": "timeout",
                "message": f"command did not finish within {timeout_seconds}s",
            },
        }
    except asyncssh.Error as exc:
        return {"ok": False, "error": {"code": "execution_failed", "message": str(exc)}}
    finally:
        conn.close()
        with contextlib.suppress(Exception):
            await conn.wait_closed()


def build_server(store: HostKeyStore) -> Server:
    server: Server = Server("ssh-mcp", instructions=_INSTRUCTIONS)

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [TOOL]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
        if name != TOOL.name:
            payload = {
                "ok": False,
                "error": {"code": "unknown_tool", "message": f"Unknown tool: {name}"},
            }
            return [types.TextContent(type="text", text=json.dumps(payload))]

        try:
            request = server.request_context.request
        except LookupError:
            request = None

        try:
            key_bytes, passphrase = extract_credentials(request)
        except CredentialError as exc:
            payload = {
                "ok": False,
                "error": {"code": "missing_credentials", "message": exc.message},
            }
            return [types.TextContent(type="text", text=json.dumps(payload))]

        payload = await run_ssh_command(
            store,
            key_bytes,
            passphrase,
            host=arguments["host"],
            port=int(arguments.get("port", 22)),
            username=arguments["username"],
            command=arguments["command"],
            timeout_seconds=int(arguments.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
        )
        return [types.TextContent(type="text", text=json.dumps(payload))]

    return server


class _MCPEndpoint:
    """Class instance, not a function -- Starlette only treats instances as
    raw ASGI (see Route.__init__); a function gets wrapped as
    func(request)->Response and, if mounted by prefix, 307-redirects a bare
    path, which LibreChat's MCP client blocks as SSRF hardening against
    private/reserved addresses (every Docker-internal MCP address
    qualifies) -- broke a companion project (time-mcp-http) live. Route
    with a class-instance endpoint never redirects.
    """

    def __init__(self) -> None:
        self._session_manager: Optional[StreamableHTTPSessionManager] = None

    async def __call__(self, scope, receive, send) -> None:
        if self._session_manager is None:
            response = PlainTextResponse("starting up", status_code=503)
            await response(scope, receive, send)
            return
        await self._session_manager.handle_request(scope, receive, send)


def build_app() -> Router:
    endpoint = _MCPEndpoint()
    store = HostKeyStore(HOST_KEY_STORE_PATH)

    async def livez(_request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    async def readyz(_request: Request) -> PlainTextResponse:
        if endpoint._session_manager is None:
            return PlainTextResponse("not ready", status_code=503)
        return PlainTextResponse("ok")

    @contextlib.asynccontextmanager
    async def lifespan(_app: Router):
        server = build_server(store)
        session_manager = StreamableHTTPSessionManager(
            app=server, json_response=False, stateless=True,
        )
        async with session_manager.run():
            endpoint._session_manager = session_manager
            logger.info("ssh-mcp up, host key store=%s", HOST_KEY_STORE_PATH)
            yield
        endpoint._session_manager = None

    return Router(
        routes=[
            Route("/livez", livez),
            Route("/readyz", readyz),
            Route("/mcp", endpoint, methods=["GET", "POST", "DELETE"]),
        ],
        lifespan=lifespan,
    )
