# ssh-mcp

Per-user SSH command execution for LibreChat assistants: one tool,
`ssh_exec(host, port, username, command)`, authenticated with the calling
chat user's own personal SSH private key -- never a shared service
account. Deployed as a plain streamable-HTTP Docker service (no `ports:`
exposed publicly, no per-user OAuth at the MCP layer), same shape as
`ews-mcp`'s multi-user mode and `jenkins-mcp`.

## Why this exists (and why it's custom code, not a wrapper)

Unlike Jenkins, where `mcp-jenkins` already ships exactly the header-based
multi-user auth needed, no existing open-source SSH MCP server checked
(`vignitin/multi-ssh-mcp`, `giuliolibrando/ssh-mcp-server`,
`tufantunc/ssh-mcp`) supports per-request credentials at all -- every one
of them bakes a single host/user/credential into environment variables or
a config file at startup. So this is a small (~150 line) purpose-built
server against [`asyncssh`](https://asyncssh.readthedocs.io/), not a
wrapper around someone else's CLI.

## How it works

```
LibreChat --(streamable-http, /mcp, per-user headers)--> ssh-mcp
                                                              |
                                                              | asyncssh,
                                                              | one connection
                                                              | per tool call
                                                              v
                                                        arbitrary target host
```

**Credentials**, via LibreChat's `customUserVars` -> per-request headers
(same mechanism as `ews-mcp`/`jenkins-mcp`):

- `x-ssh-private-key` -- the user's personal private key, **base64-encoded**
  (a raw multi-line PEM block can't survive as an HTTP header value)
- `x-ssh-key-passphrase` -- optional, if that key is passphrase-protected

Decoded once per tool call, handed straight to `asyncssh`, never written to
disk, never cached across requests.

**No host allowlist, no command whitelist.** `ssh_exec` accepts whatever
host/port/username/command the model passes. That's a deliberate
trade-off, not an oversight: unlike `jenkins-mcp`'s "everything except the
Groovy console," there's no equivalent built-in permission matrix to lean
on for an arbitrary SSH target. The only two things standing between a
chat message and a real shell are:

1. **Which LibreChat users can even see this server** -- not enforced by
   this code at all, see "Restricting visibility" below.
2. **The real Unix permissions of whatever key a user brings.**

If either of those isn't actually in place, this tool is exactly as
dangerous as handing that user a bare terminal on every host their key
opens.

**Host keys use genuine TOFU** (`ssh_mcp/hostkeys.py`), not "accept
anything, always": the first connection to a given `host:port` pins its
key fingerprint to a JSON file on a volume; every later connection must
match that pin exactly or gets refused with `host_key_mismatch`. This
can't stop a MITM on the very first contact with a host, but it turns an
unannounced key change afterwards -- rotation or a real MITM -- into a
loud, explicit failure instead of a silent hole.

No `MCP_API_KEY`, no auth gate on the MCP connection itself --
deliberately, same reasoning as every other BOS MCP: a 401 from any gate
makes LibreChat's non-OAuth MCP client try (and get stuck on) OAuth.
Docker network isolation is the transport-level boundary; real access
control lives one layer up, in LibreChat.

## Missing host/username: asked via MCP elicitation, not guessed by the model

`host` and `username` are deliberately **not** in the tool's `required`
schema fields (`command` stays required -- deciding *what to run* is the
model's job, not a human's). Making host/username required would make a
spec-compliant model refuse to even call the tool without them and
improvise a plain-text follow-up question itself instead -- which is
exactly the bad UX this replaces. When either is missing,
`ssh_mcp/app.py`'s `elicit_missing_ssh_args()` asks the *human* directly,
in **one combined form**, via [MCP elicitation](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation)
(`elicitation/create`, form mode) -- not something the model has to phrase
itself, and not two or three separate round trips for host/username/port.
`port` rides along in that same form, pre-filled with its usual default
(22) via the schema's `default`, editable but not itself a reason to
interrupt when it's the only thing unset.

**This degrades safely if the client doesn't support it.** As of this
writing, LibreChat's MCP client does **not** implement elicitation at all
-- confirmed: its `initialize` handshake always sends `elicitation: null`
in `ClientCapabilities`. (The form-like UI some users may have seen
elsewhere in LibreChat, `ask_user_question`, is a separate, LibreChat-native
*agent tool* the model calls directly -- unrelated to the MCP protocol and
not something any MCP server, this one included, can trigger. Real MCP
elicitation support remains an open request:
[Discussion #8681](https://github.com/danny-avila/LibreChat/discussions/8681),
[Issue #11526](https://github.com/danny-avila/LibreChat/issues/11526).)
`elicit_missing_ssh_args()` checks `session.check_client_capability(...)`
before ever sending a request, and catches any failure from the call
itself; either way it falls back to plain `missing_host`/`missing_username`
errors the model can still relay as text questions, rather than the tool
call erroring out or hanging. This is forward-compatible, inert-but-free
groundwork, not something currently doing anything for LibreChat users --
kept because it costs nothing and activates automatically the moment any
client (LibreChat or otherwise) adds real elicitation support, no code
changes needed here.

Verified with a real `ClientSession` via `mcp.shared.memory`'s in-memory
transport: with and without an `elicitation_callback` registered, the
accept/decline/cancel branches, and a full combined form (host + username
missing, port's default overridden) -- confirmed all three values actually
reach the SSH call exactly as elicited, not just asserted from reading the
spec.

## Restricting visibility to specific users

**No SSO/Bearer validation needed inside this MCP.** LibreChat itself
(0.8.5+) has a DB-backed config override system (Admin Panel ->
Configuration Management) that scopes an additional `mcpServers` entry to
a specific role or group -- at login, a user's effective config is the
base config merged with whatever overrides apply to them. A user outside
the group simply doesn't have the `ssh` entry in their resolved config;
it's not hidden UI, it's absent. Keycloak groups/roles can feed that
directly via `OPENID_SYNC_GROUPS_FROM_TOKEN` +
`OPENID_GROUPS_CLAIM_PATH=realm_access.roles` + `OPENID_TREAT_ROLES_AS_GROUPS`.

Two caveats worth checking live before relying on this, not assuming:

- The feature is documented as **"in preview,"** not GA.
- There was a real bug ([#13172](https://github.com/danny-avila/LibreChat/issues/13172),
  May 2026) where group-scoped overrides silently didn't apply while
  role-scoped ones did; closed via PR #13176, but confirm your running
  LibreChat version actually includes the fix -- put a test user in/out of
  the group and check whether `ssh` actually (dis)appears, don't just
  trust the changelog.

## Run

```bash
docker build -t ssh-mcp .
docker run --rm -p 8080:8080 -v ssh-mcp-hostkeys:/data ssh-mcp
```

The `/data` volume is what makes TOFU pins survive a container recreate --
without it, every redeploy forgets every previously-seen host key and
re-pins on next contact (not a security hole, just loses the "detect a
later change" property until the fleet's been re-contacted once).

## Deploy (BOS pattern)

`docker-compose.yml`:

```yaml
  ssh-mcp:
    build: /home/bos/ssh-mcp   # git clone https://github.com/thekk1/ssh-mcp
    container_name: ssh-mcp
    volumes:
      - ssh-mcp-hostkeys:/data
    restart: always

volumes:
  ssh-mcp-hostkeys:
```

`librechat.yaml` -- both `customUserVars` entries need **both** `title`
*and* `description`, or LibreChat's config Zod schema fails at startup
with a confusing multi-branch `invalid_union` error (see `ews-mcp`'s
jenkins-mcp writeup for the exact failure shape):

```yaml
mcpSettings:
  allowedAddresses:
    - 'ssh-mcp:8080'

mcpServers:
  ssh:
    type: streamable-http
    url: http://ssh-mcp:8080/mcp
    serverInstructions: true
    headers:
      X-SSH-Private-Key: '{{SSH_PRIVATE_KEY}}'
      X-SSH-Key-Passphrase: '{{SSH_KEY_PASSPHRASE}}'
    customUserVars:
      SSH_PRIVATE_KEY:
        title: "SSH-Private-Key (Base64)"
        description: "Dein persoenlicher SSH-Private-Key, Base64-kodiert: `base64 -w0 ~/.ssh/id_ed25519`"
      SSH_KEY_PASSPHRASE:
        title: "SSH-Key-Passphrase (optional)"
        description: "Nur ausfuellen, falls dein privater Key passphrase-geschuetzt ist"
```

Restart LibreChat after editing -- `librechat.yaml` is read once at
container startup, no hot-reload.

## Verify

```bash
curl -s http://127.0.0.1:8080/readyz   # "ok" once the session manager is up
```

Verified end-to-end manually (not just unit-tested): built the image, ran
it, connected a real MCP client over streamable-http with the credential
headers, `tools/list` showed `ssh_exec`, `tools/call` against a live
throwaway `asyncssh`-based SSH server executed a real command over a real
SSH handshake and returned its actual stdout. Also exercised directly
(bypassing the HTTP layer) against that same throwaway server: TOFU pin on
first contact, acceptance on a matching second contact, hard rejection on
a changed/mismatched host key, a garbage private key rejected as
`invalid_key`, an unauthorized key rejected as `connection_failed`, and a
non-zero remote exit code passed through as `ok: true` with that exit
code (not treated as a tool failure).

## Test

```bash
pip install -e '.[dev]'
pytest
```

Unit tests (credential-header parsing, TOFU pin/accept/reject logic, tool
schema, `elicit_missing_ssh_args`'s capability-check/field-selection/
accept/decline/cancel/failure branches against a fake session) -- no real
network, subprocess, or MCP transport. The real-handshake scenarios and
the real `ClientSession` elicitation round trips (see above) were run
manually, not part of the automated suite.
