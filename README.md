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

Unit tests only (credential-header parsing, TOFU pin/accept/reject logic,
tool schema) -- no real network or subprocess. The real-handshake
scenarios above were run manually against a throwaway local SSH server,
not part of the automated suite.
