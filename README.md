# ssh-mcp

An [MCP](https://modelcontextprotocol.io/) server that lets an LLM run
shell commands over SSH, authenticated with each user's own personal SSH
key rather than a single shared service account. Built for multi-user
chat platforms (e.g. [LibreChat](https://www.librechat.ai/)) where the
server is shared but the SSH identity per request should not be.

One tool: `ssh_exec(host, port, username, command)`. No host allowlist, no
command whitelist -- see "Security model" below for why, and what that
means for anyone deploying this.

## Why this exists

A few existing open-source SSH MCP servers were checked before writing
this one (`vignitin/multi-ssh-mcp`, `giuliolibrando/ssh-mcp-server`,
`tufantunc/ssh-mcp`). None of them support per-request credentials: every
one bakes a single host/user/credential into environment variables or a
config file at startup, which only works for a single-user deployment or
a shared service account. None of that fits a setup where many different
people, each with their own SSH key, share one running MCP server.

So this is a small, purpose-built server against
[`asyncssh`](https://asyncssh.readthedocs.io/) rather than a wrapper
around an existing tool -- there was nothing suitable to wrap.

## How it works

```
MCP client --(streamable-http, /mcp, per-request headers)--> ssh-mcp
                                                                  |
                                                                  | asyncssh,
                                                                  | one connection
                                                                  | per tool call
                                                                  v
                                                            arbitrary target host
```

**Credentials travel as per-request HTTP headers**, not server
configuration:

- `x-ssh-private-key` -- the private key to authenticate with, **base64-encoded**
  (a raw multi-line PEM block can't survive as an HTTP header value)
- `x-ssh-key-passphrase` -- optional, if that key is passphrase-protected

Both are read fresh on every tool call, decoded, handed straight to
`asyncssh`, and then discarded -- nothing is written to disk, and nothing
is cached across requests. It's the calling client's job to attach the
right headers for the right user; see "Using this with LibreChat" below
for one way to do that.

**Host keys use genuine trust-on-first-use (TOFU)**, not "accept anything,
always": the first connection to a given `host:port` pins its key
fingerprint to a JSON file on disk (`hostkeys.py`); every later connection
must match that pin exactly or gets refused with `host_key_mismatch`. This
can't stop a machine-in-the-middle attack on the very first contact with a
host, but it turns an unannounced key change afterwards -- rotation or a
real attack -- into a loud, explicit failure instead of a silent hole.

No API key or bearer-token gate on the MCP connection itself. That's a
deliberate simplicity choice for a specific deployment shape: a server
reachable only from a trusted internal network, where the client attaches
per-user SSH credentials itself (see below) and network placement is the
actual access boundary. If you're exposing this somewhere less trusted,
put a gate in front of it -- this project doesn't include one.

## Security model

`ssh_exec` does not filter which hosts, commands, or users are allowed.
Whatever host/port/username/command a caller passes gets attempted, full
stop. That's a deliberate trade-off, not an oversight: filtering by host
or command from inside the MCP server would be security theater, since
any caller with a valid key can just SSH there directly outside this tool
too. The two things that actually stand between a request and a real
shell are:

1. **Whoever can reach this server and set the credential headers at
   all** -- entirely outside this code's control. If you're deploying
   this behind a multi-tenant client, restricting which of your users can
   even see/use this tool is that client's job (see "Using this with
   LibreChat" for one concrete way to do it).
2. **The real Unix permissions attached to whichever key gets used.**
   `ssh_exec` runs with exactly the authority that key's target account
   has -- nothing more, nothing less.

If neither of those is actually enforced for a given deployment, this
tool is exactly as dangerous as handing every caller a bare terminal on
every host their key can reach. That's the intended model -- SSH's own
authorization, not a reimplementation of it -- so make sure it's a model
you actually want before deploying this.

## Missing host/username: asked via MCP elicitation, not guessed by the model

`host` and `username` are deliberately **not** in the tool's `required`
schema fields (`command` stays required -- deciding *what to run* is the
model's job, not a human's). Making host/username required would make a
spec-compliant model refuse to even call the tool without them and
improvise a plain-text follow-up question itself instead -- which is
exactly the UX this avoids. When either is missing, `elicit_missing_ssh_args()`
in `ssh_mcp/app.py` asks the *human* directly, in **one combined form**,
via [MCP elicitation](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation)
(`elicitation/create`, form mode) -- not something the model has to phrase
itself, and not separate round trips per field. `port` rides along in
that same form, pre-filled with its usual default (22) via the schema's
`default`, editable but not itself a reason to interrupt when it's the
only thing unset.

**This degrades safely on a client that doesn't support elicitation.**
`elicit_missing_ssh_args()` checks the client's declared capability
(`session.check_client_capability(...)`) before ever sending a request,
and catches any failure from the call itself; either way it falls back to
plain `missing_host`/`missing_username` errors the model can still relay
as text questions, rather than the tool call erroring out or hanging.
Elicitation support varies by client -- at the time of writing, several
popular MCP clients (including LibreChat) don't implement it yet, so this
mostly acts as forward-compatible groundwork today. It costs nothing when
unsupported and activates automatically on any client that adds real
elicitation support later, with no changes needed here.

Verified with a real `ClientSession` via `mcp.shared.memory`'s in-memory
transport: with and without an `elicitation_callback` registered, the
accept/decline/cancel branches, and a full combined form (host + username
missing, port's default overridden) -- confirmed all three values actually
reach the SSH call exactly as elicited, not just asserted from reading the
spec.

## Using this with LibreChat

LibreChat can attach per-user values to MCP request headers via
[`customUserVars`](https://www.librechat.ai/docs/configuration/librechat_yaml/object_structure/mcp_servers)
-- each user enters their own key once in Settings, and LibreChat injects
it into the configured header on every request for that user. `librechat.yaml`:

```yaml
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
        title: "SSH Private Key (Base64)"
        description: "Your personal SSH private key, base64-encoded: `base64 -w0 ~/.ssh/id_ed25519`"
      SSH_KEY_PASSPHRASE:
        title: "SSH Key Passphrase (optional)"
        description: "Only fill in if your private key is passphrase-protected"
```

Both `customUserVars` entries need **both** `title` *and* `description` --
a `title`-only entry fails LibreChat's config validation at startup with a
`ZodError` that, confusingly, gets reported against unrelated-looking
fields (LibreChat validates the whole `mcpServers` block as one union of
transport types, so one missing field surfaces as several apparently
unrelated errors at once). `librechat.yaml` is only read at container
startup -- restart LibreChat after editing it.

### Restricting which users can see this server

Nothing in this project restricts who can use it -- any user who can set
the `SSH_PRIVATE_KEY` header can call `ssh_exec`. If you need to limit
that to a subset of your users, that has to happen in LibreChat (or
whatever client you're using), not here. As of LibreChat 0.8.5+, its
admin panel has a config-override system (Configuration Management) that
can scope an additional `mcpServers` entry to a specific role or group --
a user outside that group has no `ssh` entry in their resolved config at
all, not just a hidden one. Two things worth checking against your own
LibreChat version before relying on this, rather than assuming:

- It's documented as **"in preview,"** not GA, as of this writing.
- There's a known history of group-scoped overrides silently not applying
  while role-scoped ones did ([danny-avila/LibreChat#13172](https://github.com/danny-avila/LibreChat/issues/13172)).
  Confirm the fix is in your running version by testing directly -- put a
  user in/out of the group and check whether the server actually
  (dis)appears for them.

## Run

```bash
docker build -t ssh-mcp .
docker run --rm -p 8080:8080 -v ssh-mcp-hostkeys:/data ssh-mcp
```

The `/data` volume is what makes TOFU host-key pins survive a container
recreate -- without it, every redeploy forgets every previously-seen host
key and re-pins on next contact (not a security hole, just a temporary
loss of the "detect a later change" property until each host has been
re-contacted once).

Example `docker-compose.yml` service, building from a local clone:

```yaml
services:
  ssh-mcp:
    build: .
    container_name: ssh-mcp
    volumes:
      - ssh-mcp-hostkeys:/data
    restart: always

volumes:
  ssh-mcp-hostkeys:
```

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
