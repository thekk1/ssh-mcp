import base64

import pytest
from starlette.requests import Request

from ssh_mcp.app import (
    PASSPHRASE_HEADER,
    PRIVATE_KEY_HEADER,
    TOOL,
    CredentialError,
    _TofuClient,
    elicit_missing_ssh_args,
    extract_credentials,
)
from ssh_mcp.hostkeys import HostKeyStore


def _request(headers: dict) -> Request:
    scope = {
        "type": "http",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }
    return Request(scope)


def test_extract_credentials_no_request_raises():
    with pytest.raises(CredentialError, match="No request context"):
        extract_credentials(None)


def test_extract_credentials_missing_header_raises():
    with pytest.raises(CredentialError, match=PRIVATE_KEY_HEADER):
        extract_credentials(_request({}))


def test_extract_credentials_invalid_base64_raises():
    request = _request({PRIVATE_KEY_HEADER: "not-valid-base64!!"})
    with pytest.raises(CredentialError, match="not valid base64"):
        extract_credentials(request)


def test_extract_credentials_valid_key_no_passphrase():
    raw = base64.b64encode(b"fake-pem-bytes").decode()
    request = _request({PRIVATE_KEY_HEADER: raw})
    key_bytes, passphrase = extract_credentials(request)
    assert key_bytes == b"fake-pem-bytes"
    assert passphrase is None


def test_extract_credentials_passphrase_passed_through():
    raw = base64.b64encode(b"fake-pem-bytes").decode()
    request = _request({PRIVATE_KEY_HEADER: raw, PASSPHRASE_HEADER: "s3cr3t"})
    _key_bytes, passphrase = extract_credentials(request)
    assert passphrase == "s3cr3t"


def test_tool_has_no_host_or_command_restriction_in_schema():
    props = TOOL.inputSchema["properties"]
    assert set(props) == {"host", "port", "username", "command", "timeout_seconds"}
    assert TOOL.inputSchema["required"] == ["command"]


class _FakeKey:
    def __init__(self, fingerprint: str) -> None:
        self._fingerprint = fingerprint

    def get_fingerprint(self, _hash_name: str = "sha256") -> str:
        return self._fingerprint


def test_tofu_client_pins_and_accepts_first_key(tmp_path):
    store = HostKeyStore(str(tmp_path / "host_keys.json"))
    client = _TofuClient(store, "example.com", 22)
    accepted = client.validate_host_public_key(
        "example.com", "1.2.3.4", 22, _FakeKey("sha256:aaa"),
    )
    assert accepted is True
    assert store.get("example.com", 22) == "sha256:aaa"


def test_tofu_client_accepts_matching_key_on_later_contact(tmp_path):
    store = HostKeyStore(str(tmp_path / "host_keys.json"))
    store.put("example.com", 22, "sha256:aaa")
    client = _TofuClient(store, "example.com", 22)
    accepted = client.validate_host_public_key(
        "example.com", "1.2.3.4", 22, _FakeKey("sha256:aaa"),
    )
    assert accepted is True


def test_tofu_client_rejects_mismatched_key(tmp_path):
    store = HostKeyStore(str(tmp_path / "host_keys.json"))
    store.put("example.com", 22, "sha256:aaa")
    client = _TofuClient(store, "example.com", 22)
    accepted = client.validate_host_public_key(
        "example.com", "1.2.3.4", 22, _FakeKey("sha256:different"),
    )
    assert accepted is False
    assert store.get("example.com", 22) == "sha256:aaa"


class _FakeElicitResult:
    def __init__(self, action: str, content: dict | None = None) -> None:
        self.action = action
        self.content = content


class _FakeSession:
    def __init__(self, elicitation_supported: bool, result=None, raise_exc=None) -> None:
        self._elicitation_supported = elicitation_supported
        self._result = result
        self._raise_exc = raise_exc
        self.elicit_calls: list[tuple] = []

    def check_client_capability(self, _capability) -> bool:
        return self._elicitation_supported

    async def elicit_form(self, message, requestedSchema):
        self.elicit_calls.append((message, requestedSchema))
        if self._raise_exc is not None:
            raise self._raise_exc
        return self._result


@pytest.mark.asyncio
async def test_elicit_nothing_missing_returns_none_and_never_asks():
    session = _FakeSession(elicitation_supported=True)
    result = await elicit_missing_ssh_args(session, {"host": "example.com", "username": "marc"})
    assert result is None
    assert session.elicit_calls == []


@pytest.mark.asyncio
async def test_elicit_no_session_returns_none():
    result = await elicit_missing_ssh_args(None, {"host": "example.com"})
    assert result is None


@pytest.mark.asyncio
async def test_elicit_unsupported_client_returns_none_and_never_asks():
    session = _FakeSession(elicitation_supported=False)
    result = await elicit_missing_ssh_args(session, {"host": "example.com"})
    assert result is None
    assert session.elicit_calls == []


@pytest.mark.asyncio
async def test_elicit_only_asks_for_the_missing_fields():
    session = _FakeSession(
        elicitation_supported=True,
        result=_FakeElicitResult(action="accept", content={"username": "marc"}),
    )
    result = await elicit_missing_ssh_args(session, {"host": "10.49.8.87", "port": 2222})
    assert result == {"username": "marc"}
    message, schema = session.elicit_calls[0]
    assert set(schema["properties"]) == {"username"}
    assert schema["required"] == ["username"]


@pytest.mark.asyncio
async def test_elicit_both_missing_bundles_port_as_prefilled_default():
    session = _FakeSession(
        elicitation_supported=True,
        result=_FakeElicitResult(
            action="accept", content={"host": "10.49.8.87", "username": "marc", "port": 2222},
        ),
    )
    result = await elicit_missing_ssh_args(session, {})
    assert result == {"host": "10.49.8.87", "username": "marc", "port": 2222}
    _message, schema = session.elicit_calls[0]
    assert set(schema["properties"]) == {"host", "username", "port"}
    assert schema["required"] == ["host", "username"]
    assert schema["properties"]["port"]["default"] == 22


@pytest.mark.asyncio
async def test_elicit_port_alone_present_is_not_re_offered():
    session = _FakeSession(
        elicitation_supported=True,
        result=_FakeElicitResult(action="accept", content={"username": "marc"}),
    )
    await elicit_missing_ssh_args(session, {"host": "example.com", "port": 2222})
    _message, schema = session.elicit_calls[0]
    assert "port" not in schema["properties"]


@pytest.mark.asyncio
async def test_elicit_declined_returns_none():
    session = _FakeSession(
        elicitation_supported=True,
        result=_FakeElicitResult(action="decline"),
    )
    assert await elicit_missing_ssh_args(session, {"host": "example.com"}) is None


@pytest.mark.asyncio
async def test_elicit_cancelled_returns_none():
    session = _FakeSession(
        elicitation_supported=True,
        result=_FakeElicitResult(action="cancel"),
    )
    assert await elicit_missing_ssh_args(session, {"host": "example.com"}) is None


@pytest.mark.asyncio
async def test_elicit_request_failure_falls_back_to_none():
    session = _FakeSession(elicitation_supported=True, raise_exc=RuntimeError("boom"))
    assert await elicit_missing_ssh_args(session, {"host": "example.com"}) is None


@pytest.mark.asyncio
async def test_elicit_accept_without_answering_asked_field_is_treated_as_no_answer():
    # Client says "accept" but the form data doesn't actually cover
    # something we asked for -- must not be treated as a partial win.
    session = _FakeSession(
        elicitation_supported=True,
        result=_FakeElicitResult(action="accept", content={"port": 22}),
    )
    result = await elicit_missing_ssh_args(session, {"host": "example.com"})
    assert result is None
