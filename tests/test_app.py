import base64

import asyncssh
import pytest
from starlette.requests import Request

from ssh_mcp.app import (
    GENERATE_TOOL,
    PASSPHRASE_HEADER,
    PRIVATE_KEY_HEADER,
    TOOL,
    CredentialError,
    _TofuClient,
    extract_credentials,
    generate_keypair,
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
    assert TOOL.inputSchema["required"] == ["host", "username", "command"]


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


def test_generate_tool_has_no_required_arguments():
    assert GENERATE_TOOL.inputSchema.get("required", []) == []


def test_generate_keypair_default_is_ed25519_and_loadable():
    result = generate_keypair(key_type="ed25519", passphrase=None, comment=None)
    assert result["ok"] is True
    assert result["public_key"].startswith("ssh-ed25519 ")

    private_bytes = base64.b64decode(result["private_key_base64"])
    key = asyncssh.import_private_key(private_bytes)
    assert key.get_fingerprint("sha256") == result["fingerprint"]


def test_generate_keypair_rsa():
    result = generate_keypair(key_type="rsa", passphrase=None, comment=None)
    assert result["ok"] is True
    assert result["public_key"].startswith("ssh-rsa ")


def test_generate_keypair_unknown_type_is_an_error():
    result = generate_keypair(key_type="not-a-real-type", passphrase=None, comment=None)
    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_key_type"


def test_generate_keypair_comment_appears_in_public_key():
    result = generate_keypair(key_type="ed25519", passphrase=None, comment="test@example.com")
    assert result["public_key"].endswith("test@example.com")


def test_generate_keypair_passphrase_protects_private_key():
    result = generate_keypair(key_type="ed25519", passphrase="s3cr3t", comment=None)
    private_bytes = base64.b64decode(result["private_key_base64"])

    with pytest.raises(asyncssh.KeyImportError):
        asyncssh.import_private_key(private_bytes)  # no passphrase given -> must fail

    key = asyncssh.import_private_key(private_bytes, passphrase="s3cr3t")
    assert key.get_fingerprint("sha256") == result["fingerprint"]


def test_generate_keypair_is_fresh_every_call():
    first = generate_keypair(key_type="ed25519", passphrase=None, comment=None)
    second = generate_keypair(key_type="ed25519", passphrase=None, comment=None)
    assert first["fingerprint"] != second["fingerprint"]
