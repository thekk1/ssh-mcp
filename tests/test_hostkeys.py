from ssh_mcp.hostkeys import HostKeyStore


def test_unknown_host_returns_none(tmp_path):
    store = HostKeyStore(str(tmp_path / "host_keys.json"))
    assert store.get("example.com", 22) is None


def test_pin_then_get_returns_same_fingerprint(tmp_path):
    store = HostKeyStore(str(tmp_path / "host_keys.json"))
    store.put("example.com", 22, "sha256:abc123")
    assert store.get("example.com", 22) == "sha256:abc123"


def test_different_ports_are_independent(tmp_path):
    store = HostKeyStore(str(tmp_path / "host_keys.json"))
    store.put("example.com", 22, "sha256:abc123")
    assert store.get("example.com", 2222) is None


def test_pin_persists_across_store_instances(tmp_path):
    path = str(tmp_path / "host_keys.json")
    HostKeyStore(path).put("example.com", 22, "sha256:abc123")
    reloaded = HostKeyStore(path)
    assert reloaded.get("example.com", 22) == "sha256:abc123"


def test_creates_parent_directory(tmp_path):
    path = str(tmp_path / "nested" / "dir" / "host_keys.json")
    store = HostKeyStore(path)
    store.put("example.com", 22, "sha256:abc123")
    assert store.get("example.com", 22) == "sha256:abc123"


def test_corrupt_file_is_treated_as_empty(tmp_path):
    path = tmp_path / "host_keys.json"
    path.write_text("not json")
    store = HostKeyStore(str(path))
    assert store.get("example.com", 22) is None
