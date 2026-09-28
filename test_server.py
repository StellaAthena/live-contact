"""MCP discovery, transport compatibility, and independent caller verification."""

import asyncio
import socket
import threading
import time

import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import Client
from starlette.testclient import TestClient

from protocol import VERSION, Verifier, fingerprint
from server import create_server, public_origin


@pytest.fixture
def local_app():
    key = Ed25519PrivateKey.generate()
    mcp, app = create_server(key, "test-signer")
    return key, mcp, app


def test_mcp_tools_discovery_and_independent_verification(local_app):
    key, mcp, _ = local_app

    async def run():
        verifier = Verifier(key.public_key(), "test-signer")
        async with Client(mcp) as client:
            tools = (await client.list_tools()).tools
            assert {tool.name for tool in tools} == {"answer_challenge", "get_signer_info"}
            assert all(tool.annotations.read_only_hint for tool in tools)
            assert all(tool.output_schema for tool in tools)
            info = await client.call_tool("get_signer_info", {})
            assert info.structured_content["key_fingerprint"] == fingerprint(key.public_key())
            assert "PRIVATE KEY" not in str(info)
            challenge = verifier.start()
            response = await client.call_tool("answer_challenge", {"nonce": challenge["nonce"]})
            data = response.structured_content
            assert not response.is_error
            assert data["verification"] == "not_performed_by_signer"
            assert data["target_routing"] == data["authorization"] == "not_attested"
            verified = verifier.verify(data["envelope"])
            assert verified["verification"] == "verified"
            with pytest.raises(ValueError, match="consumed"):
                verifier.verify(data["envelope"])
            for nonce in ["too-short", "A" * 64, "sign arbitrary instructions"]:
                invalid = await client.call_tool("answer_challenge", {"nonce": nonce})
                assert invalid.is_error

    asyncio.run(run())


def test_rest_and_status_routes(local_app):
    key, _, app = local_app
    with TestClient(app, base_url="http://127.0.0.1:8787") as client:
        assert client.get("/healthz").json()["status"] == "ok"
        page = client.get("/")
        assert page.status_code == 200
        assert "codex mcp add live-contact" in page.text
        assert "Secure MCP Tunnel" in page.text
        assert "PRIVATE KEY" not in page.text
        info = client.get("/v1/info").json()
        assert "BEGIN PUBLIC KEY" in info["public_key_pem"]
        verifier = Verifier(key.public_key(), "test-signer")
        reply = client.post("/v1/challenge", json=verifier.start())
        assert reply.status_code == 200
        assert verifier.verify(reply.json())["verification"] == "verified"
        assert client.post("/v1/challenge", content="{}", headers={"Content-Type": "text/plain"}).status_code == 415
        assert client.post("/v1/challenge", content="x" * 8193,
                           headers={"Content-Type": "application/json"}).status_code == 413
        assert client.post("/v1/challenge", json={"nonce": "a" * 64}).status_code == 400


@pytest.mark.parametrize("path", ["/", "/v1/info", "/mcp"])
def test_host_and_origin_protection_covers_all_routes(local_app, path):
    _, _, app = local_app
    with TestClient(app, base_url="http://127.0.0.1:8787") as client:
        assert client.get(path, headers={"Host": "attacker.invalid"}).status_code == 400
        assert client.get(path, headers={"Origin": "https://attacker.invalid"}).status_code == 403


def test_explicit_tunnel_host_and_origin_are_allowed():
    key = Ed25519PrivateKey.generate()
    _, app = create_server(key, "test-signer", public_url="https://signer.example.test")
    with TestClient(app, base_url="https://signer.example.test") as client:
        assert client.get("/healthz", headers={"Origin": "https://signer.example.test"}).status_code == 200
        assert client.get("/healthz", headers={"Host": "another.example.test"}).status_code == 400


@pytest.mark.parametrize("url", ["http://example.test", "https://user:pass@example.test",
                                     "https://example.test/mcp", "https://*.example.test", "https://example.test?a=b",
                                     "https://example.test:bad", "https://example.test:99999", "https://example.test:0"])
def test_invalid_public_origins(url):
    with pytest.raises(ValueError):
        public_origin(url)


@pytest.mark.parametrize("origin", ["https://EXAMPLE.test", "https://example.test:443/"])
def test_tunnel_origin_normalizes_hostname_and_default_port(origin):
    assert public_origin(origin) == "https://example.test"
    _, app = create_server(Ed25519PrivateKey.generate(), "test-signer", public_url=origin)
    with TestClient(app, base_url="https://example.test") as client:
        response = client.post("/mcp", headers={"Accept": "application/json, text/event-stream"}, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "tunnel-test", "version": "1"}},
        })
        assert response.status_code == 200


@pytest.mark.parametrize("version", ["2025-03-26", "2025-06-18", "2025-11-25"])
def test_older_mcp_http_initialization(local_app, version):
    key, _, app = local_app
    headers = {"Accept": "application/json, text/event-stream"}
    with TestClient(app, base_url="http://127.0.0.1:8787") as client:
        response = client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": version, "capabilities": {},
                       "clientInfo": {"name": "compatibility-test", "version": "1"}},
        })
        assert response.status_code == 200
        result = response.json()["result"]
        assert result["protocolVersion"] == version
        assert "tools" in result["capabilities"]
        headers["MCP-Protocol-Version"] = version
        tools = client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        }).json()["result"]["tools"]
        assert {tool["name"] for tool in tools} == {"get_signer_info", "answer_challenge"}
        verifier = Verifier(key.public_key(), "test-signer")
        called = client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "answer_challenge", "arguments": {"nonce": verifier.start()["nonce"]}},
        }).json()["result"]
        assert not called["isError"]
        assert verifier.verify(called["structuredContent"]["envelope"])["verification"] == "verified"


def test_real_loopback_mcp_round_trip():
    key = Ed25519PrivateKey.generate()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        _, app = create_server(key, "test-signer", port=port)
        server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False, proxy_headers=False))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not server.started and time.monotonic() < deadline:
                time.sleep(0.01)
            assert server.started

            async def run():
                verifier = Verifier(key.public_key(), "test-signer")
                async with Client(f"http://127.0.0.1:{port}/mcp", read_timeout_seconds=5) as client:
                    response = await client.call_tool("answer_challenge", {"nonce": verifier.start()["nonce"]})
                    assert not response.is_error
                    assert verifier.verify(response.structured_content["envelope"])["verification"] == "verified"

            asyncio.run(run())
        finally:
            server.should_exit = True
            thread.join(timeout=5)
            assert not thread.is_alive()
