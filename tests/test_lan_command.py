"""Offline tests for LAN commands: sender, relay endpoints, confirmation and fallback.

Needs no eWeLink account, no relay, no broker and no device. The sender is run
against a small HTTP server on localhost that decrypts what it receives the way
a device would; the command path uses a fake sender and a fake cloud client,
with relay records fed straight into the receiver.

Usage:
    PYTHONPATH=src .venv/bin/python -m unittest tests/test_lan_command.py -v
"""

# 1. Standard library
import asyncio
import base64
import hashlib
import json
import os
import socket
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest import mock

# 2. Third-party
from aiohttp import ClientSession, web
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# 3. Project-local
from sonoff_mqtt import lan_relay as lan_relay_module
from sonoff_mqtt import observer as observer_module
from sonoff_mqtt.config import ConfigError, LanRelayConfig, VerificationConfig, _load_lan_relay
from sonoff_mqtt.lan_relay import (
    LanCommandSender,
    LanRelayReceiver,
    decrypt_params,
    encrypt_payload,
)
from sonoff_mqtt.observer import Observer

# Made-up key in the same 36 character format as a real devicekey
DEVICEKEY = "00000000-1111-2222-3333-444444444444"
RELAY = "192.168.100.20"
CAMERA = "10020db9d1"
FOURCH = "1001d504c3"


def encrypt_params(params: Dict[str, Any], devicekey: str = DEVICEKEY):
    """Encrypt like a device does: AES-128-CBC, key md5(devicekey), PKCS7."""
    plaintext = json.dumps(params, separators=(",", ":")).encode("utf-8")
    key = hashlib.md5(devicekey.encode("utf-8")).digest()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()


def record(deviceid: str, seq: int, params: Dict[str, Any], n: int,
           event: str = "Updated", addresses=("192.168.100.243",), port: Any = 8081) -> bytes:
    """One relay datagram in protocol v1."""
    data, iv = encrypt_params(params)
    txt = {"data1": data, "id": deviceid, "seq": str(seq), "encrypt": "true", "iv": iv}
    message = {"v": 1, "boot": "run1", "n": n, "event": event, "ts": 0.0,
               "name": f"eWeLink_{deviceid}._ewelink._tcp.local.", "deviceid": deviceid,
               "addresses": list(addresses), "port": port, "txt": txt}
    return json.dumps(message).encode()


def relay_config(command_devices: Optional[List[str]] = None) -> LanRelayConfig:
    return LanRelayConfig(enabled=True, allowed_sources=[RELAY],
                          command_devices=list(command_devices or []))


# ==============================================================================
# Encryption and relay endpoints
# ==============================================================================


class EncryptTests(unittest.TestCase):
    def test_encrypt_payload_roundtrip(self):
        payload = encrypt_payload(
            {"sequence": "1", "deviceid": CAMERA, "selfApikey": "123",
             "data": {"switch": "on"}},
            DEVICEKEY,
        )
        self.assertIs(payload["encrypt"], True)
        self.assertEqual(payload["selfApikey"], "123")
        self.assertEqual(decrypt_params(payload["data"], payload["iv"], DEVICEKEY),
                         {"switch": "on"})


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.receiver = LanRelayReceiver(relay_config(), lambda *a: None, lambda d: DEVICEKEY)

    def feed(self, datagram: bytes):
        self.receiver.datagram_received(datagram, (RELAY, 5353))

    def test_endpoint_from_record(self):
        self.feed(record(CAMERA, 1, {"switch": "off"}, 1))
        self.assertEqual(self.receiver.endpoint_for(CAMERA), ("192.168.100.243", 8081))

    def test_resync_with_same_seq_refreshes_and_follows_new_address(self):
        self.feed(record(CAMERA, 1, {"switch": "off"}, 1))
        address, port, _ = self.receiver._endpoints[CAMERA]
        stale = time.monotonic() - lan_relay_module.ENDPOINT_FRESH_SECONDS - 1
        self.receiver._endpoints[CAMERA] = (address, port, stale)
        self.assertIsNone(self.receiver.endpoint_for(CAMERA))
        self.feed(record(CAMERA, 1, {"switch": "off"}, 2, event="Resync",
                         addresses=("192.168.100.99",)))
        self.assertEqual(self.receiver.endpoint_for(CAMERA), ("192.168.100.99", 8081))

    def test_removed_forgets_endpoint(self):
        self.feed(record(CAMERA, 1, {"switch": "off"}, 1))
        removed = {"v": 1, "boot": "run1", "n": 2, "event": "Removed", "ts": 0.0,
                   "name": "x", "deviceid": CAMERA}
        self.feed(json.dumps(removed).encode())
        self.assertIsNone(self.receiver.endpoint_for(CAMERA))

    def test_ipv6_only_and_bad_port_are_ignored(self):
        self.feed(record(CAMERA, 1, {"switch": "off"}, 1, addresses=("fe80::1",)))
        self.assertIsNone(self.receiver.endpoint_for(CAMERA))
        self.feed(record(CAMERA, 2, {"switch": "off"}, 2, port="8081"))
        self.assertIsNone(self.receiver.endpoint_for(CAMERA))
        self.feed(record(CAMERA, 3, {"switch": "off"}, 3, port=True))
        self.assertIsNone(self.receiver.endpoint_for(CAMERA))


# ==============================================================================
# Configuration
# ==============================================================================


class ConfigTests(unittest.TestCase):
    def base(self, **extra):
        raw = {"enabled": True, "allowed_sources": [RELAY]}
        raw.update(extra)
        return raw

    def test_absent_means_empty(self):
        self.assertEqual(_load_lan_relay(self.base()).command_devices, [])

    def test_valid_ids_are_lowercased_and_deduplicated(self):
        config = _load_lan_relay(self.base(command_devices=["10020DB9D1", CAMERA]))
        self.assertEqual(config.command_devices, [CAMERA])

    def test_number_is_rejected(self):
        with self.assertRaises(ConfigError):
            _load_lan_relay(self.base(command_devices=[1001234567]))

    def test_not_a_deviceid_is_rejected(self):
        for bad in ["10020db9d", "10020db9d1x", "1002-db9d1", "Webbkamera"]:
            with self.assertRaises(ConfigError, msg=bad):
                _load_lan_relay(self.base(command_devices=[bad]))

    def test_requires_enabled_relay(self):
        with self.assertRaises(ConfigError):
            _load_lan_relay({"enabled": False, "command_devices": [CAMERA]})


# ==============================================================================
# Sender against a local HTTP server acting as a device
# ==============================================================================


class SenderTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests: List[Dict[str, Any]] = []
        self.reply: Any = {"seq": 7, "error": 0}
        self.delay = 0.0
        app = web.Application()
        app.router.add_post("/zeroconf/{command}", self.handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = self.runner.addresses[0][1]
        self.session = ClientSession()
        sequence = mock.AsyncMock(return_value="1700000000000")
        self.sender = LanCommandSender(self.session, sequence)

    async def asyncTearDown(self):
        await self.session.close()
        await self.runner.cleanup()

    async def handle(self, request: web.Request) -> web.StreamResponse:
        body = await request.json()
        self.requests.append({
            "command": request.match_info["command"],
            "connection": request.headers.get("Connection"),
            "body": body,
            "params": decrypt_params(body["data"], body["iv"], DEVICEKEY),
        })
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.reply == "html":
            return web.Response(text="<html></html>", content_type="text/html")
        return web.json_response(self.reply)

    async def send(self, params, timeout=2.0):
        return await self.sender.send("127.0.0.1", self.port, CAMERA, DEVICEKEY, params, timeout)

    async def test_wire_format_and_success(self):
        self.assertEqual(await self.send({"switch": "on"}), "online")
        request = self.requests[0]
        self.assertEqual(request["command"], "switch")
        self.assertEqual(request["connection"], "close")
        self.assertEqual(request["params"], {"switch": "on"})
        self.assertEqual(request["body"]["deviceid"], CAMERA)
        self.assertEqual(request["body"]["selfApikey"], "123")
        self.assertEqual(request["body"]["sequence"], "1700000000000")
        self.assertIs(request["body"]["encrypt"], True)

    async def test_multi_channel_uses_switches_command(self):
        params = {"switches": [{"outlet": 2, "switch": "off"}]}
        self.assertEqual(await self.send(params), "online")
        self.assertEqual(self.requests[0]["command"], "switches")
        self.assertEqual(self.requests[0]["params"], params)

    async def test_device_error_is_reported(self):
        self.reply = {"seq": 7, "error": 400}
        self.assertEqual(await self.send({"switch": "on"}), "error 400")

    async def test_html_and_non_object_replies(self):
        self.reply = "html"
        self.assertEqual(await self.send({"switch": "on"}), "text/html")
        self.reply = [0]
        self.assertEqual(await self.send({"switch": "on"}), "bad reply")

    async def test_timeout(self):
        self.delay = 1.0
        self.assertEqual(await self.send({"switch": "on"}, timeout=0.2), "timeout")

    async def test_not_posted_once_superseded(self):
        result = await self.sender.send(
            "127.0.0.1", self.port, CAMERA, DEVICEKEY, {"switch": "on"}, 2.0,
            still_wanted=lambda: False,
        )
        self.assertEqual(result, "superseded")
        self.assertEqual(self.requests, [])

    async def test_connection_refused(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]
        result = await self.sender.send(
            "127.0.0.1", closed_port, CAMERA, DEVICEKEY, {"switch": "on"}, 2.0
        )
        self.assertEqual(result, "E#CON")


# ==============================================================================
# Command path: LAN first, relay confirmation, cloud fallback
# ==============================================================================


class FakeMqtt:
    def __init__(self, config=None):
        self.published: List[tuple] = []
        self.on_command = None

    def publish(self, topic, payload):
        self.published.append((topic, payload))


class FakeCloud:
    """Accepts every command; a later query makes the device report it."""

    def __init__(self, registry):
        self.registry = registry
        self.calls: List[Optional[Dict[str, Any]]] = []
        self.pending: Dict[str, Dict[str, Any]] = {}

    async def send(self, raw, params=None, timeout=10):
        self.calls.append(params)
        device = self.registry.get(raw["deviceid"])
        if params:
            self.pending[device.deviceid] = params
        elif device.deviceid in self.pending:
            device.merge_params(self.pending.pop(device.deviceid))
        return "online"


class FakeSender:
    """Stands in for LanCommandSender; can make the relay report a state."""

    def __init__(self):
        self.calls: List[tuple] = []
        self.receipt = "online"
        self.then = None  # zero-argument callable run shortly after the send
        # Per-call overrides, used in order: (delay, receipt, then). The delay
        # stands for a POST that takes that long before returning the receipt.
        self.script: List[tuple] = []

    async def send(self, host, port, deviceid, devicekey, params, timeout, still_wanted=None):
        self.calls.append((host, port, deviceid, params))
        delay, receipt, then = self.script.pop(0) if self.script else (0.0, self.receipt, self.then)
        if then is not None:
            asyncio.get_running_loop().call_later(0.05, then)
        if delay:
            await asyncio.sleep(delay)
        return receipt


class CommandTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.saved = observer_module.LAN_CONFIRM_TIMEOUT_SECONDS
        observer_module.LAN_CONFIRM_TIMEOUT_SECONDS = 0.3
        config = SimpleNamespace(
            mqtt=SimpleNamespace(base_topic="sonoff"),
            verification=VerificationConfig(settle_seconds=0.1, retry_backoff_seconds=0.0),
            lan_relay=relay_config([CAMERA, FOURCH]),
        )
        with mock.patch.object(observer_module, "MqttPublisher", FakeMqtt):
            self.observer = Observer(config)
        self.cloud = FakeCloud(self.observer.registry)
        for deviceid, name, uiid, params in (
            (CAMERA, "Webbkamera", 1, {"switch": "off"}),
            (FOURCH, "4CHPROR3", 4, {"switches": [{"outlet": i, "switch": "off"} for i in range(4)]}),
            ("1001df4bd4", "13.8V Powersupply", 1, {"switch": "off"}),
        ):
            raw = {"deviceid": deviceid, "name": name, "extra": {"uiid": uiid},
                   "apikey": "own", "online": True, "params": params, "devicekey": DEVICEKEY}
            self.observer.registry.add(raw, self.cloud, "own")
        self.receiver = LanRelayReceiver(
            self.observer.config.lan_relay, self.observer._on_lan_state, self.observer._devicekey_for
        )
        self.observer._lan_relay = self.receiver
        self.sender = FakeSender()
        self.observer._lan_sender = self.sender
        self.n = 0
        for deviceid in (CAMERA, FOURCH, "1001df4bd4"):
            device = self.observer.registry.get(deviceid)
            self.relay(deviceid, 100, device.params)

    async def asyncTearDown(self):
        observer_module.LAN_CONFIRM_TIMEOUT_SECONDS = self.saved
        self.assertEqual(self.observer._lan_waiters, {})

    def relay(self, deviceid, seq, params, event="Updated"):
        self.n += 1
        self.receiver.datagram_received(record(deviceid, seq, params, self.n, event=event),
                                        (RELAY, 5353))

    def published(self, topic):
        return [p for t, p in self.observer.mqtt.published if t == topic]

    async def test_confirmed_via_lan_skips_cloud(self):
        self.sender.then = lambda: self.relay(CAMERA, 101, {"switch": "on"})
        await self.observer._send_command(CAMERA, "switch", "ON")
        self.assertEqual(self.sender.calls, [("192.168.100.243", 8081, CAMERA, {"switch": "on"})])
        self.assertEqual(self.cloud.calls, [])
        self.assertEqual(self.published(f"sonoff/{CAMERA}/switch/error"), [""])
        self.assertIn("ON", self.published(f"sonoff/{CAMERA}/switch"))

    async def test_no_relay_record_falls_back_to_cloud(self):
        await self.observer._send_command(CAMERA, "switch", "ON")
        self.assertEqual(len(self.sender.calls), 1)
        self.assertEqual(self.cloud.calls, [{"switch": "on"}, None])
        self.assertEqual(self.published(f"sonoff/{CAMERA}/switch/error"), [""])

    async def test_resync_with_old_seq_does_not_confirm(self):
        self.sender.then = lambda: self.relay(CAMERA, 100, {"switch": "on"}, event="Resync")
        await self.observer._send_command(CAMERA, "switch", "ON")
        self.assertEqual(self.cloud.calls, [{"switch": "on"}, None])

    async def test_new_seq_with_wrong_state_does_not_confirm(self):
        self.sender.then = lambda: self.relay(CAMERA, 101, {"switch": "off"})
        await self.observer._send_command(CAMERA, "switch", "ON")
        self.assertEqual(self.cloud.calls, [{"switch": "on"}, None])

    async def test_other_outlet_does_not_confirm(self):
        switches = [{"outlet": i, "switch": "on" if i == 1 else "off"} for i in range(4)]
        self.sender.then = lambda: self.relay(FOURCH, 101, {"switches": switches})
        await self.observer._send_command(FOURCH, "switch0", "ON")
        self.assertEqual(self.sender.calls[0][3], {"switches": [{"outlet": 0, "switch": "on"}]})
        self.assertEqual(self.cloud.calls[0], {"switches": [{"outlet": 0, "switch": "on"}]})

    async def test_rejected_lan_command_falls_back_at_once(self):
        self.sender.receipt = "error 400"
        started = time.monotonic()
        await self.observer._send_command(CAMERA, "switch", "ON")
        self.assertEqual(self.cloud.calls, [{"switch": "on"}, None])
        # No wait for a confirmation that cannot come: only the cloud settle time
        self.assertLess(time.monotonic() - started, 0.25)

    async def test_device_not_listed_never_goes_lan(self):
        await self.observer._send_command("1001df4bd4", "switch", "ON")
        self.assertEqual(self.sender.calls, [])
        self.assertEqual(self.cloud.calls, [{"switch": "on"}, None])

    async def test_stale_endpoint_goes_to_cloud(self):
        address, port, _ = self.receiver._endpoints[CAMERA]
        stale = time.monotonic() - lan_relay_module.ENDPOINT_FRESH_SECONDS - 1
        self.receiver._endpoints[CAMERA] = (address, port, stale)
        await self.observer._send_command(CAMERA, "switch", "ON")
        self.assertEqual(self.sender.calls, [])
        self.assertEqual(self.cloud.calls, [{"switch": "on"}, None])

    async def test_cloud_failure_still_reaches_error_topic(self):
        async def refuse(raw, params=None, timeout=10):
            self.cloud.calls.append(params)
            return "timeout"
        self.cloud.send = refuse
        await self.observer._send_command(CAMERA, "switch", "ON")
        errors = self.published(f"sonoff/{CAMERA}/switch/error")
        self.assertEqual(errors, ["command ON not confirmed after 3 attempt(s)"])

    # --------------------------------------------------------------------------
    # Ordering of commands to the same channel, and unexpected exceptions
    # --------------------------------------------------------------------------

    def switches(self, on_outlets):
        return {"switches": [{"outlet": i, "switch": "on" if i in on_outlets else "off"}
                             for i in range(4)]}

    async def test_superseded_command_skips_cloud_fallback_and_error_topic(self):
        # PTT on switch1: ON times out on the LAN, OFF is confirmed over the LAN
        # while ON is still waiting. ON must not go on to the cloud.
        self.sender.script = [
            (0.2, "timeout", None),
            (0.0, "online", lambda: self.relay(FOURCH, 101, self.switches(set()))),
        ]
        with self.assertLogs(observer_module._LOGGER, level="INFO") as logs:
            older = asyncio.create_task(self.observer._send_command(FOURCH, "switch1", "ON"))
            await asyncio.sleep(0.05)
            await self.observer._send_command(FOURCH, "switch1", "OFF")
            await older
        self.assertEqual(len(self.sender.calls), 2)
        self.assertEqual(self.cloud.calls, [])
        # Cleared once, by OFF; ON neither clears nor sets it
        self.assertEqual(self.published(f"sonoff/{FOURCH}/switch1/error"), [""])
        superseded = [r for r in logs.records if "superseded" in r.getMessage()]
        self.assertEqual(len(superseded), 1)
        self.assertEqual(superseded[0].levelname, "INFO")
        self.assertIn("cloud fallback", superseded[0].getMessage())
        self.assertFalse([r for r in logs.records if r.levelname == "ERROR"])

    async def test_superseded_command_stops_cloud_retries(self):
        # ON is already in the cloud path, its first cloud send unanswered,
        # when OFF starts. ON must not retry and must not report an error.
        self.sender.script = [
            (0.0, "error 400", None),
            (0.0, "online", lambda: self.relay(FOURCH, 101, self.switches(set()))),
        ]

        async def slow_refuse(raw, params=None, timeout=10):
            self.cloud.calls.append(params)
            await asyncio.sleep(0.15)
            return "timeout"
        self.cloud.send = slow_refuse
        with self.assertLogs(observer_module._LOGGER, level="INFO") as logs:
            older = asyncio.create_task(self.observer._send_command(FOURCH, "switch1", "ON"))
            await asyncio.sleep(0.05)
            await self.observer._send_command(FOURCH, "switch1", "OFF")
            await older
        self.assertEqual(self.cloud.calls, [{"switches": [{"outlet": 1, "switch": "on"}]}])
        self.assertEqual(self.published(f"sonoff/{FOURCH}/switch1/error"), [""])
        self.assertTrue([r for r in logs.records if "superseded" in r.getMessage()])
        self.assertFalse([r for r in logs.records if r.levelname == "ERROR"])

    async def test_other_channel_does_not_supersede(self):
        self.sender.script = [
            (0.2, "timeout", None),
            (0.0, "online", lambda: self.relay(FOURCH, 101, self.switches({2}))),
        ]
        with self.assertLogs(observer_module._LOGGER, level="INFO") as logs:
            older = asyncio.create_task(self.observer._send_command(FOURCH, "switch1", "ON"))
            await asyncio.sleep(0.05)
            await self.observer._send_command(FOURCH, "switch2", "ON")
            await older
        # switch1 ON still went through the cloud with its read-back
        self.assertEqual(self.cloud.calls, [{"switches": [{"outlet": 1, "switch": "on"}]}, None])
        self.assertEqual(self.published(f"sonoff/{FOURCH}/switch1/error"), [""])
        self.assertEqual(self.published(f"sonoff/{FOURCH}/switch2/error"), [""])
        self.assertFalse([r for r in logs.records if "superseded" in r.getMessage()])

    async def test_other_device_does_not_supersede(self):
        self.sender.script = [(0.2, "timeout", None)]
        older = asyncio.create_task(self.observer._send_command(CAMERA, "switch", "ON"))
        await asyncio.sleep(0.05)
        await self.observer._send_command("1001df4bd4", "switch", "ON")
        await older
        self.assertIn({"switch": "on"}, self.cloud.calls)
        self.assertEqual(self.published(f"sonoff/{CAMERA}/switch/error"), [""])

    async def test_lan_exception_falls_back_to_cloud_and_is_logged(self):
        async def explode(*args, **kwargs):
            raise RuntimeError("boom")
        self.sender.send = explode
        with self.assertLogs(observer_module._LOGGER, level="ERROR") as logs:
            await self.observer._send_command(CAMERA, "switch", "ON")
        self.assertEqual(self.cloud.calls, [{"switch": "on"}, None])
        self.assertEqual(self.published(f"sonoff/{CAMERA}/switch/error"), [""])
        self.assertEqual(len(logs.records), 1)
        self.assertIn("LAN attempt failed", logs.records[0].getMessage())
        self.assertIsInstance(logs.records[0].exc_info[1], RuntimeError)

    async def test_exception_escaping_send_command_is_logged(self):
        async def broken(deviceid, channel, payload):
            raise RuntimeError("escaped")
        self.observer._loop = asyncio.get_running_loop()
        self.observer._send_command = broken
        with self.assertLogs(observer_module._LOGGER, level="ERROR") as logs:
            self.observer._on_mqtt_command(CAMERA, "switch", "ON")
            for _ in range(20):
                await asyncio.sleep(0.01)
                if logs.records:
                    break
        self.assertEqual(len(logs.records), 1)
        self.assertIn("failed unexpectedly", logs.records[0].getMessage())
        self.assertIsInstance(logs.records[0].exc_info[1], RuntimeError)


if __name__ == "__main__":
    unittest.main()
