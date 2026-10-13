"""Offline tests for the LAN relay receiver and its merge into device state.

Needs no eWeLink account, no relay and no broker: records are encrypted here the
same way a device does it (mirroring upstream encrypt() in SonoffLAN local.py),
and the one end-to-end case sends real datagrams over localhost.

Usage:
    PYTHONPATH=src .venv/bin/python -m unittest tests/test_lan_relay.py -v
"""

# 1. Standard library
import asyncio
import base64
import hashlib
import json
import os
import socket
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple

# 2. Third-party
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# 3. Project-local
from sonoff_mqtt.config import LanRelayConfig
from sonoff_mqtt.devices import DeviceRegistry
from sonoff_mqtt.lan_relay import LanRelayReceiver, decrypt_params
from sonoff_mqtt.observer import Observer

# Made-up key in the same 36 character format as a real devicekey
DEVICEKEY = "00000000-1111-2222-3333-444444444444"
RELAY = "192.168.100.20"


def encrypt_params(params: Dict[str, Any], devicekey: str) -> Tuple[str, str]:
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
           event: str = "Updated", devicekey: str = DEVICEKEY, boot: str = "run1") -> bytes:
    """One relay datagram, with the payload split over data fields like TXT."""
    data, iv = encrypt_params(params, devicekey)
    chunks = [data[i:i + 249] for i in range(0, len(data), 249)]
    txt = {f"data{i + 1}": chunk for i, chunk in enumerate(chunks)}
    txt.update({"id": deviceid, "type": "plug", "seq": str(seq), "encrypt": "true", "iv": iv})
    message = {"v": 1, "boot": boot, "n": n, "event": event, "ts": 0.0,
               "name": f"eWeLink_{deviceid}._ewelink._tcp.local.", "deviceid": deviceid,
               "addresses": ["192.168.100.243"], "port": 8081, "txt": txt}
    return json.dumps(message).encode()


class Collector:
    def __init__(self):
        self.calls: List[Tuple[str, Dict[str, Any], str, str]] = []

    def __call__(self, deviceid, params, seq, event):
        self.calls.append((deviceid, params, seq, event))


def make_receiver(collector: Collector) -> LanRelayReceiver:
    config = LanRelayConfig(enabled=True, allowed_sources=[RELAY])
    keys = {"10020db9d1": DEVICEKEY, "1001d504c3": DEVICEKEY}
    return LanRelayReceiver(config, collector, keys.get)


class ReceiverTests(unittest.TestCase):
    def test_decrypt_roundtrip(self):
        data, iv = encrypt_params({"switch": "on"}, DEVICEKEY)
        self.assertEqual(decrypt_params(data, iv, DEVICEKEY), {"switch": "on"})

    def test_applies_new_seq_and_skips_repeated_seq(self):
        collector = Collector()
        receiver = make_receiver(collector)
        receiver.datagram_received(record("10020db9d1", 8420, {"switch": "on"}, 1, "Added"), (RELAY, 5000))
        receiver.datagram_received(record("10020db9d1", 8420, {"switch": "on"}, 2, "Resync"), (RELAY, 5000))
        receiver.datagram_received(record("10020db9d1", 8421, {"switch": "off"}, 3), (RELAY, 5000))
        self.assertEqual([(c[2], c[1]["switch"]) for c in collector.calls], [("8420", "on"), ("8421", "off")])

    def test_lower_seq_is_applied(self):
        # A device that restarts may count from a lower seq; it must not be ignored
        collector = Collector()
        receiver = make_receiver(collector)
        receiver.datagram_received(record("10020db9d1", 8421, {"switch": "off"}, 1), (RELAY, 5000))
        receiver.datagram_received(record("10020db9d1", 3, {"switch": "on"}, 2), (RELAY, 5000))
        self.assertEqual(len(collector.calls), 2)

    def test_drops_other_sources(self):
        collector = Collector()
        receiver = make_receiver(collector)
        receiver.datagram_received(record("10020db9d1", 1, {"switch": "on"}, 1), ("192.168.100.99", 5000))
        self.assertEqual(collector.calls, [])

    def test_wrong_key_is_not_applied_and_retried_on_resync(self):
        collector = Collector()
        receiver = make_receiver(collector)
        bad = record("10020db9d1", 5, {"switch": "on"}, 1, devicekey="ffffffff-1111-2222-3333-444444444444")
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            receiver.datagram_received(bad, (RELAY, 5000))
        self.assertEqual(collector.calls, [])
        self.assertIn("could not be decrypted", logs.output[0])
        # Same seq with a decryptable payload is applied, since nothing was applied for it
        receiver.datagram_received(record("10020db9d1", 5, {"switch": "on"}, 2, "Resync"), (RELAY, 5000))
        self.assertEqual(len(collector.calls), 1)

    def test_unknown_device_and_junk_are_ignored(self):
        collector = Collector()
        receiver = make_receiver(collector)
        receiver.datagram_received(record("ffffffffff", 1, {"switch": "on"}, 1), (RELAY, 5000))
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            receiver.datagram_received(b"[1, 2, 3]", (RELAY, 5000))
            receiver.datagram_received(b"not json", (RELAY, 5000))
        self.assertEqual(collector.calls, [])

    def test_removed_resets_seq(self):
        collector = Collector()
        receiver = make_receiver(collector)
        receiver.datagram_received(record("10020db9d1", 7, {"switch": "on"}, 1), (RELAY, 5000))
        removed = json.dumps({"v": 1, "boot": "run1", "n": 2, "event": "Removed", "ts": 0.0,
                              "name": "x", "deviceid": "10020db9d1"}).encode()
        receiver.datagram_received(removed, (RELAY, 5000))
        receiver.datagram_received(record("10020db9d1", 7, {"switch": "on"}, 3, "Added"), (RELAY, 5000))
        self.assertEqual(len(collector.calls), 2)

    def test_lost_datagram_is_logged(self):
        receiver = make_receiver(Collector())
        receiver.datagram_received(record("10020db9d1", 1, {"switch": "on"}, 1), (RELAY, 5000))
        with self.assertLogs("sonoff_mqtt.lan_relay", level="INFO") as logs:
            receiver.datagram_received(record("10020db9d1", 2, {"switch": "on"}, 4), (RELAY, 5000))
        self.assertIn("2 datagram(s) lost", logs.output[0])


class FakeMqtt:
    def __init__(self):
        self.published: List[Tuple[str, str]] = []

    def publish(self, topic, payload):
        self.published.append((topic, payload))


class ObserverMergeTests(unittest.TestCase):
    """The LAN path through Observer._on_lan_state into Device and MQTT."""

    def make_observer(self) -> Observer:
        observer = Observer.__new__(Observer)
        observer.registry = DeviceRegistry("sonoff")
        observer.mqtt = FakeMqtt()
        observer._lan_seen = set()
        for deviceid, uiid, params in (
            ("10020db9d1", 1, {"switch": "on", "rssi": -60}),
            ("1001d504c3", 4, {"switches": [{"outlet": i, "switch": "off"} for i in range(4)]}),
        ):
            raw = {"deviceid": deviceid, "name": deviceid, "extra": {"uiid": uiid},
                   "apikey": "own", "online": True, "params": params, "devicekey": DEVICEKEY}
            device = observer.registry.add(raw, client=None, own_apikey="own")
            # As at startup: everything from the cloud listing is already published
            for topic, payload in device.topics():
                device.mark_published(topic, payload)
        return observer

    def test_unchanged_state_publishes_nothing(self):
        observer = self.make_observer()
        observer._on_lan_state("10020db9d1", {"switch": "on", "ssid": "x"}, "1", "Added")
        self.assertEqual(observer.mqtt.published, [])

    def test_switch_change_is_published_and_extra_keys_ignored(self):
        observer = self.make_observer()
        observer._on_lan_state("10020db9d1", {"switch": "off", "ssid": "x", "rssi": -40}, "2", "Updated")
        self.assertIn(("sonoff/10020db9d1/switch", "OFF"), observer.mqtt.published)
        device = observer.registry.get("10020db9d1")
        self.assertNotIn("ssid", device.params)
        self.assertEqual(device.params["rssi"], -60)

    def test_four_channel_outlet_mapping(self):
        observer = self.make_observer()
        switches = [{"outlet": i, "switch": "on" if i == 1 else "off"} for i in range(4)]
        observer._on_lan_state("1001d504c3", {"switches": switches, "configure": []}, "3411", "Updated")
        published = [p for p in observer.mqtt.published if "/switch" in p[0]]
        self.assertEqual(published, [("sonoff/1001d504c3/switch1", "ON")])

    def test_first_record_per_device_is_logged(self):
        observer = self.make_observer()
        with self.assertLogs("sonoff_mqtt.observer", level="INFO") as logs:
            observer._on_lan_state("10020db9d1", {"switch": "on"}, "1", "Added")
        self.assertIn("LAN state received (Added, seq 1)", logs.output[0])
        with self.assertNoLogs("sonoff_mqtt.observer", level="INFO"):
            observer._on_lan_state("10020db9d1", {"switch": "on"}, "2", "Updated")

    def test_devicekey_lookup(self):
        observer = self.make_observer()
        self.assertEqual(observer._devicekey_for("10020db9d1"), DEVICEKEY)
        self.assertIsNone(observer._devicekey_for("ffffffffff"))


class UdpEndToEndTest(unittest.IsolatedAsyncioTestCase):
    async def test_real_datagram_over_localhost(self):
        collector = Collector()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        config = LanRelayConfig(enabled=True, listen_port=port, allowed_sources=["127.0.0.1"])
        receiver = LanRelayReceiver(config, collector, {"10020db9d1": DEVICEKEY}.get)
        await receiver.start()
        try:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.sendto(record("10020db9d1", 9, {"switch": "off"}, 1), ("127.0.0.1", port))
            sender.close()
            for _ in range(50):
                if collector.calls:
                    break
                await asyncio.sleep(0.02)
        finally:
            await receiver.stop()
        self.assertEqual([(c[0], c[1]["switch"], c[2]) for c in collector.calls], [("10020db9d1", "off", "9")])


if __name__ == "__main__":
    unittest.main()
