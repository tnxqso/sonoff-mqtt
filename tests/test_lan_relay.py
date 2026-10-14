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
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple
from unittest import mock

# 2. Third-party
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# 3. Project-local
from sonoff_mqtt.config import LanRelayConfig
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


def with_txt(datagram: bytes, **changes: Any) -> bytes:
    """A relay datagram with TXT fields replaced, or removed when given None."""
    message = json.loads(datagram)
    for key, value in changes.items():
        if value is None:
            message["txt"].pop(key, None)
        else:
            message["txt"][key] = value
    return json.dumps(message).encode()


def plaintext(deviceid: str, seq: int, params: Dict[str, Any], n: int,
              event: str = "Updated", boot: str = "run1") -> bytes:
    """A relay datagram as a device without encryption sends it."""
    message = {"v": 1, "boot": boot, "n": n, "event": event, "ts": 0.0,
               "name": f"eWeLink_{deviceid}._ewelink._tcp.local.", "deviceid": deviceid,
               "addresses": ["192.168.100.66"], "port": 8081,
               "txt": {"data1": json.dumps(params), "id": deviceid, "seq": str(seq)}}
    return json.dumps(message).encode()


def removed(deviceid: str, n: int, boot: str = "run1") -> bytes:
    return json.dumps({"v": 1, "boot": boot, "n": n, "event": "Removed", "ts": 0.0,
                       "name": "x", "deviceid": deviceid}).encode()


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


class RecordCheckTests(unittest.TestCase):
    """Records carrying TXT are checked as a whole before any of them is used."""

    def setUp(self):
        self.collector = Collector()
        self.receiver = make_receiver(self.collector)

    def feed(self, datagram: bytes):
        self.receiver.datagram_received(datagram, (RELAY, 5000))

    def test_plaintext_for_device_with_devicekey_is_rejected(self):
        self.feed(record("10020db9d1", 1, {"switch": "on"}, 1, "Added"))
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed(plaintext("10020db9d1", 2, {"switch": "off"}, 2))
        self.assertIn("is not encrypted although the device has a devicekey", logs.output[0])
        self.assertEqual([c[2] for c in self.collector.calls], ["1"])
        self.assertEqual(self.receiver.endpoint_for("10020db9d1"), ("192.168.100.243", 8081))
        self.assertEqual(self.receiver._last_seq["10020db9d1"], "1")
        self.assertEqual(self.receiver._last_applied["10020db9d1"], ("run1", 1))

    def test_encrypted_for_device_with_devicekey_is_accepted(self):
        with self.assertNoLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            self.feed(record("10020db9d1", 1, {"switch": "on"}, 1, "Added"))
        self.assertEqual([(c[2], c[1]) for c in self.collector.calls], [("1", {"switch": "on"})])
        self.assertEqual(self.receiver.endpoint_for("10020db9d1"), ("192.168.100.243", 8081))

    def test_plaintext_for_device_without_devicekey_keeps_endpoint_only(self):
        # As before: the record is not rejected, so the endpoint is kept, but
        # no state is handed on for a device without a devicekey
        with self.assertNoLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            self.feed(plaintext("ffffffffff", 1, {"switch": "on"}, 1, "Added"))
        self.assertEqual(self.collector.calls, [])
        self.assertEqual(self.receiver.endpoint_for("ffffffffff"), ("192.168.100.66", 8081))

    def test_missing_txt_id_is_rejected(self):
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed(with_txt(record("10020db9d1", 1, {"switch": "on"}, 1, "Added"), id=None))
        self.assertIn("without a txt id", logs.output[0])
        self.assertEqual(self.collector.calls, [])
        self.assertIsNone(self.receiver.endpoint_for("10020db9d1"))
        self.assertNotIn("10020db9d1", self.receiver._last_applied)

    def test_mismatched_txt_id_is_rejected(self):
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed(with_txt(record("10020db9d1", 1, {"switch": "on"}, 1, "Added"), id="1001d504c3"))
        self.assertIn("txt id for another device", logs.output[0])
        self.assertEqual(self.collector.calls, [])
        self.assertIsNone(self.receiver.endpoint_for("10020db9d1"))

    def test_missing_seq_is_rejected_and_logged_once_until_a_valid_record(self):
        no_seq = lambda n, **kw: with_txt(record("10020db9d1", 1, {"switch": "on"}, n), **kw)
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed(no_seq(1, seq=None))
            self.feed(no_seq(2, seq=""))
            self.feed(no_seq(3, seq=None))
        self.assertEqual(len(logs.output), 1)
        self.assertIn("without a seq", logs.output[0])
        self.assertEqual(self.collector.calls, [])
        self.assertIsNone(self.receiver.endpoint_for("10020db9d1"))

        # A valid record re-arms the warning
        self.feed(record("10020db9d1", 5, {"switch": "on"}, 4))
        self.assertEqual([c[2] for c in self.collector.calls], ["5"])
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed(no_seq(5, seq=None))
            self.feed(no_seq(6, seq=None))
        self.assertEqual(len(logs.output), 1)
        self.assertEqual([c[2] for c in self.collector.calls], ["5"])

    def test_rejections_are_logged_once_per_reason(self):
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed(plaintext("10020db9d1", 1, {"switch": "on"}, 1))
            self.feed(plaintext("10020db9d1", 2, {"switch": "on"}, 2))
            self.feed(with_txt(record("10020db9d1", 3, {"switch": "on"}, 3), seq=None))
        self.assertEqual(len(logs.output), 2)

    def test_non_string_data_field_is_skipped(self):
        # data1 is not a string, so it is left out of the payload and data2
        # carries all of it; joined as str(123) in front, it would have shifted
        # the base64 and broken the decryption
        datagram = record("10020db9d1", 1, {"switch": "on"}, 1, "Added")
        ciphertext = json.loads(datagram)["txt"]["data1"]
        self.feed(with_txt(datagram, data1=123, data2=ciphertext))
        self.assertEqual([(c[2], c[1]) for c in self.collector.calls], [("1", {"switch": "on"})])

    def test_removed_needs_no_txt_or_seq(self):
        self.feed(record("10020db9d1", 1, {"switch": "on"}, 1, "Added"))
        with self.assertNoLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            self.feed(removed("10020db9d1", 2))
        self.assertIsNone(self.receiver.endpoint_for("10020db9d1"))


class RelayCounterTests(unittest.TestCase):
    """Late datagrams within one relay run, by the relay's boot and n."""

    def setUp(self):
        self.collector = Collector()
        self.receiver = make_receiver(self.collector)

    def feed(self, datagram: bytes):
        self.receiver.datagram_received(datagram, (RELAY, 5000))

    def seqs(self):
        return [c[2] for c in self.collector.calls]

    def test_same_boot_lower_or_equal_n_is_dropped(self):
        self.feed(record("10020db9d1", 10, {"switch": "on"}, 5))
        with self.assertLogs("sonoff_mqtt.lan_relay", level="DEBUG") as logs:
            self.feed(record("10020db9d1", 9, {"switch": "off"}, 4))
            self.feed(with_txt(record("10020db9d1", 11, {"switch": "off"}, 5), port=1))
        self.assertTrue(all("dropped" in line for line in logs.output))
        self.assertEqual(self.seqs(), ["10"])
        self.assertEqual(self.receiver._last_seq["10020db9d1"], "10")
        self.assertEqual(self.receiver._last_applied["10020db9d1"], ("run1", 5))

    def test_same_boot_higher_n_is_applied(self):
        self.feed(record("10020db9d1", 10, {"switch": "on"}, 5))
        self.feed(record("10020db9d1", 11, {"switch": "off"}, 6))
        self.assertEqual(self.seqs(), ["10", "11"])
        self.assertEqual(self.receiver._last_applied["10020db9d1"], ("run1", 6))

    def test_late_datagram_does_not_move_endpoint(self):
        self.feed(record("10020db9d1", 10, {"switch": "on"}, 5))
        late = json.loads(record("10020db9d1", 10, {"switch": "on"}, 3, "Resync"))
        late["addresses"] = ["192.168.100.99"]
        self.feed(json.dumps(late).encode())
        self.assertEqual(self.receiver.endpoint_for("10020db9d1"), ("192.168.100.243", 8081))

    def test_new_boot_with_lower_n_is_applied(self):
        self.feed(record("10020db9d1", 10, {"switch": "on"}, 50))
        self.feed(record("10020db9d1", 11, {"switch": "off"}, 1, "Added", boot="run2"))
        self.assertEqual(self.seqs(), ["10", "11"])
        self.assertEqual(self.receiver._last_applied["10020db9d1"], ("run2", 1))

    def test_late_added_after_removed_does_not_revive(self):
        self.feed(record("10020db9d1", 10, {"switch": "on"}, 5, "Added"))
        self.feed(removed("10020db9d1", 7))
        self.feed(record("10020db9d1", 10, {"switch": "on"}, 6, "Added"))
        self.assertEqual(self.seqs(), ["10"])
        self.assertIsNone(self.receiver.endpoint_for("10020db9d1"))
        self.assertNotIn("10020db9d1", self.receiver._last_seq)
        # A newer record after the removal is applied, the same seq included
        self.feed(record("10020db9d1", 10, {"switch": "on"}, 8, "Added"))
        self.assertEqual(self.seqs(), ["10", "10"])

    def test_late_removed_is_dropped(self):
        self.feed(record("10020db9d1", 10, {"switch": "on"}, 5))
        self.feed(removed("10020db9d1", 4))
        self.assertEqual(self.receiver.endpoint_for("10020db9d1"), ("192.168.100.243", 8081))
        self.assertEqual(self.receiver._last_seq["10020db9d1"], "10")

    def test_seq_differs_rule_holds_across_boot_change(self):
        self.feed(record("10020db9d1", 10, {"switch": "on"}, 50))
        # New relay run, same seq: refreshes the endpoint, applies nothing
        self.feed(record("10020db9d1", 10, {"switch": "on"}, 1, "Added", boot="run2"))
        self.assertEqual(self.seqs(), ["10"])
        # New relay run, lower seq: applied, as the seq only has to differ
        self.feed(record("10020db9d1", 3, {"switch": "off"}, 2, boot="run2"))
        self.assertEqual(self.seqs(), ["10", "3"])

    def test_counter_is_per_device(self):
        self.feed(record("10020db9d1", 10, {"switch": "on"}, 5))
        self.feed(record("1001d504c3", 20, {"switch": "on"}, 3))
        self.assertEqual(self.seqs(), ["10", "20"])


class FakeMqtt:
    def __init__(self):
        self.published: List[Tuple[str, str]] = []

    def publish(self, topic, payload):
        self.published.append((topic, payload))


class ObserverMergeTests(unittest.TestCase):
    """The LAN path through Observer._on_lan_state into Device and MQTT."""

    def make_observer(self) -> Observer:
        # The real __init__, so attributes added to it later are present here
        # too; only the MQTT client is replaced, as it would reach for a broker
        config = SimpleNamespace(mqtt=SimpleNamespace(base_topic="sonoff"))
        with mock.patch("sonoff_mqtt.observer.MqttPublisher", lambda _config: FakeMqtt()):
            observer = Observer(config)
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
