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
import ipaddress
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
from sonoff_mqtt import lan_relay as lan_relay_module
from sonoff_mqtt.config import LanRelayConfig
from sonoff_mqtt.lan_relay import (
    ENDPOINT_FRESH_SECONDS,
    LanRelayReceiver,
    _usable_device_address,
    decrypt_params,
)
from sonoff_mqtt.observer import Observer

# Made-up key in the same 36 character format as a real devicekey
DEVICEKEY = "00000000-1111-2222-3333-444444444444"
RELAY = "192.0.2.20"


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


def record(deviceid: str, seq: int, params: Dict[str, Any], n: Any,
           event: str = "Updated", devicekey: str = DEVICEKEY, boot: str = "run1",
           addresses: Tuple[Any, ...] = ("198.51.100.43",)) -> bytes:
    """One relay datagram, with the payload split over data fields like TXT."""
    data, iv = encrypt_params(params, devicekey)
    chunks = [data[i:i + 249] for i in range(0, len(data), 249)]
    txt = {f"data{i + 1}": chunk for i, chunk in enumerate(chunks)}
    txt.update({"id": deviceid, "type": "plug", "seq": str(seq), "encrypt": "true", "iv": iv})
    message = {"v": 1, "boot": boot, "n": n, "event": event, "ts": 0.0,
               "name": f"eWeLink_{deviceid}._ewelink._tcp.local.", "deviceid": deviceid,
               "addresses": list(addresses), "port": 8081, "txt": txt}
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
               "addresses": ["198.51.100.66"], "port": 8081,
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
    keys = {"100000000a": DEVICEKEY, "100000000b": DEVICEKEY}
    return LanRelayReceiver(config, collector, keys.get)


class ReceiverTests(unittest.TestCase):
    def test_decrypt_roundtrip(self):
        data, iv = encrypt_params({"switch": "on"}, DEVICEKEY)
        self.assertEqual(decrypt_params(data, iv, DEVICEKEY), {"switch": "on"})

    def test_applies_new_seq_and_skips_repeated_seq(self):
        collector = Collector()
        receiver = make_receiver(collector)
        receiver.datagram_received(record("100000000a", 8420, {"switch": "on"}, 1, "Added"), (RELAY, 5000))
        receiver.datagram_received(record("100000000a", 8420, {"switch": "on"}, 2, "Resync"), (RELAY, 5000))
        receiver.datagram_received(record("100000000a", 8421, {"switch": "off"}, 3), (RELAY, 5000))
        self.assertEqual([(c[2], c[1]["switch"]) for c in collector.calls], [("8420", "on"), ("8421", "off")])

    def test_lower_seq_is_applied(self):
        # A device that restarts may count from a lower seq; it must not be ignored
        collector = Collector()
        receiver = make_receiver(collector)
        receiver.datagram_received(record("100000000a", 8421, {"switch": "off"}, 1), (RELAY, 5000))
        receiver.datagram_received(record("100000000a", 3, {"switch": "on"}, 2), (RELAY, 5000))
        self.assertEqual(len(collector.calls), 2)

    def test_drops_other_sources(self):
        collector = Collector()
        receiver = make_receiver(collector)
        receiver.datagram_received(record("100000000a", 1, {"switch": "on"}, 1), ("198.51.100.99", 5000))
        self.assertEqual(collector.calls, [])

    def test_wrong_key_is_not_applied_and_retried_on_resync(self):
        collector = Collector()
        receiver = make_receiver(collector)
        bad = record("100000000a", 5, {"switch": "on"}, 1, devicekey="ffffffff-1111-2222-3333-444444444444")
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            receiver.datagram_received(bad, (RELAY, 5000))
        self.assertEqual(collector.calls, [])
        self.assertIn("could not be decrypted", logs.output[0])
        # Same seq with a decryptable payload is applied, since nothing was applied for it
        receiver.datagram_received(record("100000000a", 5, {"switch": "on"}, 2, "Resync"), (RELAY, 5000))
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
        receiver.datagram_received(record("100000000a", 7, {"switch": "on"}, 1), (RELAY, 5000))
        removed = json.dumps({"v": 1, "boot": "run1", "n": 2, "event": "Removed", "ts": 0.0,
                              "name": "x", "deviceid": "100000000a"}).encode()
        receiver.datagram_received(removed, (RELAY, 5000))
        receiver.datagram_received(record("100000000a", 7, {"switch": "on"}, 3, "Added"), (RELAY, 5000))
        self.assertEqual(len(collector.calls), 2)

    def test_lost_datagram_is_logged(self):
        receiver = make_receiver(Collector())
        receiver.datagram_received(record("100000000a", 1, {"switch": "on"}, 1), (RELAY, 5000))
        with self.assertLogs("sonoff_mqtt.lan_relay", level="INFO") as logs:
            receiver.datagram_received(record("100000000a", 2, {"switch": "on"}, 4), (RELAY, 5000))
        self.assertIn("2 datagram(s) lost", logs.output[0])


class RecordCheckTests(unittest.TestCase):
    """Records carrying TXT are checked as a whole before any of them is used."""

    def setUp(self):
        self.collector = Collector()
        self.receiver = make_receiver(self.collector)

    def feed(self, datagram: bytes):
        self.receiver.datagram_received(datagram, (RELAY, 5000))

    def test_plaintext_for_device_with_devicekey_is_rejected(self):
        self.feed(record("100000000a", 1, {"switch": "on"}, 1, "Added"))
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed(plaintext("100000000a", 2, {"switch": "off"}, 2))
        self.assertIn("is not encrypted although the device has a devicekey", logs.output[0])
        self.assertEqual([c[2] for c in self.collector.calls], ["1"])
        self.assertEqual(self.receiver.endpoint_for("100000000a"), ("198.51.100.43", 8081))
        self.assertEqual(self.receiver._last_seq["100000000a"], "1")
        self.assertEqual(self.receiver._last_applied[("100000000a", RELAY)], ("run1", 1))

    def test_encrypted_for_device_with_devicekey_is_accepted(self):
        with self.assertNoLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            self.feed(record("100000000a", 1, {"switch": "on"}, 1, "Added"))
        self.assertEqual([(c[2], c[1]) for c in self.collector.calls], [("1", {"switch": "on"})])
        self.assertEqual(self.receiver.endpoint_for("100000000a"), ("198.51.100.43", 8081))

    def test_plaintext_for_device_without_devicekey_stores_nothing(self):
        # The record is not rejected, but a device without a devicekey can be
        # neither decrypted nor commanded, so no state, endpoint or counter is
        # kept for it
        with self.assertNoLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            self.feed(plaintext("ffffffffff", 1, {"switch": "on"}, 1, "Added"))
        self.assertEqual(self.collector.calls, [])
        self.assertIsNone(self.receiver.endpoint_for("ffffffffff"))
        self.assertEqual(self.receiver._devices, {})
        self.assertEqual(self.receiver._last_applied, {})

    def test_rejection_for_device_without_devicekey_keeps_no_state(self):
        with self.assertNoLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            self.feed(with_txt(plaintext("ffffffffff", 1, {"switch": "on"}, 1), id=None))
        self.assertEqual(self.receiver._rejected, {})

    def test_missing_txt_id_is_rejected(self):
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed(with_txt(record("100000000a", 1, {"switch": "on"}, 1, "Added"), id=None))
        self.assertIn("without a txt id", logs.output[0])
        self.assertEqual(self.collector.calls, [])
        self.assertIsNone(self.receiver.endpoint_for("100000000a"))
        self.assertNotIn(("100000000a", RELAY), self.receiver._last_applied)

    def test_mismatched_txt_id_is_rejected(self):
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed(with_txt(record("100000000a", 1, {"switch": "on"}, 1, "Added"), id="100000000b"))
        self.assertIn("txt id for another device", logs.output[0])
        self.assertEqual(self.collector.calls, [])
        self.assertIsNone(self.receiver.endpoint_for("100000000a"))

    def test_missing_seq_is_rejected_and_logged_once_until_a_valid_record(self):
        no_seq = lambda n, **kw: with_txt(record("100000000a", 1, {"switch": "on"}, n), **kw)
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed(no_seq(1, seq=None))
            self.feed(no_seq(2, seq=""))
            self.feed(no_seq(3, seq=None))
        self.assertEqual(len(logs.output), 1)
        self.assertIn("without a seq", logs.output[0])
        self.assertEqual(self.collector.calls, [])
        self.assertIsNone(self.receiver.endpoint_for("100000000a"))

        # A valid record re-arms the warning
        self.feed(record("100000000a", 5, {"switch": "on"}, 4))
        self.assertEqual([c[2] for c in self.collector.calls], ["5"])
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed(no_seq(5, seq=None))
            self.feed(no_seq(6, seq=None))
        self.assertEqual(len(logs.output), 1)
        self.assertEqual([c[2] for c in self.collector.calls], ["5"])

    def test_rejections_are_logged_once_per_reason(self):
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed(plaintext("100000000a", 1, {"switch": "on"}, 1))
            self.feed(plaintext("100000000a", 2, {"switch": "on"}, 2))
            self.feed(with_txt(record("100000000a", 3, {"switch": "on"}, 3), seq=None))
        self.assertEqual(len(logs.output), 2)

    def test_non_string_data_field_is_skipped(self):
        # data1 is not a string, so it is left out of the payload and data2
        # carries all of it; joined as str(123) in front, it would have shifted
        # the base64 and broken the decryption
        datagram = record("100000000a", 1, {"switch": "on"}, 1, "Added")
        ciphertext = json.loads(datagram)["txt"]["data1"]
        self.feed(with_txt(datagram, data1=123, data2=ciphertext))
        self.assertEqual([(c[2], c[1]) for c in self.collector.calls], [("1", {"switch": "on"})])

    def test_removed_needs_no_txt_or_seq(self):
        self.feed(record("100000000a", 1, {"switch": "on"}, 1, "Added"))
        with self.assertNoLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            self.feed(removed("100000000a", 2))
        self.assertIsNone(self.receiver.endpoint_for("100000000a"))


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
        self.feed(record("100000000a", 10, {"switch": "on"}, 5))
        with self.assertLogs("sonoff_mqtt.lan_relay", level="DEBUG") as logs:
            self.feed(record("100000000a", 9, {"switch": "off"}, 4))
            self.feed(with_txt(record("100000000a", 11, {"switch": "off"}, 5), port=1))
        self.assertTrue(all("dropped" in line for line in logs.output))
        self.assertEqual(self.seqs(), ["10"])
        self.assertEqual(self.receiver._last_seq["100000000a"], "10")
        self.assertEqual(self.receiver._last_applied[("100000000a", RELAY)], ("run1", 5))

    def test_same_boot_higher_n_is_applied(self):
        self.feed(record("100000000a", 10, {"switch": "on"}, 5))
        self.feed(record("100000000a", 11, {"switch": "off"}, 6))
        self.assertEqual(self.seqs(), ["10", "11"])
        self.assertEqual(self.receiver._last_applied[("100000000a", RELAY)], ("run1", 6))

    def test_late_datagram_does_not_move_endpoint(self):
        self.feed(record("100000000a", 10, {"switch": "on"}, 5))
        late = json.loads(record("100000000a", 10, {"switch": "on"}, 3, "Resync"))
        late["addresses"] = ["198.51.100.99"]
        self.feed(json.dumps(late).encode())
        self.assertEqual(self.receiver.endpoint_for("100000000a"), ("198.51.100.43", 8081))

    def test_new_boot_with_lower_n_is_applied(self):
        self.feed(record("100000000a", 10, {"switch": "on"}, 50))
        self.feed(record("100000000a", 11, {"switch": "off"}, 1, "Added", boot="run2"))
        self.assertEqual(self.seqs(), ["10", "11"])
        self.assertEqual(self.receiver._last_applied[("100000000a", RELAY)], ("run2", 1))

    def test_late_added_after_removed_does_not_revive(self):
        self.feed(record("100000000a", 10, {"switch": "on"}, 5, "Added"))
        self.feed(removed("100000000a", 7))
        self.feed(record("100000000a", 10, {"switch": "on"}, 6, "Added"))
        self.assertEqual(self.seqs(), ["10"])
        self.assertIsNone(self.receiver.endpoint_for("100000000a"))
        self.assertNotIn("100000000a", self.receiver._last_seq)
        # A newer record after the removal is applied, the same seq included
        self.feed(record("100000000a", 10, {"switch": "on"}, 8, "Added"))
        self.assertEqual(self.seqs(), ["10", "10"])

    def test_late_removed_is_dropped(self):
        self.feed(record("100000000a", 10, {"switch": "on"}, 5))
        self.feed(removed("100000000a", 4))
        self.assertEqual(self.receiver.endpoint_for("100000000a"), ("198.51.100.43", 8081))
        self.assertEqual(self.receiver._last_seq["100000000a"], "10")

    def test_seq_differs_rule_holds_across_boot_change(self):
        self.feed(record("100000000a", 10, {"switch": "on"}, 50))
        # New relay run, same seq: refreshes the endpoint, applies nothing
        self.feed(record("100000000a", 10, {"switch": "on"}, 1, "Added", boot="run2"))
        self.assertEqual(self.seqs(), ["10"])
        # New relay run, lower seq: applied, as the seq only has to differ
        self.feed(record("100000000a", 3, {"switch": "off"}, 2, boot="run2"))
        self.assertEqual(self.seqs(), ["10", "3"])

    def test_counter_is_per_device(self):
        self.feed(record("100000000a", 10, {"switch": "on"}, 5))
        self.feed(record("100000000b", 20, {"switch": "on"}, 3))
        self.assertEqual(self.seqs(), ["10", "20"])


# ==============================================================================
# Several relays: per-relay counters and silence, endpoints and ownership
# ==============================================================================

# Documentation addresses (RFC 5737) for the relays and the devices behind them
RELAY_A = "192.0.2.10"
RELAY_B = "198.51.100.10"
DEVICE = "100000000a"
ADDRESS_A = "203.0.113.10"
ADDRESS_B = "203.0.113.20"
WRONG_KEY = "ffffffff-1111-2222-3333-444444444444"


class Clock:
    """Stands in for the time module in lan_relay, which only uses monotonic()."""

    def __init__(self, now: float = 1000.0):
        self.now = now

    def monotonic(self) -> float:
        return self.now


class MultiRelayCase(unittest.TestCase):
    """A receiver accepting RELAY_A and RELAY_B, with a clock the test controls."""

    sources: Tuple[str, ...] = (RELAY_A, RELAY_B)

    def setUp(self):
        self.clock = Clock()
        patcher = mock.patch.object(lan_relay_module, "time", self.clock)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.collector = Collector()
        config = LanRelayConfig(enabled=True, allowed_sources=list(self.sources),
                                silence_warning_seconds=180.0)
        keys = {DEVICE: DEVICEKEY, "100000000b": DEVICEKEY}
        self.receiver = LanRelayReceiver(config, self.collector, keys.get)

    def feed(self, source: str, datagram: bytes):
        self.receiver.datagram_received(datagram, (source, 5000))

    def state(self, source: str):
        return self.receiver._sources[ipaddress.ip_address(source)]

    def seqs(self):
        return [c[2] for c in self.collector.calls]

    def owner(self, deviceid: str = DEVICE):
        entry = self.receiver._devices.get(deviceid)
        return entry.owner if entry is not None else None


class PerSourceCounterTests(MultiRelayCase):
    def test_first_datagram_since_start_is_logged_per_source(self):
        with self.assertLogs("sonoff_mqtt.lan_relay", level="INFO") as logs:
            self.feed(RELAY_A, record(DEVICE, 1, {"switch": "on"}, 7, boot="runA"))
            self.feed(RELAY_B, record("100000000b", 1, {"switch": "on"}, 3, boot="runB"))
        self.assertEqual(logs.output, [
            f"INFO:sonoff_mqtt.lan_relay:LAN relay {RELAY_A}: first datagram since start (run runA, n=7)",
            f"INFO:sonoff_mqtt.lan_relay:LAN relay {RELAY_B}: first datagram since start (run runB, n=3)",
        ])

    def test_switching_relays_is_not_a_restart(self):
        with self.assertLogs("sonoff_mqtt.lan_relay", level="INFO") as logs:
            self.feed(RELAY_A, record(DEVICE, 1, {"switch": "on"}, 1, boot="runA"))
            self.feed(RELAY_B, record("100000000b", 1, {"switch": "on"}, 1, boot="runB"))
            self.feed(RELAY_A, record(DEVICE, 2, {"switch": "on"}, 2, boot="runA"))
            self.feed(RELAY_B, record("100000000b", 2, {"switch": "on"}, 2, boot="runB"))
        self.assertFalse([line for line in logs.output if "restarted" in line or "lost" in line])
        self.assertEqual(len([line for line in logs.output if "first datagram" in line]), 2)

    def test_restart_is_per_source(self):
        self.feed(RELAY_A, record(DEVICE, 1, {"switch": "on"}, 5, boot="run1"))
        self.feed(RELAY_B, record("100000000b", 1, {"switch": "on"}, 1, boot="runB"))
        with self.assertLogs("sonoff_mqtt.lan_relay", level="INFO") as logs:
            self.feed(RELAY_A, record(DEVICE, 2, {"switch": "on"}, 1, boot="run2"))
            self.feed(RELAY_B, record("100000000b", 2, {"switch": "on"}, 2, boot="runB"))
        self.assertEqual(logs.output, [
            f"INFO:sonoff_mqtt.lan_relay:LAN relay {RELAY_A}: relay restarted (run run2, was run1)",
        ])

    def test_loss_counted_after_switch(self):
        self.feed(RELAY_A, record(DEVICE, 1, {"switch": "on"}, 1, boot="runA"))
        self.feed(RELAY_B, record("100000000b", 1, {"switch": "on"}, 1, boot="runB"))
        with self.assertLogs("sonoff_mqtt.lan_relay", level="INFO") as logs:
            self.feed(RELAY_A, record(DEVICE, 2, {"switch": "on"}, 4, boot="runA"))
        self.assertEqual(logs.output, [
            f"INFO:sonoff_mqtt.lan_relay:LAN relay {RELAY_A}: 2 datagram(s) lost (run runA, n=4 after 1)",
        ])

    def test_loss_at_start_of_new_run(self):
        self.feed(RELAY_A, record(DEVICE, 1, {"switch": "on"}, 9, boot="run1"))
        with self.assertLogs("sonoff_mqtt.lan_relay", level="INFO") as logs:
            self.feed(RELAY_A, record(DEVICE, 2, {"switch": "on"}, 3, boot="run2"))
        self.assertEqual(logs.output, [
            f"INFO:sonoff_mqtt.lan_relay:LAN relay {RELAY_A}: relay restarted (run run2, was run1), "
            f"2 datagram(s) of the new run lost",
        ])

    def test_late_datagram_does_not_double_count(self):
        with self.assertLogs("sonoff_mqtt.lan_relay", level="INFO") as logs:
            for n in (5, 7, 6, 8):
                self.feed(RELAY_A, record(DEVICE, n, {"switch": "on"}, n))
        self.assertEqual([line for line in logs.output if "lost" in line], [
            f"INFO:sonoff_mqtt.lan_relay:LAN relay {RELAY_A}: 1 datagram(s) lost (run run1, n=7 after 5)",
        ])
        self.assertEqual(self.state(RELAY_A).n, 8)

    def test_late_datagram_of_previous_run_is_not_a_restart(self):
        self.feed(RELAY_A, record(DEVICE, 1, {"switch": "on"}, 5, boot="run1"))
        with self.assertLogs("sonoff_mqtt.lan_relay", level="INFO") as logs:
            self.feed(RELAY_A, record(DEVICE, 2, {"switch": "on"}, 1, boot="run2"))
            self.feed(RELAY_A, record(DEVICE, 3, {"switch": "on"}, 6, boot="run1"))
            self.feed(RELAY_A, record(DEVICE, 4, {"switch": "on"}, 2, boot="run2"))
        self.assertEqual([line for line in logs.output if "restarted" in line or "lost" in line], [
            f"INFO:sonoff_mqtt.lan_relay:LAN relay {RELAY_A}: relay restarted (run run2, was run1)",
        ])
        state = self.state(RELAY_A)
        self.assertEqual((state.boot, state.previous_boot, state.n), ("run2", "run1", 2))

    def test_bool_n_is_not_counted(self):
        with self.assertNoLogs("sonoff_mqtt.lan_relay", level="INFO"):
            self.feed(RELAY_A, record(DEVICE, 1, {"switch": "on"}, True))
        state = self.state(RELAY_A)
        self.assertIsNone(state.boot)
        self.assertIsNone(state.n)
        # The record itself is still used, without a counter for the late filter
        self.assertEqual(self.seqs(), ["1"])
        self.assertEqual(self.receiver._last_applied, {})


class PerSourceSilenceTests(MultiRelayCase):
    def test_silence_is_per_source(self):
        self.feed(RELAY_A, record(DEVICE, 1, {"switch": "on"}, 1))
        self.feed(RELAY_B, record("100000000b", 1, {"switch": "on"}, 1))
        self.clock.now += 100
        self.feed(RELAY_A, record(DEVICE, 2, {"switch": "on"}, 2))
        self.clock.now += 100
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.receiver._check_silence()
        self.assertEqual(logs.output, [
            f"WARNING:sonoff_mqtt.lan_relay:LAN relay {RELAY_B}: nothing received for 200s, "
            f"LAN state from this relay is going stale",
        ])
        self.assertFalse(self.state(RELAY_A).silent)
        self.assertTrue(self.state(RELAY_B).silent)

    def test_never_heard_source_is_warned_once(self):
        self.clock.now += 100
        self.feed(RELAY_A, record(DEVICE, 1, {"switch": "on"}, 1))
        self.clock.now += 81
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.receiver._check_silence()
        self.assertEqual(logs.output, [
            f"WARNING:sonoff_mqtt.lan_relay:LAN relay {RELAY_B}: nothing received since start 181s ago",
        ])
        self.clock.now += 50
        self.feed(RELAY_A, record(DEVICE, 2, {"switch": "on"}, 2))
        with self.assertNoLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            self.receiver._check_silence()

    def test_quiet_below_threshold_is_not_warned(self):
        self.clock.now += 180
        with self.assertNoLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            self.receiver._check_silence()

    def test_receiving_again_per_source(self):
        self.feed(RELAY_A, record(DEVICE, 1, {"switch": "on"}, 1))
        self.feed(RELAY_B, record("100000000b", 1, {"switch": "on"}, 1))
        self.clock.now += 190
        self.feed(RELAY_A, record(DEVICE, 2, {"switch": "on"}, 2))
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            self.receiver._check_silence()
        self.clock.now += 10
        with self.assertLogs("sonoff_mqtt.lan_relay", level="INFO") as logs:
            self.feed(RELAY_B, record("100000000b", 2, {"switch": "on"}, 2))
        self.assertEqual(logs.output, [
            f"INFO:sonoff_mqtt.lan_relay:LAN relay {RELAY_B}: receiving again after 200s",
        ])
        self.assertFalse(self.state(RELAY_B).silent)
        # A later silence of B is a new episode and warned again
        self.clock.now += 181
        self.feed(RELAY_A, record(DEVICE, 3, {"switch": "on"}, 3))
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.receiver._check_silence()
        self.assertEqual(len(logs.output), 1)
        self.assertIn(f"LAN relay {RELAY_B}: nothing received for 181s", logs.output[0])

    def test_start_resets_the_reference_for_unheard_sources(self):
        async def run():
            config = LanRelayConfig(enabled=True, listen_port=0, allowed_sources=[RELAY_A])
            receiver = LanRelayReceiver(config, Collector(), {}.get)
            self.clock.now += 500
            await receiver.start()
            try:
                self.clock.now += 100
                with self.assertNoLogs("sonoff_mqtt.lan_relay", level="WARNING"):
                    receiver._check_silence()
            finally:
                await receiver.stop()
        asyncio.run(run())


class SourceSetTests(MultiRelayCase):
    sources = (RELAY_A, RELAY_A, RELAY_B)

    def test_duplicate_allowed_sources_give_one_state(self):
        self.assertEqual(sorted(state.address for state in self.receiver._sources.values()),
                         sorted([RELAY_A, RELAY_B]))
        self.clock.now += 200
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.receiver._check_silence()
        self.assertEqual(len(logs.output), 2)

    def test_unlisted_source_creates_no_state(self):
        before = dict(self.receiver._sources)
        self.feed("203.0.113.99", record(DEVICE, 1, {"switch": "on"}, 1))
        self.assertEqual(self.receiver._sources, before)
        self.assertEqual(self.collector.calls, [])
        self.assertEqual(self.receiver._devices, {})
        self.assertIsNone(self.state(RELAY_A).last_rx)


class EndpointHandlingTests(MultiRelayCase):
    def test_endpoint_not_stored_when_decryption_fails(self):
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed(RELAY_A, record(DEVICE, 5, {"switch": "on"}, 1, devicekey=WRONG_KEY,
                                      addresses=(ADDRESS_A,)))
        self.assertIn(f"LAN relay {RELAY_A}: {DEVICE} seq 5 could not be decrypted", logs.output[0])
        self.assertIsNone(self.receiver.endpoint_for(DEVICE))
        self.assertNotIn(DEVICE, self.receiver._devices)
        self.assertEqual(self.receiver._last_applied, {})

    def test_resync_with_same_seq_refreshes_endpoint_without_second_on_state(self):
        self.feed(RELAY_A, record(DEVICE, 5, {"switch": "on"}, 1, addresses=(ADDRESS_A,)))
        self.clock.now += ENDPOINT_FRESH_SECONDS + 1
        self.assertIsNone(self.receiver.endpoint_for(DEVICE))
        self.feed(RELAY_A, record(DEVICE, 5, {"switch": "on"}, 2, "Resync", addresses=(ADDRESS_A,)))
        self.assertEqual(self.receiver.endpoint_for(DEVICE), (ADDRESS_A, 8081))
        self.assertEqual(self.seqs(), ["5"])

    def test_rejected_addresses(self):
        for bad in ("127.0.0.1", "224.0.0.251", "255.255.255.255", "0.0.0.0", "0.1.2.3",
                    "169.254.1.1", "240.0.0.1", "fe80::1", "junk", None, 3405803786):
            with self.subTest(address=bad):
                self.assertIsNone(_usable_device_address(bad))
                receiver = LanRelayReceiver(
                    LanRelayConfig(enabled=True, allowed_sources=[RELAY_A]), Collector(),
                    {DEVICE: DEVICEKEY}.get,
                )
                receiver.datagram_received(record(DEVICE, 1, {"switch": "on"}, 1, addresses=(bad,)),
                                           (RELAY_A, 5000))
                self.assertIsNone(receiver.endpoint_for(DEVICE))
                # The record itself is still used and claims the device
                self.assertEqual(receiver._devices[DEVICE].owner, RELAY_A)

    def test_usable_addresses(self):
        for good in (ADDRESS_A, "10.1.2.3", "100.64.1.1", "192.0.2.255"):
            with self.subTest(address=good):
                self.assertEqual(str(_usable_device_address(good)), good)

    def test_first_usable_address_is_taken(self):
        addresses = ("127.0.0.1", "fe80::1", "169.254.1.1", ADDRESS_A, ADDRESS_B)
        self.feed(RELAY_A, record(DEVICE, 1, {"switch": "on"}, 1, addresses=addresses))
        self.assertEqual(self.receiver.endpoint_for(DEVICE), (ADDRESS_A, 8081))

    def test_record_without_usable_address_keeps_the_previous_one(self):
        self.feed(RELAY_A, record(DEVICE, 1, {"switch": "on"}, 1, addresses=(ADDRESS_A,)))
        self.clock.now += 10
        self.feed(RELAY_A, record(DEVICE, 1, {"switch": "on"}, 2, "Resync", addresses=("127.0.0.1",)))
        self.assertEqual(self.receiver.endpoint_for(DEVICE), (ADDRESS_A, 8081))
        # It is not refreshed by that record, so it goes stale from the first one
        self.clock.now += ENDPOINT_FRESH_SECONDS - 5
        self.assertIsNone(self.receiver.endpoint_for(DEVICE))


class OwnershipTests(MultiRelayCase):
    def feed_a(self, seq: int, n: int, event: str = "Updated", **kw):
        self.feed(RELAY_A, record(DEVICE, seq, {"switch": "on"}, n, event,
                                  addresses=(ADDRESS_A,), **kw))

    def feed_b(self, seq: int, n: int, event: str = "Updated", **kw):
        self.feed(RELAY_B, record(DEVICE, seq, {"switch": "off"}, n, event, boot="runB",
                                  addresses=(ADDRESS_B,), **kw))

    def test_first_source_owns_and_conflict_names_both(self):
        self.feed_a(1, 1, "Added")
        self.clock.now += 20
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed_b(2, 1, "Added")
        self.assertEqual(logs.output, [
            f"WARNING:sonoff_mqtt.lan_relay:LAN relay {RELAY_B}: Added {DEVICE} ignored, "
            f"owned by {RELAY_A} (last record 20s ago)",
        ])
        self.assertEqual(self.owner(), RELAY_A)
        self.assertEqual(self.receiver.endpoint_for(DEVICE), (ADDRESS_A, 8081))
        self.assertEqual(self.seqs(), ["1"])

    def test_conflict_logged_once(self):
        self.feed_a(1, 1)
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            for n in (1, 2, 3):
                self.feed_b(10 + n, n)
        self.assertEqual(len(logs.output), 1)
        self.assertEqual(self.seqs(), ["1"])

    def test_owner_change_after_fresh_window(self):
        self.feed_a(1, 1)
        self.clock.now += ENDPOINT_FRESH_SECONDS + 1
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed_b(2, 1)
        self.assertEqual(logs.output, [
            f"WARNING:sonoff_mqtt.lan_relay:LAN relay {RELAY_B}: {DEVICE} now owned by this relay, "
            f"{RELAY_A} silent for 151s",
        ])
        self.assertEqual(self.owner(), RELAY_B)
        self.assertEqual(self.receiver.endpoint_for(DEVICE), (ADDRESS_B, 8081))
        self.assertEqual(self.seqs(), ["1", "2"])
        # Now A is the one that is ignored while B is fresh
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed_a(3, 2)
        self.assertIn(f"LAN relay {RELAY_A}: Updated {DEVICE} ignored, owned by {RELAY_B}",
                      logs.output[0])

    def test_no_owner_change_within_window(self):
        self.feed_a(1, 1)
        self.clock.now += ENDPOINT_FRESH_SECONDS - 1
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed_b(2, 1)
        self.assertIn("ignored, owned by", logs.output[0])
        self.assertEqual(self.owner(), RELAY_A)
        self.assertEqual(self.receiver.endpoint_for(DEVICE), (ADDRESS_A, 8081))
        self.assertEqual(self.seqs(), ["1"])

    def test_owner_record_keeps_ownership_fresh(self):
        self.feed_a(1, 1)
        self.clock.now += 100
        self.feed_a(1, 2, "Resync")
        self.clock.now += 100
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed_b(2, 1)
        self.assertIn("(last record 100s ago)", logs.output[0])
        self.assertEqual(self.owner(), RELAY_A)

    def test_owner_restart_keeps_owner(self):
        self.feed_a(1, 5, boot="run1")
        with self.assertNoLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            self.feed_a(2, 1, "Added", boot="run2")
        self.assertEqual(self.owner(), RELAY_A)
        self.assertEqual(self.seqs(), ["1", "2"])
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed_b(3, 1)
        self.assertIn("ignored, owned by", logs.output[0])
        self.assertEqual(self.owner(), RELAY_A)

    def test_owner_silent_then_back_without_rival_stays_owner(self):
        self.feed_a(1, 1)
        self.clock.now += ENDPOINT_FRESH_SECONDS + 50
        self.assertIsNone(self.receiver.endpoint_for(DEVICE))
        with self.assertNoLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            self.feed_a(1, 2, "Resync")
        self.assertEqual(self.owner(), RELAY_A)
        self.assertEqual(self.receiver.endpoint_for(DEVICE), (ADDRESS_A, 8081))

    def test_removed_from_non_owner_is_ignored(self):
        self.feed_a(1, 1)
        with self.assertLogs("sonoff_mqtt.lan_relay", level="DEBUG") as logs:
            self.feed(RELAY_B, removed(DEVICE, 2, boot="runB"))
        self.assertTrue(any(f"LAN relay {RELAY_B}: Removed {DEVICE} ignored, owned by {RELAY_A}" in line
                            for line in logs.output))
        self.assertFalse([line for line in logs.output if not line.startswith("DEBUG")
                          and "first datagram" not in line])
        self.assertEqual(self.owner(), RELAY_A)
        self.assertEqual(self.receiver.endpoint_for(DEVICE), (ADDRESS_A, 8081))
        self.assertEqual(self.receiver._last_seq[DEVICE], "1")

    def test_removed_from_owner_frees_device(self):
        self.feed_a(1, 1)
        with self.assertLogs("sonoff_mqtt.lan_relay", level="INFO") as logs:
            self.feed(RELAY_A, removed(DEVICE, 2))
        self.assertIn(f"INFO:sonoff_mqtt.lan_relay:LAN relay {RELAY_A}: {DEVICE} left mDNS", logs.output)
        self.assertNotIn(DEVICE, self.receiver._devices)
        self.assertNotIn(DEVICE, self.receiver._last_seq)
        self.assertIsNone(self.receiver.endpoint_for(DEVICE))
        # Another relay may take it at once
        with self.assertNoLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            self.feed_b(1, 1)
        self.assertEqual(self.owner(), RELAY_B)
        self.assertEqual(self.receiver.endpoint_for(DEVICE), (ADDRESS_B, 8081))
        self.assertEqual(self.seqs(), ["1", "1"])

    def test_first_seen_via_removed(self):
        with self.assertLogs("sonoff_mqtt.lan_relay", level="DEBUG") as logs:
            self.feed(RELAY_A, removed(DEVICE, 1))
        self.assertTrue(any(f"LAN relay {RELAY_A}: {DEVICE} left mDNS, not known here" in line
                            for line in logs.output))
        self.assertEqual(self.receiver._devices, {})
        self.assertEqual(self.receiver._last_applied, {})
        self.feed_a(1, 2)
        self.assertEqual(self.owner(), RELAY_A)
        self.assertEqual(self.seqs(), ["1"])

    def test_late_filter_is_per_source(self):
        self.feed_a(1, 10, boot="run1")
        self.clock.now += ENDPOINT_FRESH_SECONDS + 1
        # Same boot string and a lower n, but from another relay: not late
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING"):
            self.feed(RELAY_B, record(DEVICE, 2, {"switch": "off"}, 5, boot="run1",
                                      addresses=(ADDRESS_B,)))
        self.assertEqual(self.owner(), RELAY_B)
        self.assertEqual(self.receiver._last_applied[(DEVICE, RELAY_A)], ("run1", 10))
        self.assertEqual(self.receiver._last_applied[(DEVICE, RELAY_B)], ("run1", 5))
        self.clock.now += ENDPOINT_FRESH_SECONDS + 1
        # A late datagram of A's run is still late for A, even with B stale
        with self.assertLogs("sonoff_mqtt.lan_relay", level="DEBUG") as logs:
            self.feed_a(3, 8, boot="run1")
        self.assertTrue(any("dropped" in line for line in logs.output))
        self.assertEqual(self.owner(), RELAY_B)
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed_a(3, 11, boot="run1")
        self.assertIn(f"LAN relay {RELAY_A}: {DEVICE} now owned by this relay", logs.output[0])
        self.assertEqual(self.owner(), RELAY_A)
        self.assertEqual(self.seqs(), ["1", "2", "3"])

    def test_undecryptable_record_cannot_claim(self):
        self.feed_a(1, 1)
        self.clock.now += ENDPOINT_FRESH_SECONDS + 1
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed_b(2, 1, devicekey=WRONG_KEY)
        self.assertEqual(len(logs.output), 1)
        self.assertIn("could not be decrypted", logs.output[0])
        self.assertEqual(self.owner(), RELAY_A)
        self.assertIsNone(self.receiver.endpoint_for(DEVICE))
        self.assertNotIn((DEVICE, RELAY_B), self.receiver._last_applied)
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed_b(2, 2)
        self.assertIn("now owned by this relay", logs.output[0])
        self.assertEqual(self.owner(), RELAY_B)
        self.assertEqual(self.receiver.endpoint_for(DEVICE), (ADDRESS_B, 8081))

    def test_conflict_warning_is_rearmed_by_an_owner_change(self):
        self.feed_a(1, 1)
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed_b(2, 1)
            self.clock.now += ENDPOINT_FRESH_SECONDS + 1
            self.feed_b(2, 2)
            self.clock.now += ENDPOINT_FRESH_SECONDS + 1
            self.feed_a(3, 2)
        self.assertEqual(len(logs.output), 3)
        self.assertEqual(self.owner(), RELAY_A)
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed_b(4, 3)
        self.assertEqual(len(logs.output), 1)
        self.assertIn("ignored, owned by", logs.output[0])

    def test_rejection_reasons_are_kept_per_source(self):
        with self.assertLogs("sonoff_mqtt.lan_relay", level="WARNING") as logs:
            self.feed(RELAY_A, with_txt(record(DEVICE, 1, {"switch": "on"}, 1), seq=None))
            self.feed(RELAY_B, with_txt(record(DEVICE, 1, {"switch": "on"}, 1), seq=None))
            self.feed(RELAY_A, with_txt(record(DEVICE, 1, {"switch": "on"}, 2), seq=None))
        self.assertEqual(len(logs.output), 2)
        self.assertIn(f"LAN relay {RELAY_A}:", logs.output[0])
        self.assertIn(f"LAN relay {RELAY_B}:", logs.output[1])


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
            ("100000000a", 1, {"switch": "on", "rssi": -60}),
            ("100000000b", 4, {"switches": [{"outlet": i, "switch": "off"} for i in range(4)]}),
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
        observer._on_lan_state("100000000a", {"switch": "on", "ssid": "x"}, "1", "Added")
        self.assertEqual(observer.mqtt.published, [])

    def test_switch_change_is_published_and_extra_keys_ignored(self):
        observer = self.make_observer()
        observer._on_lan_state("100000000a", {"switch": "off", "ssid": "x", "rssi": -40}, "2", "Updated")
        self.assertIn(("sonoff/100000000a/switch", "OFF"), observer.mqtt.published)
        device = observer.registry.get("100000000a")
        self.assertNotIn("ssid", device.params)
        self.assertEqual(device.params["rssi"], -60)

    def test_four_channel_outlet_mapping(self):
        observer = self.make_observer()
        switches = [{"outlet": i, "switch": "on" if i == 1 else "off"} for i in range(4)]
        observer._on_lan_state("100000000b", {"switches": switches, "configure": []}, "3411", "Updated")
        published = [p for p in observer.mqtt.published if "/switch" in p[0]]
        self.assertEqual(published, [("sonoff/100000000b/switch1", "ON")])

    def test_first_record_per_device_is_logged(self):
        observer = self.make_observer()
        with self.assertLogs("sonoff_mqtt.observer", level="INFO") as logs:
            observer._on_lan_state("100000000a", {"switch": "on"}, "1", "Added")
        self.assertIn("LAN state received (Added, seq 1)", logs.output[0])
        with self.assertNoLogs("sonoff_mqtt.observer", level="INFO"):
            observer._on_lan_state("100000000a", {"switch": "on"}, "2", "Updated")

    def test_devicekey_lookup(self):
        observer = self.make_observer()
        self.assertEqual(observer._devicekey_for("100000000a"), DEVICEKEY)
        self.assertIsNone(observer._devicekey_for("ffffffffff"))


class UdpEndToEndTest(unittest.IsolatedAsyncioTestCase):
    async def test_real_datagram_over_localhost(self):
        collector = Collector()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        config = LanRelayConfig(enabled=True, listen_port=port, allowed_sources=["127.0.0.1"])
        receiver = LanRelayReceiver(config, collector, {"100000000a": DEVICEKEY}.get)
        await receiver.start()
        try:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.sendto(record("100000000a", 9, {"switch": "off"}, 1), ("127.0.0.1", port))
            sender.close()
            for _ in range(50):
                if collector.calls:
                    break
                await asyncio.sleep(0.02)
        finally:
            await receiver.stop()
        self.assertEqual([(c[0], c[1]["switch"], c[2]) for c in collector.calls], [("100000000a", "off", "9")])


if __name__ == "__main__":
    unittest.main()
