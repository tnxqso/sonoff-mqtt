"""Offline tests for the mDNS relay in relay/mdns_relay.py.

zeroconf and ifaddr are not installed where these tests run, and are not
needed: the modules the relay imports from them are replaced by small stubs in
sys.modules before the relay is loaded from its file path (relay/ is not a
package). The tests then swap in fakes for AsyncServiceInfo,
AsyncServiceBrowser and AsyncZeroconf, and the adapters ifaddr reports, where
they need them. The contract test sends real datagrams over localhost to a real
LanRelayReceiver.

Usage:
    PYTHONPATH=src .venv/bin/python -m unittest tests/test_mdns_relay.py -v
"""

# 1. Standard library
import asyncio
import contextlib
import enum
import importlib.util
import io
import json
import signal
import socket
import sys
import types
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

# 3. Project-local
from sonoff_mqtt.config import LanRelayConfig
from sonoff_mqtt.lan_relay import ENDPOINT_FRESH_SECONDS, LanRelayReceiver
from tests.test_lan_relay import DEVICEKEY, encrypt_params


# ==============================================================================
# zeroconf stubs and loading the relay
# ==============================================================================


class ServiceStateChange(enum.Enum):
    Added = 1
    Removed = 2
    Updated = 3


class _Unused:
    """Placeholder for a zeroconf class a test has not replaced."""

    def __init__(self, *args, **kwargs):
        raise AssertionError(f"{type(self).__name__} stub used without a fake")


class IP:
    """ifaddr 0.2.0 IP: a str for IPv4, an (ip, flowinfo, scope_id) tuple for IPv6."""

    def __init__(self, ip, network_prefix: int, nice_name: str) -> None:
        self.ip = ip
        self.network_prefix = network_prefix
        self.nice_name = nice_name

    @property
    def is_IPv4(self) -> bool:
        return not isinstance(self.ip, tuple)

    @property
    def is_IPv6(self) -> bool:
        return isinstance(self.ip, tuple)


class Adapter:
    """ifaddr 0.2.0 Adapter; on Linux nice_name is the same as name."""

    def __init__(self, name: str, nice_name: str, ips: List[IP], index: Optional[int] = None) -> None:
        self.name = name
        self.nice_name = nice_name
        self.ips = ips
        self.index = index


def adapter(name: str, *ips: Tuple[Any, int], index: Optional[int] = None) -> Adapter:
    return Adapter(name, name, [IP(ip, prefix, name) for ip, prefix in ips], index=index)


# What the ifaddr stub reports unless a test replaces it: loopback, one LAN
# address and an IPv6 link-local one, as on a typical host
DEFAULT_ADAPTERS = [
    adapter("lo", ("127.0.0.1", 8), (("::1", 0, 0), 128), index=1),
    adapter("eth0", ("192.0.2.50", 24), (("fe80::1", 0, 2), 64), index=2),
]


def _get_adapters(include_unconfigured: bool = False):
    # ifaddr returns the values view of a dict keyed by adapter name
    return {a.name: a for a in DEFAULT_ADAPTERS}.values()


def _stub_modules() -> Dict[str, types.ModuleType]:
    """Exactly the modules relay/mdns_relay.py imports from zeroconf and ifaddr."""
    zeroconf = types.ModuleType("zeroconf")
    zeroconf.ServiceStateChange = ServiceStateChange
    zeroconf.Zeroconf = type("Zeroconf", (_Unused,), {})
    zeroconf_asyncio = types.ModuleType("zeroconf.asyncio")
    for name in ("AsyncServiceBrowser", "AsyncServiceInfo", "AsyncZeroconf"):
        setattr(zeroconf_asyncio, name, type(name, (_Unused,), {}))
    zeroconf.asyncio = zeroconf_asyncio
    ifaddr = types.ModuleType("ifaddr")
    ifaddr.IP = IP
    ifaddr.Adapter = Adapter
    ifaddr.get_adapters = _get_adapters
    return {"zeroconf": zeroconf, "zeroconf.asyncio": zeroconf_asyncio, "ifaddr": ifaddr}


_STUBS = _stub_modules()
# What was there before, so tearDownModule can put it back (normally nothing)
_SAVED_MODULES = {name: sys.modules.get(name) for name in _STUBS}
sys.modules.update(_STUBS)

_spec = importlib.util.spec_from_file_location("mdns_relay", ROOT / "relay" / "mdns_relay.py")
relay_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(relay_mod)


def tearDownModule():
    # The loaded relay keeps its own references to the stubs, so removing them
    # here does not affect it, only later imports of zeroconf or ifaddr
    for name, module in _SAVED_MODULES.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


# ==============================================================================
# Fakes and helpers
# ==============================================================================

DEVICE = "100000000a"
NAME = f"eWeLink_{DEVICE}._ewelink._tcp.local."


class FakeSocket:
    def __init__(self):
        self.sent: List[Tuple[bytes, Tuple[str, int]]] = []
        self.fail = False
        self.closed = False

    def sendto(self, payload: bytes, target):
        if self.fail:
            raise OSError(113, "No route to host")
        self.sent.append((payload, target))

    def close(self):
        self.closed = True

    def messages(self) -> List[Dict[str, Any]]:
        return [json.loads(payload) for payload, _ in self.sent]


def make_relay() -> Any:
    relay = relay_mod.Relay("192.0.2.10", 15353)
    relay.sock.close()
    relay.sock = FakeSocket()
    return relay


def fake_service_info(properties: Dict[str, Dict[bytes, Any]], gate: Optional[asyncio.Event] = None,
                      events: Optional[List[str]] = None):
    """An AsyncServiceInfo class answering from properties per service name.

    With a gate, async_request waits for it, so a test can act while a
    resolve is in flight. A cancelled wait is noted in events.
    """

    class FakeServiceInfo:
        def __init__(self, service_type: str, name: str):
            self.name = name
            self.port: Optional[int] = None
            self.properties: Optional[Dict[bytes, Any]] = None

        async def async_request(self, zeroconf, timeout) -> bool:
            if gate is not None:
                try:
                    await gate.wait()
                except asyncio.CancelledError:
                    if events is not None:
                        events.append("resolve cancelled")
                    raise
            if self.name not in properties:
                return False
            self.port = 8081
            self.properties = dict(properties[self.name])
            return True

        def parsed_addresses(self) -> List[str]:
            return ["198.51.100.43", "fe80::1"]

    return FakeServiceInfo


def txt_for(deviceid: str, seq: int = 7) -> Dict[bytes, Any]:
    return {b"id": deviceid.encode(), b"seq": str(seq).encode(), b"encrypt": b"true",
            b"iv": b"aXY=", b"data1": b"ZGF0YQ==", b"type": b"plug"}


# ==============================================================================
# Sending
# ==============================================================================


class SendTests(unittest.TestCase):
    def test_envelope_fields_and_types(self):
        relay = make_relay()
        record = {"name": NAME, "deviceid": DEVICE, "addresses": ["198.51.100.43"],
                  "port": 8081, "txt": {"seq": "1"}}
        self.assertTrue(relay.send("Added", record))
        (payload, target), = relay.sock.sent
        self.assertEqual(target, ("192.0.2.10", 15353))
        message = json.loads(payload)
        self.assertEqual(message["v"], 1)
        self.assertIsInstance(message["boot"], str)
        self.assertEqual(len(message["boot"]), 8)
        self.assertEqual(message["n"], 1)
        self.assertIsInstance(message["n"], int)
        self.assertEqual(message["event"], "Added")
        self.assertIsInstance(message["ts"], float)
        for key, value in record.items():
            self.assertEqual(message[key], value)
        # Compact JSON, as the relay sends it
        self.assertNotIn(b", ", payload)

    def test_n_increases_and_boot_is_stable(self):
        relay = make_relay()
        for i in range(5):
            relay.send("Resync", {"name": NAME, "deviceid": DEVICE})
        messages = relay.sock.messages()
        self.assertEqual([m["n"] for m in messages], [1, 2, 3, 4, 5])
        self.assertEqual(len({m["boot"] for m in messages}), 1)
        self.assertNotEqual(make_relay().boot, relay.boot)

    def test_oversized_datagram_is_warned_about_and_still_sent(self):
        relay = make_relay()
        record = {"name": NAME, "deviceid": DEVICE, "txt": {"data1": "x" * 1400}}
        with self.assertLogs("mdns_relay", level="WARNING") as logs:
            self.assertTrue(relay.send("Updated", record))
        self.assertIn("above the safe payload size of 1392", logs.output[0])
        self.assertEqual(len(relay.sock.sent), 1)

    def test_datagram_at_the_limit_is_not_warned_about(self):
        relay = make_relay()
        record = {"name": NAME, "deviceid": DEVICE, "txt": {"data1": ""}}
        # A fixed clock and the same counter width, so only the padding changes the size
        with mock.patch.object(relay_mod, "time", types.SimpleNamespace(time=lambda: 1760000000.5)):
            relay.send("Updated", record)
            size = len(relay.sock.sent[0][0])
            record["txt"]["data1"] = "x" * (relay_mod.SAFE_PAYLOAD_BYTES - size)
            with self.assertNoLogs("mdns_relay", level="WARNING"):
                relay.send("Updated", record)
        self.assertEqual(len(relay.sock.sent[1][0]), relay_mod.SAFE_PAYLOAD_BYTES)

    def test_repeated_send_errors_log_first_failure_and_recovery_only(self):
        relay = make_relay()
        relay.sock.fail = True
        with self.assertLogs("mdns_relay", level="INFO") as logs:
            results = [relay.send("Resync", {"deviceid": DEVICE}) for _ in range(3)]
            relay.sock.fail = False
            results += [relay.send("Resync", {"deviceid": DEVICE}) for _ in range(2)]
        self.assertEqual(results, [False, False, False, True, True])
        self.assertEqual(len(logs.output), 2)
        self.assertIn("WARNING", logs.output[0])
        self.assertIn("sending to 192.0.2.10:15353 failed: OSError", logs.output[0])
        self.assertIn("sending to 192.0.2.10:15353 works again", logs.output[1])


# ==============================================================================
# Names, state changes and resolving
# ==============================================================================


class NameTests(unittest.TestCase):
    def test_deviceid_matches_the_old_slice(self):
        self.assertEqual(relay_mod.deviceid_from_name(NAME), NAME[8:18])
        self.assertEqual(relay_mod.deviceid_from_name(NAME), DEVICE)

    def test_service_type_case_is_ignored(self):
        self.assertEqual(relay_mod.deviceid_from_name(f"eWeLink_{DEVICE}._EWELINK._tcp.local."), DEVICE)

    def test_names_that_do_not_match_are_rejected(self):
        for name in (
            f"ewelink_{DEVICE}._ewelink._tcp.local.",   # prefix case differs
            f"EWELINK_{DEVICE}._ewelink._tcp.local.",
            f"eWeLink{DEVICE}._ewelink._tcp.local.",    # no underscore
            f"eWeLinkX_{DEVICE}._ewelink._tcp.local.",
            "eWeLink_._ewelink._tcp.local.",             # empty deviceid
            f"Other_{DEVICE}._ewelink._tcp.local.",
            f"eWeLink_{DEVICE}._http._tcp.local.",       # other service type
            f"eWeLink_{DEVICE}",
        ):
            with self.subTest(name=name):
                self.assertIsNone(relay_mod.deviceid_from_name(name))


class ChangeAndResolveTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.relay = make_relay()

    async def settle(self):
        while self.relay.tasks:
            await asyncio.gather(*list(self.relay.tasks))

    def patch_info(self, properties, gate=None):
        patcher = mock.patch.object(relay_mod, "AsyncServiceInfo", fake_service_info(properties, gate))
        patcher.start()
        self.addCleanup(patcher.stop)

    async def test_added_resolves_and_sends_record(self):
        props = txt_for(DEVICE)
        props[b"txtvers"] = None  # a key without a value
        self.patch_info({NAME: props})
        with self.assertLogs("mdns_relay", level="INFO") as logs:
            self.relay.on_change(None, relay_mod.SERVICE_TYPE, NAME, ServiceStateChange.Added)
            await self.settle()
        message, = self.relay.sock.messages()
        self.assertEqual(message["event"], "Added")
        self.assertEqual(message["name"], NAME)
        self.assertEqual(message["deviceid"], DEVICE)
        self.assertEqual(message["addresses"], ["198.51.100.43", "fe80::1"])
        self.assertEqual(message["port"], 8081)
        self.assertEqual(message["txt"], {"id": DEVICE, "seq": "7", "encrypt": "true",
                                          "iv": "aXY=", "data1": "ZGF0YQ==", "type": "plug"})
        self.assertNotIn("txtvers", message["txt"])
        self.assertIn(f"Added {DEVICE} seq=7 n=1", logs.output[0])

    async def test_non_bytes_values_are_kept_as_they_are(self):
        props = txt_for(DEVICE)
        props[b"type"] = "plug"
        self.patch_info({NAME: props})
        self.relay.on_change(None, relay_mod.SERVICE_TYPE, NAME, ServiceStateChange.Added)
        await self.settle()
        self.assertEqual(self.relay.sock.messages()[0]["txt"]["type"], "plug")

    async def test_updated_sends_changes_only(self):
        props = {NAME: txt_for(DEVICE, 7)}
        self.patch_info(props)
        self.relay.on_change(None, relay_mod.SERVICE_TYPE, NAME, ServiceStateChange.Added)
        await self.settle()
        with self.assertLogs("mdns_relay", level="DEBUG") as logs:
            self.relay.on_change(None, relay_mod.SERVICE_TYPE, NAME, ServiceStateChange.Updated)
            await self.settle()
        self.assertIn("unchanged, not sent", logs.output[0])
        props[NAME] = txt_for(DEVICE, 8)
        self.relay.on_change(None, relay_mod.SERVICE_TYPE, NAME, ServiceStateChange.Updated)
        await self.settle()
        messages = self.relay.sock.messages()
        self.assertEqual([(m["event"], m["txt"]["seq"], m["n"]) for m in messages],
                         [("Added", "7", 1), ("Updated", "8", 2)])
        self.assertEqual(self.relay.records[NAME]["txt"]["seq"], "8")

    async def test_no_zeroconf_info_sends_nothing(self):
        self.patch_info({})
        self.relay.on_change(None, relay_mod.SERVICE_TYPE, NAME, ServiceStateChange.Added)
        await self.settle()
        self.assertEqual(self.relay.sock.sent, [])

    async def test_removed_is_forwarded_and_forgets_the_record(self):
        self.patch_info({NAME: txt_for(DEVICE)})
        self.relay.on_change(None, relay_mod.SERVICE_TYPE, NAME, ServiceStateChange.Added)
        await self.settle()
        with self.assertLogs("mdns_relay", level="INFO") as logs:
            self.relay.on_change(None, relay_mod.SERVICE_TYPE, NAME, ServiceStateChange.Removed)
        self.assertIn(f"Removed {DEVICE}", logs.output[0])
        removed = self.relay.sock.messages()[-1]
        self.assertEqual({k: removed[k] for k in ("event", "name", "deviceid", "n")},
                         {"event": "Removed", "name": NAME, "deviceid": DEVICE, "n": 2})
        self.assertNotIn("txt", removed)
        self.assertNotIn(NAME, self.relay.records)

    async def test_other_names_are_skipped(self):
        self.patch_info({})
        for name in (f"ewelink_{DEVICE}._ewelink._tcp.local.", "eWeLink_._ewelink._tcp.local.",
                     f"Other_{DEVICE}._ewelink._tcp.local."):
            for change in (ServiceStateChange.Added, ServiceStateChange.Removed):
                with self.assertLogs("mdns_relay", level="DEBUG") as logs:
                    self.relay.on_change(None, relay_mod.SERVICE_TYPE, name, change)
                self.assertIn("not an eWeLink device name, skipped", logs.output[0])
        self.assertEqual(self.relay.tasks, set())
        self.assertEqual(self.relay.sock.sent, [])
        self.assertEqual(self.relay.generations, {})

    async def test_removed_during_resolve_discards_the_result(self):
        gate = asyncio.Event()
        self.patch_info({NAME: txt_for(DEVICE)}, gate)
        self.relay.on_change(None, relay_mod.SERVICE_TYPE, NAME, ServiceStateChange.Added)
        await asyncio.sleep(0)  # the resolve is now waiting in async_request
        self.relay.on_change(None, relay_mod.SERVICE_TYPE, NAME, ServiceStateChange.Removed)
        with self.assertLogs("mdns_relay", level="DEBUG") as logs:
            gate.set()
            await self.settle()
        self.assertIn("removed while resolving (Added), result discarded", logs.output[0])
        self.assertEqual([m["event"] for m in self.relay.sock.messages()], ["Removed"])
        self.assertNotIn(NAME, self.relay.records)

        # A later Added is resolved and sent as usual
        self.relay.on_change(None, relay_mod.SERVICE_TYPE, NAME, ServiceStateChange.Added)
        await self.settle()
        self.assertEqual([m["event"] for m in self.relay.sock.messages()], ["Removed", "Added"])
        self.assertIn(NAME, self.relay.records)

    async def test_removed_before_the_resolve_starts_also_counts(self):
        self.patch_info({NAME: txt_for(DEVICE)})
        # Both in the same loop iteration: the task has not run yet
        self.relay.on_change(None, relay_mod.SERVICE_TYPE, NAME, ServiceStateChange.Added)
        self.relay.on_change(None, relay_mod.SERVICE_TYPE, NAME, ServiceStateChange.Removed)
        await self.settle()
        self.assertEqual([m["event"] for m in self.relay.sock.messages()], ["Removed"])

    async def test_removed_of_another_name_does_not_discard(self):
        other = "eWeLink_100000000b._ewelink._tcp.local."
        gate = asyncio.Event()
        self.patch_info({NAME: txt_for(DEVICE)}, gate)
        self.relay.on_change(None, relay_mod.SERVICE_TYPE, NAME, ServiceStateChange.Added)
        await asyncio.sleep(0)
        self.relay.on_change(None, relay_mod.SERVICE_TYPE, other, ServiceStateChange.Removed)
        gate.set()
        await self.settle()
        self.assertEqual([(m["event"], m["deviceid"]) for m in self.relay.sock.messages()],
                         [("Removed", "100000000b"), ("Added", DEVICE)])

    async def test_zeroconf_error_is_logged(self):
        class FailingInfo:
            def __init__(self, service_type, name):
                pass

            async def async_request(self, zeroconf, timeout):
                raise RuntimeError("boom")

        with mock.patch.object(relay_mod, "AsyncServiceInfo", FailingInfo):
            with self.assertLogs("mdns_relay", level="WARNING") as logs:
                await self.relay.resolve(None, relay_mod.SERVICE_TYPE, NAME, "Added")
        self.assertIn(f"{DEVICE}: zeroconf error RuntimeError: boom", logs.output[0])


# ==============================================================================
# Resync
# ==============================================================================


class StopLoop(Exception):
    pass


class ResyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_resends_every_record_at_the_interval(self):
        relay = make_relay()
        other = "eWeLink_100000000b._ewelink._tcp.local."
        relay.records = {
            NAME: {"name": NAME, "deviceid": DEVICE, "txt": {"seq": "1"}},
            other: {"name": other, "deviceid": "100000000b", "txt": {"seq": "2"}},
        }
        intervals = []

        async def fake_sleep(seconds):
            intervals.append(seconds)
            if len(intervals) > 2:
                raise StopLoop

        # Only the relay's view of asyncio is replaced, not the test's loop
        fake_asyncio = types.SimpleNamespace(sleep=fake_sleep)
        with mock.patch.object(relay_mod, "asyncio", fake_asyncio):
            with self.assertLogs("mdns_relay", level="DEBUG") as logs:
                with self.assertRaises(StopLoop):
                    await relay.resync_loop(60)
        self.assertEqual(intervals, [60, 60, 60])
        messages = relay.sock.messages()
        self.assertEqual([(m["event"], m["deviceid"], m["n"]) for m in messages], [
            ("Resync", DEVICE, 1), ("Resync", "100000000b", 2),
            ("Resync", DEVICE, 3), ("Resync", "100000000b", 4),
        ])
        self.assertIn("Resync: 2 of 2 record(s) sent", logs.output[0])

    async def test_runs_with_a_real_short_interval(self):
        relay = make_relay()
        relay.records = {NAME: {"name": NAME, "deviceid": DEVICE, "txt": {"seq": "1"}}}
        task = asyncio.create_task(relay.resync_loop(0.02))
        try:
            for _ in range(50):
                if len(relay.sock.sent) >= 2:
                    break
                await asyncio.sleep(0.01)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.assertGreaterEqual(len(relay.sock.sent), 2)


# ==============================================================================
# Arguments and the run loop
# ==============================================================================


class MainTests(unittest.TestCase):
    def call_main(self, *args: str):
        """Run main() with these arguments; returns the arguments given to run()."""
        calls = []

        async def fake_run(*run_args):
            calls.append(run_args)
            return 0

        with mock.patch.object(sys, "argv", ["mdns_relay.py", *args]), \
                mock.patch.object(relay_mod, "run", fake_run), \
                mock.patch.object(relay_mod.logging, "basicConfig") as basic_config:
            self.assertEqual(relay_mod.main(), 0)
        return calls[0], basic_config.call_args.kwargs["level"]

    def call_main_error(self, *args: str) -> str:
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["mdns_relay.py", *args]), \
                mock.patch.object(relay_mod, "run") as run, \
                contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                relay_mod.main()
        self.assertEqual(raised.exception.code, 2)
        run.assert_not_called()
        return stderr.getvalue()

    def test_defaults_are_unchanged(self):
        run_args, level = self.call_main("--target", "192.0.2.10")
        self.assertEqual(run_args, ("192.0.2.10", 15353, 0, 60))
        self.assertEqual(level, relay_mod.logging.INFO)

    def test_all_options(self):
        run_args, level = self.call_main("--target", "192.0.2.10", "--port", "4000",
                                         "--duration", "30", "--resync", "5", "--debug")
        self.assertEqual(run_args, ("192.0.2.10", 4000, 30, 5))
        self.assertEqual(level, relay_mod.logging.DEBUG)

    def test_resync_below_five_is_rejected(self):
        error = self.call_main_error("--target", "192.0.2.10", "--resync", "4")
        self.assertIn("argument --resync: must be at least 5 seconds, got 4", error)

    def test_resync_not_a_number_is_rejected(self):
        error = self.call_main_error("--target", "192.0.2.10", "--resync", "1m")
        self.assertIn("argument --resync: not a whole number of seconds: '1m'", error)

    def test_target_is_required(self):
        self.assertIn("--target", self.call_main_error())

    def test_target_must_be_an_ipv4_address(self):
        for target in ("", "not-an-ip", "2001:db8::1", "192.0.2.256", "host.example"):
            with self.subTest(target=target):
                error = self.call_main_error("--target", target)
                self.assertIn(f"argument --target: not an IPv4 address: {target!r}", error)

    def test_valid_ipv4_target_is_accepted(self):
        run_args, _ = self.call_main("--target", "198.51.100.7")
        self.assertEqual(run_args[0], "198.51.100.7")
        self.assertIsInstance(run_args[0], str)

    def test_exit_status_of_run_is_returned(self):
        async def fake_run(*run_args):
            return relay_mod.EXIT_ADDRESSES_CHANGED

        with mock.patch.object(sys, "argv", ["mdns_relay.py", "--target", "192.0.2.10"]), \
                mock.patch.object(relay_mod, "run", fake_run), \
                mock.patch.object(relay_mod.logging, "basicConfig"):
            self.assertEqual(relay_mod.main(), 75)

    def test_exit_status_for_changed_addresses_is_not_the_argument_error(self):
        # The systemd unit has RestartPreventExitStatus=2
        self.assertEqual(relay_mod.EXIT_ADDRESSES_CHANGED, 75)
        self.assertNotEqual(relay_mod.EXIT_ADDRESSES_CHANGED, 2)

    def test_help_mentions_the_receiver_freshness(self):
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", ["mdns_relay.py", "--help"]), \
                contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit):
                relay_mod.main()
        text = " ".join(stdout.getvalue().split())
        self.assertIn(f"fresh for {ENDPOINT_FRESH_SECONDS:.0f} s", text)
        self.assertIn("ENDPOINT_FRESH_SECONDS in src/sonoff_mqtt/lan_relay.py", text)


class RunShutdownTests(unittest.IsolatedAsyncioTestCase):
    async def test_shutdown_cancels_and_awaits_tasks_before_close(self):
        events: List[str] = []

        class FakeZeroconf:
            def __init__(self):
                self.zeroconf = object()

            async def async_close(self):
                events.append("close")

        class FakeBrowser:
            def __init__(self, zeroconf, service_type, handlers):
                # Announce a device whose resolve never completes on its own
                for handler in handlers:
                    handler(zeroconf, service_type, NAME, ServiceStateChange.Added)

            async def async_cancel(self):
                events.append("browser cancel")

        async def fake_resync_loop(self, interval):
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                events.append("resync cancelled")
                raise

        info = fake_service_info({NAME: txt_for(DEVICE)}, asyncio.Event(), events)
        with mock.patch.object(relay_mod, "AsyncZeroconf", FakeZeroconf), \
                mock.patch.object(relay_mod, "AsyncServiceBrowser", FakeBrowser), \
                mock.patch.object(relay_mod, "AsyncServiceInfo", info), \
                mock.patch.object(relay_mod.Relay, "resync_loop", fake_resync_loop):
            # Nothing at WARNING or above anywhere, so no traceback either
            with self.assertNoLogs(level="WARNING"):
                with self.assertLogs("mdns_relay", level="INFO") as logs:
                    result = await relay_mod.run("127.0.0.1", 15353, 0.05, 60)
        self.assertEqual(result, 0)
        # assertLogs stops propagation from mdns_relay, so check its own records too
        self.assertFalse([line for line in logs.output if not line.startswith("INFO:")])
        self.assertEqual(events[0], "browser cancel")
        self.assertEqual(sorted(events[1:3]), ["resolve cancelled", "resync cancelled"])
        self.assertEqual(events[3:], ["close"])
        self.assertIn("stopped, 0 datagram(s) sent", logs.output[-1])


# ==============================================================================
# IPv4 addresses: waiting for the first one, and exiting when they change
# ==============================================================================

LOOPBACK_ONLY = [adapter("lo", ("127.0.0.1", 8), (("::1", 0, 0), 128), index=1)]
BASE = LOOPBACK_ONLY + [adapter("eth0", ("192.0.2.50", 24), index=2)]
CHANGED = LOOPBACK_ONLY + [adapter("eth0", ("192.0.2.60", 24), index=2)]


class AdapterSequence:
    """Replaces ifaddr.get_adapters: one step per call, the last one repeated.

    A step is a list of adapters, or an exception to raise. Every call is noted
    in events, so a test can check the order against zeroconf's construction.
    """

    def __init__(self, events: List[str], *steps):
        self.events = events
        self.steps = list(steps)
        self.calls = 0

    def __call__(self, include_unconfigured: bool = False):
        step = self.steps[min(self.calls, len(self.steps) - 1)]
        self.calls += 1
        self.events.append("addresses read")
        if isinstance(step, BaseException):
            raise step
        return {a.name: a for a in step}.values()


class AddressSetTests(unittest.TestCase):
    def test_address_set_equals_zeroconfs_expression(self):
        adapters = [
            adapter("lo", ("127.0.0.1", 8), (("::1", 0, 0), 128), index=1),
            adapter("eth0", ("192.0.2.50", 24), ("192.0.2.51", 32), (("fe80::1", 0, 2), 64), index=2),
            adapter("eth0:1", ("169.254.3.4", 16)),
            adapter("tun0", ("198.51.100.7", 32), ("192.0.2.50", 24)),
            adapter("wlan0", (("2001:db8::5", 0, 0), 64)),
        ]
        with mock.patch.object(relay_mod.ifaddr, "get_adapters", AdapterSequence([], adapters)):
            current = relay_mod.Addresses().current()
        # zeroconf 0.151.5, zeroconf/_utils/net.py, get_all_addresses_ipv4
        zeroconf_view = list({addr.ip for iface in adapters for addr in iface.ips if addr.is_IPv4})
        self.assertEqual(current, frozenset(zeroconf_view))
        self.assertEqual(current, frozenset(
            {"127.0.0.1", "192.0.2.50", "192.0.2.51", "169.254.3.4", "198.51.100.7"}))

    def test_default_stub_mirrors_ifaddr(self):
        adapters = relay_mod.ifaddr.get_adapters()
        self.assertEqual(type(adapters).__name__, "dict_values")
        ips = [ip for a in adapters for ip in a.ips]
        self.assertEqual([ip.is_IPv4 for ip in ips], [True, False, True, False])
        self.assertEqual([ip.is_IPv6 for ip in ips], [False, True, False, True])
        self.assertEqual(ips[1].ip, ("::1", 0, 0))

    def test_usable_means_outside_loopback(self):
        self.assertFalse(relay_mod.has_usable_address(frozenset()))
        self.assertFalse(relay_mod.has_usable_address(frozenset({"127.0.0.1", "127.0.1.1"})))
        self.assertTrue(relay_mod.has_usable_address(frozenset({"127.0.0.1", "169.254.3.4"})))

    def test_oserror_from_get_adapters_is_no_addresses_and_logged_once(self):
        steps = AdapterSequence([], OSError(105, "No buffer space available"),
                                OSError(105, "No buffer space available"), BASE)
        addresses = relay_mod.Addresses()
        with mock.patch.object(relay_mod.ifaddr, "get_adapters", steps):
            with self.assertLogs("mdns_relay", level="INFO") as logs:
                self.assertEqual(addresses.current(), frozenset())
                self.assertEqual(addresses.current(), frozenset())
                self.assertEqual(addresses.current(), frozenset({"127.0.0.1", "192.0.2.50"}))
        self.assertEqual(logs.output, [
            "WARNING:mdns_relay:listing the network interfaces failed: OSError: "
            "[Errno 105] No buffer space available",
            "INFO:mdns_relay:listing the network interfaces works again",
        ])


class AddressWatchRunTests(unittest.IsolatedAsyncioTestCase):
    """run() with fake zeroconf, a short check interval and scripted adapters."""

    def setUp(self):
        self.events: List[str] = []
        events = self.events

        class FakeZeroconf:
            def __init__(self):
                events.append("zeroconf constructed")
                self.zeroconf = object()

            async def async_close(self):
                events.append("zeroconf closed")

        class FakeBrowser:
            def __init__(self, zeroconf, service_type, handlers):
                events.append("browser started")

            async def async_cancel(self):
                events.append("browser cancelled")

        async def fake_resync_loop(relay, interval):
            await asyncio.Event().wait()

        original_watch = relay_mod.watch_addresses

        async def watch(*args):
            try:
                return await original_watch(*args)
            except asyncio.CancelledError:
                events.append("watch cancelled")
                raise

        for target, name, value in (
            (relay_mod, "AsyncZeroconf", FakeZeroconf),
            (relay_mod, "AsyncServiceBrowser", FakeBrowser),
            (relay_mod, "ADDRESS_CHECK_INTERVAL_SECONDS", 0.01),
            (relay_mod, "watch_addresses", watch),
            (relay_mod.Relay, "resync_loop", fake_resync_loop),
        ):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def use_adapters(self, *steps) -> AdapterSequence:
        sequence = AdapterSequence(self.events, *steps)
        patcher = mock.patch.object(relay_mod.ifaddr, "get_adapters", sequence)
        patcher.start()
        self.addCleanup(patcher.stop)
        return sequence

    async def run_relay(self, duration: float = 0) -> int:
        return await asyncio.wait_for(relay_mod.run("127.0.0.1", 15353, duration, 60), 5)

    async def test_change_during_run_returns_75(self):
        self.use_adapters(BASE, BASE, CHANGED)
        with self.assertLogs("mdns_relay", level="INFO") as logs:
            result = await self.run_relay()
        self.assertEqual(result, relay_mod.EXIT_ADDRESSES_CHANGED)
        self.assertIn(
            "WARNING:mdns_relay:IPv4 addresses changed (127.0.0.1, 192.0.2.50 -> 127.0.0.1, "
            "192.0.2.60), exiting so systemd restarts the relay",
            logs.output,
        )
        self.assertIn("browser cancelled", self.events)
        self.assertLess(self.events.index("browser cancelled"), self.events.index("zeroconf closed"))
        self.assertNotIn("watch cancelled", self.events)

    async def test_unchanged_addresses_keep_running_and_stop_returns_0(self):
        sequence = self.use_adapters(BASE)
        with self.assertNoLogs("mdns_relay", level="WARNING"):
            result = await self.run_relay(duration=0.1)
        self.assertEqual(result, 0)
        # The snapshot and several checks while running
        self.assertGreater(sequence.calls, 2)
        self.assertEqual(self.events[-3:], ["browser cancelled", "watch cancelled", "zeroconf closed"])

    async def test_only_loopback_at_start_waits_until_an_address_appears(self):
        self.use_adapters(LOOPBACK_ONLY, LOOPBACK_ONLY, BASE)
        with self.assertLogs("mdns_relay", level="INFO") as logs:
            result = await self.run_relay(duration=0.05)
        self.assertEqual(result, 0)
        warnings = [line for line in logs.output if line.startswith("WARNING:")]
        self.assertEqual(warnings, ["WARNING:mdns_relay:no IPv4 address yet, waiting before joining mDNS"])
        self.assertIn("INFO:mdns_relay:IPv4 address found, joining mDNS", logs.output)
        self.assertIn("INFO:mdns_relay:IPv4 addresses: 127.0.0.1, 192.0.2.50", logs.output)
        # No zeroconf before the third read, the first with an address
        self.assertEqual(self.events[:4], ["addresses read"] * 3 + ["zeroconf constructed"])

    async def test_no_ipv4_at_all_waits_as_well(self):
        self.use_adapters([adapter("lo", (("::1", 0, 0), 128))], BASE)
        with self.assertLogs("mdns_relay", level="WARNING") as logs:
            result = await self.run_relay(duration=0.05)
        self.assertEqual(result, 0)
        self.assertEqual(logs.output, ["WARNING:mdns_relay:no IPv4 address yet, waiting before joining mDNS"])
        self.assertEqual(self.events[:3], ["addresses read"] * 2 + ["zeroconf constructed"])

    async def test_stop_during_the_startup_wait_returns_0_without_zeroconf(self):
        self.use_adapters(LOOPBACK_ONLY)
        handlers: Dict[int, Any] = {}
        loop = asyncio.get_running_loop()
        loop.call_later(0.05, lambda: handlers[signal.SIGTERM]())
        with mock.patch.object(loop, "add_signal_handler", lambda sig, callback: handlers.update({sig: callback})):
            with self.assertLogs("mdns_relay", level="INFO") as logs:
                result = await self.run_relay()
        self.assertEqual(result, 0)
        self.assertEqual(set(handlers), {signal.SIGTERM, signal.SIGINT})
        self.assertNotIn("zeroconf constructed", self.events)
        self.assertTrue(any("stopped before joining mDNS" in line for line in logs.output))

    async def test_snapshot_is_taken_right_before_zeroconf_is_constructed(self):
        self.use_adapters(BASE)
        with self.assertLogs("mdns_relay", level="INFO"):
            await self.run_relay(duration=0.02)
        self.assertEqual(self.events[:3], ["addresses read", "zeroconf constructed", "browser started"])

    async def test_runtime_error_from_zeroconf_returns_75(self):
        self.use_adapters(BASE)

        def refuse():
            self.events.append("zeroconf constructed")
            raise RuntimeError("No interfaces to listen on, check that any interfaces have IP version "
                               "IPVersion.V4Only")

        with mock.patch.object(relay_mod, "AsyncZeroconf", refuse):
            with self.assertLogs("mdns_relay", level="WARNING") as logs:
                result = await self.run_relay()
        self.assertEqual(result, relay_mod.EXIT_ADDRESSES_CHANGED)
        self.assertEqual(len(logs.output), 1)
        self.assertIn("zeroconf could not start (No interfaces to listen on", logs.output[0])
        self.assertIn("exiting so systemd restarts the relay", logs.output[0])
        self.assertNotIn("browser started", self.events)

    async def test_oserror_during_the_startup_wait_is_logged_once(self):
        error = OSError(105, "No buffer space available")
        self.use_adapters(error, error, error, BASE)
        with self.assertLogs("mdns_relay", level="WARNING") as logs:
            result = await self.run_relay(duration=0.02)
        self.assertEqual(result, 0)
        self.assertEqual(len([line for line in logs.output if "listing the network interfaces failed" in line]), 1)
        self.assertIn("zeroconf constructed", self.events)


# ==============================================================================
# Contract with the receiver
# ==============================================================================


class Collector:
    def __init__(self):
        self.calls: List[Tuple[str, Dict[str, Any], str, str]] = []

    def __call__(self, deviceid, params, seq, event):
        self.calls.append((deviceid, params, seq, event))


class ContractTest(unittest.IsolatedAsyncioTestCase):
    async def test_relay_datagram_is_understood_by_the_receiver(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        collector = Collector()
        config = LanRelayConfig(enabled=True, listen_port=port, allowed_sources=["127.0.0.1"])
        receiver = LanRelayReceiver(config, collector, {DEVICE: DEVICEKEY}.get)
        await receiver.start()
        relay = relay_mod.Relay("127.0.0.1", port)
        try:
            data, iv = encrypt_params({"switch": "on"}, DEVICEKEY)
            props = {b"id": DEVICE.encode(), b"seq": b"42", b"encrypt": b"true",
                     b"iv": iv.encode(), b"data1": data.encode(), b"txtvers": None}
            with mock.patch.object(relay_mod, "AsyncServiceInfo", fake_service_info({NAME: props})):
                await relay.resolve(None, relay_mod.SERVICE_TYPE, NAME, "Added")
            for _ in range(50):
                if collector.calls:
                    break
                await asyncio.sleep(0.02)
        finally:
            relay.sock.close()
            await receiver.stop()
        self.assertEqual(collector.calls, [(DEVICE, {"switch": "on"}, "42", "Added")])
        self.assertEqual(receiver.endpoint_for(DEVICE), ("198.51.100.43", 8081))


if __name__ == "__main__":
    unittest.main()
