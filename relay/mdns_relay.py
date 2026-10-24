"""mDNS relay for eWeLink (Sonoff) devices, feeding sonoff-mqtt.

Watches _ewelink._tcp on the local link and forwards every TXT record
unchanged, as one JSON datagram over UDP, to sonoff-mqtt on another network.
The data1..dataN fields stay encrypted with the devicekey: the relay holds no
devicekeys and never decrypts. All current records are resent every --resync
seconds, so a lost datagram or a restart of the receiver heals by itself.

The zeroconf filtering, resolving and TXT handling are modelled on
AlexxIT/SonoffLAN local.py (_handler1 and _handler2). The datagram format is
documented in sonoff-mqtt, src/sonoff_mqtt/lan_relay.py (protocol version 1).

Runs until stopped (SIGTERM or SIGINT) unless --duration is given. Logs to
stdout, which systemd sends to the journal.

zeroconf reads the host's IPv4 addresses only once, when it is constructed, and
joins the mDNS group on each of them; it never notices an address that appears
later. So the relay waits for an IPv4 address outside 127.0.0.0/8 before it
starts zeroconf, and then checks the addresses every
ADDRESS_CHECK_INTERVAL_SECONDS. On any change it stops and exits with
EXIT_ADDRESSES_CHANGED, and systemd starts it again with the new addresses.
"""

# 1. Standard library
import argparse
import asyncio
import ipaddress
import json
import logging
import signal
import socket
import sys
import time
import uuid
from typing import FrozenSet, Optional

# 2. Third-party
import ifaddr
from zeroconf import ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

_LOGGER = logging.getLogger("mdns_relay")

SERVICE_TYPE = "_ewelink._tcp.local."
# Instance names are "eWeLink_<deviceid>", so the full service name is
# "eWeLink_<deviceid>._ewelink._tcp.local."
INSTANCE_PREFIX = "eWeLink_"
PROTOCOL_VERSION = 1
# WireGuard MTU is usually 1420; minus 20 (IPv4) and 8 (UDP) leaves 1392 bytes
SAFE_PAYLOAD_BYTES = 1392
# Lower bound for --resync, so a typo cannot make the relay flood the path home
MIN_RESYNC_SECONDS = 5
# How often the IPv4 addresses are checked, while waiting for the first one and
# while running
ADDRESS_CHECK_INTERVAL_SECONDS = 15
# Exit status when the addresses changed or zeroconf found none to listen on.
# EX_TEMPFAIL from sysexits.h; never 2, which the systemd unit treats as an
# argument error that a restart cannot fix (RestartPreventExitStatus=2).
EXIT_ADDRESSES_CHANGED = 75
_LOOPBACK = ipaddress.IPv4Network("127.0.0.0/8")


def deviceid_from_name(name: str) -> Optional[str]:
    """The deviceid in "eWeLink_<deviceid>._ewelink._tcp.local.", else None.

    The service type is compared without regard to case, as DNS names are; the
    instance prefix has to match exactly.
    """
    suffix = "." + SERVICE_TYPE
    if not name.lower().endswith(suffix.lower()):
        return None
    instance = name[:-len(suffix)]
    if not instance.startswith(INSTANCE_PREFIX):
        return None
    return instance[len(INSTANCE_PREFIX):] or None


class Addresses:
    """The host's IPv4 addresses as zeroconf sees them when it is constructed."""

    def __init__(self):
        # A failure to list the interfaces is logged on the first one and on
        # recovery only, as the check runs every ADDRESS_CHECK_INTERVAL_SECONDS
        self.failing = False

    def current(self) -> FrozenSet[str]:
        """The IPv4 addresses on all interfaces; empty when they cannot be listed.

        Copies zeroconf 0.151.5 get_all_addresses_ipv4 (zeroconf/_utils/net.py),
        which InterfaceChoice.All uses at construction, on purpose instead of
        importing that private module: loopback, /32 and link-local addresses
        are included, IPv6 is not. A change of the zeroconf version must check
        that this still matches.
        """
        try:
            adapters = ifaddr.get_adapters()
        except OSError as e:
            if not self.failing:
                self.failing = True
                _LOGGER.warning("listing the network interfaces failed: %s: %s", type(e).__name__, e)
            return frozenset()
        if self.failing:
            self.failing = False
            _LOGGER.info("listing the network interfaces works again")
        return frozenset(ip.ip for adapter in adapters for ip in adapter.ips if ip.is_IPv4)


def has_usable_address(addresses: FrozenSet[str]) -> bool:
    """Whether any address is outside 127.0.0.0/8, so mDNS can reach the LAN."""
    return any(ipaddress.IPv4Address(address) not in _LOOPBACK for address in addresses)


def format_addresses(addresses: FrozenSet[str]) -> str:
    return ", ".join(sorted(addresses, key=ipaddress.IPv4Address)) or "none"


async def stopped_within(stop: asyncio.Event, seconds: float) -> bool:
    """Wait up to seconds; True as soon as stop is set, False on the timeout."""
    try:
        await asyncio.wait_for(stop.wait(), seconds)
    except asyncio.TimeoutError:
        return False
    return True


async def wait_for_address(addresses: Addresses, stop: asyncio.Event) -> Optional[FrozenSet[str]]:
    """The current addresses once one is outside 127.0.0.0/8, or None when stopped first."""
    current = addresses.current()
    if has_usable_address(current):
        return current
    _LOGGER.warning("no IPv4 address yet, waiting before joining mDNS")
    while True:
        if await stopped_within(stop, ADDRESS_CHECK_INTERVAL_SECONDS):
            return None
        current = addresses.current()
        if has_usable_address(current):
            _LOGGER.info("IPv4 address found, joining mDNS")
            return current


async def watch_addresses(addresses: Addresses, baseline: FrozenSet[str], stop: asyncio.Event) -> bool:
    """Set stop and return True once the addresses differ from baseline."""
    while True:
        await asyncio.sleep(ADDRESS_CHECK_INTERVAL_SECONDS)
        current = addresses.current()
        if current != baseline:
            _LOGGER.warning("IPv4 addresses changed (%s -> %s), exiting so systemd restarts the relay",
                            format_addresses(baseline), format_addresses(current))
            stop.set()
            return True


class Relay:
    def __init__(self, target: str, port: int):
        self.target = (target, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        # Lets the receiver tell a relay restart from lost datagrams
        self.boot = uuid.uuid4().hex[:8]
        self.counter = 0
        self.records: dict[str, dict] = {}
        # Keep task references so they are not garbage collected mid-flight
        self.tasks: set[asyncio.Task] = set()
        # Bumped on every Removed per service name. A resolve started before a
        # Removed sees a different generation once its await returns, and then
        # sends nothing, so it cannot bring a removed device back. Kept per
        # name for the life of the process: names are bounded by the devices
        # on the LAN.
        self.generations: dict[str, int] = {}
        # Send failures are logged on the first one and on recovery only, so a
        # long outage of the path home does not flood the journal
        self.send_failing = False

    def send(self, event: str, record: dict) -> bool:
        self.counter += 1
        message = {"v": PROTOCOL_VERSION, "boot": self.boot, "n": self.counter,
                   "event": event, "ts": round(time.time(), 3), **record}
        payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
        if len(payload) > SAFE_PAYLOAD_BYTES:
            _LOGGER.warning("%s %s: %d bytes, above the safe payload size of %d",
                            event, record.get("deviceid"), len(payload), SAFE_PAYLOAD_BYTES)
        try:
            self.sock.sendto(payload, self.target)
        except OSError as e:
            if not self.send_failing:
                self.send_failing = True
                _LOGGER.warning("sending to %s:%d failed: %s: %s",
                                self.target[0], self.target[1], type(e).__name__, e)
            return False
        if self.send_failing:
            self.send_failing = False
            _LOGGER.info("sending to %s:%d works again", *self.target)
        return True

    def on_change(self, zeroconf: Zeroconf, service_type: str, name: str,
                  state_change: ServiceStateChange) -> None:
        """Same filter as upstream _handler1, but Removed is forwarded too."""
        deviceid = deviceid_from_name(name)
        if deviceid is None:
            _LOGGER.debug("%s: not an eWeLink device name, skipped", name)
            return
        if state_change == ServiceStateChange.Removed:
            self.generations[name] = self.generations.get(name, 0) + 1
            self.records.pop(name, None)
            self.send("Removed", {"name": name, "deviceid": deviceid})
            _LOGGER.info("Removed %s", deviceid)
            return
        # The generation is taken here, not when the task first runs, so a
        # Removed that comes before the task starts also counts
        task = asyncio.create_task(self.resolve(zeroconf, service_type, name, state_change.name,
                                                self.generations.get(name, 0)))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def resolve(self, zeroconf: Zeroconf, service_type: str, name: str, change: str,
                      generation: Optional[int] = None) -> None:
        """Upstream _handler2, forwarding the raw TXT instead of decoding it."""
        deviceid = deviceid_from_name(name)
        if deviceid is None:
            _LOGGER.debug("%s: not an eWeLink device name, skipped", name)
            return
        if generation is None:
            generation = self.generations.get(name, 0)
        try:
            info = AsyncServiceInfo(service_type, name)
            found = await info.async_request(zeroconf, 3000)
            if self.generations.get(name, 0) != generation:
                _LOGGER.debug("%s: removed while resolving (%s), result discarded", deviceid, change)
                return
            if not found or not info.properties:
                _LOGGER.debug("%s: no zeroconf info (%s)", deviceid, change)
                return
            # A TXT key without a value comes as None and is not sent
            txt = {
                k.decode(): v.decode() if isinstance(v, bytes) else v
                for k, v in info.properties.items()
                if v is not None
            }
            record = {"name": name, "deviceid": deviceid, "addresses": info.parsed_addresses(),
                      "port": info.port, "txt": txt}
            if self.records.get(name) == record:
                _LOGGER.debug("%s %s seq=%s unchanged, not sent", change, deviceid, txt.get("seq"))
                return
            self.records[name] = record
            if self.send(change, record):
                _LOGGER.info("%s %s seq=%s n=%d", change, deviceid, txt.get("seq"), self.counter)
        except Exception as e:
            _LOGGER.warning("%s: zeroconf error %s: %s", deviceid, type(e).__name__, e)

    async def resync_loop(self, interval: int) -> None:
        while True:
            await asyncio.sleep(interval)
            records = list(self.records.values())
            sent = sum(self.send("Resync", record) for record in records)
            # One line per resync at DEBUG; at INFO only the sends that failed
            # show, through send()
            _LOGGER.debug("Resync: %d of %d record(s) sent", sent, len(records))


async def run(target: str, port: int, duration: int, resync: int) -> int:
    relay = Relay(target, port)
    _LOGGER.info("relaying %s to %s:%d, resync every %d s, run %s",
                 SERVICE_TYPE, target, port, resync, relay.boot)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    # zeroconf joins mDNS only on the addresses present when it is constructed,
    # so it is not started before there is one beyond loopback
    addresses = Addresses()
    baseline = await wait_for_address(addresses, stop)
    if baseline is None:
        relay.sock.close()
        _LOGGER.info("stopped before joining mDNS, run %s", relay.boot)
        return 0
    # The baseline is the snapshot taken last, with no await between it and the
    # construction below, so zeroconf's own scan cannot see an address the
    # watch does not know about
    _LOGGER.info("IPv4 addresses: %s", format_addresses(baseline))
    try:
        aiozc = AsyncZeroconf()
    except RuntimeError as e:
        # Raised when zeroconf finds no interface at all to listen on
        _LOGGER.warning("zeroconf could not start (%s), exiting so systemd restarts the relay", e)
        relay.sock.close()
        return EXIT_ADDRESSES_CHANGED
    browser = AsyncServiceBrowser(aiozc.zeroconf, SERVICE_TYPE, handlers=[relay.on_change])
    resync_task = asyncio.create_task(relay.resync_loop(resync))
    # zeroconf runs on this event loop (it attaches to the running loop when
    # constructed inside one), so the watch needs no locking
    watch_task = asyncio.create_task(watch_addresses(addresses, baseline, stop))
    try:
        if duration > 0:
            try:
                await asyncio.wait_for(stop.wait(), duration)
            except asyncio.TimeoutError:
                pass
        else:
            await stop.wait()
    finally:
        # No new resolves once the browser is gone; then stop and wait for the
        # ones in flight and the resync, so nothing is cut off by the close
        await browser.async_cancel()
        pending = [resync_task, watch_task, *relay.tasks]
        for task in pending:
            task.cancel()
        # return_exceptions, so the cancellations do not propagate or log
        await asyncio.gather(*pending, return_exceptions=True)
        await aiozc.async_close()
        relay.sock.close()
    _LOGGER.info("stopped, %d datagram(s) sent in run %s", relay.counter, relay.boot)
    # cancel() leaves a task that had already finished as it was
    if not watch_task.cancelled() and watch_task.exception() is None and watch_task.result():
        return EXIT_ADDRESSES_CHANGED
    return 0


def ipv4_address(value: str) -> str:
    """argparse type for --target: an IPv4 address, returned in its normal form."""
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an IPv4 address: {value!r}") from None


def resync_seconds(value: str) -> int:
    """argparse type for --resync: a whole number of seconds, at least the minimum."""
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number of seconds: {value!r}") from None
    if seconds < MIN_RESYNC_SECONDS:
        raise argparse.ArgumentTypeError(
            f"must be at least {MIN_RESYNC_SECONDS} seconds, got {seconds}")
    return seconds


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", required=True, type=ipv4_address,
                        help="IPv4 address of sonoff-mqtt, checked at start; "
                             "a host name is not accepted")
    parser.add_argument("--port", type=int, default=15353)
    parser.add_argument("--duration", type=int, default=0, help="seconds to run, 0 = until stopped")
    parser.add_argument("--resync", type=resync_seconds, default=60,
                        help=f"seconds between full resends, at least {MIN_RESYNC_SECONDS}. "
                             "The receiver treats a device address as fresh for 150 s "
                             "(ENDPOINT_FRESH_SECONDS in src/sonoff_mqtt/lan_relay.py), "
                             "which assumes the default of 60")
    parser.add_argument("--debug", action="store_true", help="also log unchanged records and resyncs")
    args = parser.parse_args()

    # No timestamps: the journal adds its own
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(levelname)s %(message)s")
    logging.getLogger("zeroconf").setLevel(logging.WARNING)
    return asyncio.run(run(args.target, args.port, args.duration, args.resync))


if __name__ == "__main__":
    sys.exit(main())
