"""Device state from mDNS relays on the devices' own networks.

eWeLink devices announce their state over mDNS (_ewelink._tcp). The params are
encrypted with the devicekey and split over the TXT fields data1..dataN, next
to a plaintext seq that the device counts up on every change. This service
cannot see that multicast when the devices sit on another network, and asking
from off-link does not help either, because devices ignore mDNS queries that do
not come from their own link (RFC 6762 section 11).

So a small relay on each of those networks forwards every TXT record
unchanged, as one JSON datagram over UDP. The relays hold no devicekeys and
never decrypt: data1..dataN are still encrypted when they cross the network,
and only this service, which already has the devicekeys from the cloud device
listing, can read them. Each relay also resends every current record at a
fixed interval, so a lost datagram or a restart here heals by itself.

There can be one or more relays. Nothing in a datagram names the relay or its
site, so a relay is identified only by the source address its datagrams arrive
from, which must be listed in lan_relay.allowed_sources. Run counters, losses
and silence are tracked per relay, and every log line about a datagram names
its relay first. Each device has one owner, the relay whose latest record for
it was accepted and decrypted. Records from another relay are ignored while
the owner's record for the device is fresh (ENDPOINT_FRESH_SECONDS), so a
device seen by two relays does not flap between them, and only the owner can
remove it.

Datagram format, protocol version 1:

    {"v": 1, "boot": "<relay run id>", "n": <counter per relay run>,
     "event": "Added" | "Updated" | "Resync" | "Removed", "ts": <unix time>,
     "name": "<mDNS service name>", "deviceid": "<deviceid>",
     "addresses": ["<ip>", ...], "port": <port>, "txt": {"<key>": "<value>"}}

"Removed" carries only name and deviceid.

The addresses and port are plaintext next to the encrypted TXT fields. A record
is only used once its payload decrypts, but that does not authenticate the
address: it is taken as the relay sent it, after a check that it is a usable
unicast IPv4 address.

Only state is taken from the relays. The relays do not carry commands: for the
devices listed in lan_relay.command_devices, LanCommandSender below posts a
command straight to the address and port in the device's latest relay record
from its owner, and the observer waits for a relay to report the result (see
Observer._try_lan_command). Every other device, and every LAN command that is
not confirmed, still goes through the cloud.
"""

# 1. Standard library
import asyncio
import base64
import errno
import hashlib
import ipaddress
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional, Set, Tuple

# 2. Third-party
import aiohttp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 3. Project-local
from .config import LanRelayConfig

_LOGGER = logging.getLogger(__name__)

PROTOCOL_VERSION = 1

# Upstream SonoffLAN joins only data1..data4 (local.py, _handler3). A device
# sending more fields would be decrypted incompletely, so that is logged rather
# than silently truncated.
DATA_FIELDS = 4

# How often the silence check runs. The threshold itself is configured.
SILENCE_CHECK_INTERVAL_SECONDS = 10.0

# How old the latest relay record for a device may be for its address to be
# used for a LAN command. The relay resends every record each 60 s, so this
# allows two lost resyncs plus some margin before falling back to the cloud.
# That assumes the relay's default resync of 60 s (--resync, RELAY_RESYNC); a
# longer resync needs a longer value here. Fresh only means that the relay keeps
# resending the record from its own cache, not that the device is reachable: a
# device that has gone quiet keeps a fresh address for as long as the relay
# holds its record. The same age decides when another relay may take a device
# over from its owner: only once the owner's latest record for it is older.
ENDPOINT_FRESH_SECONDS = 150.0

# 0.0.0.0/8 is "this network" (RFC 1122) and never a device address, but only
# 0.0.0.0 itself is is_unspecified
_THIS_NETWORK = ipaddress.IPv4Network("0.0.0.0/8")

# A device's web server handles one request at a time and resets a connection
# that arrives while it is busy. Upstream retries that this many times with this
# delay; the caller's overall timeout still bounds the total.
LAN_CONNRESET_RETRIES = 10
LAN_CONNRESET_DELAY_SECONDS = 0.1

# Called with deviceid, decrypted params, seq and the relay's event name
StateCallback = Callable[[str, Dict[str, Any], str, str], None]
# Returns the devicekey for a deviceid, or None if the device is unknown
KeyLookup = Callable[[str], Optional[str]]
# Returns a unique request sequence, as the vendored XRegistryBase.sequence()
SequenceSource = Callable[[], Awaitable[str]]


# ==============================================================================
# Decryption, mirrored from AlexxIT/SonoffLAN
# custom_components/sonoff/core/ewelink/local.py at commit 73690b7
# (decrypt() and XRegistryLocal.decrypt_msg()). local.py is not vendored
# because it also pulls in zeroconf and the LAN sender, neither of which this
# module needs.
# ==============================================================================


def _decrypt(data_b64: str, iv_b64: str, devicekey: str) -> bytes:
    """AES-128-CBC with key md5(devicekey) and PKCS7 padding, as upstream."""
    ciphertext = base64.b64decode(data_b64)
    key = hashlib.md5(devicekey.encode("utf-8")).digest()
    iv = base64.b64decode(iv_b64)

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def decrypt_params(data_b64: str, iv_b64: str, devicekey: str) -> Dict[str, Any]:
    """Decrypt a TXT payload into params, with the same fixes as upstream."""
    # Empty message from SPM-Main and ZbBridge-U
    if not data_b64:
        return {}

    data = _decrypt(data_b64, iv_b64, devicekey)

    # RF Bridge syntax bug
    if data and data.startswith(b'{"rf'):
        data = data.replace(b'"="', b'":"')

    # https://github.com/AlexxIT/SonoffLAN/issues/1160
    data = data.rstrip(b"\x02")

    params = json.loads(data)
    if not isinstance(params, dict):
        raise ValueError(f"decrypted payload is a {type(params).__name__}, not an object")
    return params


def encrypt_payload(payload: Dict[str, Any], devicekey: str) -> Dict[str, Any]:
    """Encrypt the data of a LAN command in place, mirrored from upstream encrypt().

    Same commit as the decryption above. The params are serialised compactly,
    encrypted with AES-128-CBC under md5(devicekey) with a random IV and PKCS7
    padding, and replaced by their base64 form, with the IV and the encrypt flag
    added next to them.
    """
    plaintext = json.dumps(payload["data"], separators=(",", ":")).encode("utf-8")
    key = hashlib.md5(devicekey.encode("utf-8")).digest()
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    payload["encrypt"] = True
    payload["data"] = base64.b64encode(ciphertext).decode("utf-8")
    payload["iv"] = base64.b64encode(iv).decode("utf-8")
    return payload


# ==============================================================================
# Receiver
# ==============================================================================


@dataclass
class _SourceState:
    """What is known about one relay, by the address its datagrams come from."""

    address: str
    # The relay run seen last, and the one before it, so a late datagram of
    # the previous run is not taken for another restart
    boot: Optional[str] = None
    previous_boot: Optional[str] = None
    # Highest n seen in boot
    n: Optional[int] = None
    # Monotonic time of the last datagram, None until the first one
    last_rx: Optional[float] = None
    silent: bool = False


@dataclass
class _DeviceEntry:
    """The relay that owns a device, and the device's address from it."""

    owner: str
    # Monotonic time of the owner's latest accepted record for the device
    received: float
    # (IPv4 address, port, monotonic receive time) for LAN commands, or None
    # while no record from the owner carried a usable one. Refreshed by every
    # accepted record, including a Resync with an unchanged seq, so it follows
    # a device that changed address by DHCP.
    endpoint: Optional[Tuple[str, int, float]] = None


def _usable_device_address(value: Any) -> Optional[ipaddress.IPv4Address]:
    """The value as an IPv4 address a LAN command can be sent to, else None.

    IPv4 only, as everywhere else on the relay path. Addresses that cannot be a
    device's own unicast address are refused. A directed broadcast address
    such as x.y.z.255 cannot be told apart, as the record carries no prefix.
    """
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    if ip.version != 4:
        return None
    if (ip.is_unspecified or ip in _THIS_NETWORK or ip.is_loopback or ip.is_multicast
            or ip.is_link_local or ip.is_reserved):
        return None
    return ip


class LanRelayReceiver(asyncio.DatagramProtocol):
    """Receives relay datagrams, decrypts them and hands params to a callback.

    A record is applied when its seq differs from the last seq applied for that
    device, not only when it is greater. Whether a device resets seq when it
    restarts is not known, and a greater-than rule would ignore such a device
    for good. With the differs rule a Resync carrying the seq already applied is
    a no-op, while a Resync with a new seq, after a lost datagram or a restart
    of this service, is applied.

    On top of that, the relay's boot and n of the last record applied per
    device and relay filter out a datagram that arrives late within the same
    relay run: with the same boot, a record whose n is not greater is dropped,
    Removed included. A different boot is a new relay run, which counts n from
    1 again, so its records pass this filter. The seq rule above still applies
    to everything that passes.

    Each device is owned by the relay whose latest record for it was accepted
    and decrypted. A record from another relay is ignored until the owner's
    latest record for the device is older than ENDPOINT_FRESH_SECONDS, and a
    Removed counts only from the owner. A restart of the owner is not a change
    of owner.
    """

    def __init__(self, config: LanRelayConfig, on_state: StateCallback, devicekey_for: KeyLookup):
        self.config = config
        self.on_state = on_state
        self.devicekey_for = devicekey_for
        # One state per configured relay, created here so that a relay never
        # heard from is watched as well. Keyed by ip_address, so duplicates and
        # different spellings of one address collapse into one relay.
        self._sources: Dict[Any, _SourceState] = {}
        for entry in config.allowed_sources:
            ip = ipaddress.ip_address(entry)
            self._sources.setdefault(ip, _SourceState(str(ip)))

        self._transport: Optional[asyncio.DatagramTransport] = None
        self._silence_task: Optional[asyncio.Task] = None
        # Reference time for relays not heard from yet; set again by start()
        self._started = time.monotonic()

        self._last_seq: Dict[str, str] = {}
        # (boot, n) of the last record applied per (deviceid, relay), Removed
        # included, so a late Added from before a removal cannot bring the
        # device back. Only for devices with a devicekey.
        self._last_applied: Dict[Tuple[str, str], Tuple[str, int]] = {}
        # Rejection reasons already logged per (deviceid, relay). Cleared when
        # a valid record from that relay is accepted, so the next rejection is
        # logged again, but a device rejected on every resync does not flood
        # the log. Only for devices with a devicekey.
        self._rejected: Dict[Tuple[str, str], Set[str]] = {}
        # Last seq reported per (deviceid, relay, kind), so a failing record is
        # logged once rather than on every resync, without growing without bound
        self._reported: Dict[Tuple[str, str, str], str] = {}
        # Owner and LAN endpoint per device
        self._devices: Dict[str, _DeviceEntry] = {}
        # (deviceid, relay) whose ignored records have been logged as a
        # conflict with the owner, so that is logged once per conflict
        self._conflicts_logged: Set[Tuple[str, str]] = set()

    # --------------------------------------------------------------------------
    # Lifecycle
    # --------------------------------------------------------------------------

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        # IPv4 only, matching the relay and the firewall exception for it
        await loop.create_datagram_endpoint(
            lambda: self, local_addr=("0.0.0.0", self.config.listen_port)
        )
        self._started = time.monotonic()
        self._silence_task = asyncio.create_task(self._watch_silence())
        _LOGGER.info(
            "LAN relay: listening on UDP %d, accepting %s",
            self.config.listen_port,
            ", ".join(state.address for state in self._sources.values()),
        )

    def connection_made(self, transport) -> None:
        self._transport = transport

    async def stop(self) -> None:
        if self._silence_task is not None:
            self._silence_task.cancel()
        if self._transport is not None:
            self._transport.close()

    async def _watch_silence(self) -> None:
        while True:
            await asyncio.sleep(SILENCE_CHECK_INTERVAL_SECONDS)
            self._check_silence()

    def _check_silence(self) -> None:
        """Warn once when a relay goes quiet; datagram_received says when it is back.

        Each relay resends everything at a fixed interval, so silence well past
        that interval means that relay, its tunnel or its firewall path is
        down, and the LAN view of its devices is going stale. A relay not heard
        from since start is measured from start.
        """
        now = time.monotonic()
        threshold = self.config.silence_warning_seconds
        for state in self._sources.values():
            if state.silent:
                continue
            if state.last_rx is None:
                quiet_for = now - self._started
                if quiet_for > threshold:
                    state.silent = True
                    _LOGGER.warning(
                        "LAN relay %s: nothing received since start %.0fs ago",
                        state.address, quiet_for,
                    )
            else:
                quiet_for = now - state.last_rx
                if quiet_for > threshold:
                    state.silent = True
                    _LOGGER.warning(
                        "LAN relay %s: nothing received for %.0fs, LAN state from this relay "
                        "is going stale",
                        state.address, quiet_for,
                    )

    # --------------------------------------------------------------------------
    # Datagram handling
    # --------------------------------------------------------------------------

    def datagram_received(self, payload: bytes, addr) -> None:
        try:
            source_ip = ipaddress.ip_address(addr[0])
        except ValueError:
            return
        state = self._sources.get(source_ip)
        if state is None:
            _LOGGER.debug("LAN relay: dropped %d bytes from %s", len(payload), addr[0])
            return
        source = state.address

        now = time.monotonic()
        if state.silent:
            state.silent = False
            since = state.last_rx if state.last_rx is not None else self._started
            _LOGGER.info("LAN relay %s: receiving again after %.0fs", source, now - since)
        state.last_rx = now

        try:
            message = json.loads(payload)
        except ValueError:
            _LOGGER.warning("LAN relay %s: invalid JSON, %d bytes", source, len(payload))
            return
        if not isinstance(message, dict) or message.get("v") != PROTOCOL_VERSION:
            _LOGGER.warning("LAN relay %s: unexpected message, %d bytes", source, len(payload))
            return

        self._track_counter(state, message)

        deviceid = message.get("deviceid")
        event = message.get("event")
        if not isinstance(deviceid, str) or not deviceid:
            return

        counter = self._relay_counter(message)
        if counter is not None and self._is_late(deviceid, source, str(event), counter):
            return

        if event == "Removed":
            self._handle_removed(deviceid, source, counter)
            return

        txt = message.get("txt")
        if not isinstance(txt, dict):
            _LOGGER.warning("LAN relay %s: %s %s without a txt object", source, event, deviceid)
            return

        devicekey = self.devicekey_for(deviceid)
        if not self._is_valid_record(deviceid, source, str(event), txt, devicekey):
            return
        if not self._may_take(deviceid, source, str(event), now):
            return

        seq = str(txt.get("seq"))
        if not devicekey:
            # Nothing is stored for such a device: without a devicekey it can
            # be neither decrypted nor commanded
            self._report_once(
                "unknown", deviceid, source, seq, logging.DEBUG,
                "LAN relay %s: %s is not a known device with a devicekey", source, deviceid,
            )
            return

        # Every record is decrypted, a Resync with an unchanged seq included, so
        # that only a record that decrypts can claim the device or refresh its
        # address
        params = self._decrypt_record(deviceid, source, seq, txt, devicekey)
        if params is None:
            return

        entry = self._accept(deviceid, source, counter, now)
        self._remember_endpoint(entry, message, now)
        self._apply_record(deviceid, str(event), seq, params)

    @staticmethod
    def _relay_counter(message: Dict[str, Any]) -> Optional[Tuple[str, int]]:
        """The (boot, n) of a datagram, or None when either is missing or invalid."""
        boot, n = message.get("boot"), message.get("n")
        if not isinstance(boot, str) or isinstance(n, bool) or not isinstance(n, int):
            return None
        return boot, n

    def _is_late(self, deviceid: str, source: str, event: str, counter: Tuple[str, int]) -> bool:
        """True for a record of the same relay run that is not newer than the last applied."""
        last = self._last_applied.get((deviceid, source))
        if last is None or last[0] != counter[0] or counter[1] > last[1]:
            return False
        _LOGGER.debug(
            "LAN relay %s: %s %s n=%d dropped, n=%d of run %s already applied",
            source, event, deviceid, counter[1], last[1], counter[0],
        )
        return True

    def _handle_removed(self, deviceid: str, source: str, counter: Optional[Tuple[str, int]]) -> None:
        """Forget a device that left mDNS, if the Removed comes from its owner."""
        entry = self._devices.get(deviceid)
        if entry is None:
            _LOGGER.debug("LAN relay %s: %s left mDNS, not known here", source, deviceid)
            return
        if entry.owner != source:
            # Expected after a device moved to another relay: the old one
            # reports the removal once its cache expires
            _LOGGER.debug(
                "LAN relay %s: Removed %s ignored, owned by %s", source, deviceid, entry.owner
            )
            return
        # Forget the seq so the device is applied again when it reappears
        self._last_seq.pop(deviceid, None)
        # And its owner and address, so no LAN command goes to a device that
        # has left, and any relay may take it when it reappears
        del self._devices[deviceid]
        self._clear_conflicts(deviceid)
        # But keep boot and n, so a late record from before the removal is
        # still recognised as late
        if counter is not None:
            self._last_applied[(deviceid, source)] = counter
        _LOGGER.info("LAN relay %s: %s left mDNS", source, deviceid)

    def _is_valid_record(
        self, deviceid: str, source: str, event: str, txt: Dict[str, Any], devicekey: Optional[str]
    ) -> bool:
        """Check a record carrying TXT before any of it is used.

        A record that fails is ignored as a whole: no address, port, seq or
        state is taken from it.
        """
        known = bool(devicekey)
        txt_id = txt.get("id")
        if not txt_id:
            return self._reject(
                deviceid, source, known, "id missing",
                "LAN relay %s: %s %s without a txt id, record ignored", source, event, deviceid,
            )
        if txt_id != deviceid:
            return self._reject(
                deviceid, source, known, "id mismatch",
                "LAN relay %s: %s %s with a txt id for another device, record ignored",
                source, event, deviceid,
            )

        # The LAN the devices are on is treated as trusted. This check only stops plaintext
        # records for a device that encrypts; a replay of an old ciphertext
        # with a new seq is still possible, as the payload is AES-CBC without a
        # MAC. That is an accepted risk.
        if devicekey and txt.get("encrypt") != "true":
            return self._reject(
                deviceid, source, known, "plaintext",
                "LAN relay %s: %s %s is not encrypted although the device has a devicekey, "
                "record ignored", source, event, deviceid,
            )

        seq = txt.get("seq")
        if seq is None or str(seq) == "":
            return self._reject(
                deviceid, source, known, "seq missing",
                "LAN relay %s: %s %s without a seq, record ignored", source, event, deviceid,
            )
        return True

    def _reject(self, deviceid: str, source: str, known: bool, reason: str, msg: str, *args) -> bool:
        """Log a rejected record once per device, relay and reason. Always returns False.

        For a device without a devicekey nothing is kept, so its rejections are
        logged at DEBUG only, each time.
        """
        if not known:
            _LOGGER.debug(msg, *args)
            return False
        reported = self._rejected.setdefault((deviceid, source), set())
        if reason not in reported:
            reported.add(reason)
            _LOGGER.warning(msg, *args)
        return False

    def _may_take(self, deviceid: str, source: str, event: str, now: float) -> bool:
        """Whether a record from source may be used for the device, by ownership."""
        entry = self._devices.get(deviceid)
        if entry is None or entry.owner == source:
            return True
        age = now - entry.received
        if age > ENDPOINT_FRESH_SECONDS:
            return True
        key = (deviceid, source)
        if key not in self._conflicts_logged:
            self._conflicts_logged.add(key)
            _LOGGER.warning(
                "LAN relay %s: %s %s ignored, owned by %s (last record %.0fs ago)",
                source, event, deviceid, entry.owner, age,
            )
        return False

    def _accept(
        self, deviceid: str, source: str, counter: Optional[Tuple[str, int]], now: float
    ) -> _DeviceEntry:
        """Record a decrypted record from source: owner, time, counter."""
        entry = self._devices.get(deviceid)
        if entry is None:
            entry = _DeviceEntry(owner=source, received=now)
            self._devices[deviceid] = entry
        elif entry.owner != source:
            _LOGGER.warning(
                "LAN relay %s: %s now owned by this relay, %s silent for %.0fs",
                source, deviceid, entry.owner, now - entry.received,
            )
            entry.owner = source
            # The previous owner's address is stale by now; only the new
            # owner's records may set one
            entry.endpoint = None
            self._clear_conflicts(deviceid)
        entry.received = now
        self._conflicts_logged.discard((deviceid, source))
        self._rejected.pop((deviceid, source), None)
        if counter is not None:
            self._last_applied[(deviceid, source)] = counter
        return entry

    def _clear_conflicts(self, deviceid: str) -> None:
        self._conflicts_logged = {key for key in self._conflicts_logged if key[0] != deviceid}

    def _remember_endpoint(self, entry: _DeviceEntry, message: Dict[str, Any], now: float) -> None:
        """Keep the first usable IPv4 address and the port from a relay record."""
        addresses, port = message.get("addresses"), message.get("port")
        if not isinstance(addresses, list) or isinstance(port, bool) or not isinstance(port, int):
            return
        if not 1 <= port <= 65535:
            return
        for address in addresses:
            ip = _usable_device_address(address)
            if ip is not None:
                entry.endpoint = (str(ip), port, now)
                return

    def endpoint_for(self, deviceid: str) -> Optional[Tuple[str, int]]:
        """The (address, port) of a device from a fresh relay record, else None."""
        entry = self._devices.get(deviceid)
        if entry is None or entry.endpoint is None:
            return None
        address, port, received = entry.endpoint
        if time.monotonic() - received > ENDPOINT_FRESH_SECONDS:
            return None
        return address, port

    def _track_counter(self, state: _SourceState, message: Dict[str, Any]) -> None:
        """Note lost datagrams and relay restarts, per relay. The resync heals both."""
        boot, n = message.get("boot"), message.get("n")
        if not isinstance(boot, str) or isinstance(n, bool) or not isinstance(n, int):
            return
        source = state.address
        if state.boot is None or state.n is None:
            # Nothing can be concluded about losses before the first datagram
            _LOGGER.info("LAN relay %s: first datagram since start (run %s, n=%d)", source, boot, n)
            state.boot, state.n = boot, n
            return
        if boot == state.boot:
            if n > state.n + 1:
                _LOGGER.info(
                    "LAN relay %s: %d datagram(s) lost (run %s, n=%d after %d)",
                    source, n - state.n - 1, boot, n, state.n,
                )
            # A late datagram must not wind the counter back, or the next one
            # would report the same gap again
            state.n = max(state.n, n)
            return
        if boot == state.previous_boot:
            # A late datagram of the run before the restart
            return
        # A new run, which counts n from 1, so everything before n was lost
        lost = n - 1
        if lost > 0:
            _LOGGER.info(
                "LAN relay %s: relay restarted (run %s, was %s), %d datagram(s) of the new run lost",
                source, boot, state.boot, lost,
            )
        else:
            _LOGGER.info("LAN relay %s: relay restarted (run %s, was %s)", source, boot, state.boot)
        state.previous_boot, state.boot, state.n = state.boot, boot, n

    def _decrypt_record(
        self, deviceid: str, source: str, seq: str, txt: Dict[str, Any], devicekey: str
    ) -> Optional[Dict[str, Any]]:
        """The decrypted params of a record, or None when it cannot be decrypted."""
        extra = sorted(
            k for k in txt
            if k.startswith("data") and k[4:].isdigit() and int(k[4:]) > DATA_FIELDS
        )
        if extra:
            self._report_once(
                "fields", deviceid, source, seq, logging.WARNING,
                "LAN relay %s: %s sends fields beyond data%d (%s), state may be incomplete",
                source, deviceid, DATA_FIELDS, ",".join(extra),
            )

        # Only string fields: anything else cannot be part of the base64 payload
        raw = "".join(
            txt[f"data{i}"] for i in range(1, DATA_FIELDS + 1) if isinstance(txt.get(f"data{i}"), str)
        )
        try:
            # _is_valid_record lets a record through only encrypted when there is a devicekey
            return decrypt_params(raw, str(txt.get("iv", "")), devicekey)
        except Exception as e:  # report the failure type only, never the payload
            self._report_once(
                "decrypt", deviceid, source, seq, logging.WARNING,
                "LAN relay %s: %s seq %s could not be decrypted (%s). If this persists the "
                "device may have been paired again and have a new devicekey; a restart "
                "of this service fetches the current one.",
                source, deviceid, seq, type(e).__name__,
            )
            return None

    def _apply_record(self, deviceid: str, event: str, seq: str, params: Dict[str, Any]) -> None:
        """Hand on the params of a decrypted record whose seq differs from the last applied."""
        if self._last_seq.get(deviceid) == seq:
            return
        self._last_seq[deviceid] = seq
        self.on_state(deviceid, params, seq, event)

    def _report_once(
        self, kind: str, deviceid: str, source: str, seq: str, level: int, msg: str, *args
    ) -> None:
        key = (deviceid, source, kind)
        if self._reported.get(key) == seq:
            return
        self._reported[key] = seq
        _LOGGER.log(level, msg, *args)


# ==============================================================================
# LAN command sender, mirrored from AlexxIT/SonoffLAN local.py at 73690b7
# (XRegistryLocal.send), reduced to what this service uses: no getState, no
# sub-devices, no state taken from the reply. On firmware 3.7.6 the reply
# carries only seq and error, and the result is confirmed through the relay.
# ==============================================================================


class LanCommandSender:
    """Posts encrypted commands to a device's own HTTP server.

    The address and port are passed in by the caller, which takes them from the
    device's latest relay record (see LanRelayReceiver.endpoint_for).
    """

    def __init__(self, session: aiohttp.ClientSession, sequence: SequenceSource):
        self._session = session
        self._sequence = sequence

    async def send(
        self,
        host: str,
        port: int,
        deviceid: str,
        devicekey: str,
        params: Dict[str, Any],
        timeout: float,
        still_wanted: Optional[Callable[[], bool]] = None,
    ) -> str:
        """Send one command. Returns "online" when the device answered error 0.

        Anything else is a short reason for the log ("timeout", "error 400",
        "E#CON" and so on, the E# codes as upstream). Error 0 only means the
        device accepted the request, not that the relay moved.

        still_wanted, when given, is asked before every POST, including each
        retry after a reset connection. Once it returns False nothing more is
        posted and the result is "superseded", so a retry of an older command
        cannot reach the device after a newer command for the same channel.
        """
        try:
            return await asyncio.wait_for(
                self._send(host, port, deviceid, devicekey, params, still_wanted), timeout
            )
        except asyncio.TimeoutError:
            _LOGGER.debug("%s => LAN %s:%d timeout %.1fs", deviceid, host, port, timeout)
            return "timeout"

    async def _send(
        self,
        host: str,
        port: int,
        deviceid: str,
        devicekey: str,
        params: Dict[str, Any],
        still_wanted: Optional[Callable[[], bool]] = None,
    ) -> str:
        # The command is the first key of the params: switch or switches here
        command = next(iter(params))
        payload = encrypt_payload(
            {
                "sequence": await self._sequence(),
                "deviceid": deviceid,
                "selfApikey": "123",
                "data": params,
            },
            devicekey,
        )
        url = f"http://{host}:{port}/zeroconf/{command}"
        log = f"{deviceid} => LAN {host}:{port} {command} {params}"

        for _ in range(LAN_CONNRESET_RETRIES + 1):
            if still_wanted is not None and not still_wanted():
                _LOGGER.debug("%s !! superseded, not posting", log)
                return "superseded"
            try:
                async with self._session.post(
                    url, json=payload, headers={"Connection": "close"}
                ) as response:
                    # Some devices answer unsupported commands with an HTML page
                    if response.content_type == "text/html":
                        _LOGGER.debug("%s <= text/html", log)
                        return "text/html"
                    try:
                        # Not every firmware sets application/json
                        reply = await response.json(content_type=None)
                    except ValueError:
                        _LOGGER.debug("%s <= reply is not JSON", log)
                        return "bad reply"
                    _LOGGER.debug("%s <= %s", log, reply)
                    if not isinstance(reply, dict):
                        return "bad reply"
                    error = reply.get("error")
                    return "online" if error == 0 else f"error {error}"

            # ClientConnectorError is a ClientOSError, so it has to come first
            except aiohttp.ClientConnectorError as e:
                _LOGGER.debug("%s !! can't connect: %s", log, e)
                return "E#CON"
            except aiohttp.ClientOSError as e:
                if e.errno != errno.ECONNRESET:
                    _LOGGER.debug("%s !! %s", log, e)
                    return "E#COE"
                _LOGGER.debug("%s !! connection reset, retrying", log)
                await asyncio.sleep(LAN_CONNRESET_DELAY_SECONDS)
            except aiohttp.ServerDisconnectedError as e:
                _LOGGER.debug("%s !! %s", log, e)
                return "E#COS"
            except aiohttp.ClientError as e:
                _LOGGER.debug("%s !! %s", log, e)
                return "E#CLI"

        return "E#CRE"
