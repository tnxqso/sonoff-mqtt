"""Device state from an mDNS relay on the devices' own network.

eWeLink devices announce their state over mDNS (_ewelink._tcp). The params are
encrypted with the devicekey and split over the TXT fields data1..dataN, next
to a plaintext seq that the device counts up on every change. This service
cannot see that multicast when the devices sit on another network, and asking
from off-link does not help either, because devices ignore mDNS queries that do
not come from their own link (RFC 6762 section 11).

So a small relay on the devices' own network forwards every TXT record
unchanged, as one JSON datagram over UDP. The relay holds no devicekeys and
never decrypts: data1..dataN are still encrypted when they cross the network,
and only this service, which already has the devicekeys from the cloud device
listing, can read them. The relay also resends every current record at a fixed
interval, so a lost datagram or a restart here heals by itself.

Datagram format, protocol version 1:

    {"v": 1, "boot": "<relay run id>", "n": <counter per relay run>,
     "event": "Added" | "Updated" | "Resync" | "Removed", "ts": <unix time>,
     "name": "<mDNS service name>", "deviceid": "<deviceid>",
     "addresses": ["<ip>", ...], "port": <port>, "txt": {"<key>": "<value>"}}

"Removed" carries only name and deviceid.

Only state is taken from the relay. The relay does not carry commands: for the
devices listed in lan_relay.command_devices, LanCommandSender below posts a
command straight to the address and port in the device's latest relay record,
and the observer waits for the relay to report the result (see
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
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

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
ENDPOINT_FRESH_SECONDS = 150.0

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


class LanRelayReceiver(asyncio.DatagramProtocol):
    """Receives relay datagrams, decrypts them and hands params to a callback.

    A record is applied when its seq differs from the last seq applied for that
    device, not only when it is greater. Whether a device resets seq when it
    restarts is not known, and a greater-than rule would ignore such a device
    for good. With the differs rule a Resync carrying the seq already applied is
    a no-op, while a Resync with a new seq, after a lost datagram or a restart
    of this service, is applied.
    """

    def __init__(self, config: LanRelayConfig, on_state: StateCallback, devicekey_for: KeyLookup):
        self.config = config
        self.on_state = on_state
        self.devicekey_for = devicekey_for
        self._allowed = {ipaddress.ip_address(a) for a in config.allowed_sources}

        self._transport: Optional[asyncio.DatagramTransport] = None
        self._silence_task: Optional[asyncio.Task] = None

        self._last_seq: Dict[str, str] = {}
        self._last_n: Dict[str, int] = {}
        # Last seq reported per (deviceid, kind), so a failing record is logged
        # once rather than on every resync, without growing without bound
        self._reported: Dict[Tuple[str, str], str] = {}
        self._last_rx = time.monotonic()
        self._silent = False
        # Latest (IPv4 address, port, monotonic receive time) per device, for
        # LAN commands. Refreshed by every record, including a Resync with an
        # unchanged seq, so it follows a device that changed address by DHCP.
        self._endpoints: Dict[str, Tuple[str, int, float]] = {}

    # --------------------------------------------------------------------------
    # Lifecycle
    # --------------------------------------------------------------------------

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        # IPv4 only, matching the relay and the firewall exception for it
        await loop.create_datagram_endpoint(
            lambda: self, local_addr=("0.0.0.0", self.config.listen_port)
        )
        self._last_rx = time.monotonic()
        self._silence_task = asyncio.create_task(self._watch_silence())
        _LOGGER.info(
            "LAN relay: listening on UDP %d, accepting %s",
            self.config.listen_port,
            ", ".join(self.config.allowed_sources),
        )

    def connection_made(self, transport) -> None:
        self._transport = transport

    async def stop(self) -> None:
        if self._silence_task is not None:
            self._silence_task.cancel()
        if self._transport is not None:
            self._transport.close()

    async def _watch_silence(self) -> None:
        """Warn once when the relay goes quiet, and say so when it is back.

        The relay resends everything at a fixed interval, so silence well past
        that interval means the relay, the tunnel or the firewall path is down,
        and the LAN view of the devices is going stale.
        """
        while True:
            await asyncio.sleep(SILENCE_CHECK_INTERVAL_SECONDS)
            quiet_for = time.monotonic() - self._last_rx
            if not self._silent and quiet_for > self.config.silence_warning_seconds:
                self._silent = True
                _LOGGER.warning(
                    "LAN relay: nothing received for %.0fs, LAN state is going stale",
                    quiet_for,
                )

    # --------------------------------------------------------------------------
    # Datagram handling
    # --------------------------------------------------------------------------

    def datagram_received(self, payload: bytes, addr) -> None:
        try:
            source = ipaddress.ip_address(addr[0])
        except ValueError:
            return
        if source not in self._allowed:
            _LOGGER.debug("LAN relay: dropped %d bytes from %s", len(payload), addr[0])
            return

        self._last_rx = time.monotonic()
        if self._silent:
            self._silent = False
            _LOGGER.info("LAN relay: receiving again")

        try:
            message = json.loads(payload)
        except ValueError:
            _LOGGER.warning("LAN relay: invalid JSON, %d bytes from %s", len(payload), addr[0])
            return
        if not isinstance(message, dict) or message.get("v") != PROTOCOL_VERSION:
            _LOGGER.warning("LAN relay: unexpected message, %d bytes from %s", len(payload), addr[0])
            return

        self._track_counter(message)

        deviceid = message.get("deviceid")
        event = message.get("event")
        if not isinstance(deviceid, str) or not deviceid:
            return

        if event == "Removed":
            # Forget the seq so the device is applied again when it reappears
            self._last_seq.pop(deviceid, None)
            # And its address, so no LAN command goes to a device that has left
            self._endpoints.pop(deviceid, None)
            _LOGGER.info("LAN relay: %s left mDNS", deviceid)
            return

        txt = message.get("txt")
        if not isinstance(txt, dict):
            _LOGGER.warning("LAN relay: %s %s without a txt object", event, deviceid)
            return

        # Before _handle_record, which returns early on an unchanged seq
        self._remember_endpoint(deviceid, message)
        self._handle_record(deviceid, str(event), txt)

    def _remember_endpoint(self, deviceid: str, message: Dict[str, Any]) -> None:
        """Keep the first IPv4 address and the port from a relay record."""
        addresses, port = message.get("addresses"), message.get("port")
        if not isinstance(addresses, list) or isinstance(port, bool) or not isinstance(port, int):
            return
        if not 1 <= port <= 65535:
            return
        for address in addresses:
            try:
                ip = ipaddress.ip_address(str(address))
            except ValueError:
                continue
            # IPv4 only, as everywhere else on the relay path
            if ip.version == 4:
                self._endpoints[deviceid] = (str(ip), port, time.monotonic())
                return

    def endpoint_for(self, deviceid: str) -> Optional[Tuple[str, int]]:
        """The (address, port) of a device from a fresh relay record, else None."""
        endpoint = self._endpoints.get(deviceid)
        if endpoint is None:
            return None
        address, port, received = endpoint
        if time.monotonic() - received > ENDPOINT_FRESH_SECONDS:
            return None
        return address, port

    def _track_counter(self, message: Dict[str, Any]) -> None:
        """Note lost datagrams and relay restarts. The resync heals both."""
        boot, n = message.get("boot"), message.get("n")
        if not isinstance(boot, str) or not isinstance(n, int):
            return
        previous = self._last_n.get(boot)
        if previous is None:
            if self._last_n:
                _LOGGER.info("LAN relay: relay restarted (run %s)", boot)
            # Only the current relay run is worth remembering
            self._last_n = {}
        elif n > previous + 1:
            _LOGGER.info("LAN relay: %d datagram(s) lost", n - previous - 1)
        self._last_n[boot] = n

    def _handle_record(self, deviceid: str, event: str, txt: Dict[str, Any]) -> None:
        seq = str(txt.get("seq"))
        if self._last_seq.get(deviceid) == seq:
            return

        devicekey = self.devicekey_for(deviceid)
        if not devicekey:
            self._report_once(
                "unknown", deviceid, seq, logging.DEBUG,
                "LAN relay: %s is not a known device with a devicekey", deviceid,
            )
            return

        extra = sorted(
            k for k in txt
            if k.startswith("data") and k[4:].isdigit() and int(k[4:]) > DATA_FIELDS
        )
        if extra:
            self._report_once(
                "fields", deviceid, seq, logging.WARNING,
                "LAN relay: %s sends fields beyond data%d (%s), state may be incomplete",
                deviceid, DATA_FIELDS, ",".join(extra),
            )

        raw = "".join(str(txt[f"data{i}"]) for i in range(1, DATA_FIELDS + 1) if f"data{i}" in txt)
        try:
            if txt.get("encrypt") == "true":
                params = decrypt_params(raw, str(txt.get("iv", "")), devicekey)
            else:
                params = json.loads(raw) if raw else {}
                if not isinstance(params, dict):
                    raise ValueError("plaintext payload is not an object")
        except Exception as e:  # report the failure type only, never the payload
            self._report_once(
                "decrypt", deviceid, seq, logging.WARNING,
                "LAN relay: %s seq %s could not be decrypted (%s). If this persists the "
                "device may have been paired again and have a new devicekey; a restart "
                "of this service fetches the current one.",
                deviceid, seq, type(e).__name__,
            )
            return

        self._last_seq[deviceid] = seq
        self.on_state(deviceid, params, seq, event)

    def _report_once(self, kind: str, deviceid: str, seq: str, level: int, msg: str, *args) -> None:
        key = (deviceid, kind)
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
    """Posts encrypted commands to a device's own HTTP server on port 8081."""

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
    ) -> str:
        """Send one command. Returns "online" when the device answered error 0.

        Anything else is a short reason for the log ("timeout", "error 400",
        "E#CON" and so on, the E# codes as upstream). Error 0 only means the
        device accepted the request, not that the relay moved.
        """
        try:
            return await asyncio.wait_for(
                self._send(host, port, deviceid, devicekey, params), timeout
            )
        except asyncio.TimeoutError:
            _LOGGER.debug("%s => LAN %s:%d timeout %.1fs", deviceid, host, port, timeout)
            return "timeout"

    async def _send(
        self, host: str, port: int, deviceid: str, devicekey: str, params: Dict[str, Any]
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
