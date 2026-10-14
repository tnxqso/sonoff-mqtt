"""Bridge between the eWeLink cloud and MQTT.

Publishes device state, accepts commands from MQTT and verifies each one by
reading the state back (see _send_command). It started as a read-only observer
to establish how the cloud connection behaves over days before anything
depended on it; commands with verification were added once that was known.

Note what it can and cannot see. The cloud pushes a state update to every client
EXCEPT the one that caused the change, so while another client is driving these
devices this process sees everything it does, but it does not see echoes of its
own commands and has to read state back with a query instead.

Optionally, state also arrives from an mDNS relay on the devices' own network
(see lan_relay.py). That is a second, independent view of the same devices and
goes through the same merge-and-publish path, so a change reported by both the
cloud and the LAN is published once.

For devices listed in lan_relay.command_devices, commands are sent over the LAN
first and confirmed by the relay (see _try_lan_command). The cloud path with its
read-back stays in place as the fallback for every command that is not.
"""

# 1. Standard library
import asyncio
import concurrent.futures
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

# 2. Third-party
import aiohttp

# 3. Project-local
from .config import Config
from .devices import DeviceRegistry
from .lan_relay import LanCommandSender, LanRelayReceiver
from .mqtt import MqttPublisher
from .vendor.ewelink.base import SIGNAL_CONNECTED, SIGNAL_UPDATE, XRegistryBase
from .vendor.ewelink.cloud import XRegistryCloud

_LOGGER = logging.getLogger(__name__)

# How long to wait for a cloud session to come online before giving up on it
CONNECT_TIMEOUT_SECONDS = 60

# Params taken from the LAN relay. The TXT records carry more (ssid, startup,
# pulse and so on), but only the switch state has been compared against the
# cloud's format, so nothing else is merged until it has been.
LAN_STATE_KEYS = ("switch", "switches")

# LAN commands. The HTTP request gets this long in total, including upstream's
# retries on a connection reset. The relay then has until this long after the
# command was started to report the new state; in the first live test the state
# arrived 0.1 to 0.8 s after the command. Missing either falls back to the cloud.
LAN_COMMAND_TIMEOUT_SECONDS = 2.0
LAN_CONFIRM_TIMEOUT_SECONDS = 3.0


class Observer:
    # Occasional drops are normal. This many in one run suggests something is
    # actively evicting the session rather than the network being unreliable.
    EVICTION_SUSPECTED_AFTER = 3

    def __init__(self, config: Config):
        self.config = config
        self.registry = DeviceRegistry(config.mqtt.base_topic)
        self.mqtt = MqttPublisher(config.mqtt)
        self._clients: Dict[str, XRegistryCloud] = {}
        self._session: aiohttp.ClientSession | None = None
        self._disconnects: Dict[str, int] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lan_relay: LanRelayReceiver | None = None
        # Devices with at least one applied LAN record, so the first one is
        # logged even when it changes nothing
        self._lan_seen: set[str] = set()
        self._lan_sender: LanCommandSender | None = None
        # LAN commands waiting for the relay, per device: (expected topic,
        # expected value, future resolved by _on_lan_state)
        self._lan_waiters: Dict[str, List[Tuple[str, str, asyncio.Future]]] = {}
        # Command generation per (deviceid, channel). Each command takes the
        # next number when it starts, and an older command stops at its next
        # step once a newer one exists (see _send_command). Only touched on the
        # event loop, so it needs no lock.
        self._command_generation: Dict[Tuple[str, str], int] = {}

    async def run(self) -> None:
        self._loop = asyncio.get_running_loop()
        self.mqtt.on_command = self._on_mqtt_command
        self.mqtt.start()
        self._session = aiohttp.ClientSession()

        try:
            for account in self.config.accounts:
                await self._start_account(account)

            if len(self.registry) == 0:
                _LOGGER.error("No devices found on any account, nothing to observe")
                return

            # Started after the accounts, so the registry and its devicekeys are
            # in place before the first datagram can arrive
            if self.config.lan_relay.enabled:
                self._lan_relay = LanRelayReceiver(
                    self.config.lan_relay, self._on_lan_state, self._devicekey_for
                )
                await self._lan_relay.start()

                if self.config.lan_relay.command_devices:
                    self._lan_sender = LanCommandSender(self._session, XRegistryBase.sequence)
                    self._check_command_devices()

            _LOGGER.info("Observing %d device(s). Ctrl-C to stop.", len(self.registry))
            # The cloud clients each run their own task; this just parks until
            # cancelled
            await asyncio.Event().wait()

        finally:
            await self._shutdown()

    async def _start_account(self, account) -> None:
        _LOGGER.info("Account %s: logging in as %s", account.name, account.email)

        cloud = XRegistryCloud(self._session)
        await cloud.login(account.email, account.password, account.country_code)
        own_apikey = cloud.auth["user"]["apikey"]
        _LOGGER.info("Account %s: logged in, region %s", account.name, cloud.region)

        # A plain device listing returns only the home that is currently active
        # in the phone app, so every family has to be asked for by id or devices
        # in the other homes stay invisible.
        homes = await cloud.get_homes()
        _LOGGER.info("Account %s: homes %s", account.name, homes)

        wanted = account.homes or list(homes.keys())
        raw_devices = await cloud.get_devices(wanted)
        _LOGGER.info(
            "Account %s: %d device(s) across %d home(s)",
            account.name,
            len(raw_devices),
            len(wanted),
        )

        for raw in raw_devices:
            device = self.registry.add(raw, cloud, own_apikey)
            _LOGGER.info(
                "  %s  %-6s uiid=%-3s online=%-5s %s",
                device.deviceid,
                "shared" if device.shared else "own",
                device.uiid,
                device.online,
                device.name,
            )

        cloud.dispatcher_connect(SIGNAL_UPDATE, self._on_update)
        cloud.dispatcher_connect(
            SIGNAL_CONNECTED, lambda: self._on_connected(account.name, cloud)
        )

        # self.auth is already set from the login above, so run_forever goes
        # straight to connect() rather than logging in a second time
        cloud.start()
        self._clients[account.name] = cloud

        connected = asyncio.Event()
        unsubscribe = cloud.dispatcher_connect(
            SIGNAL_CONNECTED, lambda: connected.set() if cloud.online else None
        )
        try:
            await asyncio.wait_for(connected.wait(), CONNECT_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            _LOGGER.error(
                "Account %s: WebSocket did not come online within %ds",
                account.name,
                CONNECT_TIMEOUT_SECONDS,
            )
        finally:
            unsubscribe()

        # The device listing already carried current params, so publish that as
        # the starting point rather than waiting for the first push, which for
        # an untouched device could be hours away
        for device in self.registry.all():
            self._publish(device)

    def _on_connected(self, account_name: str, cloud: XRegistryCloud) -> None:
        _LOGGER.info("Account %s: cloud connection state %s", account_name, cloud.online)

        if cloud.online:
            self._disconnects[account_name] = 0
            return

        # Repeated drops on an otherwise healthy network usually mean something
        # else is logged in with the same credentials. The cloud evicts the
        # older session whenever a newer one appears with the same appid, so two
        # clients take turns kicking each other out indefinitely. The vendored
        # client logs the underlying error 406 as an authentication failure,
        # which reads as a password problem rather than as a second client.
        count = self._disconnects.get(account_name, 0) + 1
        self._disconnects[account_name] = count

        if count == self.EVICTION_SUSPECTED_AFTER:
            _LOGGER.warning(
                "Account %s has lost the cloud connection %d times in this run. If "
                "this keeps repeating, something else is probably logged in with "
                "the same eWeLink account: the phone app is fine, but another "
                "bridge, binding or a second copy of this service will evict this "
                "one. Give the other client its own appid and appsecret, or stop "
                "it.",
                account_name,
                count,
            )

    def _on_update(self, data: Dict[str, Any]) -> None:
        """Handle a state push or a sysmsg from the cloud."""
        deviceid = data.get("deviceid")
        if not deviceid:
            return

        device = self.registry.get(deviceid)
        if device is None:
            _LOGGER.debug("Update for unknown device %s, ignoring", deviceid)
            return

        params = data.get("params")
        if isinstance(params, dict):
            # online arrives either inside params or alongside it depending on
            # whether this is a sysmsg or an ordinary update
            if "online" in params:
                device.set_online(bool(params["online"]))
            device.merge_params(params)

        if "online" in data:
            device.set_online(bool(data["online"]))

        self._publish(device)

    def _devicekey_for(self, deviceid: str) -> Optional[str]:
        """The devicekey from the cloud device listing, kept in memory only."""
        device = self.registry.get(deviceid)
        if device is None:
            return None
        return device.raw.get("devicekey")

    def _check_command_devices(self) -> None:
        """Say at startup which configured devices can actually take LAN commands."""
        usable = []
        for deviceid in self.config.lan_relay.command_devices:
            device = self.registry.get(deviceid)
            if device is None:
                _LOGGER.warning(
                    "LAN commands: %s is not on any account, it will not be commanded",
                    deviceid,
                )
            elif not self._devicekey_for(deviceid):
                _LOGGER.warning(
                    "LAN commands: %s (%s) has no devicekey in the device listing, "
                    "its commands will go through the cloud",
                    device.name,
                    deviceid,
                )
            else:
                usable.append(device.name)
        _LOGGER.info("LAN commands enabled for: %s", ", ".join(usable) or "(none)")

    def _on_lan_state(self, deviceid: str, params: Dict[str, Any], seq: str, event: str) -> None:
        """Merge switch state decrypted from a relayed mDNS record.

        The LAN and the cloud report the same change independently, and
        whichever arrives first is published; the other then changes nothing.
        In the first live test (2026-10-13) the LAN was first every time, under
        a second after a command against about three seconds for the cloud
        read-back, but that is not guaranteed. A channel toggled faster than the
        slower source reports can therefore briefly be published in its
        intermediate state after the faster source already reported the final
        one, until the next record corrects it. Not handled until it is seen to
        matter.
        """
        device = self.registry.get(deviceid)
        if device is None:
            return

        state = {key: params[key] for key in LAN_STATE_KEYS if key in params}
        if not state:
            _LOGGER.debug("%s: LAN %s seq %s carried no switch state", device.name, event, seq)
            return

        device.merge_params(state)
        changes = [
            (topic.rsplit("/", 1)[-1], payload)
            for topic, payload in device.changed_topics()
            if topic.rsplit("/", 1)[-1].startswith("switch")
        ]
        # Worded unlike the "-> ON" line of _send_command, so a state report is
        # not mistaken for a command sent over the LAN
        for channel, payload in changes:
            _LOGGER.info("%s %s is %s (LAN state, seq %s)", device.name, channel, payload, seq)

        # Usually the cloud has already reported the same change, so most LAN
        # records change nothing. The first one per device is still logged, as
        # proof that the LAN path works for it at all.
        if deviceid not in self._lan_seen:
            self._lan_seen.add(deviceid)
            _LOGGER.info("%s: LAN state received (%s, seq %s)", device.name, event, seq)
        elif not changes:
            _LOGGER.debug("%s: LAN %s seq %s, no change", device.name, event, seq)

        self._resolve_lan_waiters(device)
        self._publish(device)

    def _resolve_lan_waiters(self, device) -> None:
        """Confirm the LAN commands this record shows to have taken effect.

        Called only for a record with a new seq, so a Resync repeating the state
        from before the command cannot confirm it. A record caused by something
        else can, but only when the channel really is in the commanded state,
        which is what confirmation means.
        """
        waiters = self._lan_waiters.get(device.deviceid)
        if not waiters:
            return
        current = dict(device.topics())
        for topic, value, future in waiters:
            if not future.done() and current.get(topic) == value:
                future.set_result(True)

    def _on_mqtt_command(self, deviceid: str, channel: str, payload: str) -> None:
        """Handle a command from MQTT.

        Called on paho's network thread, not the event loop, so the actual work
        is handed to the loop rather than done here.
        """
        if self._loop is None:
            return
        future = asyncio.run_coroutine_threadsafe(
            self._send_command(deviceid, channel, payload), self._loop
        )
        future.add_done_callback(self._command_done_callback(deviceid, channel, payload))

    @staticmethod
    def _command_done_callback(
        deviceid: str, channel: str, payload: str
    ) -> Callable[[concurrent.futures.Future], None]:
        """Log anything that escapes _send_command, which would otherwise be lost.

        Nothing else ever looks at the future, so without this an exception
        would leave no log line, no cloud fallback and no error topic.
        """

        def done(future: concurrent.futures.Future) -> None:
            if future.cancelled():
                return
            exc = future.exception()
            if exc is not None:
                _LOGGER.error(
                    "Command %s %s -> %s failed unexpectedly",
                    deviceid,
                    channel,
                    payload,
                    exc_info=exc,
                )

        return done

    def _is_current(self, deviceid: str, channel: str, generation: int) -> bool:
        """Whether no newer command for this device and channel has started."""
        return self._command_generation.get((deviceid, channel)) == generation

    async def _send_command(self, deviceid: str, channel: str, payload: str) -> None:
        """Send a command and confirm it actually took effect.

        The cloud acknowledges a command with a receipt and nothing more. It
        does not push the resulting state back to the client that caused the
        change, and a receipt of error 0 only means the request was accepted,
        not that the relay moved. A command can be accepted and then quietly
        dropped, which is how a lamp ends up burning all night while every log
        line says the switch off succeeded.

        So each command is read back. Send, wait for the device to settle, issue
        a query, and compare the state that comes back against what was asked
        for. On a mismatch, back off and try again. When the attempts run out,
        publish to the error topic so whatever consumes this can raise it with a
        human.

        A device in lan_relay.command_devices is first commanded over the LAN.
        Only when the relay confirms the new state is the cloud left out; in
        every other case the cloud path below runs exactly as without the LAN,
        so the error topic means the same either way. Resending after an
        unconfirmed LAN command is safe because commands are ON or OFF, never a
        toggle.
        """
        device = self.registry.get(deviceid)
        if device is None:
            _LOGGER.warning("Command for unknown device %s, ignoring", deviceid)
            return

        client = self.registry.client_for(deviceid)
        if client is None:
            _LOGGER.error("No cloud client for %s", deviceid)
            return

        params = device.command_params(channel, payload)
        if params is None:
            return

        expected = device.expected_after(channel, payload)
        if expected is None:
            return
        expected_topic, expected_value = expected

        error_topic = f"{device.topic_prefix}/{channel}/error"

        # Taken before the first await, so commands are numbered in the order
        # the loop starts them, which is the order MQTT delivered them in
        key = (deviceid, channel)
        generation = self._command_generation.get(key, 0) + 1
        self._command_generation[key] = generation

        def superseded(step: str) -> bool:
            """True, after one INFO line, when a newer command for the channel exists.

            Checked before every further step, so the cloud fallback, the cloud
            retries and the error topic of an older command cannot undo or
            misreport a newer one. A command already handed to the device or the
            cloud cannot be recalled this way.
            """
            if self._is_current(deviceid, channel, generation):
                return False
            _LOGGER.info(
                "%s %s -> %s: superseded by a newer command, stopping before %s",
                device.name,
                channel,
                expected_value,
                step,
            )
            return True

        try:
            lan_confirmed = await self._try_lan_command(
                device,
                channel,
                params,
                expected_topic,
                expected_value,
                still_wanted=lambda: self._is_current(deviceid, channel, generation),
            )
        except Exception:
            _LOGGER.exception(
                "%s %s: LAN attempt failed unexpectedly, falling back to the cloud",
                device.name,
                channel,
            )
            lan_confirmed = False

        if lan_confirmed:
            if superseded("clearing the error topic"):
                return
            self.mqtt.publish(error_topic, "")
            return

        if superseded("the cloud fallback"):
            return

        config = self.config.verification
        attempts = config.max_attempts if config.enabled else 1
        backoff = config.retry_backoff_seconds

        for attempt in range(1, attempts + 1):
            if attempt > 1:
                if superseded(f"cloud retry {attempt}"):
                    return
                _LOGGER.info(
                    "%s %s: retry %d of %d in %.1fs",
                    device.name,
                    channel,
                    attempt,
                    attempts,
                    backoff,
                )
                await asyncio.sleep(backoff)
                backoff *= 2
                if superseded(f"cloud retry {attempt}"):
                    return

            _LOGGER.info("%s %s -> %s", device.name, channel, expected_value)
            receipt = await client.send(device.raw, params, timeout=10)

            if superseded("checking the cloud receipt"):
                return
            if receipt != "online":
                _LOGGER.warning(
                    "%s %s: not accepted, receipt %r", device.name, channel, receipt
                )
                continue

            if not config.enabled:
                _LOGGER.debug("%s %s: verification disabled", device.name, channel)
                return

            # Give the relay time to move and report before asking about it
            await asyncio.sleep(config.settle_seconds)
            if superseded("the read-back"):
                return

            verified = await self._verify(client, device, expected_topic, expected_value)
            if superseded("acting on the read-back"):
                return
            if verified is True:
                if attempt > 1:
                    _LOGGER.info(
                        "%s %s: confirmed on attempt %d", device.name, channel, attempt
                    )
                else:
                    _LOGGER.info("%s %s: confirmed", device.name, channel)
                self.mqtt.publish(error_topic, "")
                return

            if verified is None:
                _LOGGER.warning(
                    "%s %s: could not read state back, treating as unconfirmed",
                    device.name,
                    channel,
                )
            else:
                _LOGGER.warning(
                    "%s %s: state did not change to %s",
                    device.name,
                    channel,
                    expected_value,
                )

        _LOGGER.error(
            "%s %s: gave up after %d attempt(s), device may be in the wrong state",
            device.name,
            channel,
            attempts,
        )
        self.mqtt.publish(
            error_topic,
            f"command {expected_value} not confirmed after {attempts} attempt(s)",
        )

    async def _try_lan_command(
        self,
        device,
        channel: str,
        params: Dict[str, Any],
        expected_topic: str,
        expected_value: str,
        still_wanted: Optional[Callable[[], bool]] = None,
    ) -> bool:
        """Command a device over the LAN and wait for the relay to confirm it.

        Returns True only when a relay record with a new seq shows the expected
        state within LAN_CONFIRM_TIMEOUT_SECONDS. False means nothing is known
        about the outcome and the caller goes on to the cloud. There is no
        getState probe: the device's address comes from its latest relay
        record, and a device without a fresh record is not tried at all.

        still_wanted is passed on to the sender, which stops retrying a reset
        connection once it returns False (a newer command has started).
        """
        if self._lan_sender is None or self._lan_relay is None:
            return False
        if device.deviceid not in self.config.lan_relay.command_devices:
            return False

        devicekey = self._devicekey_for(device.deviceid)
        if not devicekey:
            _LOGGER.warning("%s %s: no devicekey, using the cloud", device.name, channel)
            return False
        endpoint = self._lan_relay.endpoint_for(device.deviceid)
        if endpoint is None:
            _LOGGER.warning(
                "%s %s: no fresh relay record for the address, using the cloud",
                device.name,
                channel,
            )
            return False
        host, port = endpoint

        # Registered before sending, because the relay can report the new state
        # before the HTTP reply has been read
        future = asyncio.get_running_loop().create_future()
        waiter = (expected_topic, expected_value, future)
        self._lan_waiters.setdefault(device.deviceid, []).append(waiter)
        started = time.monotonic()
        try:
            _LOGGER.info("%s %s -> %s (LAN)", device.name, channel, expected_value)
            receipt = await self._lan_sender.send(
                host,
                port,
                device.deviceid,
                devicekey,
                params,
                LAN_COMMAND_TIMEOUT_SECONDS,
                still_wanted=still_wanted,
            )
            if receipt == "superseded":
                # The caller logs this once, as for every other step
                return False
            if receipt != "online":
                _LOGGER.warning(
                    "%s %s: LAN command not accepted (%s), falling back to the cloud",
                    device.name,
                    channel,
                    receipt,
                )
                return False

            remaining = LAN_CONFIRM_TIMEOUT_SECONDS - (time.monotonic() - started)
            try:
                await asyncio.wait_for(future, max(remaining, 0.0))
            except asyncio.TimeoutError:
                _LOGGER.warning(
                    "%s %s: not confirmed via LAN within %.1fs, falling back to the cloud",
                    device.name,
                    channel,
                    LAN_CONFIRM_TIMEOUT_SECONDS,
                )
                return False

            # In milliseconds: the LAN usually confirms in about 50 ms, which
            # one decimal of seconds would show as 0.0s
            _LOGGER.info(
                "%s %s: confirmed via LAN in %d ms",
                device.name,
                channel,
                round((time.monotonic() - started) * 1000),
            )
            return True
        finally:
            waiters = self._lan_waiters.get(device.deviceid, [])
            if waiter in waiters:
                waiters.remove(waiter)
            if not waiters:
                self._lan_waiters.pop(device.deviceid, None)

    async def _verify(
        self, client, device, expected_topic: str, expected_value: str
    ) -> Optional[bool]:
        """Read the device state back and compare it against the intent.

        Returns True when the state matches, False when it does not, and None
        when the state could not be read at all, which is not the same thing:
        an unreadable device might well have obeyed.

        The query reply arrives asynchronously through the update dispatcher and
        has already been merged into the device by the time send() returns, so
        the comparison is made against the device's own topics rather than the
        return value.
        """
        query = await client.send(device.raw, timeout=10)
        if query != "online":
            _LOGGER.debug("%s: query returned %r", device.name, query)
            return None

        for topic, value in device.topics():
            if topic == expected_topic:
                return value == expected_value

        _LOGGER.debug("%s: no topic %s in current state", device.name, expected_topic)
        return None

    def _publish(self, device) -> None:
        """Publish whatever changed since the last publish for this device."""
        for topic, payload in device.changed_topics():
            self.mqtt.publish(topic, payload)
            device.mark_published(topic, payload)

    async def _shutdown(self) -> None:
        _LOGGER.info("Shutting down")
        if self._lan_relay is not None:
            await self._lan_relay.stop()
        for name, cloud in self._clients.items():
            await cloud.stop()
            _LOGGER.debug("Account %s: cloud client stopped", name)
        if self._session is not None:
            await self._session.close()
        self.mqtt.stop()
