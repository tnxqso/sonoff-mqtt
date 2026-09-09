"""Translation between eWeLink device params and MQTT topics.

The cloud sends whole params objects even when a single field changed, so a
push that only carries a new rssi still contains the switch state. Publishing
everything on every push would produce a stream of identical retained messages
and needless item updates downstream, so each value is compared against what was
last published for that topic and only differences are sent.

Only the device types actually in use are handled: uiid 1 and 6 are single
switches carrying a scalar "switch", uiid 4 is a four channel switch carrying a
"switches" array where each element names its own outlet. The outlet number is
authoritative, not the position in the array, because a partial update can carry
a single element for outlet 2.
"""

# 1. Standard library
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

_LOGGER = logging.getLogger(__name__)

# uiids we know how to translate. Anything else is published as raw state only,
# with no per-channel topics, so an unexpected device is visible but inert
# rather than silently dropped.
SINGLE_SWITCH_UIIDS = {1, 6}
MULTI_SWITCH_UIIDS = {4}

MULTI_SWITCH_MAX_OUTLETS = 4


class Device:
    """One eWeLink device, and the MQTT view of it."""

    def __init__(self, raw: Dict[str, Any], base_topic: str, own_apikey: str):
        self.deviceid: str = raw["deviceid"]
        self.name: str = raw.get("name", self.deviceid)
        self.uiid: Optional[int] = (raw.get("extra") or {}).get("uiid")
        self.model: Optional[str] = raw.get("productModel")
        self.owner_apikey: Optional[str] = raw.get("apikey")
        self.shared: bool = self.owner_apikey != own_apikey

        # The full device dict as the cloud returned it. The vendored client
        # needs this exact object when sending, because it reads apikey and
        # deviceid straight from it.
        self.raw: Dict[str, Any] = raw

        self.base_topic = base_topic
        self.online: Optional[bool] = raw.get("online")
        self.params: Dict[str, Any] = dict(raw.get("params") or {})

        # Last value published per topic, so unchanged values are not resent
        self._published: Dict[str, str] = {}

    def __repr__(self) -> str:
        return f"<Device {self.deviceid} {self.name!r} uiid={self.uiid}>"

    @property
    def topic_prefix(self) -> str:
        return f"{self.base_topic}/{self.deviceid}"

    def merge_params(self, params: Dict[str, Any]) -> None:
        """Merge an incoming params object into the held state.

        Merging rather than replacing is mandatory: a push carries only the keys
        that changed, so rebuilding from each push would wipe rssi, online and
        everything else on every toggle.
        """
        if not params:
            return
        self.params.update(params)

    def set_online(self, online: bool) -> None:
        self.online = online

    def topics(self) -> List[Tuple[str, str]]:
        """Return every (topic, payload) this device currently represents.

        Includes the raw state document, availability, and the per-channel
        topics for the device types we understand.
        """
        result: List[Tuple[str, str]] = [
            (f"{self.topic_prefix}/state", json.dumps(self.params, sort_keys=True)),
            (
                f"{self.topic_prefix}/available",
                "online" if self.online else "offline",
            ),
        ]

        if self.uiid in SINGLE_SWITCH_UIIDS:
            value = self.params.get("switch")
            if value is not None:
                result.append((f"{self.topic_prefix}/switch", str(value).upper()))

        elif self.uiid in MULTI_SWITCH_UIIDS:
            for outlet, value in self._outlet_states().items():
                result.append(
                    (f"{self.topic_prefix}/switch{outlet}", str(value).upper())
                )

        # Useful for spotting a device with a marginal connection before it
        # starts dropping commands
        rssi = self.params.get("rssi")
        if rssi is not None:
            result.append((f"{self.topic_prefix}/rssi", str(rssi)))

        return result

    def _outlet_states(self) -> Dict[int, str]:
        """Map outlet number to switch value for a multi channel device.

        The outlet field is trusted over the array position, because a partial
        update legitimately contains one element for a single outlet.
        """
        states: Dict[int, str] = {}
        switches = self.params.get("switches")
        if not isinstance(switches, list):
            return states

        for index, element in enumerate(switches):
            if not isinstance(element, dict):
                continue
            outlet = element.get("outlet", index)
            value = element.get("switch")
            if value is None:
                continue
            try:
                outlet = int(outlet)
            except (TypeError, ValueError):
                _LOGGER.warning(
                    "%s: unusable outlet %r, skipping element", self.deviceid, outlet
                )
                continue
            if not 0 <= outlet < MULTI_SWITCH_MAX_OUTLETS:
                _LOGGER.warning(
                    "%s: outlet %d out of range, skipping", self.deviceid, outlet
                )
                continue
            states[outlet] = value
        return states

    def command_params(self, channel: str, payload: str) -> Optional[Dict[str, Any]]:
        """Build the params object for a command on one channel.

        Returns None if the channel or the payload makes no sense for this
        device, so a stray retained message on a topic we do not own cannot be
        turned into a command.

        For a multi channel device only the changed outlet is sent. The cloud
        accepts a sparse switches array, and sending all four would fight with
        anything else driving the other outlets.
        """
        value = payload.strip().upper()
        if value not in ("ON", "OFF"):
            _LOGGER.warning(
                "%s: ignoring command %r on %s, expected ON or OFF",
                self.deviceid,
                payload,
                channel,
            )
            return None

        state = value.lower()

        if self.uiid in SINGLE_SWITCH_UIIDS:
            if channel != "switch":
                _LOGGER.warning(
                    "%s: uiid %s has no channel %r", self.deviceid, self.uiid, channel
                )
                return None
            return {"switch": state}

        if self.uiid in MULTI_SWITCH_UIIDS:
            if not channel.startswith("switch") or not channel[6:].isdigit():
                _LOGGER.warning(
                    "%s: uiid %s has no channel %r", self.deviceid, self.uiid, channel
                )
                return None
            outlet = int(channel[6:])
            if not 0 <= outlet < MULTI_SWITCH_MAX_OUTLETS:
                _LOGGER.warning("%s: outlet %d out of range", self.deviceid, outlet)
                return None
            return {"switches": [{"outlet": outlet, "switch": state}]}

        _LOGGER.warning(
            "%s: uiid %s is not a type we know how to command", self.deviceid, self.uiid
        )
        return None

    def expected_after(self, channel: str, payload: str) -> Optional[Tuple[str, str]]:
        """What the state topic for this channel should read once a command lands.

        Used by verification to tell a command that worked from one the cloud
        accepted and then dropped.
        """
        value = payload.strip().upper()
        if value not in ("ON", "OFF"):
            return None
        return (f"{self.topic_prefix}/{channel}", value)

    def changed_topics(self) -> List[Tuple[str, str]]:
        """Return only the topics whose value differs from the last publish."""
        changed = []
        for topic, payload in self.topics():
            if self._published.get(topic) != payload:
                changed.append((topic, payload))
        return changed

    def mark_published(self, topic: str, payload: str) -> None:
        self._published[topic] = payload


class DeviceRegistry:
    """All devices across all accounts, and which client owns each one.

    Routing a command means finding the session whose account can reach the
    device. With devices shared into a single account that is trivially one
    client, but the structure holds for several.
    """

    def __init__(self, base_topic: str):
        self.base_topic = base_topic
        self._devices: Dict[str, Device] = {}
        self._client_of: Dict[str, Any] = {}

    def add(self, raw: Dict[str, Any], client: Any, own_apikey: str) -> Device:
        deviceid = raw["deviceid"]
        if deviceid in self._devices:
            # Two accounts can see the same device when one shares it to the
            # other. Keep the first, which is the owning account if that account
            # was registered first.
            _LOGGER.debug("%s already registered, keeping the first client", deviceid)
            return self._devices[deviceid]

        device = Device(raw, self.base_topic, own_apikey)
        self._devices[deviceid] = device
        self._client_of[deviceid] = client
        return device

    def get(self, deviceid: str) -> Optional[Device]:
        return self._devices.get(deviceid)

    def client_for(self, deviceid: str) -> Optional[Any]:
        return self._client_of.get(deviceid)

    def all(self) -> List[Device]:
        return list(self._devices.values())

    def __len__(self) -> int:
        return len(self._devices)
