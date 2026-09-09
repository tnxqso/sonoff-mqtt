"""MQTT publishing for sonoff-mqtt.

Everything is published retained. That matters more here than it might seem: a
restarted consumer gets the current state from the broker within milliseconds
rather than waiting for the next push from the cloud, which for a device nobody
touches could be hours away.

Retained state from the broker is also strictly better than restoring an item
from disk on the consumer side, because the broker holds what the device last
reported while the consumer's own persistence holds what it last assumed. Those
are the same thing right up until a command is lost, which is the case that
matters.
"""

# 1. Standard library
import logging
from typing import Callable, Optional

# 2. Third-party
import paho.mqtt.client as mqtt

from .config import MqttConfig

_LOGGER = logging.getLogger(__name__)

# Retained on every publish, see the module docstring
RETAIN = True
QOS = 1


class MqttPublisher:
    """Thin wrapper over paho with a last will for service availability."""

    def __init__(self, config: MqttConfig):
        self.config = config
        self.status_topic = f"{config.base_topic}/status"

        self._client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=config.client_id,
        )
        if config.username:
            self._client.username_pw_set(config.username, config.password)

        # If this process dies without saying goodbye the broker publishes this
        # for us, so a consumer can tell a silent service from a quiet house
        self._client.will_set(self.status_topic, "offline", qos=QOS, retain=RETAIN)

        # Set by the observer before start(), called as (deviceid, channel, payload)
        self.on_command: Optional[Callable[[str, str, str], None]] = None

        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            _LOGGER.info("Connected to MQTT at %s:%d", self.config.host, self.config.port)
            client.publish(self.status_topic, "online", qos=QOS, retain=RETAIN)
            # Resubscribe on every connect, not just the first, because a
            # reconnect drops the broker side subscription
            topic = f"{self.config.base_topic}/+/+/set"
            client.subscribe(topic, qos=QOS)
            _LOGGER.info("Subscribed to %s", topic)
        else:
            _LOGGER.error("MQTT connection refused: %s", reason_code)

    def _on_disconnect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code != 0:
            _LOGGER.warning("Unexpected MQTT disconnect: %s", reason_code)

    def _on_message(self, client, userdata, message):
        """Route <base>/<deviceid>/<channel>/set to the command handler.

        Command topics are deliberately NOT retained when published by a
        controller, but nothing stops one arriving retained from elsewhere. The
        handler validates the device and channel, so an unexpected topic is
        logged and dropped rather than acted on.
        """
        parts = message.topic.split("/")
        if len(parts) != 4 or parts[3] != "set":
            _LOGGER.debug("Ignoring unexpected topic %s", message.topic)
            return

        _, deviceid, channel, _ = parts
        payload = message.payload.decode("utf-8", errors="replace")
        _LOGGER.debug("CMD %s %s = %s", deviceid, channel, payload)

        if self.on_command is None:
            _LOGGER.warning("Command received but no handler is set")
            return
        self.on_command(deviceid, channel, payload)

    def start(self) -> None:
        _LOGGER.info("Connecting to MQTT at %s:%d", self.config.host, self.config.port)
        self._client.connect(self.config.host, self.config.port, keepalive=60)
        # paho runs its own network thread, which is fine alongside asyncio as
        # long as publish() is all we call from the event loop
        self._client.loop_start()

    def stop(self) -> None:
        # Say goodbye properly so the last will is not triggered on a clean exit
        self._client.publish(self.status_topic, "offline", qos=QOS, retain=RETAIN)
        self._client.loop_stop()
        self._client.disconnect()
        _LOGGER.info("Disconnected from MQTT")

    def publish(self, topic: str, payload: str) -> None:
        _LOGGER.debug("PUB %s = %s", topic, payload)
        self._client.publish(topic, payload, qos=QOS, retain=RETAIN)
