"""Prevent two instances running against the same account.

Two clients logging in with the same appid for the same eWeLink account evict
each other: the cloud drops the older session when a newer one appears. Two
instances therefore do not merely duplicate work, they fight. A logs in, B is
kicked, B reconnects after its backoff, A is kicked, and so on indefinitely,
while device control works sporadically or not at all.

That failure is also hard to recognise. The log fills with reconnects and error
406, which reads as a cloud problem rather than as two processes started by
mistake.

The lock is an abstract unix domain socket, which the kernel releases when the
process ends however it ends. A pid file would have to be cleaned up, and a
stale one left by a crash blocks a legitimate start, which is a worse failure
than the one being prevented.

This only covers a second instance on the SAME machine, which is the common
mistake: running by hand to test something while the service is already up.
Two instances on different hosts can only be detected through the cloud, and
the only symptom there is error 406.
"""

# 1. Standard library
import socket
import sys
from typing import Optional


class AlreadyRunning(Exception):
    """Raised when another instance holds the lock."""


class SingleInstance:
    """Hold an abstract socket for as long as this process runs.

    Abstract sockets live in a namespace with no filesystem presence, indicated
    by the leading null byte, and are Linux specific. On any other platform this
    degrades to no locking rather than to a broken one.
    """

    def __init__(self, name: str):
        # Namespaced by the base topic so two instances bridging different
        # brokers or different topic trees can coexist
        self.address = "\0sonoff-mqtt-" + name
        self._socket: Optional[socket.socket] = None

    def acquire(self) -> None:
        if not sys.platform.startswith("linux"):
            # Abstract sockets do not exist elsewhere. Rather than reach for a
            # pid file and its stale-lock problems, accept that the check is
            # unavailable.
            return

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            sock.bind(self.address)
        except OSError:
            sock.close()
            raise AlreadyRunning(
                "Another sonoff-mqtt instance is already running on this host. "
                "Two instances log in with the same credentials and the cloud "
                "evicts one when the other appears, so they would fight over the "
                "connection. Stop the other one first, for example with "
                "'pm2 stop sonoff-mqtt'."
            )
        self._socket = sock

    def release(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def __enter__(self) -> "SingleInstance":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()
