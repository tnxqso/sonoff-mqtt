"""Probe whether a shared device can be commanded from the sharee's own session.

Our earlier testing against the openHAB binding concluded that a device shared
from another account can only be commanded over a WebSocket authenticated AS
THE OWNER. That conclusion may be wrong: the binding always sent its own apikey
and never sent selfApikey at all, so the test may have proved nothing more than
that the wrong fields fail.

AlexxIT/SonoffLAN sends the owner's apikey together with our own selfApikey over
our own session, and has done so in production for years. This script settles
which is right, because the answer decides whether sonoff-mqtt needs one session
per owning account or can drive everything from a single one.

The test device is a lamp at the other site, shared to our account and placed in
a home that is not our active one, so this also exercises multi-home discovery.

Usage:
    export SONOFF_SHAREE_PASSWORD='...'
    python tests/test_shared_device.py
"""

# 1. Standard library
import asyncio
import logging
import sys
from pathlib import Path

# 2. Third-party
import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# 3. Project-local
from sonoff_mqtt.config import load_config
from sonoff_mqtt.vendor.ewelink.cloud import XRegistryCloud

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.yml"

# A patio lamp at the other site, shared to our account. S26R2, uiid 1.
TARGET_DEVICEID = "CHANGE_ME"

# Which configured account to log in as. This is the SHAREE, the account the
# lamp was shared to, which is the whole point of the test.
ACCOUNT_NAME = "mikel"

log = logging.getLogger("probe")


async def main() -> None:
    config = load_config(CONFIG_PATH)

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    # The vendored client logs every frame at DEBUG, which is exactly what we
    # want here even if it is too much for normal running
    logging.getLogger("sonoff_mqtt.vendor.ewelink.cloud").setLevel(logging.DEBUG)

    account = next((a for a in config.accounts if a.name == ACCOUNT_NAME), None)
    if account is None:
        log.error(
            "No account named %r in the config. Configured: %s",
            ACCOUNT_NAME,
            [a.name for a in config.accounts],
        )
        return

    async with aiohttp.ClientSession() as session:
        cloud = XRegistryCloud(session)

        log.info("Logging in as %s (%s)", account.name, account.email)
        if not await cloud.login(account.email, account.password, account.country_code):
            log.error("Login failed")
            return

        own_apikey = cloud.auth["user"]["apikey"]
        log.info("Logged in. Region %s, our apikey %s", cloud.region, own_apikey)

        # The lamp lives in a home that is not our active one. A plain device
        # listing only returns the active home, so every family has to be asked
        # for explicitly. This is the multi-home handling the openHAB binding
        # lacks entirely.
        homes = await cloud.get_homes()
        log.info("Homes visible to this account: %s", homes)
        if not homes:
            log.error("No homes returned, cannot continue")
            return

        devices = await cloud.get_devices(list(homes.keys()))
        log.info("Found %d device(s) across %d home(s)", len(devices), len(homes))
        for device in devices:
            owner = device.get("apikey")
            log.info(
                "  %s  %-28s owner=%s%s",
                device.get("deviceid"),
                device.get("name"),
                owner,
                "  (shared to us)" if owner != own_apikey else "",
            )

        target = next((d for d in devices if d.get("deviceid") == TARGET_DEVICEID), None)
        if target is None:
            log.error("Device %s not found in any home", TARGET_DEVICEID)
            return

        is_shared = target.get("apikey") != own_apikey
        log.info("=" * 70)
        log.info("Target      : %s (%s)", target.get("name"), TARGET_DEVICEID)
        log.info("Owner apikey: %s", target.get("apikey"))
        log.info("Our apikey  : %s", own_apikey)
        log.info("Shared      : %s", "yes" if is_shared else "NO, we own this device")
        log.info("State now   : %s", target.get("params", {}).get("switch"))
        log.info("Online      : %s", target.get("online"))
        log.info("Model       : %s  uiid=%s", target.get("productModel"),
                 target.get("extra", {}).get("uiid"))
        log.info("=" * 70)

        if not is_shared:
            log.warning(
                "This device is owned by the account we logged in as, so the test "
                "proves nothing about shared devices. Check that it really was "
                "shared and not transferred."
            )

        if not target.get("online"):
            log.warning(
                "Device reports offline. Any timeout below says nothing about "
                "the shared-device question, it only means the lamp is not "
                "reachable. Ask whether it has power before reading anything "
                "into the result."
            )

        # connect() only opens the socket and does the handshake. Nothing reads
        # from it until run_forever() is running, and run_forever() is the only
        # thing that calls _process_ws_msg, which is in turn the only thing that
        # resolves the futures send() waits on. Calling connect() alone leaves
        # every reply sitting unread in the socket and every send() timing out
        # after exactly its timeout, which looks convincingly like the cloud
        # refusing the command.
        #
        # start() would also log in, but self.auth is already set from the login
        # above, so run_forever skips that and goes straight to connect().
        log.info("Starting the cloud client")
        connected = asyncio.Event()
        cloud.dispatcher_connect("connected", lambda: connected.set())
        cloud.dispatcher_connect(
            "update", lambda data: log.info("PUSH: %s", data)
        )
        cloud.start()

        try:
            await asyncio.wait_for(connected.wait(), timeout=30)
        except asyncio.TimeoutError:
            log.error("Cloud client did not come online within 30s")
            return
        log.info("Cloud client online: %s", cloud.online)

        # Let the handshake settle before commanding
        await asyncio.sleep(2)

        try:
            for wanted in ("on", "off", "on"):
                log.info("--- send switch=%s ---", wanted)
                receipt = await cloud.send(target, {"switch": wanted}, timeout=10)
                log.info("Receipt: %r  (expecting 'online')", receipt)

                if receipt != "online":
                    log.warning("Not accepted. Receipt %r", receipt)

                # Read the real state back. This query frame is the mechanism
                # sonoff-mqtt will use to verify a command actually took effect,
                # so confirming it works here matters as much as the command.
                await asyncio.sleep(2)
                query = await cloud.send(target, timeout=10)
                log.info("Query returned: %r", query)

                await asyncio.sleep(3)
        finally:
            await cloud.stop()

        log.info("")
        log.info("Done. Two things decide the outcome:")
        log.info("  1. did every receipt come back 'online'")
        log.info("  2. did the lamp physically move (ask the owner, or watch the app)")


if __name__ == "__main__":
    asyncio.run(main())
