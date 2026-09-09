# Vendored from AlexxIT/SonoffLAN

Source:  https://github.com/AlexxIT/SonoffLAN
Path:    custom_components/sonoff/core/ewelink/
Commit:  d9ad28c882988ef47b6a8514d18bc0caa51efa0b
Date:    Wed Sep 2 17:05:18 2026 +0300
Licence: MIT, (c) 2020 AlexxIT (see LICENSE.md in this directory)

Files taken verbatim: base.py, cloud.py

## Do not edit these files

They import nothing from Home Assistant, only asyncio, aiohttp and the standard
library, so they work unchanged as a standalone eWeLink cloud client. Keeping
them byte-identical to upstream is the whole point: eWeLink changes its cloud
server side without notice, and when that happens the fix normally lands here
first. An unmodified copy can be diffed and updated in minutes. A modified one
cannot.

Anything we need on top belongs in the parent package, not in this directory.

## What these files give us

- HTTP login with HMAC-SHA256 body signing, and the region 10004 bounce
- The per-region host table, including the cn datacentre which uses the .cn TLD
  rather than .cc (the openHAB binding got this wrong and could never reach a
  China-region account)
- WebSocket dispatch, connect, the userOnline handshake, and a keepalive that
  honours the hbInterval the server asks for
- Reconnect with exponential backoff, 15s doubling up to 64 minutes
- Command send with the receipt error actually decoded, 0 online, 503 offline,
  504 timeout
- The {"action":"query"} frame, which is how a device's real state is read back
  after a command. This is the piece that makes verification possible and it
  exists nowhere in the openHAB binding
- Multi-home enumeration, GET /v2/family then GET /v2/device/thing?familyid=
- A monotonic, collision-free sequence generator

## What they do NOT give us, and we have to write

- Verify and retry. Upstream sends a query after a command purely to refresh
  its own state, it never compares the result against what was asked for and
  never resends. That loop is ours.
- Multi-account routing. Each XRegistryCloud instance is fully independent,
  which is exactly what we want, but the {deviceid: client} table and the
  routing on top of it is ours.
- Everything MQTT.

## How to attach our code

The two hook points are the dispatcher signals in base.py, dispatcher_connect
and dispatcher_send. Upstream's Home Assistant layer subscribes to those to
update entities. We subscribe to the same signals and publish to MQTT instead.
No change to the vendored files is needed for that.

## Updating

    cd /home/mikel/dev/SonoffLAN && git pull
    diff -u src/sonoff_mqtt/vendor/ewelink/cloud.py \
            /home/mikel/dev/SonoffLAN/custom_components/sonoff/core/ewelink/cloud.py
    diff -u src/sonoff_mqtt/vendor/ewelink/base.py \
            /home/mikel/dev/SonoffLAN/custom_components/sonoff/core/ewelink/base.py

Copy the new versions in, update the commit and date above, and re-run the
integration tests. Pay particular attention to changes in send(), the payload
field set, and anything touching apikey or selfApikey.

## Open question this code may answer

Our own testing against the openHAB binding concluded that commanding a device
shared from another account requires a WebSocket session authenticated AS THE
OWNER. This code disagrees: it sends the owner's apikey together with our own
selfApikey over our own session, and has done so in production for years.

The binding never sent selfApikey at all, so our test may simply have been
sending the wrong fields rather than proving a session requirement. This is
worth testing before the architecture is settled, because if upstream is right
the two-account setup may not be needed.
