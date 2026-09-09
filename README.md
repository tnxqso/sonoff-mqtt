# sonoff-mqtt

A small service that bridges Sonoff/eWeLink cloud devices to MQTT, and verifies
that every command it sends actually took effect.

It is built on the eWeLink cloud client from
[AlexxIT/SonoffLAN](https://github.com/AlexxIT/SonoffLAN), vendored unchanged,
with a multi-account registry, MQTT projection and a verify-and-retry loop on
top.

## Why this exists

The eWeLink cloud acknowledges a command with a receipt and nothing more. It
does not push the resulting state back to the client that sent the command, only
to the other clients. A receipt of `error: 0` therefore means the request was
accepted, not that the relay moved.

Most integrations, including the openHAB binding this replaces, paper over that
with optimistic updates: the item is set to the value that was asked for the
moment the command goes out. When the cloud drops a command, and it does, the
item claims success while the device sits in the opposite state. Nothing
notices. A lamp switched off at 23:00 can burn all night with every log line
saying the command succeeded.

This service reads the state back instead. After each command it waits for the
device to settle, issues a query, compares what came back against what was
asked for, and retries with backoff on a mismatch. When the attempts run out it
publishes to an error topic so something downstream can raise it with a human.

That read-back is the whole point. Everything else here is plumbing.

## What it does

- Connects to one or more eWeLink accounts, one WebSocket session per account
- Enumerates every eWeLink home, not just the active one
- Handles devices shared from another account, commanded from your own session
- Publishes device state to MQTT, retained
- Accepts commands from MQTT and verifies them
- Reconnects with exponential backoff when the cloud drops the connection

## What it does not do

- No local LAN control. Cloud only.
- No device discovery protocol for consumers. Topics are `deviceid` based and
  the mapping to friendly names is left to whatever consumes them.
- Only the device types actually in use here are translated to per-channel
  topics: uiid 1 and 6 (single switch) and uiid 4 (four channel switch).
  Anything else is published as raw state and cannot be commanded.

## Topics

State is published retained, so a consumer that restarts gets the current values
from the broker immediately rather than waiting for the next push from the
cloud, which for an untouched device could be hours away.

| Topic | Payload | Direction |
|---|---|---|
| `sonoff/status` | `online` / `offline` | out, last will |
| `sonoff/<deviceid>/state` | full params as JSON | out |
| `sonoff/<deviceid>/available` | `online` / `offline` | out |
| `sonoff/<deviceid>/switch` | `ON` / `OFF` | out, uiid 1 and 6 |
| `sonoff/<deviceid>/switch0` to `switch3` | `ON` / `OFF` | out, uiid 4 |
| `sonoff/<deviceid>/rssi` | signal strength in dBm | out |
| `sonoff/<deviceid>/<channel>/set` | `ON` / `OFF` | in |
| `sonoff/<deviceid>/<channel>/error` | failure text, empty when fine | out |

Note that outlet numbering on a four channel device is zero based here, matching
the wire protocol, while the eWeLink app numbers the same outlets from one.

## Setup

Requires Python 3.11 or later and an MQTT broker.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config/config.example.yml config/config.yml
```

Edit `config/config.yml`. Passwords may be written literally or as `${ENV_VAR}`
to be read from the environment, which is the better option when running as a
service.

Run it:

```bash
PYTHONPATH=src python -m sonoff_mqtt --config config/config.yml
```

`run.sh` is a launcher that sources the password from
`~/.config/sonoff-mqtt/env` and is what a process manager should call.

## Devices in another eWeLink home

A plain device listing returns only the home that is currently active in the
phone app. Devices in any other home stay invisible. This service asks for every
family explicitly, so that trap does not apply here, but it is worth knowing
about when comparing against other tools.

## Devices shared from another account

A device shared to your account can be commanded from your own session. The
payload has to carry the owner's `apikey` alongside your own `selfApikey`, which
is what the vendored client does. Sending only the owner's apikey fails, which
is a trap worth naming because it looks like evidence that a session
authenticated as the owner is required. It is not.

In practice that means one account is enough, provided every device is shared to
it. The multi-account support is there for cases where that is not possible.

## Running alongside another client

The cloud evicts an older session when a newer one logs in with the same appid
for the same account, so two clients sharing credentials will fight. Give this
service a different `appid` and `appsecret` pair while migrating.

There is an upside during a migration: because the cloud pushes state to every
client except the one that caused the change, each client is a reliable observer
of the other.

## Credits

The eWeLink cloud client under `src/sonoff_mqtt/vendor/ewelink/` is taken
verbatim from [AlexxIT/SonoffLAN](https://github.com/AlexxIT/SonoffLAN) (MIT).
It is deliberately unmodified so upstream fixes can be pulled in with a diff
when eWeLink changes something server side, which happens without notice. See
`VENDORED.md` in that directory for what it provides and how this code attaches
to it.

## Licence

MIT. See `LICENSE`.
