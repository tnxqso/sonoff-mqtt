# sonoff-mqtt

A small service that bridges Sonoff/eWeLink cloud devices to MQTT, and verifies that every command it sends actually took effect.

It is built on the eWeLink cloud client from [AlexxIT/SonoffLAN](https://github.com/AlexxIT/SonoffLAN), vendored unchanged, with a multi-account registry, MQTT projection and a verify-and-retry loop on top.

## Why this exists

The eWeLink cloud acknowledges a command with a receipt and nothing more. It does not push the resulting state back to the client that sent the command, only to the other clients. A receipt of `error: 0` therefore means the request was accepted, not that the relay moved.

Most integrations, including the openHAB binding this replaces, paper over that with optimistic updates: the item is set to the value that was asked for the moment the command goes out. When the cloud drops a command, and it does, the item claims success while the device sits in the opposite state. Nothing notices. A lamp switched off at 23:00 can burn all night with every log line saying the command succeeded.

This service reads the state back instead. After each command it waits for the device to settle, issues a query, compares what came back against what was asked for, and retries with backoff on a mismatch. When the attempts run out it publishes to an error topic so something downstream can raise it with a human.

That read-back is the whole point. Everything else here is plumbing.

## What it does

- Connects to one or more eWeLink accounts, one WebSocket session per account
- Enumerates every eWeLink home, not just the active one
- Handles devices shared from another account, commanded from your own session
- Publishes device state to MQTT, retained
- Accepts commands from MQTT and verifies them
- Reconnects with exponential backoff when the cloud drops the connection

## What it does not do

- No LAN control unless asked for. Commands go through the cloud, except for devices listed in `lan_relay.command_devices`. Device state can optionally also be received over the LAN. Both are described below.
- No device discovery protocol for consumers. Topics are `deviceid` based and the mapping to friendly names is left to whatever consumes them.
- Only the device types actually in use here are translated to per-channel topics: uiid 1 and 6 (single switch) and uiid 4 (four channel switch). Anything else is published as raw state and cannot be commanded.

## Topics

State is published retained, so a consumer that restarts gets the current values from the broker immediately rather than waiting for the next push from the cloud, which for an untouched device could be hours away.

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

Note that outlet numbering on a four channel device is zero based here, matching the wire protocol, while the eWeLink app numbers the same outlets from one.

## The mDNS relay

eWeLink devices announce their state over mDNS (`_ewelink._tcp`), encrypted with the device's devicekey. Multicast mDNS does not cross routed networks, so when the devices sit on another network these announcements never reach this service. Asking from the other network does not help either: per RFC 6762 section 11 the devices ignore mDNS queries whose source is not on their own link.

The relay in `relay/` closes that gap. It runs on a machine on the devices' own network, watches `_ewelink._tcp` and forwards every record unchanged as one UDP datagram to this service. It also resends every current record at a fixed interval, 60 s by default, so a lost datagram or a restart of this service heals by itself. The relay holds no devicekeys and never decrypts: the payload is still encrypted when it crosses the network, and this service decrypts it with the keys it already has from the cloud device listing.

There can be one relay or several, for example one per site. Nothing in a datagram names its relay or site, so this service knows a relay only by the source address its datagrams arrive from. Each relay therefore needs a fixed address, for example a DHCP reservation, listed in `lan_relay.allowed_sources`.

This service takes two things from the relay records:

- Device state, described under LAN state below.
- The device's address and port, used to send LAN commands to the devices listed in `lan_relay.command_devices`, described under LAN commands below.

Installation and upgrade of the relay are described in [relay/README.md](relay/README.md). The datagram format is documented at the top of [src/sonoff_mqtt/lan_relay.py](src/sonoff_mqtt/lan_relay.py).

### LAN state

This service merges the switch state from the relay records into the same topics as the cloud state, so a change seen by both the cloud and the LAN is published once. Only switch state is taken from the LAN.

This is optional and off by default, see `lan_relay` in `config/config.example.yml`.

### Receiver settings

The receiver is configured under `lan_relay` in `config/config.example.yml`:

- `enabled`: off by default. When on, `allowed_sources` must not be empty.
- `listen_port`: the UDP port the receiver listens on, IPv4 only, 15353 by default. It must match each relay's `RELAY_PORT`.
- `allowed_sources`: one IPv4 address per relay, not host names. Datagrams from any other address are dropped, and an IPv6 entry is refused at startup, as the receiver listens on IPv4 only. Use the address the datagrams arrive from as seen by this service, which differs from the relay's LAN address if they pass through NAT or a tunnel. A duplicate entry counts as one relay.
- `silence_warning_seconds`: log a warning when nothing has arrived from a relay for this long, 180 by default and at least 10. It applies to each relay on its own, including a relay not heard from at all since startup. Keep it at a few times the relays' resync interval.
- `command_devices`: the devices commanded over the LAN first, empty by default. Needs `enabled`. Quote a deviceid that is all digits, or YAML reads it as a number.

### Several relays

Every log line about a datagram names its relay first, for example:

```
LAN relay <relay-address>: first datagram since start (run <run-id>, n=<n>)
LAN relay <relay-address>: relay restarted (run <run-id>, was <run-id>)
LAN relay <relay-address>: 2 datagram(s) lost (run <run-id>, n=<n> after <n>)
LAN relay <relay-address>: nothing received for 190s, LAN state from this relay is going stale
LAN relay <relay-address>: nothing received since start 190s ago
LAN relay <relay-address>: receiving again after 250s
```

Run ids, lost datagrams and silence are tracked per relay, so switching between relays is not taken for a restart. The silence warning is logged once per silent spell of a relay, and the recovery line when that relay is heard again.

Each device has one owner: the relay whose latest record for it was accepted and decrypted. While the owner's latest record for the device is fresh (see below), records for it from any other relay are ignored, with one warning per device and relay:

```
LAN relay <other-address>: Updated <deviceid> ignored, owned by <owner-address> (last record 20s ago)
```

Once the owner's record is older than that, the next decrypted record from another relay takes the device over, logged as `LAN relay <new-address>: <deviceid> now owned by this relay, <old-address> silent for 151s`. A restart of the owning relay is not a change of owner. A `Removed` counts only from the owner, and frees the device for any relay; a `Removed` from another relay changes nothing. So a device that two relays can both see is used through one of them, without its state or address flapping between the two.

### How fresh a device address is

A LAN command is only sent to an address from a record of the device's owner received within the last 150 s (`ENDPOINT_FRESH_SECONDS` in `src/sonoff_mqtt/lan_relay.py`). Every accepted record refreshes it, including a Resync with an unchanged seq, so the address follows a device that has changed address. A record is only accepted once its payload decrypts with the device's devicekey, and only an IPv4 address is used. Loopback, multicast, link-local, the limited broadcast address 255.255.255.255, 0.0.0.0/8 and other reserved addresses are skipped. A directed broadcast address such as x.y.z.255 cannot be recognised, because the record carries no prefix length, so it is used like any other address. The value assumes the relays' default resync of 60 s and allows two lost resends; with a longer resync the addresses can go stale between resends, see [relay/README.md](relay/README.md).

Fresh measures only that the relay keeps resending the record, not that the device is reachable. The relay resends from its own cache, so a device that has lost power or wifi keeps a fresh address for as long as the relay holds its record, which can be about 19 minutes (see Limitations). A LAN command to such a device fails or gets no answer within 2 s, and falls back to the cloud.

### LAN commands

Devices listed in `lan_relay.command_devices` are commanded over the LAN first. The command goes straight to the device's own HTTP server, at the address and port in the latest record from its owning relay, encrypted with its devicekey the same way the SonoffLAN integration does it. The relay only carries the result: the command counts as confirmed when a record with a new seq shows the commanded state. In testing that took about 50 ms, against two to three seconds through the cloud. Firmware 3.7.6 counts seq up even for a command that changes nothing, so that is confirmed as well.

Anything short of that falls back to the cloud path with its full read-back, so the error topic means the same either way: no relay record for the device in the last 150 s, a request the device rejected or did not answer within 2 s, or no confirmation within 3 s. Resending through the cloud after an unconfirmed LAN command is safe because commands are `ON` or `OFF`, never a toggle.

Listed devices can also be commanded while the internet connection is down, but only when the path from this service to the devices, and the relay's path back to this service, do not depend on the internet. When the devices' network is reached through a tunnel over the internet, an internet outage takes the LAN path down as well as the cloud, and commands end on the error topic like any other command that cannot be confirmed. The devicekeys come from the cloud device listing at startup, so this also only applies to a service that started while the cloud was reachable.

The list is explicit per device and empty by default. Only a device whose devicekey is in the cloud device listing can be commanded this way; which of the listed devices are usable is logged at startup as `LAN commands enabled for: ...`.

## Setup

Requires Python 3.11 or later, Linux, and an MQTT broker.

```bash
git clone https://github.com/tnxqso/sonoff-mqtt.git
cd sonoff-mqtt
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config/config.example.yml config/config.yml
```

Edit `config/config.yml`. Passwords may be written literally or as `${ENV_VAR}` to be read from the environment, which is the better option when running as a service.

The eWeLink login is the same email and password used in the phone app. There is no separate API credential. The `appid` and `appsecret` identify the client program rather than you, and do not need rotating.

Check the configuration before starting anything:

```bash
PYTHONPATH=src .venv/bin/python -m sonoff_mqtt --dump-config
```

Then run it in the foreground once to confirm it finds your devices:

```bash
PYTHONPATH=src .venv/bin/python -m sonoff_mqtt --config config/config.yml
```

## Running it as a service

`run.sh` is the launcher. It sources the password from a file outside the project directory, sets `PYTHONPATH`, and uses the virtualenv interpreter:

```bash
mkdir -p ~/.config/sonoff-mqtt
echo 'SONOFF_PRIMARY_PASSWORD=your-password' > ~/.config/sonoff-mqtt/env
chmod 700 ~/.config/sonoff-mqtt
chmod 600 ~/.config/sonoff-mqtt/env
```

Keeping the password out of the project directory means it cannot be committed by accident or copied along when the source is moved to another machine.

### With pm2

pm2 is what this is developed and run against, so the instructions are concrete. systemd with an `EnvironmentFile` works equally well if you prefer it. Neither is something this project supports: if pm2 will not start, that is a pm2 question.

```bash
pm2 start ./run.sh --name sonoff-mqtt
pm2 logs sonoff-mqtt --lines 30 --nostream
```

Once it looks right, make it survive a reboot. Both steps are needed and the second is easy to forget:

```bash
pm2 save
pm2 startup        # prints a command to run with sudo, run it
```

pm2 does **not** rotate logs by default, so the file grows without bound. Install the rotation module:

```bash
pm2 install pm2-logrotate
pm2 set pm2-logrotate:max_size 10M
pm2 set pm2-logrotate:retain 7
pm2 set pm2-logrotate:compress true
pm2 set pm2-logrotate:rotateInterval '0 0 * * *'
```

Those settings apply to every pm2 process on the host, not just this one.

A few things worth knowing:

- `pm2 restart sonoff-mqtt` is safer than `pm2 restart <id>`. Id numbers shift when processes are added or removed, the name does not.
- pm2 reuses the environment from when the process was first started. `run.sh` reads the password file on every start so that does not matter here, but if a change to the environment is not picked up, `pm2 restart sonoff-mqtt --update-env` forces it.
- After editing the source, restart. A running process keeps the old code, which can produce some confusing debugging.

## Logs

Python logs to stderr, so under pm2 everything lands in the error log even though most of it is informational:

```bash
tail -f ~/.pm2/logs/sonoff-mqtt-error.log
```

`sonoff-mqtt-out.log` stays empty. That is expected.

The first line of every run is the version, so a log excerpt answers "which version are you running" without anyone having to ask.

## Debugging

### Which version

```bash
PYTHONPATH=src .venv/bin/python -m sonoff_mqtt --version
```

### What configuration is actually in effect

```bash
PYTHONPATH=src .venv/bin/python -m sonoff_mqtt --dump-config
```

Passwords and the app secret are redacted, so the output is safe to paste into an issue. It prints values you did not set as well, because "I left it at the default" and "I set it to the same as the default" are different things when something breaks.

It also works when an environment variable is missing, which is exactly when it is most useful: the line will say which variable is not set rather than refusing to print anything.

### What is on the bus

```bash
mosquitto_sub -h your-broker -t 'sonoff/#' -v
```

Command a device directly, bypassing whatever normally drives it:

```bash
mosquitto_pub -h your-broker -t 'sonoff/10020db9d1/switch/set' -m 'ON'
```

Clear a stale error topic:

```bash
mosquitto_pub -h your-broker -t 'sonoff/10020db9d1/switch/error' -r -n
```

### What a healthy command looks like

Through the cloud:

```text
Webbkamera switch -> OFF
Webbkamera switch: confirmed
```

Over the LAN, for a device in `lan_relay.command_devices`:

```text
Webbkamera switch -> OFF (LAN)
Webbkamera switch is OFF (LAN state, seq 8427)
Webbkamera switch: confirmed via LAN in 49 ms
```

The middle line is the relay reporting the new state, and it is absent when the command changed nothing. When the LAN path gives up, one of these lines comes first and the cloud lines above follow:

```text
Webbkamera switch: no fresh relay record for the address, using the cloud
Webbkamera switch: LAN command not accepted (timeout), falling back to the cloud
Webbkamera switch: not confirmed via LAN within 3.0s, falling back to the cloud
```

If `confirmed` is replaced by a line saying the state did not change, the cloud accepted the command and the device did not obey. That is the case this service exists to surface, and the one that previously went unnoticed.

### When a device does not respond

- Check `sonoff/<deviceid>/available`. Offline means it has no power or has lost wifi, and no amount of retrying will help.
- Check `sonoff/<deviceid>/rssi`. Below roughly -80 dBm, dropped packets become common.
- Check that the service itself is up and the cloud connection established.

### Turning up the detail

Set `logging.level` to `DEBUG` in the config for this service's own reasoning, or `logging.ewelink_level` to `DEBUG` to see every frame on the wire. The second is very verbose and is best turned on for a specific test rather than left on.

### Two instances

Running two copies against the same account is worth avoiding. They log in with the same credentials and the cloud evicts the older session whenever a newer one appears, so they take turns kicking each other out indefinitely while device control works sporadically. If they also share an MQTT `client_id`, the broker disconnects them in a loop as well, roughly once a second, which is at least obvious in the log.

The service takes a lock on startup and refuses to run if another instance holds it, but that only covers the same host. Two instances on different machines can only be detected through the cloud, and the symptom there is repeated reconnects. After several disconnects in one run the log says so explicitly.

If you need another client against the same account, for example while migrating away from something else, give it a different `appid` and `appsecret` pair.

## Using it with openHAB

Devices appear as ordinary MQTT things. Payloads are plain `ON` and `OFF`, so no transformation is needed.

### Things

```java
Thing mqtt:topic:Sonoff_Webcam "Sonoff S26R2: Webcam" (mqtt:broker:MyBroker) {
Channels:
    Type switch : SwitchBinary "Switch" [ stateTopic="sonoff/10020db9d1/switch", commandTopic="sonoff/10020db9d1/switch/set" ]
    Type string : CommandError "Command error" [ stateTopic="sonoff/10020db9d1/switch/error" ]
    Type number : Rssi "RSSI" [ stateTopic="sonoff/10020db9d1/rssi" ]
}
```

A four channel device gets one channel per outlet:

```java
Thing mqtt:topic:Sonoff_FourChPro "Sonoff 4CHPROR3" (mqtt:broker:MyBroker) {
Channels:
    Type switch : SwitchBinary0 "Outlet 0" [ stateTopic="sonoff/1001d504c3/switch0", commandTopic="sonoff/1001d504c3/switch0/set" ]
    Type string : CommandError0 "Command error outlet 0" [ stateTopic="sonoff/1001d504c3/switch0/error" ]
    Type switch : SwitchBinary1 "Outlet 1" [ stateTopic="sonoff/1001d504c3/switch1", commandTopic="sonoff/1001d504c3/switch1/set" ]
    Type string : CommandError1 "Command error outlet 1" [ stateTopic="sonoff/1001d504c3/switch1/error" ]
    Type number : Rssi "RSSI" [ stateTopic="sonoff/1001d504c3/rssi" ]
}
```

A channel id must not be just `Switch`. It is a reserved word in the things DSL and produces a parser error that does not obviously point at the cause. Use `SwitchBinary` or anything else.

### Items

```java
Switch WebcamOutlet "Webcam [%s]" <poweroutlet> { channel="mqtt:topic:Sonoff_Webcam:SwitchBinary" }

String WebcamError "Webcam command error [%s]" <error> { channel="mqtt:topic:Sonoff_Webcam:CommandError" }
```

### Do not persist these items

Restoring an item from disk on startup gives what openHAB last assumed, while retained MQTT gives what the device last reported. Those are the same thing right up until a command is lost, which is the case that matters. Leave persistence off for anything driven through here and let the broker be the source of truth.

Items with no MQTT channel, such as a virtual switch driven by a rule, still need persistence as usual.

### Rules

Rules that compare an item's current state before deciding whether to send a command can now trust that state, which was not true before. When the item says off, the device reported off.

Subscribing to the error topics gives you somewhere to notify from. A rule that watches a group of error items and sends a push notification when one becomes non-empty turns a silent failure into something you hear about the same evening.

## Migrating from the openHAB Sonoff binding

The device ids are the same, so the mapping is mechanical:

| Binding | Here |
|---|---|
| `sonoff:1:account:thingid:switch` | `sonoff/<deviceid>/switch` |
| `sonoff:4:account:thingid:switch0` | `sonoff/<deviceid>/switch0` |
| One bridge per account | One account entry in the config |
| A second bridge for shared devices | Not needed, see below |

Stop the binding before starting this service, or both will drive the same devices and evict each other's cloud session.

Take persistence off the items at the same time, per the section above.

## Devices in another eWeLink home

A plain device listing returns only the home that is currently active in the phone app. Devices in any other home stay invisible. This service asks for every family explicitly, so that trap does not apply here, but it is worth knowing about when comparing against other tools.

## Devices shared from another account

A device shared to your account can be commanded from your own session. The payload has to carry the owner's `apikey` alongside your own `selfApikey`, which is what the vendored client does. Sending only the owner's apikey fails, which is a trap worth naming because it looks like evidence that a session authenticated as the owner is required. It is not.

In practice that means one account is enough, provided every device is shared to it, and you never need to hold anyone else's password. The multi-account support is there for cases where sharing is not possible.

## Limitations

These are known and accepted:

- A cloud command whose receipt is `timeout` may still be carried out later, with no known upper bound. The local timeout (`CLOUD_SEND_TIMEOUT_SECONDS`) only stops the waiting; the request has already gone out and is not recalled.
- When a newer command checks the final state after an older send overlapped it and the cloud state cannot be read, the state from the relay is used instead. If a later relay datagram was lost, that state can report an agreement that is false.
- The devices' LAN network is treated as trusted. A record must be encrypted when the device has a devicekey, but the payload is AES-CBC without a MAC, so a replay of an old ciphertext with a new seq is possible.
- After a relay restart, a delayed datagram from the previous relay run counts as a new run, because late datagrams are only recognised within the same run, and it can be applied. The next resync corrects it.
- In the relay, two resolves for the same device that overlap (for example Added then Updated) can finish out of order, and the one that finishes last is the record that is sent and resent. The order of their results has not been verified against zeroconf's cache behaviour; a later announcement of the device corrects it.
- The device address and port travel in plaintext next to the encrypted payload. A record is only used once its payload decrypts, but that does not authenticate the address: whoever can send datagrams from a relay's address can point LAN commands at another address. Network rules must restrict where this service can connect to.
- The relay's zeroconf library raises any PTR TTL below 1125 s to 1125 s, so a device that loses power can stay in a relay's cache, and keep a fresh address here, for up to about 19 minutes. LAN commands to it fail or time out and fall back to the cloud. For the same reason another relay can take such a device over only once its old relay has dropped it.

## Running the tests

The offline tests need no eWeLink account, no broker, no relay and no device. Run them from the repository root with the project's virtual environment:

```bash
PYTHONPATH=src .venv/bin/python -m unittest tests/test_lan_relay.py tests/test_lan_command.py tests/test_mdns_relay.py
```

- `tests/test_lan_relay.py`: the relay receiver and its merge into device state.
- `tests/test_lan_command.py`: LAN commands, from the sender to confirmation, cloud fallback and overlapping commands.
- `tests/test_mdns_relay.py`: the relay itself, `relay/mdns_relay.py`, including a contract test against the receiver over localhost.

zeroconf is not needed to run the tests and is not in the project's `requirements.txt`: `tests/test_mdns_relay.py` replaces the zeroconf modules the relay imports with stubs before loading it.

`tests/test_shared_device.py` is not part of this set. It is a live probe against a real eWeLink account, run directly with Python, and is described at the top of the file.

## Credits

The eWeLink cloud client under `src/sonoff_mqtt/vendor/ewelink/` is taken verbatim from [AlexxIT/SonoffLAN](https://github.com/AlexxIT/SonoffLAN) (MIT). It is deliberately unmodified so upstream fixes can be pulled in with a diff when eWeLink changes something server side, which happens without notice. See `VENDORED.md` in that directory for what it provides and how this code attaches to it.

## Licence

MIT. See `LICENSE`.
