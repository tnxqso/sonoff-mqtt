# sonoff-lan-relay

A small mDNS relay for eWeLink (Sonoff) devices. Multicast mDNS does not cross routed networks, and the devices ignore mDNS queries that do not come from their own link, so sonoff-mqtt cannot see their LAN announcements from another network. This relay runs on a machine on the devices' own network, watches `_ewelink._tcp` and forwards every record unchanged as one UDP datagram to sonoff-mqtt. It holds no devicekeys and never decrypts: the payload stays encrypted until sonoff-mqtt reads it.

For the full background see the top-level `README.md` of this repository. The datagram format is documented at the top of `src/sonoff_mqtt/lan_relay.py`.

## Files

| File | Installed as |
|------|--------------|
| `mdns_relay.py` | `/opt/sonoff-lan-relay/mdns_relay.py` |
| `requirements.txt` | `/opt/sonoff-lan-relay/requirements.txt` |
| `sonoff-lan-relay.service` | `/etc/systemd/system/sonoff-lan-relay.service` |
| `sonoff-lan-relay.env.example` | `/etc/default/sonoff-lan-relay` (then edited) |

## Requirements

- Tested on a Raspberry Pi with Debian bookworm and Python 3.11.2.
- `python3-venv`, to create the relay's own virtual environment.
- The Pi must be on the same network (link) as the devices.
- The network path from the Pi to the host running sonoff-mqtt must allow UDP to the receiver port (15353 by default), including any firewall in between.
- A firewall on the Pi itself must accept both incoming mDNS (UDP port 5353, multicast to 224.0.0.251) and IGMP. Without mDNS the relay hears no devices at all. Without IGMP it works at first and then goes deaf: routers that act as IGMP querier with IGMP snooping (seen on Asus routers) send periodic membership queries, and if the Pi does not answer them its membership of the mDNS group 224.0.0.251 expires after about 260 s. From then on no IPv4 multicast reaches the Pi. With nftables and an input chain with policy drop, add these rules to that chain:

  ```
  udp dport 5353 accept
  ip protocol igmp accept
  ```

  To accept mDNS only from the devices' network, use `ip saddr <devices-subnet> udp dport 5353 accept` instead of the first rule.
- sonoff-mqtt must have the relay enabled and accept the Pi as a source. In its config, under `lan_relay`: `enabled: true`, `listen_port` equal to the relay's port, and the Pi's address in `allowed_sources` (IPv4 addresses, not host names). With several relays, for example one per site, each has its own entry there. sonoff-mqtt knows a relay only by this address, so each Pi needs a fixed one, for example a DHCP reservation. Use the address the datagrams arrive from as seen by sonoff-mqtt, which differs from the Pi's LAN address if they pass through NAT or a tunnel. See `config/config.example.yml`.

## Installation on a new Pi

All commands run as root on the Pi (for example after `sudo -i`), unless stated otherwise. Placeholders are in angle brackets.

### 1. Get the files onto the Pi

Either clone the repository on the Pi, if git is installed there:

```sh
git clone https://github.com/tnxqso/sonoff-mqtt /root/sonoff-mqtt
SRC=/root/sonoff-mqtt/relay
```

Or copy the `relay/` directory from a machine that has the repository. On that machine:

```sh
scp -r relay <user>@<pi-address>:/tmp/sonoff-lan-relay-src
```

Then on the Pi, as root:

```sh
SRC=/tmp/sonoff-lan-relay-src
```

### 2. Install the relay and its virtual environment

The service runs as an unprivileged dynamic user, so everything under `/opt/sonoff-lan-relay` is owned by root and readable by all.

```sh
apt install python3-venv
install -d -o root -g root -m 0755 /opt/sonoff-lan-relay
install -o root -g root -m 0644 "$SRC/mdns_relay.py" "$SRC/requirements.txt" /opt/sonoff-lan-relay/
python3 -m venv /opt/sonoff-lan-relay/.venv
/opt/sonoff-lan-relay/.venv/bin/pip install -r /opt/sonoff-lan-relay/requirements.txt
chmod -R a+rX /opt/sonoff-lan-relay
```

### 3. Configure

```sh
install -o root -g root -m 0644 "$SRC/sonoff-lan-relay.env.example" /etc/default/sonoff-lan-relay
nano /etc/default/sonoff-lan-relay
```

Set `RELAY_TARGET` to the IPv4 address of the host running sonoff-mqtt, for example `RELAY_TARGET=<sonoff-mqtt-ipv4>`. Change `RELAY_PORT` only if `lan_relay.listen_port` in the sonoff-mqtt config differs from 15353. The unit does not start without this file, and the relay exits at start if `RELAY_TARGET` is empty or not an IPv4 address.

### 4. Install and start the service

```sh
install -o root -g root -m 0644 "$SRC/sonoff-lan-relay.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sonoff-lan-relay
```

### 5. Verify

```sh
systemctl status sonoff-lan-relay
journalctl -u sonoff-lan-relay -b --no-pager
```

A healthy start logs the target and the run id, the IPv4 addresses the relay listens on, then one line per device as it is found and sent:

```
INFO relaying _ewelink._tcp.local. to <sonoff-mqtt-ipv4>:15353, resync every 60 s, run <run-id>
INFO IPv4 addresses: 127.0.0.1, <pi-lan-ipv4>
INFO Added <deviceid> seq=<seq> n=<n>
```

Later state changes show as `INFO Updated <deviceid> seq=<seq> n=<n>`, and a device that leaves as `INFO Removed <deviceid>`. The resends every 60 s are only logged with `--debug`.

Signs of trouble:

- `WARNING sending to <address>:<port> failed: ...`: the path to sonoff-mqtt is down. Only the first failure is logged, then `INFO sending to ... works again` when it recovers.
- `error: argument --target: not an IPv4 address: ''` and the service stopped with status 2 instead of restarting: `RELAY_TARGET` is not set in `/etc/default/sonoff-lan-relay`. Set it, then run `systemctl restart sonoff-lan-relay`.
- No `Added` lines at all: the Pi does not see the devices' mDNS, for example because it is on another network or VLAN.
- `INFO Removed <deviceid>` for every device at once after a normal start, with no warning or error before it: the router has stopped sending multicast to the Pi, usually because a firewall on the Pi drops IGMP (see Requirements). On one site, multicast stopped about 4 minutes after start, when the membership expired, and the `Removed` lines followed roughly 20 minutes after start, because zeroconf keeps records for up to about 1125 s (see Limitations in the top-level `README.md`). To check, with `<iface>` the Pi's interface on the devices' network:

  ```sh
  tcpdump -ni <iface> igmp
  ```

  This is the conclusive check. It must show a membership report from the Pi after each query from the router. A query from the router with no report from the Pi after it means IGMP is blocked on the Pi.

  ```sh
  ip -4 maddr show dev <iface>
  ```

  This only shows the Pi's own kernel membership, which stays even when the router has stopped forwarding. 224.0.0.251 in the list confirms that the relay joined the mDNS group, but does not detect this fault.
- `WARNING no IPv4 address yet, waiting before joining mDNS`: the relay started before the Pi had an IPv4 address other than loopback. It checks every 15 s and logs `INFO IPv4 address found, joining mDNS` when one appears. If it keeps waiting, the Pi's network is not up.
- `WARNING IPv4 addresses changed (<old> -> <new>), exiting so systemd restarts the relay`, then a new start: expected after an address change, see Network addresses below. Repeated after every restart, it points to an interface whose address keeps coming and going.
- `WARNING zeroconf could not start (...), exiting so systemd restarts the relay`: zeroconf found no interface to listen on. systemd starts the relay again after 10 s.
- `WARNING listing the network interfaces failed: ...`: the relay could not read the interface addresses and treats that as none. Logged once, then `INFO listing the network interfaces works again`.

On the sonoff-mqtt side, the log shows the first LAN state received per device.

## Network addresses

zeroconf, the mDNS library the relay uses, reads the Pi's IPv4 addresses only once, when it starts, and joins mDNS on each of them. An address that appears later is never used, so a relay started before the Pi's network was up would stay deaf for good. The relay therefore:

- Waits at start until the Pi has an IPv4 address outside 127.0.0.0/8, checking every 15 s, before it starts zeroconf.
- Then checks the IPv4 addresses on all interfaces every 15 s. On any change it stops and exits with status 75, and systemd starts it again after `RestartSec=10` with the new addresses. Status 75 is never treated as an argument error (status 2), so the unit always restarts it.

The gap is about 10 s plus the time to find the devices again, well inside the 150 s for which sonoff-mqtt treats a device address as fresh, so LAN commands keep working through it. The check covers every interface zeroconf listens on, so an IPv4 change on any of them restarts the relay, also one on a VPN or a container bridge that has nothing to do with the devices.

## Upgrade

Get the newer files onto the Pi as in step 1, then as root:

```sh
sha256sum "$SRC/mdns_relay.py" /opt/sonoff-lan-relay/mdns_relay.py
cmp "$SRC/requirements.txt" /opt/sonoff-lan-relay/requirements.txt \
  && echo "requirements unchanged" || echo "requirements changed"
cmp "$SRC/sonoff-lan-relay.service" /etc/systemd/system/sonoff-lan-relay.service \
  && echo "unit unchanged" || echo "unit changed"
```

Replace the relay, and the requirements only if they changed:

```sh
install -o root -g root -m 0644 "$SRC/mdns_relay.py" /opt/sonoff-lan-relay/
# Only if requirements.txt changed:
install -o root -g root -m 0644 "$SRC/requirements.txt" /opt/sonoff-lan-relay/
/opt/sonoff-lan-relay/.venv/bin/pip install -r /opt/sonoff-lan-relay/requirements.txt
chmod -R a+rX /opt/sonoff-lan-relay
```

If the unit changed, install it again and reload systemd:

```sh
install -o root -g root -m 0644 "$SRC/sonoff-lan-relay.service" /etc/systemd/system/
systemctl daemon-reload
```

Also compare `sonoff-lan-relay.env.example` with `/etc/default/sonoff-lan-relay` for new settings. If `/etc/default/sonoff-lan-relay` does not exist (an older installation with the target on the ExecStart line), create it as in step 3 before restarting, or the service will not start. Then check that the installed files match the repository, restart and verify:

```sh
sha256sum "$SRC/mdns_relay.py" /opt/sonoff-lan-relay/mdns_relay.py
systemctl restart sonoff-lan-relay
journalctl -u sonoff-lan-relay -b --no-pager -n 50
```

Both checksums must be the same. Every start gets a new run id (`run <run-id>` in the first log line). sonoff-mqtt notices the new run, logs `LAN relay <relay-address>: relay restarted (run <run-id>, was <run-id>)`, and takes the records of the new run as they come.

If a NetworkManager dispatcher script or something similar was installed to restart the relay when the network came up, it is no longer needed: the relay now waits for an address and restarts itself when the addresses change. Remove it after the upgrade.

## Resync interval and the receiver

The relay resends every current record every `RELAY_RESYNC` seconds (60 by default, at least 5), so a lost datagram or a restart of sonoff-mqtt heals by itself. sonoff-mqtt treats a device address from the relay as fresh for 150 s (`ENDPOINT_FRESH_SECONDS` in `src/sonoff_mqtt/lan_relay.py`) and only sends LAN commands to a fresh address. 150 s allows two lost resends at the default of 60. A resync interval above about 75 s leaves no room for a lost resend, and one above 150 s makes the addresses go stale between resends, so commands fall back to the cloud. Keep `lan_relay.silence_warning_seconds` in the sonoff-mqtt config at a few times the resync interval.
