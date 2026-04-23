# burrow

A WireGuard userspace gateway. Two directions of traffic, plus a few extras:

- **Forward** (peer → burrow's LAN): peers reach internal services on
  burrow's local network. burrow MASQUERADEs as the source — internal hosts
  see burrow's LAN IP, not the peer.
- **Reverse** (anything → client): a client (peer running `burrow-client`)
  asks the burrow host to bind a real OS listener on burrow's interface;
  connections to that listener get tunneled back to the client and
  originated from the client's machine. SSH `-R` semantics.
- DNS resolver on `(wg_ip, 53/udp)`, using burrow's host resolver.
- Remote shell on the burrow host (interactive PTY, one-shot, fire-and-forget).
- Config generator for the whole three-party setup in one shot.

- No TUN interface. No Wintun, no `wireguard-nt`, no `/dev/net/tun`.
- No kernel drivers.
- No admin/root required (raw sockets for ICMP are optional; burrow falls back
  to userspace ICMP responses when unprivileged).
- No OS network configuration. No routing tables, no firewall rules on the
  gateway host.
- Cross-platform. Tested on Windows; should run anywhere tokio plus smoltcp do.

Built on [boringtun](https://github.com/cloudflare/boringtun) (noise protocol
only) and [smoltcp](https://github.com/smoltcp-rs/smoltcp) (userspace TCP/IP).

## Table of Contents

- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [Install](#install)
- [Commands](#commands)
- [Examples](#examples)
- [Deploy: single self-contained binary](#deploy-single-self-contained-binary)
- [Remote deploy helpers](#remote-deploy-helpers)
- [Logging](#logging)
- [How it works](#how-it-works)
- [Limitations](#limitations)
- [Development](#development)
- [License](#license)

## What it does

You have a host inside a private network. You want external WireGuard peers to
reach internal resources through it. The standard answer on Linux is

```
wireguard-tools + iptables -j MASQUERADE + net.ipv4.ip_forward=1
```

That requires Linux, root, kernel modules, and OS-level configuration. burrow
does the same thing as a single unprivileged userspace process, plus reverse
tunnels, DNS, and a remote shell on the same control channel.

### Forward direction (the NAT gateway)

```
[peer]
   | WireGuard
   v
[WG server]          standard wg, publicly reachable
   | routes via AllowedIPs
   v
[burrow]             behind NAT, no privileges, userspace only
   | real OS sockets (MASQUERADE)
   v
[internal hosts]     see burrow's LAN IP as the source
```

### Reverse direction (the tunnel)

The burrow host binds a real OS `TcpListener` / `UdpSocket` on its own
network interfaces (default `0.0.0.0`, configurable via the BIND prefix in
`-R BIND:LISTEN:HOST:PORT`). Anything that can route to that interface can
hit the listener. The connection is multiplexed (yamux) over the WG control
flow back to the owning client, which dials `forward_to` locally and pipes
bytes.

```
[anyone with network access to burrow's listening interface]
                   |
                   v
            [burrow:LISTEN]   (real OS socket on burrow's host network)
                   |
                   |  yamux substream over the WG control flow
                   v
            [burrow-client]   (process holding the tunnel open)
                   |
                   |  fresh local TCP/UDP, originated by the client
                   v
            [HOST:PORT]       (client-side forward_to)
```

Two common shapes:

- **Cloud burrow → home service** (ngrok-style): burrow runs on a VPS with
  a public IP. Anyone on the internet hits `vps_public_ip:LISTEN`, traffic
  tunnels to the home machine running `burrow-client`, originates locally.
- **Office burrow → laptop service**: burrow runs on a corp LAN host.
  Anyone on the LAN hits `office_lan_ip:LISTEN`; tunnels to a laptop
  running `burrow-client` over WG, originates from the laptop.

Reverse tunnels do *not* listen on `wg_ip` and are not reachable through
the WG tunnel itself (the burrow host is userspace and has no TUN
interface; there is nothing on the WG side for the OS kernel to deliver to).
The control channel rides on `wg_ip`; the listeners do not.

### Extras

- DNS resolver on `(wg_ip, 53/udp)` answering A queries via the burrow
  host's system resolver. Opt-in for clients via `--dns 10.0.0.2` to
  `burrow-client gen`, or by setting `DNS = 10.0.0.2` in the client's
  `[Interface]` section.
- Remote shell. `burrow-client shell` gives you an interactive PTY, a
  one-shot capture, or fire-and-forget.
- Config generator. `burrow-client gen` writes a ready-to-use trio of wg-quick
  configs in one shot.

## Quick start

The three-party setup needs a WireGuard server, a burrow host, and at least
one client peer. `burrow-client gen` bootstraps everything.

```sh
# 1. build
cargo build --release

# 2. generate the trio (keys, IPs, subnet, routes all in one go)
./target/release/burrow-client gen \
    --endpoint your.server.example:51820 \
    --routes 192.168.1.0/24 \
    --clients 1
# wrote 3 config(s) to ./burrow-configs:
#   server.conf
#   burrow.conf
#   client1.conf

# 3. deploy
# on the WG server (Linux, kernel WireGuard):
sudo sysctl -w net.ipv4.ip_forward=1
sudo wg-quick up ./burrow-configs/server.conf

# on the burrow host (anywhere tokio runs):
./target/release/burrow --config ./burrow-configs/burrow.conf

# on the client:
sudo wg-quick up ./burrow-configs/client1.conf
# or load client1.conf into the official WireGuard app on Windows/macOS.
```

The client can now reach anything in `192.168.1.0/24` through burrow.

For ephemeral / scratch deploys to a remote Linux box, the helper
scripts in `scripts/` (and matching `just deploy-server` /
`just deploy-client` recipes) bring up the server or a client inside
a network namespace, with no systemd unit and no `/etc/wireguard`
file. State lives in the namespace; teardown or reboot wipes it. See
[Remote deploy helpers](#remote-deploy-helpers).

## Install

### From source

```sh
git clone https://github.com/aimogging/burrow
cd burrow
cargo build --release
# binaries in target/release/
```

### With just (build helpers)

[just](https://github.com/casey/just) is a small cross-platform command
runner. The `justfile` at the repo root has Windows + Unix recipes for
the common build paths.

```sh
just build                            # debug build
just release                          # release build
just release TARGET                   # release build, cross-compiled
just test                             # full test suite
just embed CONFIG                     # min-sized silent binary with CONFIG baked in
just embed CONFIG TARGET              # cross-compiled embedded binary
just gen-embed --endpoint ... --routes ...
                                      # generate the config trio AND embed
                                      # burrow.conf in one step (host target)
just size                             # list sizes of all built burrow binaries
```

For recipes that take a variadic (gen, gen-embed) and don't have a
positional `TARGET` slot, set the cross-compile target via the just
variable override:

```sh
just target=x86_64-unknown-linux-musl gen-embed --endpoint ... --routes ...
```

Or as an env var that sticks for the session:

```sh
# bash / zsh
export BURROW_TARGET=x86_64-unknown-linux-musl
just gen-embed --endpoint ... --routes ...

# pwsh
$env:BURROW_TARGET = "x86_64-unknown-linux-musl"
just gen-embed --endpoint ... --routes ...
```

Cross-compilation requires the target toolchain (`rustup target add
<triple>`) and a suitable linker. For non-native targets, `cargo
install cross` and substitute `cross` for `cargo` is the smoothest
path.

## Commands

```
# Gateway (intentionally minimal — just the runtime).
burrow [--config <PATH>] [--endpoint host:port] [--keepalive <secs>]

# Companion CLI: tunnels, shell, plus local utilities (keygen, gen).
burrow-client tunnel <wg_ip> [--control-port N] start -R [BIND:]LISTEN:HOST:PORT [-U]
burrow-client tunnel <wg_ip> [--control-port N] stop <tunnel_id>
burrow-client tunnel <wg_ip> [--control-port N] list
burrow-client shell  <wg_ip> [--control-port N]                          # interactive PTY
burrow-client shell  <wg_ip> [--control-port N] --output -               # one-shot to local stdio
burrow-client shell  <wg_ip> [--control-port N] --output run.log         # one-shot to file
burrow-client shell  <wg_ip> [--control-port N] --detach                 # fire-and-forget (returns pid)
burrow-client shell  <wg_ip> [--control-port N] --program <exe> -- <args...>
burrow-client keygen
burrow-client gen --endpoint <ip:port>
                  [--routes cidr[,cidr...]]
                  [--dns ip[,ip...]]
                  [--subnet 10.0.0.0/24]
                  [--clients N]
                  [--listen-port 51820]
                  [--out ./burrow-configs]
```

`BIND` (optional) selects which OS interface on the burrow host the
tunnel's listener binds on. Omitted = default (currently `0.0.0.0`,
INADDR_ANY). `0.0.0.0` = explicit INADDR_ANY. Any other IPv4 = bind
only to that interface (the burrow host must actually own the
address, same rule as any program calling `bind()`).

## Examples

### Generate configs for three clients with public DNS fallback

```sh
burrow-client gen \
    --endpoint vpn.example.com:51820 \
    --routes 10.50.0.0/24,192.168.1.0/24 \
    --dns 10.0.0.2,1.1.1.1 \
    --clients 3 \
    --out ./configs
```

Produces `server.conf`, `burrow.conf`, and `client1.conf` through
`client3.conf`. Clients get both burrow's built-in resolver and Cloudflare
as a fallback.

### Expose a laptop service to the office LAN

Laptop runs a dev server on `localhost:8080`. burrow runs on a desktop
sitting at `192.168.1.50` on the office LAN. Goal: anyone on the office
LAN can hit `192.168.1.50:443` and reach the laptop's dev server.

```sh
# on the laptop:
burrow-client tunnel 10.0.0.2 start -R 443:127.0.0.1:8080
# tunnel 1 started (Tcp 0.0.0.0:443 -> 127.0.0.1:8080). press ctrl-c to stop.
```

The burrow host now binds `0.0.0.0:443` on all of its OS interfaces.
Anyone on the office LAN that can reach `192.168.1.50:443` lands on the
laptop's `127.0.0.1:8080`. The tunnel stays up until Ctrl-C; close the
laptop and the tunnel goes with it.

Hostnames for the forward target work: `-R 443:internal.corp.lan:8080`.

### Pin the listener to a single interface

```sh
burrow-client tunnel 10.0.0.2 start -R 192.168.1.50:443:127.0.0.1:8080
# binds only on the burrow host's 192.168.1.50 interface; loopback /
# other LAN segments / etc are not exposed
```

### Cloud burrow as an ngrok-style ingress

burrow on a VPS with public IP `203.0.113.7`. Home service on
`localhost:8000`. Goal: expose the home service to the public internet.

```sh
# on the home machine:
burrow-client tunnel 10.0.0.2 start -R 0.0.0.0:443:127.0.0.1:8000
# anyone hitting 203.0.113.7:443 reaches the home machine's :8000
```

### UDP tunnel for a DNS forwarder

burrow exposes `0.0.0.0:5353/udp` on its host network; client machine
forwards each datagram to Cloudflare's `1.1.1.1:53`.

```sh
burrow-client tunnel 10.0.0.2 start -U -R 5353:1.1.1.1:53
```

### Interactive shell on the burrow host

```sh
burrow-client shell 10.0.0.2
# drops into cmd.exe on Windows, $SHELL on Unix
```

Custom program:

```sh
burrow-client shell 10.0.0.2 --program /usr/bin/python3 -- -i
```

Capture the output of a one-shot command:

```sh
burrow-client shell 10.0.0.2 --output - --program cmd.exe -- /c "dir C:\"
```

### Query burrow's DNS directly

With `DnsEnabled = true` in `burrow.conf` (the default):

```sh
dig @10.0.0.2 example.com
```

Or set `10.0.0.2` as the peer's system resolver via `DNS = 10.0.0.2` in the
client's `[Interface]` section (or pass `--dns 10.0.0.2` to `burrow-client gen`).

## Deploy: single self-contained binary

For a deploy binary that carries its config embedded, emits nothing on
stdout/stderr, and is size-stripped for shipping:

```sh
just embed ./path/to/burrow.conf
# builds target/min/burrow(.exe) - features embedded-config + silent,
# release profile with opt-level=z, LTO, no debug, stripped symbols
```

Under the hood:

```sh
BURROW_EMBEDDED_CONFIG=./path/to/burrow.conf \
    cargo build --profile min --features embedded-config,silent
```

The resulting binary contains the config as a `&'static str` in its read-only
data segment, so plain `burrow` works without `--config`. Anyone with read
access to the binary can extract the PrivateKey via `strings` — do not ship
this binary to anyone you would not trust with the `.conf` itself.

## Remote deploy helpers

For scratch deploys (a fresh test peer, a one-off staging server, etc.)
the scripts in `scripts/` push a config to a remote Linux host and
bring up WireGuard inside a network namespace. State lives in the
namespace plus a `/tmp/burrow-<ns>.conf`; no systemd unit, no
`/etc/wireguard` file. Teardown or reboot wipes everything.

```sh
# Server side. Three target shapes — anything `ssh` accepts:
just deploy-server --target myhost --config burrow-configs/server.conf
just deploy-server --target root@1.2.3.4 --config burrow-configs/server.conf --key ~/.ssh/id_ed25519
just deploy-server --target root@1.2.3.4 --config burrow-configs/server.conf --password hunter2

# Client side. Same shape; routes for [Peer] AllowedIPs are auto-added
# inside the namespace.
just deploy-client --target peer1 --config burrow-configs/client1.conf

# Tear down.
just deploy-server --target root@1.2.3.4 --teardown
just deploy-client --target peer1 --teardown
```

The WG UDP socket runs in the host network namespace (so the server is
publicly reachable / the client can dial the server's public IP); the
`wg` interface lives in the target namespace. This is the standard
pattern from <https://www.wireguard.com/netns/>.

After deploy, operate on the remote inside the namespace:

```sh
ssh root@1.2.3.4 sudo ip netns exec burrow wg show
ssh root@1.2.3.4 sudo ip netns exec burrow bash      # interactive shell in the netns
```

Requirements on the remote: `wireguard-tools` + `iproute2` (script
auto-installs via `apt-get` / `yum` if missing); a sudoer SSH user (or
log in as root). Requirement on the local side: `ssh` + `scp`, plus
`sshpass` if you use `--password`.

`--namespace NAME` (default `burrow`) lets you name the netns / wg
interface. Run multiple isolated instances on the same host by giving
each a distinct namespace.

## Logging

Controlled via `RUST_LOG` (env-filter syntax). Default is `info,burrow=debug`.
The `silent` feature compiles out all `tracing` events in release builds.

```sh
RUST_LOG=burrow=trace burrow --config burrow.conf
```

Useful filters:

- `burrow::nat=debug` - connection-tracking decisions
- `burrow::runtime=debug` - smoltcp poll loop, periodic socket-count cardinality
- `burrow::proxy=debug` - per-connection TCP proxy lifecycle
- `burrow::control=debug` - control-channel requests (tunnel start/stop, shell)

## How it works

1. boringtun decrypts inbound WireGuard datagrams to raw IPv4 packets.
2. A NAT table records the original destination and rewrites it (and the
   destination port) to smoltcp's interface address plus a per-flow gateway
   port from the 32768-65535 pool.
3. For TCP, burrow first dials the original destination as an OS `TcpStream`.
   Only on a successful connect does it hand the SYN to smoltcp, so a closed
   port returns RST to the peer instead of a false-positive SYN-ACK. On
   smoltcp accepting the rewritten connection, the OS stream is paired with
   the smoltcp socket and bytes are pumped both directions.
4. UDP bypasses smoltcp: burrow binds an OS `UdpSocket` per flow and forwards
   datagrams. Idle flows are swept after 30 seconds.
5. ICMP echo: if the process can open a raw ICMP socket, requests are
   forwarded and replies are demuxed by `(id, seq)`. Otherwise burrow
   constructs `Type 3 Code 13` (Communication Administratively Prohibited)
   in userspace and tunnels it back - semantically accurate and distinguishable
   from host-unreachable.
6. For reverse tunnels, `burrow-client tunnel start` holds a control flow
   open as a yamux client. The burrow host binds a real OS `TcpListener`
   or `UdpSocket` on the requested interface (default `0.0.0.0`). When a
   peer connects, burrow opens an outbound yamux substream to the owning
   client; the client dials its local `forward_to` and pipes bytes. UDP
   tunnels use one shared substream carrying length-plus-peer-tagged
   datagram frames.

On egress, the source IP and port are restored from the NAT table before the
packet goes back through boringtun.

## Limitations

- IPv4 only. IPv6 is not implemented.
- Single upstream peer. burrow connects to exactly one WireGuard server.
- One `[Peer]` section in `burrow.conf`. That is fine for burrow's own config;
  `server.conf` is multi-peer and consumed by `wg-quick`, not our parser.
- ICMP without raw sockets returns admin-prohibited rather than forwarding.
  On Windows this needs Administrator; on Linux it needs `CAP_NET_RAW` or
  root.
- TCP-only application protocols that embed addresses (FTP active mode, SIP,
  and so on) will not work without an ALG - burrow is a layer-3/4 NAT, not a
  protocol-aware proxy.

## Development

```sh
cargo test                              # 101 lib + 32 integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt
```

The integration tests in `tests/` exercise the TCP and UDP proxy paths
end-to-end against loopback echo servers, plus regressions for
connect-before-SYN-ACK (`closed_port_returns_rst`), per-flow gateway-port
disambiguation under nmap-style scans (`syn_collision_storm`), the full
control/shell/tunnel protocols, and the config generator.

## License

BSD-3-Clause (matching boringtun).
