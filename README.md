# burrow

A WireGuard userspace gateway. Runs as a peer behind NAT, acts as a transparent
MASQUERADE gateway for other peers reaching hosts on the gateway's local
network, and carries a small control channel for reverse tunnels, a built-in
DNS resolver, and an optional remote shell.

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
does the same thing as a single unprivileged userspace process and adds:

- Reverse tunnels. A peer runs `burrow-client tunnel start -R ...` and the
  burrow host listens on the peer's behalf, SSH-R style. Traffic to the
  listening port is multiplexed back to the client over yamux and originated
  from the client's machine.
- DNS resolver on `(wg_ip, 53/udp)`, using the burrow host's system resolver.
- Remote shell. `burrow-client shell` gives you interactive PTY, one-shot
  capture, or fire-and-forget.
- Config generator. `burrow gen` writes a ready-to-use trio of wg-quick
  configs in one shot.

```
[peer]
   | WireGuard
   v
[WG server]          standard wg, publicly reachable
   | routes via AllowedIPs
   v
[burrow]             behind NAT, no privileges, userspace only
   | real OS sockets
   v
[internal hosts]     see burrow's LAN IP as the source
```

## Quick start

The three-party setup needs a WireGuard server, a burrow host, and at least
one client peer. `burrow gen` bootstraps everything.

```sh
# 1. build
cargo build --release

# 2. generate the trio (keys, IPs, subnet, routes all in one go)
./target/release/burrow gen \
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
./target/release/burrow run --config ./burrow-configs/burrow.conf

# on the client:
sudo wg-quick up ./burrow-configs/client1.conf
# or load client1.conf into the official WireGuard app on Windows/macOS.
```

The client can now reach anything in `192.168.1.0/24` through burrow.

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
                                      # burrow.conf in one step
just size                             # list sizes of all built burrow binaries
```

Cross-compilation requires the target toolchain (`rustup target add
<triple>`) and a suitable linker. For non-native targets, `cargo
install cross` and substitute `cross` for `cargo` is the smoothest
path.

## Commands

```
burrow run --config <PATH> [--endpoint host:port] [--keepalive <secs>]
burrow gen --endpoint <ip:port>
           [--routes cidr[,cidr...]]
           [--dns ip[,ip...]]
           [--subnet 10.0.0.0/24]
           [--clients N]
           [--listen-port 51820]
           [--out ./burrow-configs]
burrow keygen

burrow-client <wg_ip> tunnel start -R LISTEN:HOST:PORT [-U]
burrow-client <wg_ip> tunnel stop  <tunnel_id>
burrow-client <wg_ip> tunnel list
burrow-client <wg_ip> shell                                  # interactive PTY
burrow-client <wg_ip> shell --output -                       # one-shot to local stdio
burrow-client <wg_ip> shell --output run.log                 # one-shot to file
burrow-client <wg_ip> shell --detach                         # fire-and-forget (returns pid)
burrow-client <wg_ip> shell --program <exe> -- <args...>     # custom program + argv
```

## Examples

### Generate configs for three clients with public DNS fallback

```sh
burrow gen \
    --endpoint vpn.example.com:51820 \
    --routes 10.50.0.0/24,192.168.1.0/24 \
    --dns 10.0.0.2,1.1.1.1 \
    --clients 3 \
    --out ./configs
```

Produces `server.conf`, `burrow.conf`, and `client1.conf` through
`client3.conf`. Clients get both burrow's built-in resolver and Cloudflare
as a fallback.

### Expose a local service through the VPN

The client machine runs a service on `localhost:8080` and wants VPN peers to
reach it at `<burrow_wg_ip>:443`.

```sh
# on the client (or anywhere that can route to burrow over WG):
burrow-client 10.0.0.2 tunnel start -R 443:127.0.0.1:8080
# tunnel 1 started (Tcp 443 -> 127.0.0.1:8080). press ctrl-c to stop.
```

The tunnel stays up until Ctrl-C. Peer connections to `(10.0.0.2, 443)`
land on `127.0.0.1:8080` of the client machine. Hostnames work too:
`-R 443:internal.corp.lan:8080`.

### UDP tunnel for a DNS forwarder

```sh
burrow-client 10.0.0.2 tunnel start -U -R 5353:1.1.1.1:53
```

### Interactive shell on the burrow host

```sh
burrow-client 10.0.0.2 shell
# drops into cmd.exe on Windows, $SHELL on Unix
```

Custom program:

```sh
burrow-client 10.0.0.2 shell --program /usr/bin/python3 -- -i
```

Capture the output of a one-shot command:

```sh
burrow-client 10.0.0.2 shell --output - --program cmd.exe -- /c "dir C:\"
```

### Query burrow's DNS directly

With `DnsEnabled = true` in `burrow.conf` (the default):

```sh
dig @10.0.0.2 example.com
```

Or set `10.0.0.2` as the peer's system resolver via `DNS = 10.0.0.2` in the
client's `[Interface]` section (or pass `--dns 10.0.0.2` to `burrow gen`).

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
data segment, so `burrow run` works without `--config`. Anyone with read
access to the binary can extract the PrivateKey via `strings` — do not ship
this binary to anyone you would not trust with the `.conf` itself.

## Logging

Controlled via `RUST_LOG` (env-filter syntax). Default is `info,burrow=debug`.
The `silent` feature compiles out all `tracing` events in release builds.

```sh
RUST_LOG=burrow=trace burrow run --config burrow.conf
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
   open as a yamux client. When a peer hits the listen port, burrow opens an
   outbound yamux substream to the owning client; the client dials its local
   `forward_to` and pipes bytes. UDP tunnels use one shared substream carrying
   length-plus-peer-tagged datagram frames.

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
cargo test                              # 96 lib + 36 integration tests
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
