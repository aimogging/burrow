# wgnat

A WireGuard userspace NAT gateway. Connects outbound to a WireGuard server as
a peer and acts as a transparent MASQUERADE NAT for other peers reaching hosts
on the gateway's local network.

- **No TUN interface.** No Wintun, no `wireguard-nt`, no `/dev/net/tun`.
- **No kernel drivers.** No admin/root required (raw sockets for ICMP are
  optional — wgnat falls back to userspace ICMP responses).
- **No OS network configuration.** No routing tables, no firewall rules on
  the gateway host.
- **Cross-platform.** Tested on Windows; should run anywhere tokio + smoltcp do.

Built on [boringtun](https://github.com/cloudflare/boringtun) (noise protocol
only) and [smoltcp](https://github.com/smoltcp-rs/smoltcp) (userspace TCP/IP).

## What problem does it solve?

You have a host inside a private network. You want external WireGuard peers to
reach internal resources through it. The standard answer is:

```
wireguard-tools + iptables -j MASQUERADE + net.ipv4.ip_forward=1
```

That requires Linux, root, kernel modules, and OS-level configuration. wgnat
does the same thing as a single unprivileged userspace process.

```
[external peer]
    | WireGuard
    v
[WireGuard server]            standard wg, publicly reachable
    | routes via AllowedIPs
    v
[wgnat]                       behind NAT, connects outbound, no privileges
    | real OS sockets
    v
[internal hosts]              see wgnat's LAN IP as the source
```

## Quick start

### 1. Build

```sh
cargo build --release
# binary lands at target/release/wgnat (or wgnat.exe on Windows)
```

### 2. Generate a keypair

```sh
wgnat keygen
# PrivateKey = <base64>
# PublicKey  = <base64>
```

### 3. Add wgnat as a peer on your WireGuard server

`/etc/wireguard/wg0.conf` on the server:

```ini
[Interface]
PrivateKey = <server private key>
ListenPort = 51820
Address    = 198.51.100.1/24

[Peer]
# external client
PublicKey  = <client public key>
AllowedIPs = 198.51.100.10/32

[Peer]
# wgnat — the /24 it advertises is what external peers will route through it
PublicKey  = <wgnat public key>
AllowedIPs = 198.51.100.20/32, 192.168.1.0/24
```

Make sure `net.ipv4.ip_forward = 1` is set on the server.

### 4. Write a wg-quick config for wgnat

`wgnat.conf`:

```ini
[Interface]
PrivateKey = <wgnat private key>
Address    = 198.51.100.20/24

[Peer]
PublicKey           = <server public key>
Endpoint            = your.server.example:51820
AllowedIPs          = 198.51.100.0/24
PersistentKeepalive = 25
```

`PersistentKeepalive` is required to keep the outbound NAT mapping alive.

### 5. Run wgnat

```sh
wgnat run --config wgnat.conf
```

That's it. The external peer can now `ssh 192.168.1.50`, `curl http://192.168.1.10`,
etc., and wgnat opens real OS sockets to those destinations on its behalf.

## CLI

```
wgnat run --config <PATH> [--endpoint host:port] [--keepalive <secs>]
wgnat keygen
```

- `--endpoint` overrides `Endpoint` from the config.
- `--keepalive` overrides `PersistentKeepalive`; `0` disables.

## Logging

Controlled via `RUST_LOG` (env-filter syntax). Defaults to `info,wgnat=debug`.

```sh
RUST_LOG=wgnat=trace wgnat run --config wgnat.conf
```

Useful filters:
- `wgnat::nat=debug` — connection-tracking decisions
- `wgnat::runtime=debug` — smoltcp poll loop, periodic socket-count cardinality
- `wgnat::proxy=debug` — per-connection TCP proxy lifecycle

## How it works

1. boringtun decrypts inbound WireGuard datagrams to raw IPv4 packets.
2. A NAT table records the original destination and replaces it (and the
   destination port) with smoltcp's interface address and a per-flow gateway
   port from the 32768..=65535 pool.
3. For TCP, wgnat first dials the original destination as an OS `TcpStream`.
   Only on a successful connect does it hand the SYN to smoltcp — so a closed
   port returns RST to the peer instead of a false-positive SYN-ACK. On
   smoltcp accepting the (rewritten) connection, the OS stream is paired with
   the smoltcp socket and bytes are pumped both directions.
4. UDP bypasses smoltcp: wgnat binds an OS `UdpSocket` per flow and forwards
   datagrams. Idle flows are swept after 30s.
5. ICMP echo: if the process can open a raw ICMP socket, requests are
   forwarded and replies are demuxed by `(id, seq)`. Otherwise wgnat
   constructs `Type 3 / Code 13` (Communication Administratively Prohibited)
   in userspace and tunnels it back — semantically accurate and distinguishable
   from host-unreachable.

On egress, the source IP and port are restored from the NAT table before the
packet goes back through boringtun.

## Limitations

- **IPv4 only.** IPv6 is not implemented yet.
- **Single peer.** wgnat connects to exactly one upstream WireGuard server.
- **One [Peer] section.** The config parser accepts only one peer.
- **ICMP without raw sockets** returns admin-prohibited rather than forwarding.
  On Windows this needs Administrator; on Linux it needs `CAP_NET_RAW` (or root).
- **TCP-only application protocols** that embed addresses (FTP active mode,
  SIP, etc.) won't work without an ALG — wgnat is a layer-3/4 NAT, not a
  protocol-aware proxy.

## Testing

```sh
cargo test                              # 48 lib + 7 integration tests
cargo clippy --all-targets -- -D warnings
```

The integration tests in `tests/` exercise the TCP and UDP proxy paths
end-to-end against loopback echo servers, plus regressions for
connect-before-SYN-ACK (`closed_port_returns_rst`) and per-flow gateway-port
disambiguation under nmap-style scans (`syn_collision_storm`).

## License

BSD-3-Clause (matching boringtun).
