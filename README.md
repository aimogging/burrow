# burrow

A WireGuard userspace gateway. Runs as a peer behind NAT, acts as a transparent
MASQUERADE gateway for other peers reaching hosts on the gateway's local
network, and carries a small control channel for reverse tunnels, a DNS
resolver, and an optional remote shell.

- **No TUN interface.** No Wintun, no `wireguard-nt`, no `/dev/net/tun`.
- **No kernel drivers.** No admin/root required (raw sockets for ICMP are
  optional — burrow falls back to userspace ICMP responses).
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

That requires Linux, root, kernel modules, and OS-level configuration. burrow
does the same thing as a single unprivileged userspace process, plus some
extras:

- **Reverse tunnels.** A peer runs `burrow-client tunnel start -R ...` and the
  burrow host listens on behalf of the peer, SSH-R-style. Traffic to the
  listening port is multiplexed back to the client over yamux and originated
  from the client's machine.
- **DNS resolver.** Optional on-box DNS service at `(wg_ip, 53/udp)`.
- **Remote shell.** `burrow-client shell` — interactive PTY, one-shot, or
  fire-and-forget.
- **Config generator.** `burrow gen` emits server/burrow/client configs in
  one shot.

```
[external peer]
    | WireGuard
    v
[WireGuard server]            standard wg, publicly reachable
    | routes via AllowedIPs
    v
[burrow]                      behind NAT, connects outbound, no privileges
    | real OS sockets
    v
[internal hosts]              see burrow's LAN IP as the source
```

## Quick start

### 1. Build

```sh
cargo build --release
# binaries land at target/release/burrow and target/release/burrow-client
```

### 2. Generate the config trio

```sh
burrow gen \
  --endpoint your.server.example:51820 \
  --routes 192.168.1.0/24 \
  --clients 1
# wrote 3 config(s) to ./burrow-configs:
#   server.conf
#   burrow.conf
#   client1.conf
```

Multiple exposed subnets: `--routes 192.168.1.0/24,10.50.0.0/24`. Multiple
clients: `--clients 3`. Opt clients into burrow's DNS: `--dns 10.0.0.2`
(add public fallbacks with `--dns 10.0.0.2,1.1.1.1`). Custom WG network:
`--subnet 10.42.0.0/24`.

### 3. Deploy

- **WG server** (Linux with kernel WireGuard): `wg-quick up ./server.conf` after
  setting `net.ipv4.ip_forward = 1`.
- **burrow host** (anywhere tokio runs): `burrow run --config ./burrow.conf`.
- **Each client**: `wg-quick up ./client1.conf` (or use the official WireGuard
  client on Windows/macOS).

That's it. Clients can now reach the advertised routes through burrow.

## CLI

```
burrow run --config <PATH> [--endpoint host:port] [--keepalive <secs>]
burrow gen --endpoint <ip:port> [--routes ...] [--dns ...] [--subnet ...] [--clients N]
burrow keygen

burrow-client <wg_ip> tunnel start -R LISTEN:HOST:PORT [-U]
burrow-client <wg_ip> tunnel stop  <tunnel_id>
burrow-client <wg_ip> tunnel list
burrow-client <wg_ip> shell [--program <exe>] [-- <args>...]
burrow-client <wg_ip> shell --output - | --output <path> | --detach
```

## Logging

Controlled via `RUST_LOG` (env-filter syntax). Defaults to `info,burrow=debug`.

```sh
RUST_LOG=burrow=trace burrow run --config burrow.conf
```

Useful filters:
- `burrow::nat=debug` — connection-tracking decisions
- `burrow::runtime=debug` — smoltcp poll loop, periodic socket-count cardinality
- `burrow::proxy=debug` — per-connection TCP proxy lifecycle
- `burrow::control=debug` — control-channel requests (tunnel start/stop, shell)

## How it works

1. boringtun decrypts inbound WireGuard datagrams to raw IPv4 packets.
2. A NAT table records the original destination and replaces it (and the
   destination port) with smoltcp's interface address and a per-flow gateway
   port from the 32768..=65535 pool.
3. For TCP, burrow first dials the original destination as an OS `TcpStream`.
   Only on a successful connect does it hand the SYN to smoltcp — so a closed
   port returns RST to the peer instead of a false-positive SYN-ACK. On
   smoltcp accepting the (rewritten) connection, the OS stream is paired with
   the smoltcp socket and bytes are pumped both directions.
4. UDP bypasses smoltcp: burrow binds an OS `UdpSocket` per flow and forwards
   datagrams. Idle flows are swept after 30s.
5. ICMP echo: if the process can open a raw ICMP socket, requests are
   forwarded and replies are demuxed by `(id, seq)`. Otherwise burrow
   constructs `Type 3 / Code 13` (Communication Administratively Prohibited)
   in userspace and tunnels it back — semantically accurate and distinguishable
   from host-unreachable.
6. For reverse tunnels, a `burrow-client tunnel start` holds a control flow
   open as a yamux client. When a peer hits the listen port, burrow opens an
   outbound yamux substream to the owning client; the client dials its local
   `forward_to` and pipes bytes.

On egress, the source IP and port are restored from the NAT table before the
packet goes back through boringtun.

## Limitations

- **IPv4 only.** IPv6 is not implemented yet.
- **Single upstream peer.** burrow connects to exactly one WireGuard server.
- **One [Peer] section in burrow.conf.** The parser accepts only one peer —
  that's fine for burrow's own config; `server.conf` is multi-peer and
  consumed by `wg-quick`, not our parser.
- **ICMP without raw sockets** returns admin-prohibited rather than forwarding.
  On Windows this needs Administrator; on Linux it needs `CAP_NET_RAW` (or root).
- **TCP-only application protocols** that embed addresses (FTP active mode,
  SIP, etc.) won't work without an ALG — burrow is a layer-3/4 NAT, not a
  protocol-aware proxy.

## Testing

```sh
cargo test                              # 96 lib + 36 integration tests
cargo clippy --all-targets -- -D warnings
```

The integration tests in `tests/` exercise the TCP and UDP proxy paths
end-to-end against loopback echo servers, plus regressions for
connect-before-SYN-ACK (`closed_port_returns_rst`), per-flow gateway-port
disambiguation under nmap-style scans (`syn_collision_storm`), the full
control/shell/tunnel protocols, and the config generator.

## License

BSD-3-Clause (matching boringtun).
