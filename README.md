# burrow

Userspace WireGuard gateway. No TUN, no kernel drivers, no admin.

## TL;DR

burrow is a WireGuard peer you drop inside a private network. It acts
as a transparent MASQUERADE for other peers reaching internal hosts,
and adds SSH `-R`-style reverse tunnels (bound on real OS listeners),
a DNS resolver, and a remote shell over one control channel.

Built on [boringtun](https://github.com/cloudflare/boringtun) and
[smoltcp](https://github.com/smoltcp-rs/smoltcp).

```
[peer]                          [anyone with net access]
  | WireGuard                     | TCP/UDP
  v                               v
[WG server]                     [burrow host]:LISTEN  <- reverse tunnels land here
  | AllowedIPs                   |
  v                              | yamux substream over WG
[burrow]  -- real OS sockets --> | (to the client that `tunnel start`ed)
  |
  v
[LAN hosts]                     [client]:forward_to   <- originated locally
```

## Quick start

```sh
# 1. Build binaries + generate configs. Embeds burrow.conf into the
#    gateway binary so it runs with no config args. Artifacts:
#      target/min/burrow(.exe)         -- gateway, config embedded
#      target/min/burrow-client(.exe)  -- companion CLI
#      burrow-configs/{server,burrow,client1}.conf
just gen-embed --endpoint vpn.example.com:51820 --routes 192.168.1.0/24

# 2. Transfer the gateway binary to the host that will sit inside your
#    private network. It has the config baked in; no args needed.
scp target/min/burrow gateway-host:
ssh gateway-host ./burrow

# 3. Bring up the WG server on the public VPS (uses server.conf).
just deploy-server --target root@vpn.example.com --key ~/.ssh/id_ed25519

# 4. Bring up the WG client here + drop into the tunnel's netns.
just deploy-client
just netns-shell
# (inside the netns: anything you curl / dig / ssh to the exposed
#  subnets reaches through burrow.)
```

Three machines:
- **WG server** (step 3): public VPS running kernel WireGuard.
- **burrow host** (step 2): gateway sitting inside the private network.
- **Client** (step 4): this box, running in an isolated netns so the
  tunnel doesn't touch host routing.

Teardown mirrors deploy:

```sh
just deploy-server --target root@vpn.example.com --teardown
just deploy-client --teardown
```

## Reverse tunnels

From inside the client's netns:

```sh
burrow-client tunnel 10.0.0.2 start -R 443:127.0.0.1:8080
# Anything that connects to the burrow host on port 443 tunnels back
# here and lands on 127.0.0.1:8080. SSH -R, but over WG.
```

`-R [BIND:]LISTEN:HOST:PORT` — BIND defaults to `0.0.0.0` (bind on all
OS interfaces of the burrow host). Pin to a specific interface with
e.g. `-R 192.168.1.50:443:127.0.0.1:8080`. `-U` for UDP.

## Commands

```
burrow [--config <PATH>]                    # the gateway
burrow-client tunnel <wg_ip> start -R ...   # reverse tunnels (TCP; -U for UDP)
burrow-client shell  <wg_ip>                # interactive PTY on the burrow host
burrow-client keygen                        # base64 x25519 keypair
burrow-client gen ...                       # write server/burrow/client configs
```

`--help` on any subcommand for the full option surface. `just --list`
for build / deploy recipes.

## How it works

1. boringtun decrypts inbound WG datagrams to raw IPv4.
2. burrow's NAT table records the original destination and rewrites it
   to smoltcp's virtual IP + per-flow gateway port. smoltcp is a
   userspace TCP/IP stack; no TUN, no OS-level interfaces.
3. For TCP, burrow dials the original destination as a real OS
   `TcpStream` first — only on success does smoltcp answer the peer's
   SYN. Closed ports get an RST, not a false SYN-ACK.
4. UDP bypasses smoltcp: per-flow `UdpSocket`, idle-swept after 30s.
5. Reverse tunnels bind real OS listeners on the gateway. Incoming
   connections are yamux-multiplexed back to the owning client, which
   originates the `forward_to` connection locally.

On the WG server: standard `AllowedIPs` routing, `ip_forward = 1`. No
custom daemon.

## Limitations

- IPv4 only. No IPv6.
- Single upstream peer. One WG server per burrow.
- ICMP without raw sockets returns admin-prohibited rather than
  forwarding; raw sockets need `CAP_NET_RAW` / Administrator.
- Layer-3/4 only. FTP active mode, SIP etc. need an ALG (not provided).

## Development

```sh
cargo test                              # 101 lib + 32 integration tests
cargo clippy --all-targets -- -D warnings
```

See `justfile` for cross-compile recipes and `scripts/` for the deploy
helpers.

## License

BSD-3-Clause (matches boringtun).
