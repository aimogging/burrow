# burrow

Userspace WireGuard gateway. No TUN, no kernel drivers, no admin.

- [TL;DR](#tldr)
- [Quick start](#quick-start)
- [Examples](#examples)
- [Commands](#commands)
- [How it works](#how-it-works)
- [Limitations](#limitations)
- [Development](#development)
- [License](#license)

## TL;DR

burrow is a WireGuard peer you drop inside a private network. It acts
as a transparent MASQUERADE for other peers reaching internal hosts,
and adds SSH `-R`-style reverse tunnels (bound on real OS listeners),
a DNS resolver, and a remote shell over one control channel.

Built on [boringtun](https://github.com/cloudflare/boringtun) and
[smoltcp](https://github.com/smoltcp-rs/smoltcp).

Three-party setup: a publicly-reachable WG server in the middle, a
burrow gateway sitting inside some private network, and any number of
WG peers (your laptop, a VPS, whatever). burrow bridges the WG side to
the private LAN.

```mermaid
flowchart LR
    subgraph peers ["WG peers<br/>(anywhere)"]
        laptop[laptop]
        vps[VPS]
    end
    subgraph pub ["Public internet"]
        wgs["WG Server<br/>(kernel wireguard)"]
    end
    subgraph priv ["Private network<br/>(NAT'd, no inbound)"]
        burrow["burrow<br/>userspace gateway"]
        h1[internal host]
        h2[internal host]
    end
    laptop <-->|WireGuard| wgs
    vps <-->|WireGuard| wgs
    wgs <-->|WireGuard| burrow
    burrow --- h1
    burrow --- h2
```

Reverse tunnels flip the direction. Any machine on burrow's network
(WG peer, LAN host, the public internet if burrow is reachable there)
hits a real OS listener on the burrow host; the connection rides back
to whichever client called `tunnel start` and is originated locally.

```mermaid
flowchart LR
    caller([anyone with network<br/>access to burrow]) -->|plain TCP/UDP| listener["burrow:LISTEN_PORT"]
    listener -.->|through the WG mesh| client["burrow-client<br/>(holding the tunnel open)"]
    client -->|plain TCP/UDP| dst([forward_to])
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
#    Linux gateway:
scp target/min/burrow gateway-host:
ssh gateway-host ./burrow
#    Windows gateway, over SMB using the built-in C$ admin share
#    (from PowerShell on this box; works if you have admin creds on
#    the target — `net use` prompts if not cached):
Copy-Item target\min\burrow.exe \\gateway-host\c$\Users\Administrator\
# then RDP / `Enter-PSSession gateway-host` and run `.\burrow.exe`.
# (Or enable the optional OpenSSH Server on the Windows host and
# use `scp target/min/burrow.exe gateway-host:` like Linux.)

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

### `--routes`: split tunnel vs full tunnel

`--routes` controls which destinations get directed through burrow.
Two modes:

- **Split tunnel** (typical): one or more specific CIDRs. Only traffic
  destined for those ranges rides the tunnel; everything else uses
  the client's normal network.

  ```sh
  just gen-embed --endpoint vpn.example.com:51820 \
      --routes 192.168.1.0/24,10.50.0.0/24
  ```

- **Full tunnel**: `0.0.0.0/0`. All client traffic goes through the WG
  server, through burrow, and out burrow's LAN uplink — burrow
  becomes a self-hosted VPN egress. MASQUERADE is implicit (it's
  already how burrow handles outbound). Pair with `--dns` so DNS has
  a reachable resolver through the tunnel:

  ```sh
  just gen-embed --endpoint vpn.example.com:51820 \
      --routes 0.0.0.0/0 --dns 10.0.0.2
  ```

  Throughput is bounded by burrow's LAN pipe; fine for a handful of
  peers, not a commercial-grade VPN service.

Teardown mirrors deploy:

```sh
just deploy-server --target root@vpn.example.com --teardown
just deploy-client --teardown
```

## Examples

All of these run from inside the client netns (`just netns-shell`) so
traffic uses the tunnel. `10.0.0.2` is the burrow host's WG address in
the examples — adjust for your subnet.

### Reach an internal host

Plain clients over the tunnel. Nothing burrow-client-specific:

```sh
curl http://192.168.1.10/
ssh user@192.168.1.50
psql -h 192.168.1.20 -U postgres
```

### DNS

burrow answers A queries on `wg_ip:53` using the burrow host's system
resolver (on by default; `DnsEnabled = true` in `burrow.conf`):

```sh
dig @10.0.0.2 internal.corp.lan
```

Pass `--dns 10.0.0.2` to `burrow-client gen` to have the generated
client.conf set `DNS = 10.0.0.2`, so wg-quick points every tool's
resolver at burrow automatically while the tunnel is up.

### Reverse tunnel — expose a local service

SSH `-R`, but over WG. The burrow host binds a real OS listener;
connections tunnel back here and originate on `forward_to` locally.

```sh
# Anything that connects to burrow_host:443 lands on 127.0.0.1:8080.
burrow-client tunnel 10.0.0.2 start -R 443:127.0.0.1:8080
# Hold Ctrl-C to stop — burrow-client holds the control flow open
# for the tunnel's lifetime.
```

`HOST` can be a hostname — resolved on the machine running
`burrow-client` when a connection arrives, using whatever DNS
the client's system has configured. That includes burrow's built-in
resolver if `client.conf` set `DNS = 10.0.0.2` (pass `--dns` to
`burrow-client gen`); otherwise it uses the client's system resolver
/ `/etc/resolv.conf`.

```sh
burrow-client tunnel 10.0.0.2 start -R 443:db.internal.example.com:5432
```

`-R [BIND:]LISTEN:HOST:PORT` — BIND defaults to `0.0.0.0` (all OS
interfaces on the burrow host). Pin to one interface with
`-R 192.168.1.50:443:127.0.0.1:8080`. `-U` for UDP. Stop by id:

```sh
burrow-client tunnel 10.0.0.2 list
burrow-client tunnel 10.0.0.2 stop 42
```

### Shell — interactive

PTY session on the burrow host (default mode):

```sh
burrow-client shell 10.0.0.2
# drops into cmd.exe on Windows, $SHELL / /bin/sh on Unix
```

### Shell — one-shot

Run a command, capture stdout + stderr + exit code, return:

```sh
# `--output -` pipes captured output to the local terminal:
burrow-client shell 10.0.0.2 --output - --program whoami

# `--output <path>` writes it to a file (stderr still goes to terminal):
burrow-client shell 10.0.0.2 --output build.log --program make
```

### Shell — fire-and-forget

Spawn detached; the server returns the pid and the process outlives
the `burrow-client` invocation. Nothing is captured.

```sh
burrow-client shell 10.0.0.2 --detach --program ./long-running-task
# 47412        <- pid printed to local stdout
```

### Shell — custom program + argv

`--program` picks the executable; anything after `--` is argv:

```sh
burrow-client shell 10.0.0.2 --program /usr/bin/python3 -- -i
burrow-client shell 10.0.0.2 --program cmd.exe -- /c "dir C:\"
```

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
