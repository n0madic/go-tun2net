# go-tun2net

A userspace **gVisor TCP/IP stack over an arbitrary packet tunnel**. Feed it
anything that carries raw IP datagrams (one Read/Write == one IP packet) and it
gives you an ordinary `DialContext` surface — no kernel TUN, no root.

A VPN client plugs in by implementing `PacketTunnel`:

```go
type PacketTunnel interface {
    TunnelConn() net.Conn                          // one Write == one outbound IP packet
    Config() TunConfig                             // assigned IP / routes / MTU
    SetInbound(func(ip []byte)) (detach func())    // inbound fast-path (one call == one packet)
    OnReconfigure(func(TunConfig)) (detach func()) // reconnect / rekey / MOBIKE
}
```

```go
ns, err := tun2net.New(tun, logger) // tun implements PacketTunnel
if err != nil { ... }
defer ns.Close()

// ns.DialContext matches mihomo's C.Dialer signature byte-for-byte, so it
// drops straight into a mihomo outbound or any http.Transport.
httpClient := &http.Client{Transport: &http.Transport{DialContext: ns.DialContext}}

// Server side: an in-stack TCP listener, also free of gVisor types — it
// returns a plain net.Listener.
ln, err := ns.ListenTCP(netip.MustParseAddrPort("10.9.0.2:80"))
if err != nil { ... }
conn, err := ln.Accept()
```

## Features

- Single-NIC gVisor stack (IPv4 + IPv6), TCP/UDP/ICMP.
- `DialContext(ctx, network, addr)` (literal-IP; no DNS) — mihomo `C.Dialer`-compatible.
- `ListenTCP(addr)` — in-stack TCP listener returning a `net.Listener`, no gVisor types.
- Live reconfiguration: `OnReconfigure` re-applies addresses/routes and force-
  closes stale conns on tunnel IP change (reconnect/rekey), matching kernel
  `RTM_CHANGE` semantics.
- Inner-MTU clamping (default 1400) so wire datagrams survive ~1500-MTU paths
  after tunnel + outer-header overhead.
- Built-in stats logger for localising stuck data paths (LinkEndpoint counters
  vs gVisor stack stats).

## Status

✅ Builds, `go vet` clean, tests pass (`go test ./...`).

## License

MIT
