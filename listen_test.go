// SPDX-License-Identifier: MIT

// Package tun2net_test is an EXTERNAL (black-box) test package: it imports only
// the module's public API plus the standard library, with zero gVisor imports.
// That makes the compiler itself the proof of ListenTCP's guarantee — a
// downstream consumer can open an in-stack TCP listener using nothing but
// net.Listener / netip.AddrPort. If ListenTCP ever leaked a gVisor type this
// file would fail to build. (netstack_test.go stays internal/white-box and
// keeps its gVisor imports; Go allows both packages in one directory.)
package tun2net_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	tun2net "github.com/n0madic/go-tun2net"
)

// wiredTunnel is a minimal in-memory PacketTunnel: egress IP packets leave via
// one end of a net.Pipe and inbound packets are pushed in through the handler
// stored by SetInbound. Two of these, cross-wired by pump, form a two-node L3
// "wire" built entirely from the public API.
type wiredTunnel struct {
	conn net.Conn
	cfg  tun2net.TunConfig

	mu      sync.Mutex // guards inbound/reconf; held across the inbound call so
	inbound func([]byte)
	reconf  func(tun2net.TunConfig)
}

func (w *wiredTunnel) TunnelConn() net.Conn      { return w.conn }
func (w *wiredTunnel) Config() tun2net.TunConfig { return w.cfg }

func (w *wiredTunnel) SetInbound(h func([]byte)) func() {
	w.mu.Lock()
	w.inbound = h
	w.mu.Unlock()
	return func() {
		w.mu.Lock()
		w.inbound = nil
		w.mu.Unlock()
	}
}

func (w *wiredTunnel) OnReconfigure(h func(tun2net.TunConfig)) func() {
	w.mu.Lock()
	w.reconf = h
	w.mu.Unlock()
	return func() {
		w.mu.Lock()
		w.reconf = nil
		w.mu.Unlock()
	}
}

func (w *wiredTunnel) Close() error { return w.conn.Close() }

// deliver hands one inbound IP packet to the stored handler. The handler call
// is held under mu so a concurrent detach (Net.Close → SetInbound's detach)
// drains any in-flight delivery before nil-ing the handler — the gVisor stack
// is then torn down with no deliverInbound in flight. This does not deadlock
// with the synchronous reply write a delivery can trigger because pump's reader
// goroutine (which drains that write) never touches mu.
func (w *wiredTunnel) deliver(pkt []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.inbound != nil {
		w.inbound(pkt)
	}
}

// pumpQueue is the per-direction buffer between a pump's reader and deliverer.
// It is sized far above the in-flight packet count of a single TCP echo so the
// reader can always enqueue and loop back to draining src, keeping the reader
// decoupled from a delivery that blocks on its own synchronous reply write.
const pumpQueue = 1024

// pump moves egress IP packets read off src to deliver, decoupled through a
// buffered channel: the reader goroutine keeps draining src no matter how long
// a delivery blocks (a delivery can synchronously write a reply back through
// the OTHER pipe, which only completes once the peer pump's reader drains it —
// so reader and deliverer MUST be separate goroutines, or two simultaneous
// replies would wedge each other). The reader exits when src errors (the peer
// Net.Close closed the pipe end) and closes the channel so the deliverer drains
// and exits too.
func pump(src net.Conn, deliver func([]byte)) {
	ch := make(chan []byte, pumpQueue)
	go func() {
		defer close(ch)
		buf := make([]byte, 65536)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				ch <- pkt
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		for pkt := range ch {
			deliver(pkt)
		}
	}()
}

// newWiredNet builds a single Net over a wiredTunnel with no peer pump — for
// tests that only inspect ListenTCP's bind decision and exchange no traffic.
func newWiredNet(t *testing.T, cfg tun2net.TunConfig) *tun2net.Net {
	t.Helper()
	conn, peer := net.Pipe()
	tun := &wiredTunnel{conn: conn, cfg: cfg}
	n, err := tun2net.New(tun, nil)
	if err != nil {
		_ = peer.Close()
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		_ = n.Close()
		_ = peer.Close()
	})
	return n
}

// newWiredPair builds two Nets whose tunnels are cross-wired so each Net's
// egress is delivered as the other's inbound. Routing works without any L2
// resolution: the endpoint is ARPHardwareNone (no CapabilityResolutionRequired)
// and buildRoutes installs a default route via the configured gateway, while
// New's promiscuous + spoofing modes make each NIC accept the peer's packets.
func newWiredPair(t *testing.T, cfgA, cfgB tun2net.TunConfig) (clientNet, serverNet *tun2net.Net) {
	t.Helper()

	connA, peerA := net.Pipe()
	connB, peerB := net.Pipe()

	tunA := &wiredTunnel{conn: connA, cfg: cfgA}
	tunB := &wiredTunnel{conn: connB, cfg: cfgB}

	netA, err := tun2net.New(tunA, nil)
	if err != nil {
		t.Fatalf("New(A): %v", err)
	}
	netB, err := tun2net.New(tunB, nil)
	if err != nil {
		_ = netA.Close()
		t.Fatalf("New(B): %v", err)
	}

	// A's egress (read off peerA) is B's inbound, and B's egress is A's inbound.
	pump(peerA, tunB.deliver)
	pump(peerB, tunA.deliver)

	t.Cleanup(func() {
		// Closing the Nets closes the tunnel-conn ends, which makes the pump
		// reads on the peer ends error out so both pumps exit. Close the peer
		// ends too so nothing is left half-open.
		_ = netA.Close()
		_ = netB.Close()
		_ = peerA.Close()
		_ = peerB.Close()
	})
	return netA, netB
}

// TestListenTCPEndToEnd proves Net.ListenTCP yields a working server-side
// listener — concrete and wildcard, IPv4 and IPv6 — reachable by Net.DialContext
// across the wire, using only stdlib types on both ends.
func TestListenTCPEndToEnd(t *testing.T) {
	v4 := func(ip string) tun2net.TunConfig {
		return tun2net.TunConfig{
			LocalIP: netip.MustParseAddr(ip),
			Netmask: netip.MustParseAddr("255.255.255.0"),
			Gateway: netip.MustParseAddr("10.0.0.1"),
			MTU:     1400,
		}
	}
	v6 := func(prefix string) tun2net.TunConfig {
		return tun2net.TunConfig{
			LocalIP6:  netip.MustParsePrefix(prefix),
			RemoteIP6: netip.MustParseAddr("fd00::1"),
			MTU:       1400,
		}
	}

	tests := []struct {
		name       string
		clientCfg  tun2net.TunConfig
		serverCfg  tun2net.TunConfig
		listenAddr string
		dialAddr   string
	}{
		{
			name:       "ipv4 concrete",
			clientCfg:  v4("10.0.0.2"),
			serverCfg:  v4("10.0.0.3"),
			listenAddr: "10.0.0.3:9000",
			dialAddr:   "10.0.0.3:9000",
		},
		{
			name:       "ipv4 wildcard",
			clientCfg:  v4("10.0.0.2"),
			serverCfg:  v4("10.0.0.3"),
			listenAddr: "0.0.0.0:9000",
			dialAddr:   "10.0.0.3:9000",
		},
		{
			name:       "ipv6 concrete",
			clientCfg:  v6("fd00::2/64"),
			serverCfg:  v6("fd00::3/64"),
			listenAddr: "[fd00::3]:9000",
			dialAddr:   "[fd00::3]:9000",
		},
		{
			name:       "ipv6 wildcard",
			clientCfg:  v6("fd00::2/64"),
			serverCfg:  v6("fd00::3/64"),
			listenAddr: "[::]:9000",
			dialAddr:   "[fd00::3]:9000",
		},
	}

	for _, tc := range tests {
		tc := tc // capture range var (pre-go1.22 loopvar semantics)
		t.Run(tc.name, func(t *testing.T) {
			clientNet, serverNet := newWiredPair(t, tc.clientCfg, tc.serverCfg)

			ln, err := serverNet.ListenTCP(netip.MustParseAddrPort(tc.listenAddr))
			if err != nil {
				t.Fatalf("ListenTCP(%s): %v", tc.listenAddr, err)
			}
			defer func() { _ = ln.Close() }()

			payload := []byte("ping-tun2net")

			// Server: accept one conn and echo exactly len(payload) bytes back.
			// SetDeadline so a routing bug fails the test fast instead of hanging.
			serverErr := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					serverErr <- fmt.Errorf("Accept: %w", err)
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, buf); err != nil {
					serverErr <- fmt.Errorf("server read: %w", err)
					return
				}
				if _, err := conn.Write(buf); err != nil {
					serverErr <- fmt.Errorf("server write: %w", err)
					return
				}
				serverErr <- nil
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := clientNet.DialContext(ctx, "tcp", tc.dialAddr)
			if err != nil {
				t.Fatalf("DialContext(%s): %v", tc.dialAddr, err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("client write: %v", err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("client read echo: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("echo = %q, want %q", got, payload)
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("server goroutine: %v", err)
			}
		})
	}
}

// TestListenTCPZeroAddrFamily covers the family-selection branch a zero/invalid
// AddrPort takes: bind on whichever family the NIC has (preferring IPv4), or
// error when the stack has no address at all. The explicit-wildcard cases above
// already prove the bind is actually reachable per family; here we only assert
// the branch picks correctly.
func TestListenTCPZeroAddrFamily(t *testing.T) {
	v4 := tun2net.TunConfig{
		LocalIP: netip.MustParseAddr("10.0.0.2"),
		Netmask: netip.MustParseAddr("255.255.255.0"),
		Gateway: netip.MustParseAddr("10.0.0.1"),
		MTU:     1400,
	}
	v6 := tun2net.TunConfig{
		LocalIP6:  netip.MustParsePrefix("fd00::2/64"),
		RemoteIP6: netip.MustParseAddr("fd00::1"),
		MTU:       1400,
	}

	t.Run("v4-only NIC binds the IPv4 wildcard", func(t *testing.T) {
		ln, err := newWiredNet(t, v4).ListenTCP(netip.AddrPort{})
		if err != nil {
			t.Fatalf("ListenTCP(zero) on a v4 NIC: %v", err)
		}
		_ = ln.Close()
	})

	t.Run("v6-only NIC binds the IPv6 wildcard", func(t *testing.T) {
		ln, err := newWiredNet(t, v6).ListenTCP(netip.AddrPort{})
		if err != nil {
			t.Fatalf("ListenTCP(zero) on a v6 NIC: %v", err)
		}
		_ = ln.Close()
	})

	t.Run("address-less NIC errors", func(t *testing.T) {
		if _, err := newWiredNet(t, tun2net.TunConfig{MTU: 1400}).ListenTCP(netip.AddrPort{}); err == nil {
			t.Fatal("ListenTCP(zero) on an address-less stack: want error, got nil")
		}
	})
}
