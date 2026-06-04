// SPDX-License-Identifier: AGPL-3.0-or-later

package tun2net

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
)

// mockTunnel is a minimal in-memory PacketTunnel for exercising New's wiring
// (Config / TunnelConn / SetInbound / OnReconfigure / CloseAll) without any
// real VPN client. Outbound writes are never exercised here, so the pipe peer
// (c2) just needs to stay open and be closed by the test.
type mockTunnel struct {
	conn    net.Conn
	cfg     TunConfig
	inbound func([]byte)
	reconf  func(TunConfig)
	closed  atomic.Bool
}

func (m *mockTunnel) TunnelConn() net.Conn { return m.conn }
func (m *mockTunnel) Config() TunConfig    { return m.cfg }

func (m *mockTunnel) SetInbound(h func([]byte)) func() {
	m.inbound = h
	return func() { m.inbound = nil }
}

func (m *mockTunnel) OnReconfigure(h func(TunConfig)) func() {
	m.reconf = h
	return func() { m.reconf = nil }
}

func (m *mockTunnel) Close() error {
	m.closed.Store(true)
	return m.conn.Close()
}

func newMock(t *testing.T, ip string) *mockTunnel {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c2.Close() })
	return &mockTunnel{
		conn: c1,
		cfg: TunConfig{
			LocalIP: netip.MustParseAddr(ip),
			Netmask: netip.MustParseAddr("255.255.255.0"),
			Gateway: netip.MustParseAddr("10.0.0.1"),
			MTU:     1400,
		},
	}
}

// TestNewWiresTunnel verifies New installs the initial config, wires the
// inbound fast-path and the reconfigure hook, and reapplies a fresh config
// when the hook fires (the reconnect/rekey path).
func TestNewWiresTunnel(t *testing.T) {
	m := newMock(t, "10.0.0.2")
	n, err := New(m, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = n.Close() }()

	if got := n.LocalIP(); got != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("LocalIP = %v, want 10.0.0.2", got)
	}
	if !n.HasIPv4() {
		t.Fatal("HasIPv4 = false, want true")
	}
	if m.inbound == nil {
		t.Fatal("SetInbound was not wired by New")
	}
	if m.reconf == nil {
		t.Fatal("OnReconfigure was not wired by New")
	}

	// Simulate a reconnect handing out a new tunnel IP.
	m.reconf(TunConfig{
		LocalIP: netip.MustParseAddr("10.0.0.7"),
		Netmask: netip.MustParseAddr("255.255.255.0"),
		Gateway: netip.MustParseAddr("10.0.0.1"),
		MTU:     1400,
	})
	if got := n.LocalIP(); got != netip.MustParseAddr("10.0.0.7") {
		t.Fatalf("post-reconfigure LocalIP = %v, want 10.0.0.7", got)
	}
}

// TestCloseAllClosesTunnel verifies CloseAll closes a PacketTunnel that
// implements io.Closer.
func TestCloseAllClosesTunnel(t *testing.T) {
	m := newMock(t, "10.0.0.2")
	n, err := New(m, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := n.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	if !m.closed.Load() {
		t.Fatal("CloseAll did not close the tunnel")
	}
}
