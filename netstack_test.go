// SPDX-License-Identifier: MIT

package tun2net

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

// fakeDispatcher captures the packets the LinkEndpoint hands upward.
type fakeDispatcher struct {
	mu      sync.Mutex
	packets []capturedPacket
	wake    chan struct{}
}

type capturedPacket struct {
	proto tcpip.NetworkProtocolNumber
	body  []byte
}

func newFakeDispatcher() *fakeDispatcher {
	return &fakeDispatcher{wake: make(chan struct{}, 16)}
}

func (f *fakeDispatcher) DeliverNetworkPacket(proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	v := pkt.ToView()
	body := append([]byte(nil), v.AsSlice()...)
	v.Release()
	f.mu.Lock()
	f.packets = append(f.packets, capturedPacket{proto: proto, body: body})
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *fakeDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func (f *fakeDispatcher) waitPacket(t *testing.T, timeout time.Duration) capturedPacket {
	t.Helper()
	select {
	case <-f.wake:
	case <-time.After(timeout):
		t.Fatal("timeout waiting for inbound packet")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.packets) == 0 {
		t.Fatal("woke up but no packet captured")
	}
	pkt := f.packets[len(f.packets)-1]
	return pkt
}

// TestEndpointInbound delivers raw IP bytes via the inbound fast-path
// (deliverInbound, as PacketTunnel.SetInbound would) and verifies that the
// LinkEndpoint hands them to the dispatcher as a PacketBuffer with the correct
// NetworkProtocolNumber.
func TestEndpointInbound(t *testing.T) {
	t.Parallel()

	cliConn, srvConn := net.Pipe()
	defer func() { _ = srvConn.Close() }()

	ep := newEndpoint(cliConn, 1500)
	disp := newFakeDispatcher()
	ep.Attach(disp)
	defer ep.Close()

	// Build a minimal IPv4 echo request (no inner payload, no real checksum
	// — endpoint doesn't validate, it just reads version + delivers).
	ipv4Pkt := []byte{
		0x45, 0x00, 0x00, 0x14, 0xab, 0xcd, 0x00, 0x00,
		0x40, 0x01, 0x00, 0x00, 10, 8, 0, 100,
		10, 8, 0, 1,
	}
	ep.deliverInbound(ipv4Pkt)

	got := disp.waitPacket(t, 2*time.Second)
	if got.proto != header.IPv4ProtocolNumber {
		t.Fatalf("proto = %d, want IPv4 (%d)", got.proto, header.IPv4ProtocolNumber)
	}
	if !bytes.Equal(got.body, ipv4Pkt) {
		t.Fatalf("body mismatch:\n got: %x\nwant: %x", got.body, ipv4Pkt)
	}

	// IPv6 dispatch path.
	ipv6Pkt := []byte{
		0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x40,
		// src ::1
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		// dst ::1
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	}
	ep.deliverInbound(ipv6Pkt)
	got = disp.waitPacket(t, 2*time.Second)
	if got.proto != header.IPv6ProtocolNumber {
		t.Fatalf("v6 proto = %d, want IPv6 (%d)", got.proto, header.IPv6ProtocolNumber)
	}
}

// retainingDispatcher keeps the delivered PacketBuffer alive (IncRef) and
// defers reading its bytes, so a test can mutate the caller's source slice
// after deliverInbound returns and detect whether the fast path aliased it.
type retainingDispatcher struct {
	pkt *stack.PacketBuffer
}

func (r *retainingDispatcher) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	pkt.IncRef()
	r.pkt = pkt
}

func (r *retainingDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// TestDeliverInboundCopiesPayload guards the zero-copy assumption in
// inject: buffer.MakeWithData MUST copy the caller's slice, because
// the direct-delivery fast path passes the session's reusable read buffer
// straight through and the caller overwrites it the moment deliverInbound
// returns. If a future gVisor bump ever switches MakeWithData to alias its
// input, this test fails loudly instead of letting a use-after-free silently
// corrupt inbound traffic.
func TestDeliverInboundCopiesPayload(t *testing.T) {
	t.Parallel()

	cliConn, srvConn := net.Pipe()
	defer func() { _ = srvConn.Close() }()

	ep := newEndpoint(cliConn, 1500)
	disp := &retainingDispatcher{}
	ep.Attach(disp)
	defer ep.Close()

	src := []byte{
		0x45, 0x00, 0x00, 0x14, 0xab, 0xcd, 0x00, 0x00,
		0x40, 0x01, 0x00, 0x00, 10, 8, 0, 100,
		10, 8, 0, 1,
	}
	want := append([]byte(nil), src...)

	ep.deliverInbound(src)

	// Per the contract the caller may reuse the backing array immediately —
	// scribble over it, then confirm the delivered packet kept the original.
	for i := range src {
		src[i] = 0xff
	}

	if disp.pkt == nil {
		t.Fatal("no packet delivered")
	}
	v := disp.pkt.ToView()
	got := append([]byte(nil), v.AsSlice()...)
	v.Release()
	disp.pkt.DecRef()
	if !bytes.Equal(got, want) {
		t.Fatalf("delivered packet aliased the caller's buffer:\n got: %x\nwant: %x", got, want)
	}
}

// TestEndpointOutbound builds a PacketBuffer, hands it to WritePackets, and
// verifies it appears verbatim on the other side of the pipe.
func TestEndpointOutbound(t *testing.T) {
	t.Parallel()

	cliConn, srvConn := net.Pipe()
	defer func() { _ = cliConn.Close() }()
	defer func() { _ = srvConn.Close() }()

	ep := newEndpoint(cliConn, 1500)
	defer ep.Close()
	// Attach is required by some stack code paths, but WritePackets does not
	// gate on it. We still Attach a dispatcher to keep the lifecycle realistic.
	ep.Attach(newFakeDispatcher())

	payload := []byte("hello-ip-packet")
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(payload),
	})
	defer pkt.DecRef()

	var pbl stack.PacketBufferList
	pbl.PushBack(pkt)

	// WritePackets blocks on net.Pipe Write until the other side reads,
	// so run it in a goroutine and read concurrently.
	wroteCh := make(chan int, 1)
	go func() {
		n, err := ep.WritePackets(pbl)
		if err != nil {
			t.Errorf("WritePackets: %v", err)
		}
		wroteCh <- n
	}()

	buf := make([]byte, 64)
	n, err := srvConn.Read(buf)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	if got := buf[:n]; !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
	if n := <-wroteCh; n != 1 {
		t.Fatalf("WritePackets returned n=%d, want 1", n)
	}
}

// TestEndpointCloseUnblocksWait: closing the endpoint must release Wait()
// (which gVisor blocks on during NIC teardown). There is no reader goroutine —
// Close drives e.done directly via the doneCh sync.Once.
func TestEndpointCloseUnblocksWait(t *testing.T) {
	t.Parallel()

	cliConn, srvConn := net.Pipe()
	defer func() { _ = srvConn.Close() }()

	ep := newEndpoint(cliConn, 1500)
	ep.Attach(newFakeDispatcher())

	done := make(chan struct{})
	go func() {
		ep.Wait()
		close(done)
	}()

	ep.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not return after Close")
	}
}

func TestMaskPrefixLen(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mask string
		want int
	}{
		{"255.255.255.0", 24},
		{"255.255.0.0", 16},
		{"255.255.255.255", 32},
		{"0.0.0.0", 0},
		{"255.255.255.240", 28},
	} {
		addr, err := netip.ParseAddr(tc.mask)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got := maskPrefixLen(addr); got != tc.want {
			t.Errorf("maskPrefixLen(%s) = %d, want %d", tc.mask, got, tc.want)
		}
	}
}

// TestTrackedConnLifecycle exercises the active-conns tracker without
// going through gVisor: it inserts mock conns, verifies they're
// remembered, force-closes them, and confirms double-close is safe and
// re-deregistration is idempotent.
func TestTrackedConnLifecycle(t *testing.T) {
	t.Parallel()

	n := &Net{}

	closer1 := &fakeCloseCounter{}
	closer2 := &fakeCloseCounter{}

	tc1 := n.trackConn(closer1).(*trackedConn)
	tc2 := n.trackConn(closer2).(*trackedConn)

	// Both registered.
	count := 0
	n.activeConns.Range(func(_, _ any) bool { count++; return true })
	if count != 2 {
		t.Fatalf("after two trackConn, active=%d, want 2", count)
	}

	// closeActiveOnReconnect closes both and clears the map.
	closed := n.closeActiveOnReconnect()
	if closed != 2 {
		t.Fatalf("closeActiveOnReconnect returned %d, want 2", closed)
	}
	if closer1.closes != 1 || closer2.closes != 1 {
		t.Fatalf("expected each underlying conn closed exactly once, got %d / %d",
			closer1.closes, closer2.closes)
	}
	count = 0
	n.activeConns.Range(func(_, _ any) bool { count++; return true })
	if count != 0 {
		t.Fatalf("after closeActiveOnReconnect, active=%d, want 0", count)
	}

	// Double-close is idempotent on the wrapper too.
	if err := tc1.Close(); err != nil {
		t.Fatalf("second Close() on tc1 returned error: %v", err)
	}
	if closer1.closes != 2 {
		// Note: the wrapper always forwards Close to the underlying conn,
		// even when already deregistered — this keeps the contract of
		// "Close returns the conn's own error" intact. The dedup is only
		// on the map removal, not on the Conn.Close call. That's safe
		// because gVisor's *TCPConn.Close is already idempotent.
		t.Fatalf("after second Close() on tc1, underlying closes=%d, want 2",
			closer1.closes)
	}

	// New conns can be tracked after a reconnect.
	closer3 := &fakeCloseCounter{}
	_ = n.trackConn(closer3)
	count = 0
	n.activeConns.Range(func(_, _ any) bool { count++; return true })
	if count != 1 {
		t.Fatalf("after fresh trackConn, active=%d, want 1", count)
	}
	_ = tc2 // keep ref for clarity
}

// fakeCloseCounter is a minimal net.Conn that counts Close calls.
// Only Close is exercised; the other net.Conn methods are nil-bodied.
type fakeCloseCounter struct {
	closes int
}

func (f *fakeCloseCounter) Read([]byte) (int, error)         { return 0, nil }
func (f *fakeCloseCounter) Write([]byte) (int, error)        { return 0, nil }
func (f *fakeCloseCounter) Close() error                     { f.closes++; return nil }
func (f *fakeCloseCounter) LocalAddr() net.Addr              { return nil }
func (f *fakeCloseCounter) RemoteAddr() net.Addr             { return nil }
func (f *fakeCloseCounter) SetDeadline(time.Time) error      { return nil }
func (f *fakeCloseCounter) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeCloseCounter) SetWriteDeadline(time.Time) error { return nil }

// fakePacketConn is a net.Conn that also implements net.PacketConn, mimicking
// gVisor's *UDPConn.
type fakePacketConn struct {
	fakeCloseCounter
	reads, writes int
}

func (f *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) { f.reads++; return 0, nil, nil }
func (f *fakePacketConn) WriteTo([]byte, net.Addr) (int, error)  { f.writes++; return 0, nil }

// TestTrackedPacketConn checks that a UDP-style conn (implementing
// net.PacketConn) is handed back as a net.PacketConn — Go's resolver relies on
// this to pick datagram framing — while a plain net.Conn is not, and that both
// remain tracked for reconnect close.
func TestTrackedPacketConn(t *testing.T) {
	t.Parallel()
	n := &Net{}

	pc := &fakePacketConn{}
	conn := n.trackConn(pc)
	got, ok := conn.(net.PacketConn)
	if !ok {
		t.Fatal("UDP-style conn must be exposed as net.PacketConn")
	}
	// ReadFrom/WriteTo forward to the underlying packet conn.
	_, _, _ = got.ReadFrom(nil)
	_, _ = got.WriteTo(nil, nil)
	if pc.reads != 1 || pc.writes != 1 {
		t.Fatalf("ReadFrom/WriteTo not forwarded: reads=%d writes=%d", pc.reads, pc.writes)
	}

	// A plain stream conn must NOT masquerade as a packet conn.
	plain := n.trackConn(&fakeCloseCounter{})
	if _, ok := plain.(net.PacketConn); ok {
		t.Fatal("stream conn must not be exposed as net.PacketConn")
	}

	// Both are tracked and force-closed on reconnect.
	if closed := n.closeActiveOnReconnect(); closed != 2 {
		t.Fatalf("closeActiveOnReconnect = %d, want 2", closed)
	}
	if pc.closes != 1 {
		t.Fatalf("packet conn closed %d times, want 1", pc.closes)
	}
}

// TestClampInnerMTU verifies the conservative NIC MTU policy: gVisor's
// NIC MTU must never exceed safeInnerMTU, regardless of what the
// server pushes. This is the architectural equivalent of the
// official OpenVPN client's MSS clamping (mssfix=1492) — gVisor TCP
// auto-negotiates MSS based on NIC MTU, so capping the NIC MTU
// caps the MSS apps inside the tunnel will use, which keeps every
// outer wire datagram comfortably under 1500 bytes after
// OpenVPN/UDP/IP encapsulation.
func TestClampInnerMTU(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		pushed uint32
		want   uint32
	}{
		{"server pushes 1500 (typical): clamp to safe", 1500, safeInnerMTU},
		{"server pushes 1492 (PPPoE): clamp to safe", 1492, safeInnerMTU},
		{"server pushes exactly safeInnerMTU: pass through", safeInnerMTU, safeInnerMTU},
		{"server pushes below safe: respect server", 1280, 1280},
		{"server pushes well below safe: respect server", 576, 576},
		{"server pushes 0 (no MTU pushed): default to safe", 0, safeInnerMTU},
	}
	for _, tc := range cases {
		tc := tc // capture range var (pre-go1.22 loopvar semantics)
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := clampInnerMTU(tc.pushed); got != tc.want {
				t.Errorf("clampInnerMTU(%d) = %d, want %d", tc.pushed, got, tc.want)
			}
		})
	}
}

func TestSubnetFromPrefix(t *testing.T) {
	t.Parallel()
	// Pin some IPv4 prefix and verify it survives the round-trip without
	// losing host bits.
	p := netip.MustParsePrefix("10.8.0.0/24")
	subnet, err := tcpipSubnetFromPrefix(p)
	if err != nil {
		t.Fatalf("subnet: %v", err)
	}
	id := subnet.ID()
	addrBytes := id.AsSlice()
	if !bytes.Equal(addrBytes, []byte{10, 8, 0, 0}) {
		t.Fatalf("got id %v, want 10.8.0.0", addrBytes)
	}
	if subnet.Prefix() != 24 {
		t.Fatalf("prefix=%d, want 24", subnet.Prefix())
	}
}

// TestBuildRoutesIPv6Only is a regression for the fallback that used to
// install only an IPv4 on-link default: a v6-only assignment (no Gateway, no
// RemoteIP6, no explicit routes) must still get an IPv6 default route, else
// gVisor has no route for its own family and every v6 dial fails.
func TestBuildRoutesIPv6Only(t *testing.T) {
	t.Parallel()
	pr := TunConfig{
		LocalIP6: netip.MustParsePrefix("2001:db8::7/64"),
		// Deliberately no Gateway / RemoteIP6 / Routes — exercise the
		// no-gateway fallback path.
	}
	routes := buildRoutes(pr)
	var sawV6Default bool
	for _, r := range routes {
		if r.Destination.Equal(header.IPv6EmptySubnet) {
			sawV6Default = true
		}
	}
	if !sawV6Default {
		t.Fatalf("v6-only config produced no IPv6 on-link default; got routes=%v", routes)
	}
}

// TestFinalizeDialReconnectGuard exercises the reconnect-generation guard in
// isolation (no gVisor, no races): when the generation moved between the
// pre-dial snapshot and finalizeDial, the conn is force-closed and
// ErrTunnelIPChanged is returned; when it didn't, the tracked conn comes back
// untouched and registered.
func TestFinalizeDialReconnectGuard(t *testing.T) {
	t.Parallel()

	t.Run("reconnect during dial", func(t *testing.T) {
		t.Parallel()
		n := &Net{}
		preGen := n.reconnectGen.Load()
		n.reconnectGen.Add(1) // simulate an OnReconfigure hook firing mid-dial
		conn := &fakeCloseCounter{}

		got, err := n.finalizeDial(conn, preGen, "tcp")
		if !errors.Is(err, ErrTunnelIPChanged) {
			t.Fatalf("err = %v, want ErrTunnelIPChanged", err)
		}
		if got != nil {
			t.Fatalf("conn = %v, want nil on guard trip", got)
		}
		if conn.closes != 1 {
			t.Fatalf("underlying conn closed %d times, want 1 (force-close on guard)", conn.closes)
		}
		count := 0
		n.activeConns.Range(func(_, _ any) bool { count++; return true })
		if count != 0 {
			t.Fatalf("activeConns has %d entries after guard trip, want 0", count)
		}
	})

	t.Run("dial sampled mid-reconfiguration", func(t *testing.T) {
		t.Parallel()
		// An odd preGen means the dial sampled the generation between the
		// OnReconfigure hook's entry and exit bumps — the conn may be bound to
		// the about-to-be-replaced address and may have slipped past
		// closeActiveOnReconnect's Range. finalizeDial must reject it even
		// though the generation does not move again before the re-check.
		n := &Net{}
		n.reconnectGen.Add(1) // hook entered (odd = reconfiguration in progress)
		preGen := n.reconnectGen.Load()
		conn := &fakeCloseCounter{}

		got, err := n.finalizeDial(conn, preGen, "tcp")
		if !errors.Is(err, ErrTunnelIPChanged) {
			t.Fatalf("err = %v, want ErrTunnelIPChanged", err)
		}
		if got != nil {
			t.Fatalf("conn = %v, want nil on guard trip", got)
		}
		if conn.closes != 1 {
			t.Fatalf("underlying conn closed %d times, want 1 (force-close on guard)", conn.closes)
		}
		count := 0
		n.activeConns.Range(func(_, _ any) bool { count++; return true })
		if count != 0 {
			t.Fatalf("activeConns has %d entries after guard trip, want 0", count)
		}
	})

	t.Run("no reconnect", func(t *testing.T) {
		t.Parallel()
		n := &Net{}
		preGen := n.reconnectGen.Load()
		conn := &fakeCloseCounter{}

		got, err := n.finalizeDial(conn, preGen, "tcp")
		if err != nil {
			t.Fatalf("finalizeDial: %v", err)
		}
		if _, ok := got.(*trackedConn); !ok {
			t.Fatalf("got %T, want *trackedConn", got)
		}
		if conn.closes != 0 {
			t.Fatalf("conn closed %d times, want 0", conn.closes)
		}
		count := 0
		n.activeConns.Range(func(_, _ any) bool { count++; return true })
		if count != 1 {
			t.Fatalf("activeConns has %d entries, want 1 (tracked)", count)
		}
	})
}

// TestWritePacketsSkipsReservedPrepend exercises the AsViewList path on a
// realistic packet shape: reserved header space plus a pushed network header
// across multiple views. WritePackets must emit exactly the on-wire bytes
// (header + payload) and drop the unused reserved prepend (off > 0), without
// which it would send garbage prepend bytes or corrupt the datagram.
func TestWritePacketsSkipsReservedPrepend(t *testing.T) {
	t.Parallel()
	cli, srv := net.Pipe()
	defer func() { _ = cli.Close() }()
	defer func() { _ = srv.Close() }()

	ep := newEndpoint(cli, 1500)
	defer ep.Close()
	ep.Attach(newFakeDispatcher())

	payload := []byte("payload-bytes")
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 40,
		Payload:            buffer.MakeWithData(payload),
	})
	hdr := pkt.NetworkHeader().Push(4)
	copy(hdr, []byte{0xDE, 0xAD, 0xBE, 0xEF})
	defer pkt.DecRef()

	var pbl stack.PacketBufferList
	pbl.PushBack(pkt)

	wroteCh := make(chan int, 1)
	go func() {
		n, err := ep.WritePackets(pbl)
		if err != nil {
			t.Errorf("WritePackets: %v", err)
		}
		wroteCh <- n
	}()

	want := append([]byte{0xDE, 0xAD, 0xBE, 0xEF}, payload...)
	buf := make([]byte, 128)
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	if got := buf[:n]; !bytes.Equal(got, want) {
		t.Fatalf("on-wire = %x, want %x (reserved prepend not skipped / views mishandled)", got, want)
	}
	if n := <-wroteCh; n != 1 {
		t.Fatalf("WritePackets returned n=%d, want 1", n)
	}
}

// TestStackDestroyDoesNotDeadlock guards the Attach(nil) Wait() fix: a caller
// using the public Stack() accessor to Destroy()/Wait() the stack must not
// hang. removeNIC detaches us via Attach(nil) and then blocks on
// LinkEndpoint.Wait(); without closing e.done from Attach(nil) that blocks
// forever (no reader goroutine exists to close it).
func TestStackDestroyDoesNotDeadlock(t *testing.T) {
	t.Parallel()
	cli, srv := net.Pipe()
	defer func() { _ = srv.Close() }()

	ep := newEndpoint(cli, 1500)
	s := stack.New(stack.Options{})
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}

	done := make(chan struct{})
	go func() {
		s.Destroy() // Close + Wait; Wait → LinkEndpoint.Wait() → <-e.done
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stack.Destroy() deadlocked on endpoint.Wait()")
	}
}

// TestNetStatsSub guards the array-based delta loop: every metric index must be
// subtracted, with no field silently skipped (the bug class the struct→array
// refactor exists to prevent).
func TestNetStatsSub(t *testing.T) {
	t.Parallel()
	var cur, prev netStats
	for i := range cur {
		cur[i] = uint64(i*100 + 1000)
		prev[i] = uint64(i * 3)
	}
	d := cur.sub(prev)
	for i := range d {
		if want := cur[i] - prev[i]; d[i] != want {
			t.Errorf("sub[%d] = %d, want %d", i, d[i], want)
		}
	}
}

// TestStatsMetricDefsComplete catches a metric index that was added to the
// enum/snapStats but forgotten in metricDefs (it would otherwise never be
// logged), and confirms the one gauge stays a gauge.
func TestStatsMetricDefsComplete(t *testing.T) {
	t.Parallel()
	for i := 0; i < numMetrics; i++ {
		m := metricDefs[i]
		if m.deltaKey == "" && m.totalKey == "" && m.gaugeKey == "" {
			t.Errorf("metric index %d has no log key — forgotten metricDefs entry", i)
		}
	}
	if metricDefs[mTCPCurEst].gaugeKey == "" {
		t.Error("mTCPCurEst must be logged as a gauge (current value, no delta)")
	}
}

// TestSnapStatsEndpointCounters verifies snapStats maps each LinkEndpoint
// counter to the correct metric index.
func TestSnapStatsEndpointCounters(t *testing.T) {
	t.Parallel()
	n, cleanup := newTestNet(t)
	defer cleanup()

	n.ep.statsOutPackets.Store(11)
	n.ep.statsOutErrors.Store(22)
	n.ep.statsInPackets.Store(33)
	n.ep.statsInTCP.Store(44)
	n.ep.statsInUDP.Store(55)
	n.ep.statsInICMP.Store(66)
	n.ep.statsInPanics.Store(77)

	s := n.snapStats()
	for _, c := range []struct {
		idx  int
		want uint64
	}{
		{mOutPkts, 11}, {mOutErr, 22}, {mInPkts, 33}, {mInTCP, 44},
		{mInUDP, 55}, {mInICMP, 66}, {mInPanics, 77},
	} {
		if s[c.idx] != c.want {
			t.Errorf("snapStats[%d] = %d, want %d", c.idx, s[c.idx], c.want)
		}
	}
}

// halfCloseConn is a net.Conn that supports half-close (like gVisor's *TCPConn),
// counting forwarded CloseWrite/CloseRead calls.
type halfCloseConn struct {
	fakeCloseCounter
	cw, cr int
}

func (h *halfCloseConn) CloseWrite() error { h.cw++; return nil }
func (h *halfCloseConn) CloseRead() error  { h.cr++; return nil }

// TestTrackedConnHalfCloseUnsupported verifies a trackedConn over a conn that
// lacks half-close (gVisor's *UDPConn) reports errors.ErrUnsupported rather than
// a misleading nil, while a conn that supports half-close (TCP) forwards.
func TestTrackedConnHalfCloseUnsupported(t *testing.T) {
	t.Parallel()
	n := &Net{}

	plain := n.trackConn(&fakeCloseCounter{}).(*trackedConn)
	if err := plain.CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("CloseWrite on a non-half-close conn = %v, want ErrUnsupported", err)
	}
	if err := plain.CloseRead(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("CloseRead on a non-half-close conn = %v, want ErrUnsupported", err)
	}

	hc := &halfCloseConn{}
	tc := n.trackConn(hc).(*trackedConn)
	if err := tc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite forward: %v", err)
	}
	if err := tc.CloseRead(); err != nil {
		t.Fatalf("CloseRead forward: %v", err)
	}
	if hc.cw != 1 || hc.cr != 1 {
		t.Fatalf("half-close not forwarded: CloseWrite=%d CloseRead=%d, want 1/1", hc.cw, hc.cr)
	}
}

// TestTrackedPacketConnWriteToRejectsNonUDPAddr guards against the gonet
// *UDPConn.WriteTo panic on a non-*net.UDPAddr: trackedPacketConn must reject
// such an address with an error (not forward it and crash), while a *net.UDPAddr
// or nil is forwarded normally.
func TestTrackedPacketConnWriteToRejectsNonUDPAddr(t *testing.T) {
	t.Parallel()
	n := &Net{}
	pc := &fakePacketConn{}
	conn := n.trackConn(pc).(*trackedPacketConn)

	// A *net.TCPAddr would panic gonet's unchecked assertion — must be rejected.
	if _, err := conn.WriteTo([]byte("x"), &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5}); err == nil {
		t.Fatal("WriteTo(*net.TCPAddr) = nil error, want a rejection")
	}
	if pc.writes != 0 {
		t.Fatalf("a rejected WriteTo was still forwarded (writes=%d)", pc.writes)
	}

	// *net.UDPAddr is forwarded.
	if _, err := conn.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5}); err != nil {
		t.Fatalf("WriteTo(*net.UDPAddr): %v", err)
	}
	// A nil addr (connected-write case) is forwarded too.
	if _, err := conn.WriteTo([]byte("x"), nil); err != nil {
		t.Fatalf("WriteTo(nil): %v", err)
	}
	if pc.writes != 2 {
		t.Fatalf("valid WriteTo not forwarded (writes=%d, want 2)", pc.writes)
	}
}

// TestFinalizeDialRejectsAfterClose verifies a dial completing concurrently with
// Net.Close() is force-closed and reported as net.ErrClosed (not handed back
// with a nil error, and not left lingering in activeConns).
func TestFinalizeDialRejectsAfterClose(t *testing.T) {
	t.Parallel()
	n := &Net{}
	n.closeMu.Lock()
	n.closed = true
	n.closeMu.Unlock()

	conn := &fakeCloseCounter{}
	got, err := n.finalizeDial(conn, n.reconnectGen.Load(), "tcp")
	if got != nil {
		t.Fatalf("conn = %v, want nil when Net is closed", got)
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("err = %v, want net.ErrClosed", err)
	}
	if conn.closes != 1 {
		t.Fatalf("underlying conn closed %d times, want 1 (force-close on closed Net)", conn.closes)
	}
	count := 0
	n.activeConns.Range(func(_, _ any) bool { count++; return true })
	if count != 0 {
		t.Fatalf("activeConns has %d entries after a rejected dial, want 0", count)
	}
}

// deadlineConn records whether SetWriteDeadline was armed and counts Writes.
type deadlineConn struct {
	fakeCloseCounter
	writes     int
	deadlineMu sync.Mutex
	armed      bool
}

func (c *deadlineConn) Write(p []byte) (int, error) { c.writes++; return len(p), nil }
func (c *deadlineConn) SetWriteDeadline(time.Time) error {
	c.deadlineMu.Lock()
	c.armed = true
	c.deadlineMu.Unlock()
	return nil
}

// TestWritePacketsArmsWriteDeadline verifies WritePackets bounds its blocking
// time by arming a write deadline on a conn that supports SetWriteDeadline, so a
// stalled tunnel write during reconnect cannot block the data path forever.
func TestWritePacketsArmsWriteDeadline(t *testing.T) {
	t.Parallel()
	c := &deadlineConn{}
	ep := newEndpoint(c, 1500)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte("hi")),
	})
	defer pkt.DecRef()
	var pbl stack.PacketBufferList
	pbl.PushBack(pkt)

	if _, err := ep.WritePackets(pbl); err != nil {
		t.Fatalf("WritePackets: %v", err)
	}
	c.deadlineMu.Lock()
	armed := c.armed
	c.deadlineMu.Unlock()
	if !armed {
		t.Fatal("WritePackets did not arm a write deadline")
	}
	if c.writes != 1 {
		t.Fatalf("writes=%d, want 1", c.writes)
	}
}
