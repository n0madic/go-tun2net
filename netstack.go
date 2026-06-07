// SPDX-License-Identifier: MIT

// Package tun2net adapts a PacketTunnel — anything that carries raw IP
// datagrams (one Read/Write == one IP packet) — to a gVisor userspace TCP/IP
// stack. The stack consumes the inbound IP packets the tunnel decrypts and
// emits the outbound IP packets the tunnel encrypts and sends to the peer,
// exposing the result as an ordinary DialContext surface (use Stack() for the
// raw gVisor stack if you need to build listeners or other endpoints). Any
// pushed-IP VPN (OpenVPN, IKEv2/IPsec, WireGuard-style, …) plugs in by
// implementing PacketTunnel.
//
// Usage:
//
//	// tun implements tun2net.PacketTunnel (e.g. an adapter over a VPN client).
//	ns, err := tun2net.New(tun, logger)
//	if err != nil { ... }
//	defer ns.Close()
//
//	httpClient := &http.Client{Transport: &http.Transport{DialContext: ns.DialContext}}
//	resp, err := httpClient.Get("http://10.8.0.1:8080/")
//
//	// Server side: an in-stack TCP listener, also free of gVisor types.
//	ln, err := ns.ListenTCP(netip.MustParseAddrPort("10.8.0.2:80"))
package tun2net

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
)

// nicID is the only NIC we register inside the stack.
const nicID tcpip.NICID = 1

// ErrTunnelIPChanged is returned from Net.DialContext when an
// AutoReconnect-driven session swap happened while the gonet dial was in
// flight. It is detected via the reconnect generation counter bumped by the
// OnReconfigure hook, so it also covers a same-IP reconnect — the server can
// hand back the identical tunnel-local IP for a brand-new session, and
// comparing the generation rather than just the IP is what catches that case.
// The conn is force-closed before this error is returned (so callers don't
// leak a zombie endpoint bound to the pre-reconnect session). Use errors.Is to
// distinguish this from a generic dial failure — it's safe to retry the same
// dial immediately, the second attempt binds to the fresh state.
var ErrTunnelIPChanged = errors.New("netstack: tunnel reconnected during dial")

// safeInnerMTU caps the gVisor NIC's MTU so that, after OpenVPN
// encryption + UDP/IP outer headers, the resulting wire datagram
// fits within the lowest common path MTU we'll realistically see.
//
// Budget per wire datagram (worst case):
//
//	outer IPv4 header (20) + UDP header (8) +
//	OpenVPN encap (1 opcode + 3 peer-id + 4 pkt-id + 16 AEAD tag = 24)
//	= 52 bytes of overhead
//
// 1400 inner IP → 1452 outer wire. That fits 1500-MTU ethernet,
// 1492-MTU PPPoE, 1480-MTU VPN-in-VPN, and several other common
// "almost-1500" paths with margin. Setting the NIC MTU here is
// architecturally equivalent to the official OpenVPN client's
// runtime MSS clamping (`mssfix=1492` rewriting TCP SYN options on
// every packet, src/openvpn/mss.c): gVisor *is* the OS for apps
// inside the tunnel, so configuring its NIC MTU directly is
// sufficient — TCP MSS auto-negotiates to NIC_MTU - 40 = 1360 on
// every SYN gVisor generates, and apps respect it. Without this,
// a default 1500 inner MTU produces ~1552-byte outer datagrams
// that fragment or silently drop on any path with a strict
// 1500-byte MTU, which manifests as "tunnel works for a while
// then degrades under sustained TCP load".
const safeInnerMTU = 1400

// defaultMTU is the inner MTU assumed when a tunnel pushes no MTU at connect
// time, before clamping to safeInnerMTU.
const defaultMTU = 1500

// clampInnerMTU caps `pushed` at safeInnerMTU — it is a ceiling, not a floor:
// a zero or over-large value becomes safeInnerMTU, any smaller value is kept
// as-is. Used both at New time and on every reconnect so a server pushing a
// different MTU still gets clamped.
func clampInnerMTU(pushed uint32) uint32 {
	if pushed == 0 || pushed > safeInnerMTU {
		return safeInnerMTU
	}
	return pushed
}

// resolveMTU derives the inner NIC MTU from a server-pushed value and the MTU
// currently installed on the NIC, encoding the whole policy in one place. A
// pushed value is always clamped to safeInnerMTU. pushed==0 means "no MTU was
// pushed": at connect time (current==0) it defaults to defaultMTU before
// clamping, while on a reconnect/rekey (current>0) the current MTU is kept —
// servers rarely re-push MTU on rekey and the value negotiated at connect time
// is still correct.
func resolveMTU(pushed, current uint32) uint32 {
	if pushed == 0 {
		if current == 0 {
			return clampInnerMTU(defaultMTU)
		}
		return current
	}
	return clampInnerMTU(pushed)
}

// endpoint is a stack.LinkEndpoint backed by a tunnel net.Conn that carries
// raw IP datagrams (one Read = one IP packet, one Write = one IP packet).
type endpoint struct {
	conn    net.Conn
	mtu     atomic.Uint32
	closeMu sync.Mutex
	closed  bool
	done    chan struct{}
	doneCh  sync.Once // closes done at most once (Attach(nil) OR Close)

	// dispatcher is read on every inbound packet (deliverInbound) and written
	// only by Attach, so it lives in an atomic.Pointer to keep that hot path
	// lock-free. Inbound IP packets are delivered via deliverInbound from the
	// tunnel inbound path (PacketTunnel.SetInbound); the endpoint never reads
	// e.conn itself — e.conn is the outbound-only pipe (WritePackets).
	dispatcher atomic.Pointer[stack.NetworkDispatcher]

	onClose func()

	// Diagnostic counters. Independent from session.statsOutboundOK
	// (which counts every WritePacket on the underlying transport,
	// including PINGs and other non-gVisor traffic). These count only
	// IP packets that traverse the gVisor LinkEndpoint, so a divergence
	// between (statsOutPackets here) and (statsOutboundOK in session)
	// localises whether a stuck data path is above or below this layer.
	statsOutPackets atomic.Uint64 // IP packets gVisor pushed to tunnel
	statsOutErrors  atomic.Uint64 // conn.Write failures
	statsInPackets  atomic.Uint64 // IP packets delivered up to gVisor

	// Per-L4-protocol counters for the inbound stream. Sniff the IP
	// header at the LinkEndpoint level (before gVisor sees the packet),
	// so we can compare "did UDP responses physically arrive from the
	// tunnel" (statsInUDP) against "did gVisor's UDP layer process them"
	// (UDP.PacketsReceived). A growing statsInUDP with flat UDP.PacketsReceived
	// pinpoints gVisor's IP-or-UDP demux as the loss point; a flat
	// statsInUDP rules our code out and indicts the network/server.
	statsInTCP  atomic.Uint64
	statsInUDP  atomic.Uint64
	statsInICMP atomic.Uint64

	// statsInPanics counts inbound packets whose DeliverNetworkPacket call
	// panicked and was recovered in endpoint.deliver. A non-zero delta means
	// gVisor's dispatch hit a bug on some inbound packet; the recover keeps a
	// single malformed packet from killing the whole inbound data path, and
	// the stats logger escalates to ERROR so the condition stays visible.
	statsInPanics atomic.Uint64

	// panicDetail holds the value + stack of the most recent recovered inbound
	// dispatch panic, captured in deliver. The stats logger surfaces it at
	// ERROR on the next tick so a black-holed traffic class is diagnosable
	// rather than a silent counter. Stored as a *string so the hot path stays
	// untouched until a (rare) panic actually fires.
	panicDetail atomic.Pointer[string]

	// statsMaxDeliverNs is the high-water mark of how long a single
	// d.DeliverNetworkPacket call took (nanoseconds) since the last
	// statsLoggerLoop snapshot. In direct-delivery mode that call runs
	// synchronously on the session's read loop, so a slow gVisor
	// dispatcher under load translates directly into back-pressure on
	// the OS UDP receive buffer (CLAUDE.md point 10 failure mode). The
	// snapshot is Swap'd to 0 each tick so the logged value reflects
	// "worst single call in this 30s window" — not lifetime worst —
	// which is the actionable signal for tail-latency investigation.
	// Only 1-in-deliverSampleN packets are timed (see inject), so this is the
	// worst among the sampled calls, not literally every call.
	statsMaxDeliverNs atomic.Int64
}

// Compile-time guard.
var _ stack.LinkEndpoint = (*endpoint)(nil)

// newEndpoint wraps the given conn into a LinkEndpoint with the given MTU.
// Inbound packets arrive via deliverInbound (wired through
// PacketTunnel.SetInbound); the endpoint never reads conn itself, so Attach
// spawns no reader goroutine and conn is used only for outbound WritePackets.
func newEndpoint(conn net.Conn, mtu uint32) *endpoint {
	e := &endpoint{
		conn: conn,
		done: make(chan struct{}),
	}
	e.mtu.Store(mtu)
	return e
}

func (e *endpoint) MTU() uint32 { return e.mtu.Load() }

func (e *endpoint) SetMTU(m uint32) { e.mtu.Store(m) }

func (*endpoint) MaxHeaderLength() uint16 { return 0 }

// LinkAddress and SetLinkAddress are required by the stack.LinkEndpoint
// interface but carry no state here: this is a header-less, no-L2 endpoint
// (MaxHeaderLength==0, ARPHardwareNone), so it has no link address. Returning a
// constant keeps the per-packet gVisor LinkAddress() call lock-free.
func (*endpoint) LinkAddress() tcpip.LinkAddress { return "" }

func (*endpoint) SetLinkAddress(tcpip.LinkAddress) {}

// Capabilities advertises RX checksum offload so gVisor does NOT re-verify the
// L4 (TCP/UDP) checksum of inbound packets. Inner packets arrive from a remote
// network where checksum offload routinely leaves forwarded/locally-generated
// segments with an incomplete checksum (normally finalized by the egress NIC);
// when such a packet is captured/encrypted before any NIC touches it (e.g. a
// VPN server forwarding internet traffic into ESP), its inner checksum is
// "wrong" yet the packet is perfectly valid. The tunnel's own integrity
// guarantee (ESP ICV / OpenVPN HMAC) already authenticates the bytes, so
// re-checking the inner checksum is both redundant and harmful — it silently
// drops legitimate traffic. TX offload is deliberately NOT set: outbound
// packets must carry a real checksum the remote stack will verify.
//
// Note the breadth of this flag in the pinned gVisor: RXChecksumOffload makes
// the IPv4 layer skip verifying the IP *header* checksum too (ipv4.go:1839),
// not just the L4 (TCP/UDP) checksum — both are treated as already validated
// by the tunnel's integrity guarantee. That is the behaviour we want here, but
// it is wider than the name suggests.
func (*endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

// Attach wires the dispatcher. No reader goroutine is started: inbound IP
// packets reach the dispatcher via deliverInbound, called from the tunnel's
// inbound fast-path (PacketTunnel.SetInbound). The endpoint uses conn only for
// outbound (WritePackets). Called once by stack.Stack.CreateNIC.
func (e *endpoint) Attach(d stack.NetworkDispatcher) {
	if d == nil {
		e.dispatcher.Store(nil)
		// d == nil means the NIC is being removed (stack teardown / RemoveNIC).
		// gVisor's removeNIC detaches us via Attach(nil) and then blocks on
		// LinkEndpoint.Wait() BEFORE any endpoint Close runs. No reader
		// goroutine exists to close e.done, so we must release Wait() here or
		// Stack().Wait()/Destroy() deadlocks. sync.Once makes this idempotent
		// with the close in Close().
		e.doneCh.Do(func() { close(e.done) })
		return
	}
	e.dispatcher.Store(&d)
}

func (e *endpoint) IsAttached() bool {
	return e.dispatcher.Load() != nil
}

func (e *endpoint) Wait() {
	<-e.done
}

func (*endpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }

func (*endpoint) AddHeader(*stack.PacketBuffer) {}

// ParseHeader on a header-less endpoint is a no-op that always succeeds.
func (*endpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

// Close shuts the endpoint. The reader goroutine exits as soon as the
// Close shuts the endpoint. Nothing reads e.conn (inbound arrives via
// deliverInbound), so there is no reader goroutine to wake — Close just closes
// the conn so further outbound Write fails, and releases Wait(). conn.Close()
// is called so non-tunnel net.Conn implementations behave normally; a tunnel
// Conn whose Close() is a no-op (some handles survive across reconnects) is
// unaffected because we never block on its Read. Idempotent.
func (e *endpoint) Close() {
	e.closeMu.Lock()
	already := e.closed
	e.closed = true
	cb := e.onClose
	e.closeMu.Unlock()
	if already {
		return
	}
	_ = e.conn.Close()
	// Nothing else closes e.done in the common path (Attach(nil) only fires on
	// NIC removal), so drive it from Close. sync.Once makes the double-close
	// with Attach(nil) harmless. Wait() returns the moment Close ran.
	e.doneCh.Do(func() { close(e.done) })
	if cb != nil {
		cb()
	}
}

func (e *endpoint) SetOnCloseAction(f func()) {
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	e.onClose = f
}

// deliverSampleN sets the 1-in-N sampling rate for the dispatcher-latency
// high-water mark in deliverInbound. Must be a power of two so the hot path can
// pick a sample with a bitmask instead of a modulo.
const deliverSampleN = 16

// deliverInbound is the inbound entry wired via PacketTunnel.SetInbound: one
// decrypted IP datagram in, delivered straight up the stack. It parses the IP
// version to pick the network protocol, buckets the L4 protocol for stats, and
// hands the packet to the attached dispatcher.
//
// ip is the plaintext datagram from the AEAD decrypt; the caller is free to
// reuse the backing memory once this returns (buffer.MakeWithData copies, see
// below). A missing dispatcher is a per-packet drop — the session keeps calling
// deliverInbound on subsequent packets and a late Attach resumes normal flow
// without restarting anything.
func (e *endpoint) deliverInbound(ip []byte) {
	n := len(ip)
	if n < 1 {
		return
	}
	var proto tcpip.NetworkProtocolNumber
	var transProto tcpip.TransportProtocolNumber
	switch header.IPVersion(ip) {
	case header.IPv4Version:
		proto = header.IPv4ProtocolNumber
		if n >= header.IPv4MinimumSize {
			transProto = tcpip.TransportProtocolNumber(header.IPv4(ip).Protocol())
		}
	case header.IPv6Version:
		proto = header.IPv6ProtocolNumber
		// NextHeader (not the deprecated TransportProtocol) keeps this cheap:
		// we deliberately don't walk IPv6 extension-header chains, so
		// mis-bucketing a fragmented/extension-laden packet is harmless for a
		// frequency-only diagnostic.
		if n >= header.IPv6MinimumSize {
			transProto = tcpip.TransportProtocolNumber(header.IPv6(ip).NextHeader())
		}
	default:
		// Unknown IP version — nothing to deliver.
		return
	}

	dp := e.dispatcher.Load()
	if dp == nil {
		return
	}

	// Bucket L4 only once we know the packet will actually be delivered, so the
	// per-protocol counters stay consistent with statsInPackets.
	switch transProto {
	case header.TCPProtocolNumber:
		e.statsInTCP.Add(1)
	case header.UDPProtocolNumber:
		e.statsInUDP.Add(1)
	case header.ICMPv4ProtocolNumber, header.ICMPv6ProtocolNumber:
		e.statsInICMP.Add(1)
	}

	// buffer.MakeWithData copies (verified in gVisor view.go:
	// NewViewWithData → newChunk(len(data)) + v.Write(data) → copy(...)).
	// The input slice is NOT retained, so it's safe to pass ip directly —
	// no defensive `append([]byte(nil), ip...)` needed even when the
	// caller (session.handleDataIn) reuses the backing array.
	// TestDeliverInboundCopiesPayload guards this assumption against a
	// future gVisor bump that might switch MakeWithData to zero-copy.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(ip),
	})
	// Sample the dispatcher latency on 1-in-deliverSampleN packets. time.Now()
	// is a cheap (~25 ns) syscall-free clock read on darwin/arm64, but on a
	// multi-Gbps inbound stream even that per-packet cost is worth shedding;
	// the 30s high-water mark stays just as useful sampled. statsInPackets is
	// the running inbound total, so masking it yields a fixed 1/deliverSampleN
	// rate with no extra counter.
	count := e.statsInPackets.Add(1)
	measure := count&(deliverSampleN-1) == 0
	var start time.Time
	if measure {
		start = time.Now()
	}
	e.deliver(*dp, proto, pkt)
	if measure {
		// Maintain the "worst single deliver in this window" high-water mark
		// with a CAS loop. The inbound path is single-goroutine, but the stats
		// logger concurrently Swap(0)s this value once per tick; a plain
		// load-then-store would race that Swap (drop a sample or write into the
		// wrong window). The CAS makes the update a single linearizable op.
		elapsed := time.Since(start).Nanoseconds()
		for {
			cur := e.statsMaxDeliverNs.Load()
			if elapsed <= cur || e.statsMaxDeliverNs.CompareAndSwap(cur, elapsed) {
				break
			}
		}
	}
}

// deliver hands one inbound PacketBuffer to the dispatcher with two
// guarantees: the buffer's ref is always released (the deferred DecRef runs
// even on a panic), and a panic inside gVisor's dispatch — e.g. a malformed
// inbound packet tripping a bug deep in the IP/transport demux — is recovered
// so it kills only this one packet, not the entire inbound data path (that path
// is the session read loop, so an unrecovered panic would tear down the whole
// tunnel).
//
// The recover does NOT re-panic, even on a runtime.Error: inbound bytes are
// network-controlled (the VPN server forwards internet traffic into the
// tunnel), so crashing here would hand a remote peer a denial-of-service
// trigger — a single crafted packet that trips a gVisor bug could kill the
// client on every retransmit. Instead the value + stack are captured into
// panicDetail and the stats logger surfaces them at ERROR on the next tick, so
// a deterministically black-holed traffic class is diagnosable rather than a
// silent counter. The single deferred closure costs a few nanoseconds per
// packet — a worthwhile premium for not letting one bad packet take down the
// data plane.
func (e *endpoint) deliver(d stack.NetworkDispatcher, proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	defer func() {
		pkt.DecRef()
		if r := recover(); r != nil {
			e.statsInPanics.Add(1)
			detail := fmt.Sprintf("%v\n%s", r, debug.Stack())
			e.panicDetail.Store(&detail)
		}
	}()
	d.DeliverNetworkPacket(proto, pkt)
}

// writeTimeout bounds how long a stalled conn.Write may block. A packet
// tunnel's Write is normally non-blocking, but during a reconnect/rekey the
// underlying transport can stall; an unbounded stall on the data path
// propagates into any goroutine driving an outbound send — including the
// OnReconfigure hook's Abort sweep, which holds Net.closeMu and would otherwise
// pin teardown (a concurrent Net.Close() blocks on the same lock).
//
// SetWriteDeadline is a single per-conn (per-fd) property, and gVisor drives
// WritePackets concurrently from many transport goroutines, so this is NOT a
// strict per-batch bound: a wedged write is released roughly writeTimeout after
// the LAST concurrent arm, not after its own. That looseness is benign here —
// in the stall case the fix targets, every writer to the wedged conn blocks
// inside conn.Write and so cannot re-arm, freezing the deadline and making the
// ~writeTimeout bound hold; and even in the worst case it is strictly better
// than the prior code, which had no deadline and blocked forever. The value is
// far above any healthy write latency, so it never trips under normal load; on
// timeout the write fails and gVisor TCP retransmits, the correct recovery.
const writeTimeout = 5 * time.Second

// WritePackets serialises each PacketBuffer to a single IP datagram and
// writes it to the underlying tunnel Conn.
//
// TODO(perf): on Linux this loop is the choke point for bulk-egress
// throughput. Each iteration becomes one sendmsg syscall down in
// internal/transport — gVisor TCP frequently hands us batches of 8-32
// PacketBuffers, so we're paying 8-32x the syscall cost we need to.
// A real sendmmsg path would require: (a) sealing each plaintext
// independently in Session, (b) collecting the wire-format encrypted
// bytes into a [][]byte, (c) handing the batch to a new
// transport.PacketBatchWriter optional interface, (d) implementing
// that via golang.org/x/net/ipv4.PacketConn.WriteBatch on Linux only.
// AEAD seal remains per-packet (the cipher state isn't batchable) so
// the saving is the syscall ratio, not the crypto.
func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	// Arm a write deadline so a stalled conn.Write can't block forever (one
	// syscall per batch, not per packet). The deadline is conn-wide and re-armed
	// by every concurrent WritePackets caller, so it bounds a wedged write to
	// roughly writeTimeout after the last arm rather than strictly per batch —
	// see the writeTimeout doc for why that is benign and still an improvement.
	if d, ok := e.conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = d.SetWriteDeadline(time.Now().Add(writeTimeout))
	}
	var wrote int
	var scratch []byte
	for _, pkt := range pkts.AsSlice() {
		// Fast path: most IP packets out of gVisor live as a single view
		// (we built the NIC with no link header, and IP fragmentation is
		// rare given our 1400-byte inner MTU). AsViewList exposes the views
		// WITHOUT allocating a [][]byte the way AsSlices does, so a
		// single-view packet really is zero-copy and zero-allocation: we
		// slice the backing bytes (past the unused reserved prepend `off`)
		// straight into conn.Write.
		vl, off := pkt.AsViewList()
		var data []byte
		switch vl.Len() {
		case 0:
			continue
		case 1:
			data = vl.Front().AsSlice()[off:]
		default:
			// Multi-view packet: must concat because conn.Write is a single
			// sendmsg per call (a UDP datagram boundary). Reuse one growing
			// scratch buffer across the batch so the cost is one alloc per
			// WritePackets call max, not per packet. Drop the first `off`
			// bytes of unused reserved prepend while copying.
			total := -off
			for v := vl.Front(); v != nil; v = v.Next() {
				total += v.Size()
			}
			if cap(scratch) < total {
				scratch = make([]byte, total)
			} else {
				scratch = scratch[:total]
			}
			skip, w := off, 0
			for v := vl.Front(); v != nil; v = v.Next() {
				s := v.AsSlice()
				if skip > 0 {
					if skip >= len(s) {
						skip -= len(s)
						continue
					}
					s = s[skip:]
					skip = 0
				}
				w += copy(scratch[w:], s)
			}
			data = scratch
		}
		if len(data) == 0 {
			continue
		}
		_, err := e.conn.Write(data)
		if err != nil {
			e.statsOutErrors.Add(1)
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
				return wrote, &tcpip.ErrClosedForSend{}
			}
			return wrote, &tcpip.ErrAborted{}
		}
		e.statsOutPackets.Add(1)
		wrote++
	}
	return wrote, nil
}

// Net is a thin facade over *stack.Stack that exposes net-like helpers
// (DialContext, plus Stack() for direct gVisor access) wired up to gVisor's
// gonet adapters.
//
// The NIC's IPv4/IPv6 addresses and route table are *not* fixed at
// construction time: when the underlying tunnel reconnects (and the
// server hands out a fresh tunnel IP / gateway / routes), `Net` reapplies
// the new config automatically via a PacketTunnel OnReconfigure hook
// registered in `New`. Without this, packets sent from gVisor after a
// reconnect would carry the old source IP and the server would silently
// drop them.
type Net struct {
	stack *stack.Stack
	ep    *endpoint
	log   *slog.Logger

	// nicMu protects the fields below — they're rewritten on every
	// reconnect when applyConfig runs. A family is "present" iff its
	// localV4/localV6 is valid; prefixV4/prefixV6 track the installed prefix
	// length so applyConfig can detect a mask-only change (same address, new
	// netmask) that an address comparison alone would miss.
	nicMu    sync.Mutex
	localV4  netip.Addr
	localV6  netip.Addr
	prefixV4 int
	prefixV6 int

	// reconnectGen is a seqlock over the OnReconfigure reconfiguration window,
	// not a plain swap counter: the hook bumps it ONCE on entry (to an odd
	// value — "reconfiguration in progress") and ONCE on exit (back to even),
	// so a completed reconnect advances it by 2. DialContext samples it before
	// dialing and finalizeDial re-checks it after; a conn is rejected when the
	// generation moved OR the sampled value was odd. Bumping on both edges (vs.
	// only before reconfiguration) closes the window where a dial samples the
	// already-incremented generation while the NIC still holds the old address:
	// such a dial sees an odd preGen and is force-closed, even when the server
	// hands back the SAME tunnel IP.
	reconnectGen atomic.Uint64

	closeMu sync.Mutex
	closed  bool
	tun     PacketTunnel

	// detachIngress is the detach function returned by
	// t.SetInbound in New. Called from Close to remove our
	// fast-path handler ONLY if it's still ours — guarding against a
	// later consumer that replaced us via a fresh SetIngressHandler
	// call. nil before New finishes wiring.
	detachIngress func()

	// detachOnReconnect unregisters the reconnect hook installed in New.
	// Called from Close so a Client that outlives this Net (rare but
	// possible — e.g. tests recreating Net for the same Client) doesn't
	// keep firing into a torn-down NIC.
	detachOnReconnect func()

	// statsStop closes when the periodic stats logger should exit.
	// Started in New, drained in Close. statsWG joins the loop so
	// Close doesn't return until the loop has finished its current
	// snap() — without that, Close racing stack.Close() can panic in
	// gVisor internals while the loop is reading Stats().
	statsStop chan struct{}
	statsWG   sync.WaitGroup

	// activeConns tracks every net.Conn handed out by DialContext so
	// they can be force-closed when the tunnel IP changes (see
	// closeActiveOnReconnect). Without this, gVisor TCP endpoints
	// bound to the OLD tunnel IP keep retransmitting with a
	// now-invalid src IP — the server drops those packets and
	// gVisor's TCP retransmit takes 60-120s to give up. Force-
	// closing matches what an OS kernel does via RTM_CHANGE when
	// a utun interface's address changes: apps see an immediate
	// ECONNRESET and retry on the new local IP. Keys are
	// *trackedConn (which embeds net.Conn). Map operations are
	// safe for concurrent use.
	activeConns sync.Map
}

// trackedConn wraps a net.Conn returned by Net.DialContext so the
// Net can force-close it on reconnect. The original conn is exposed
// via embedding for everything except Close (which deregisters from
// the tracker) and CloseWrite/CloseRead (which forward to the
// underlying conn if it supports them — gVisor's *TCPConn does,
// *UDPConn does not, and existing SOCKS5 callers depend on the
// type assertion `interface{ CloseWrite() error }` working when
// the underlying is TCP).
type trackedConn struct {
	net.Conn
	n      *Net
	closed atomic.Bool
}

// Close removes the conn from the active-conns tracker and closes
// the underlying conn. Idempotent. Safe to call from any goroutine.
func (t *trackedConn) Close() error {
	err := t.Conn.Close()
	if t.closed.CompareAndSwap(false, true) {
		t.n.activeConns.Delete(t)
	}
	return err
}

// CloseWrite forwards to the underlying conn if it supports half-close
// (gVisor's *TCPConn does). For conns that don't (gVisor's *UDPConn), it
// returns errors.ErrUnsupported rather than a misleading nil: a caller that
// type-asserts interface{ CloseWrite() error } and checks the result can then
// tell a real half-close from a no-op, instead of believing the write side was
// shut down when nothing happened. (A caller that ignores the error sees no
// behaviour change.)
func (t *trackedConn) CloseWrite() error {
	if cw, ok := t.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

// CloseRead is symmetric to CloseWrite.
func (t *trackedConn) CloseRead() error {
	if cr, ok := t.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return errors.ErrUnsupported
}

// trackedPacketConn extends trackedConn with the net.PacketConn surface
// (ReadFrom/WriteTo) so a gonet UDP conn handed back by DialContext is still
// recognised as a packet conn. This matters because Go's net.Resolver uses
// datagram framing (no 2-byte length prefix) only when the dialed conn
// satisfies net.PacketConn; without it, UDP DNS queries get a spurious TCP
// length prefix and are rejected. The embedded *trackedConn is what's
// registered in activeConns, so reconnect tracking is unchanged.
type trackedPacketConn struct {
	*trackedConn
	pc net.PacketConn
}

func (t *trackedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) { return t.pc.ReadFrom(p) }

// WriteTo forwards to the gonet *UDPConn, but first rejects any non-*net.UDPAddr
// destination: gonet's UDPConn.WriteTo does an unchecked addr.(*net.UDPAddr)
// assertion, so forwarding a *net.TCPAddr / *net.IPAddr / custom net.Addr would
// panic on the caller's goroutine (uncaught — deliver's recover only guards the
// inbound path). A nil addr is allowed through (gonet treats it as the
// connected-write case).
func (t *trackedPacketConn) WriteTo(p []byte, a net.Addr) (int, error) {
	if a != nil {
		if _, ok := a.(*net.UDPAddr); !ok {
			return 0, &net.OpError{Op: "write", Net: "udp", Addr: a,
				Err: fmt.Errorf("netstack: WriteTo requires *net.UDPAddr, got %T", a)}
		}
	}
	return t.pc.WriteTo(p, a)
}

// trackConn wraps a fresh conn from gonet into a trackedConn and
// registers it in activeConns. The returned conn is always safe to
// Close even if called multiple times. UDP conns (which implement
// net.PacketConn) are returned as a *trackedPacketConn so the packet-conn
// surface is preserved.
func (n *Net) trackConn(c net.Conn) net.Conn {
	if c == nil {
		return nil
	}
	tc := &trackedConn{Conn: c, n: n}
	n.activeConns.Store(tc, struct{}{})
	if pc, ok := c.(net.PacketConn); ok {
		return &trackedPacketConn{trackedConn: tc, pc: pc}
	}
	return tc
}

// closeActiveOnReconnect force-closes every active conn handed out
// by DialContext. Called from the OnReconnect hook AFTER the new
// PUSH_REPLY's addresses have been installed on the NIC, so any
// retry by the app's higher-level code immediately binds to the
// fresh local IP. Returns the number of conns closed (for logging).
func (n *Net) closeActiveOnReconnect() int {
	closed := 0
	n.activeConns.Range(func(k, _ any) bool {
		if tc, ok := k.(*trackedConn); ok {
			_ = tc.Close()
			closed++
		}
		return true
	})
	return closed
}

// New builds a userspace TCP/IP stack on top of a PacketTunnel. The tunnel
// must already be Dialed. The returned *Net manages a single NIC with the
// IPv4 address from PUSH_REPLY and a default route through the pushed gateway
// (or the on-link tunnel network if no gateway is pushed).
//
// Closing the Net releases the stack but does NOT close the underlying
// tunnel — the caller owns the tunnel lifecycle. (Use CloseAll if you
// want both torn down at once.)
func New(t PacketTunnel, log *slog.Logger) (*Net, error) {
	if t == nil {
		return nil, errors.New("tun2net: nil packet tunnel")
	}

	pr := t.Config()
	mtu := resolveMTU(pr.MTU, 0)

	conn := t.TunnelConn()
	if conn == nil {
		return nil, errors.New("tun2net: packet tunnel returned nil TunnelConn")
	}
	ep := newEndpoint(conn, mtu)

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		HandleLocal: false,
	})

	// stack.New already started the per-protocol worker goroutines, so every
	// error return below must close the stack or they leak (one orphaned stack
	// + its goroutines per failed New). s.Close signals those goroutines to
	// exit. ep spawns no goroutine and the tunnel conn it wraps is owned by the
	// caller, so we deliberately do NOT close ep here — a failed construction
	// must leave the caller's conn intact.
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()

	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("CreateNIC: %s", err)
	}
	// We are NAT/SNAT for ourselves — the OpenVPN endpoint already strips
	// link layer.  Spoofing & promiscuous keep the address-check liberal so
	// pushed-server-side replies reach us regardless of exact source.
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("SetSpoofing: %s", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("SetPromiscuousMode: %s", err)
	}

	n := &Net{stack: s, ep: ep, tun: t, log: log, statsStop: make(chan struct{})}

	if err := n.applyConfig(pr); err != nil {
		return nil, err
	}

	// Wire the fast-path: every decrypted inbound IP packet from the
	// session lands here synchronously on the session's read loop,
	// skipping ingressCh + Tunnel.Read + a reader-goroutine handoff. We keep
	// the returned detach func and use it from Net.Close — that's a
	// CAS-guarded clear that only fires if our handler is still the
	// registered one, so if another consumer replaced us on the Client
	// between New and Close we won't knock them out. The detach also
	// drains any in-flight invocation (via session.handlerMu), making
	// the subsequent stack.Close() race-free.
	n.detachIngress = t.SetInbound(ep.deliverInbound)

	// Track future reconnects: every successful AutoReconnect-driven session
	// replacement hands us a fresh tunnel IP / gateway. Without re-syncing
	// the NIC, post-reconnect packets carry the OLD source IP and the
	// server silently drops them.
	n.detachOnReconnect = t.OnReconfigure(func(pr TunConfig) {
		// Serialise against Close so a hook fire that overlapped with
		// Net.Close — possible because FireOnReconnect snapshots the
		// hook slice under hooksMu and then drops the lock before
		// invoking — cannot touch the gVisor stack after it has been
		// torn down. Lock order: closeMu → nicMu (Close also takes
		// closeMu first).
		n.closeMu.Lock()
		defer n.closeMu.Unlock()
		if n.closed {
			return
		}
		// Open the reconnect epoch: bump the generation to an ODD value to mark
		// "reconfiguration in progress" BEFORE applyConfig and
		// closeActiveOnReconnect run, and close it with a matching bump at the
		// end of the hook (see deferred bump below). Two edges, not one:
		//   - The entry bump catches a DialContext whose trackConn races
		//     closeActiveOnReconnect's Range — it observes the changed
		//     generation in finalizeDial and force-closes its just-registered
		//     conn (catches a same-IP reconnect an IP comparison would miss).
		//   - The odd value catches a DialContext that samples the generation
		//     AFTER this bump but while the NIC still holds the old address (the
		//     window between here and applyConfig). Its preGen is odd, so
		//     finalizeDial rejects it even though the generation never moves
		//     again before its re-check.
		// The hook holds closeMu for its whole body and returns early only above
		// (when closed), before this bump, so the odd→even invariant holds: the
		// generation is odd exactly while a reconfiguration is in flight.
		n.reconnectGen.Add(1)
		defer n.reconnectGen.Add(1)
		// Snapshot the pre-reconnect local addresses purely for log
		// context — we used to skip closing conns when the tunnel IP
		// stayed the same, but empirically that policy left zombie
		// TCP endpoints behind: ProtonVPN often hands us back the
		// same local IP (10.96.0.19 → 10.96.0.19) while the
		// server-side OpenVPN session is brand new (different
		// peer_id). The previous session's connection state is
		// gone, so even with the same 4-tuple the server doesn't
		// route packets for our old conns — gVisor TCP retransmits
		// 60-120s before giving up and apps stall. Always force-
		// close after reconnect.
		n.nicMu.Lock()
		oldV4, oldV6 := n.localV4, n.localV6
		n.nicMu.Unlock()

		if err := n.applyConfig(pr); err != nil && n.log != nil {
			n.log.Error("netstack applyConfig failed on reconnect", "err", err)
		}
		// resolveMTU keeps the current NIC MTU when the reconnect pushes none
		// (pr.MTU == 0) and clamps any value it does push.
		n.ep.SetMTU(resolveMTU(pr.MTU, n.ep.MTU()))

		n.nicMu.Lock()
		newV4, newV6 := n.localV4, n.localV6
		n.nicMu.Unlock()
		ipChanged := oldV4 != newV4 || oldV6 != newV6

		// Force-close every tracked conn unconditionally. Architectural
		// equivalent of the OS kernel's RTM_CHANGE on utun: apps see
		// ECONNRESET immediately and retry on a fresh endpoint, which
		// binds to whatever the current local IP is and registers
		// with the new server session.
		closed := n.closeActiveOnReconnect()
		if closed > 0 && n.log != nil {
			n.log.Info("netstack: force-closed conns after reconnect",
				"count", closed,
				"old_v4", oldV4, "new_v4", newV4,
				"old_v6", oldV6, "new_v6", newV6,
				"ip_changed", ipChanged,
			)
		}
		// closeActiveOnReconnect only reaches conns minted by DialContext.
		// Conns created directly through the public Stack() accessor are not
		// tracked, yet a CONNECTED one is just as bound to the now-stale server
		// session, so abort it too (idempotent for the tracked conns already
		// closed above). A TCP LISTENER is different: it is not a zombie bound
		// to a stale 4-tuple. On a same-IP reconnect its binding is still valid,
		// and aborting it would permanently break a consumer's server (Accept
		// starts erroring) on every rekey — so skip listeners unless the tunnel
		// IP actually changed (then the old-IP binding really is stale). Only a
		// TCP endpoint reports StateListen (value 10); no UDP/ICMP datagram
		// state (1..4) collides with it, so the cross-protocol State() read is
		// safe.
		for _, tep := range n.stack.RegisteredEndpoints() {
			if !ipChanged {
				if se, ok := tep.(interface{ State() uint32 }); ok &&
					tcp.EndpointState(se.State()) == tcp.StateListen {
					continue
				}
			}
			tep.Abort()
		}
	})

	// Start the periodic stats logger so operators can see whether
	// stuck data flows correspond to a problem in gVisor (e.g. growing
	// retransmits / send errors / endpoint leak) or below it. Pure
	// observability — does not take action on anything.
	n.statsWG.Add(1)
	go n.statsLoggerLoop()

	ok = true
	return n, nil
}

// applyConfig (re)installs the NIC's IPv4/IPv6 protocol addresses and route
// table from the supplied PushReply. Designed to be idempotent and safe to
// call from a reconnect hook: each family is reconciled by syncFamily, which
// adds the new address before removing the old one when only the address
// changed (no window without an address) and remove-then-adds on a mask-only
// change. Treats invalid / wrong-family PushReply fields as "drop the family"
// so a dual-stack → single-stack switch doesn't leave a stale address behind.
//
// Existing TCP/UDP gVisor connections that were bound to the OLD address
// continue to exist but their outbound packets carry the old source IP and
// will be dropped by the OpenVPN server in the new session — that's
// expected behaviour; client apps retry and the new conns bind to the
// fresh local IP.
func (n *Net) applyConfig(pr TunConfig) error {
	// Canonicalise addresses once on ingest so the v4/v6 family checks below
	// (and in buildRoutes / currentLocalFullAddress) behave identically no
	// matter which textual form the server pushed.
	pr = normalizeTunConfig(pr)

	n.nicMu.Lock()
	defer n.nicMu.Unlock()

	// Desired v4 state: a valid Is4 LocalIP plus its netmask-derived prefix,
	// else "no v4".
	var wantV4 netip.Addr
	wantV4Prefix := 0
	if pr.LocalIP.IsValid() && pr.LocalIP.Is4() {
		wantV4 = pr.LocalIP
		wantV4Prefix = maskPrefixLen(pr.Netmask)
	}
	// Desired v6 state from "ifconfig-ipv6 <local>/<plen> <peer>": LocalIP6
	// carries the address + prefix, RemoteIP6 the default next-hop (handled in
	// buildRoutes), mirroring how "route-gateway" supplies the IPv4 default.
	var wantV6 netip.Addr
	wantV6Prefix := 0
	if pr.LocalIP6.IsValid() && pr.LocalIP6.Addr().Is6() {
		wantV6 = pr.LocalIP6.Addr()
		wantV6Prefix = pr.LocalIP6.Bits()
		if wantV6Prefix < 0 || wantV6Prefix > 128 {
			wantV6Prefix = 128
		}
	}

	// Reconcile each family. Record the resulting state into the fields even on
	// error: they must mirror gVisor's actual NIC state so the next reconnect
	// neither re-adds an address gVisor already holds (ErrDuplicateAddress) nor
	// skips removing one it still does.
	var firstErr error
	v4, v4Prefix, err := n.syncFamily(ipv4.ProtocolNumber, n.localV4, n.prefixV4, wantV4, wantV4Prefix)
	n.localV4, n.prefixV4 = v4, v4Prefix
	if err != nil {
		firstErr = fmt.Errorf("v4: %w", err)
	}
	v6, v6Prefix, err := n.syncFamily(ipv6.ProtocolNumber, n.localV6, n.prefixV6, wantV6, wantV6Prefix)
	n.localV6, n.prefixV6 = v6, v6Prefix
	if err != nil && firstErr == nil {
		firstErr = fmt.Errorf("v6: %w", err)
	}

	// Reinstall the route table — SetRouteTable replaces (not merges), so any
	// old default-via-gateway entries get cleaned up automatically.
	routes := buildRoutes(pr)
	if firstErr != nil {
		// A family whose address failed to install must not keep a route
		// pointing at a NIC that has no source address of that family, or
		// egress for it blackholes until the next successful reconnect. Drop
		// those routes; keep the family that did install.
		kept := routes[:0]
		for _, r := range routes {
			if routeFamilyInstalled(r, n.localV4.IsValid(), n.localV6.IsValid()) {
				kept = append(kept, r)
			}
		}
		routes = kept
	}
	n.stack.SetRouteTable(routes)

	return firstErr
}

// normalizeTunConfig canonicalises every address in a TunConfig to its native
// family form, unmapping any IPv4-mapped-IPv6 literal (::ffff:a.b.c.d →
// a.b.c.d). applyConfig runs it on ingest so a v4 address pushed in ::ffff:
// form isn't silently dropped by the downstream Is4() family checks. Slice
// fields are only reallocated when an unmap actually changes an element, so the
// common (already-native) case stays allocation-free and never mutates the
// caller's backing array.
func normalizeTunConfig(pr TunConfig) TunConfig {
	pr.LocalIP = pr.LocalIP.Unmap()
	pr.Netmask = pr.Netmask.Unmap()
	pr.Gateway = pr.Gateway.Unmap()
	pr.RemoteIP6 = pr.RemoteIP6.Unmap()
	if pr.LocalIP6.IsValid() {
		pr.LocalIP6 = netip.PrefixFrom(pr.LocalIP6.Addr().Unmap(), pr.LocalIP6.Bits())
	}
	pr.Routes = normalizePrefixes(pr.Routes)
	pr.Routes6 = normalizePrefixes(pr.Routes6)
	return pr
}

// normalizePrefixes returns ps with every prefix's address unmapped. It returns
// ps unchanged (no allocation) when nothing is mapped; otherwise it copies so
// the caller's slice is never mutated.
func normalizePrefixes(ps []netip.Prefix) []netip.Prefix {
	for i, p := range ps {
		if !p.IsValid() || p.Addr().Unmap() == p.Addr() {
			continue
		}
		out := make([]netip.Prefix, len(ps))
		copy(out, ps)
		for j := i; j < len(out); j++ {
			if out[j].IsValid() {
				out[j] = netip.PrefixFrom(out[j].Addr().Unmap(), out[j].Bits())
			}
		}
		return out
	}
	return ps
}

// routeFamilyInstalled reports whether route r's address family currently has a
// local address on the NIC, so applyConfig can drop routes for a family whose
// address failed to install rather than blackhole its egress.
func routeFamilyInstalled(r tcpip.Route, haveV4, haveV6 bool) bool {
	switch r.Destination.ID().Len() {
	case 4:
		return haveV4
	case 16:
		return haveV6
	default:
		return true
	}
}

// syncFamily reconciles one address family on the NIC, returning the
// (address, prefix) now installed so applyConfig can record it. `have`/
// `havePrefix` is what's currently installed (have invalid == none), `want`/
// `wantPrefix` what the new config asks for (want invalid == drop the family).
//
// The reconcile order avoids a window where the NIC has no address of this
// family: on an address change the new address is added before the old one is
// removed. gVisor keys an address by its Address bytes alone, so a mask-only
// change (same Address, new PrefixLen) can't be layered on top — that returns
// ErrDuplicateAddress — so it is remove-then-add. The returned state always
// reflects what gVisor actually holds afterwards, including on an
// AddProtocolAddress failure, so a later reconnect can't desync.
func (n *Net) syncFamily(proto tcpip.NetworkProtocolNumber, have netip.Addr, havePrefix int, want netip.Addr, wantPrefix int) (netip.Addr, int, error) {
	// Family no longer wanted — drop any stale address.
	if !want.IsValid() {
		if have.IsValid() {
			n.removeAddr(have)
		}
		return netip.Addr{}, 0, nil
	}
	// Already in the desired state — nothing to do.
	if have.IsValid() && have == want && havePrefix == wantPrefix {
		return have, havePrefix, nil
	}

	// A mask-only change reuses the same Address, which AddProtocolAddress
	// would reject as a duplicate — remove the old one first.
	prefixOnly := have.IsValid() && have == want
	if prefixOnly {
		n.removeAddr(have)
	}

	addrProto := tcpip.ProtocolAddress{
		Protocol: proto,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(want.AsSlice()),
			PrefixLen: wantPrefix,
		},
	}
	if addErr := n.stack.AddProtocolAddress(nicID, addrProto, stack.AddressProperties{}); addErr != nil {
		err := fmt.Errorf("AddProtocolAddress: %s", addErr)
		if prefixOnly {
			// The old address was already removed; gVisor now holds none.
			return netip.Addr{}, 0, err
		}
		// The old address (if any) is still installed and untouched.
		return have, havePrefix, err
	}

	// Address change: now that the new address is installed it's safe to drop
	// the old one. (For prefixOnly we already removed it; for a fresh family
	// there was none.)
	if have.IsValid() && !prefixOnly {
		n.removeAddr(have)
	}
	return want, wantPrefix, nil
}

// removeAddr removes addr from the NIC, logging (but not failing on) a
// RemoveAddress error: a stale address that lingers is a diagnosable
// condition worth a WARN, not a fatal one for the reconnect path.
func (n *Net) removeAddr(addr netip.Addr) {
	if err := n.stack.RemoveAddress(nicID, tcpip.AddrFromSlice(addr.AsSlice())); err != nil && n.log != nil {
		n.log.Warn("netstack: RemoveAddress failed", "addr", addr, "err", err.String())
	}
}

// buildRoutes converts a PushReply's gateway+routes into a gVisor route
// table. Same logic the initial setup used; factored out so applyConfig
// can reuse it on reconnect.
func buildRoutes(pr TunConfig) []tcpip.Route {
	var routes []tcpip.Route
	if pr.Gateway.IsValid() && pr.Gateway.Is4() {
		routes = append(routes, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			Gateway:     netipToTCPIPAddr(pr.Gateway),
			NIC:         nicID,
		})
	}
	// IPv6 has no dedicated "route-gateway" directive; the standard OpenVPN
	// behaviour is to use the peer address from "ifconfig-ipv6" as the v6
	// default next-hop unless the server pushes an explicit "route-ipv6 ::/0".
	// gVisor's destination-match is first-hit, so synthesising the default
	// here is safe even when Routes6 also contains ::/0.
	if pr.RemoteIP6.IsValid() && pr.RemoteIP6.Is6() {
		routes = append(routes, tcpip.Route{
			Destination: header.IPv6EmptySubnet,
			Gateway:     netipToTCPIPAddr(pr.RemoteIP6),
			NIC:         nicID,
		})
	}
	addPrefixRoutes := func(prefixes []netip.Prefix) {
		for _, p := range prefixes {
			if !p.Addr().IsValid() {
				continue
			}
			sub, err := tcpipSubnetFromPrefix(p)
			if err != nil {
				continue
			}
			routes = append(routes, tcpip.Route{Destination: sub, NIC: nicID})
		}
	}
	addPrefixRoutes(pr.Routes)
	addPrefixRoutes(pr.Routes6)

	if len(routes) == 0 {
		// No gateway and no explicit routes were pushed. Install an on-link
		// default for EACH family that actually has a local address so the
		// stack knows that family's traffic should head out via the endpoint.
		// A v6-only assignment must get an IPv6 default — the old unconditional
		// IPv4-only fallback left such a NIC with no route for its own family.
		if pr.LocalIP6.IsValid() && pr.LocalIP6.Addr().Is6() {
			routes = append(routes, tcpip.Route{
				Destination: header.IPv6EmptySubnet,
				NIC:         nicID,
			})
		}
		// Add the v4 on-link default when there's a v4 address, or when nothing
		// else was added at all (preserving the prior behaviour in the fully
		// degenerate empty-config case).
		if (pr.LocalIP.IsValid() && pr.LocalIP.Is4()) || len(routes) == 0 {
			routes = append(routes, tcpip.Route{
				Destination: header.IPv4EmptySubnet,
				NIC:         nicID,
			})
		}
	}
	return routes
}

// Stack returns the underlying *stack.Stack so callers can register their own
// listeners, packet endpoints, sockopts, etc.
func (n *Net) Stack() *stack.Stack { return n.stack }

// localAddr returns the NIC's currently-installed address for one family
// (v4==true → IPv4, else IPv6), read under nicMu. It is the single locked-read
// primitive the public family accessors and the dial laddr path are built on,
// so the closeMu→nicMu lock order is honoured in exactly one place.
func (n *Net) localAddr(v4 bool) netip.Addr {
	n.nicMu.Lock()
	defer n.nicMu.Unlock()
	if v4 {
		return n.localV4
	}
	return n.localV6
}

// LocalIP returns the IPv4 address assigned to the tunnel (from PUSH_REPLY).
func (n *Net) LocalIP() netip.Addr { return n.localAddr(true) }

// LocalIP6 returns the IPv6 address assigned to the tunnel (from PUSH_REPLY's
// "ifconfig-ipv6" directive). Returns a zero value when the server did not
// push an IPv6 address.
func (n *Net) LocalIP6() netip.Addr { return n.localAddr(false) }

// HasIPv4 reports whether the NIC has an IPv4 address from the latest
// PUSH_REPLY. Callers use this to skip v4 dials when no v4 is configured.
func (n *Net) HasIPv4() bool { return n.localAddr(true).IsValid() }

// HasIPv6 reports whether the NIC has an IPv6 address from the latest
// PUSH_REPLY. Callers use this to fail fast on v6 dials when the server
// did not push an IPv6 address — gVisor would otherwise spend a route
// lookup and return ErrHostUnreachable, which is slower and noisier.
func (n *Net) HasIPv6() bool { return n.localAddr(false).IsValid() }

// Close tears down the netstack but leaves the underlying tunnel
// running. The tunnel Conn it was using is closed (so further Read/Write on
// it will fail), but Client.Close() is still the caller's responsibility.
func (n *Net) Close() error {
	n.closeMu.Lock()
	defer n.closeMu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	// Detach the fast-path BEFORE tearing down the stack. The detach
	// func returned by SetIngressHandler is CAS-guarded — it only
	// clears the Client's slot if our handler is still the registered
	// one. The session-level SetIngressHandler is RWMutex-guarded too,
	// so this call also blocks until every in-flight ep.deliverInbound
	// returns: stack.Close then runs on a quiescent gVisor stack with
	// no risk of a straggler DeliverNetworkPacket racing the teardown.
	if n.detachIngress != nil {
		n.detachIngress()
	}
	// Detach the reconnect hook so a Client outliving this Net never
	// invokes our applyConfig / closeActiveOnReconnect after the
	// underlying stack has been torn down.
	if n.detachOnReconnect != nil {
		n.detachOnReconnect()
	}
	// statsStop/stack/ep are nil on a Net assembled by hand (test helpers
	// build one directly rather than via New); guard each so Close stays
	// safe on a partially-constructed Net instead of panicking on a nil
	// channel close or a nil-receiver method call.
	if n.statsStop != nil {
		close(n.statsStop)
	}
	// Wait for statsLoggerLoop to finish its in-flight snap() before
	// tearing down the gVisor stack — without this, n.stack.Close()
	// can race a still-running n.stack.Stats() call inside the loop
	// and trip gVisor internals. Safe on a zero WaitGroup.
	n.statsWG.Wait()
	if n.stack != nil {
		n.stack.Close()
	}
	if n.ep != nil {
		n.ep.Close()
	}
	return nil
}

// statsLogPeriod is how often statsLoggerLoop emits a snapshot. Matched
// to the session's stats period so the two logs interleave on the same
// cadence and operators can correlate them.
const statsLogPeriod = 30 * time.Second

// Metric indices into netStats. Adding a counter is a one-line edit here, in
// snapStats (where it is read), and in metricDefs (where it is named for the
// log) — the delta math in sub and the logging loop both range over the array,
// so neither can silently skip or mis-pair a metric.
const (
	mOutPkts = iota
	mOutErr
	mInPkts
	mInTCP
	mInUDP
	mInICMP
	mInPanics
	mTCPSent
	mTCPSendErr
	mTCPRetrans
	mTCPResetsRcvd
	mTCPFailedOpens
	mTCPCurEst
	mUDPSent
	mUDPSendErr
	mUDPRcvd
	mUDPUnknownPort
	mIPSent
	mIPRcvd
	mIPMalformed
	mDropped
	numMetrics
)

// netStats is one snapshot of the LinkEndpoint counters plus the gVisor stack
// counters statsLoggerLoop tracks, indexed by the m* constants above.
type netStats [numMetrics]uint64

// metricDef names a metric for the structured log. deltaKey logs the per-window
// delta of a monotonic counter; totalKey additionally logs its running total;
// gaugeKey logs a gauge's current value (no delta — e.g. currently-established
// conns). Exactly the metrics with a non-empty key for a variant are emitted.
type metricDef struct {
	deltaKey string
	totalKey string
	gaugeKey string
}

var metricDefs = [numMetrics]metricDef{
	mOutPkts:        {deltaKey: "delta_ep_out", totalKey: "ep_out_total"},
	mOutErr:         {deltaKey: "delta_ep_out_err", totalKey: "ep_out_err_total"},
	mInPkts:         {deltaKey: "delta_ep_in", totalKey: "ep_in_total"},
	mInTCP:          {deltaKey: "delta_ep_in_tcp"},
	mInUDP:          {deltaKey: "delta_ep_in_udp", totalKey: "ep_in_udp_total"},
	mInICMP:         {deltaKey: "delta_ep_in_icmp"},
	mInPanics:       {deltaKey: "delta_ep_in_panics"},
	mTCPSent:        {deltaKey: "delta_tcp_sent"},
	mTCPSendErr:     {deltaKey: "delta_tcp_send_err"},
	mTCPRetrans:     {deltaKey: "delta_tcp_retrans"},
	mTCPResetsRcvd:  {deltaKey: "delta_tcp_resets_rcvd"},
	mTCPFailedOpens: {deltaKey: "delta_tcp_failed_opens"},
	mTCPCurEst:      {gaugeKey: "tcp_current_established"},
	mUDPSent:        {deltaKey: "delta_udp_sent"},
	mUDPSendErr:     {deltaKey: "delta_udp_send_err"},
	mUDPRcvd:        {deltaKey: "delta_udp_rcvd"},
	mUDPUnknownPort: {deltaKey: "delta_udp_unknown_port"},
	mIPSent:         {deltaKey: "delta_ip_sent"},
	mIPRcvd:         {deltaKey: "delta_ip_rcvd"},
	mIPMalformed:    {deltaKey: "delta_ip_malformed"},
	mDropped:        {deltaKey: "delta_dropped"},
}

// statsArgCap is the exact number of key/value slots a stats-log line emits,
// derived from metricDefs so it never drifts: each non-empty delta/total/gauge
// key contributes one key+value pair (2 slots), plus the trailing
// max_deliver_us pair. Computed once at init rather than guessed by a formula
// (the previous 2+numMetrics*2+2 hint under-counted because four metrics emit
// both a delta and a total, forcing a re-alloc every tick).
var statsArgCap = func() int {
	n := 2 // max_deliver_us
	for _, m := range metricDefs {
		if m.deltaKey != "" {
			n += 2
		}
		if m.totalKey != "" {
			n += 2
		}
		if m.gaugeKey != "" {
			n += 2
		}
	}
	return n
}()

// snapStats reads the current LinkEndpoint and gVisor stack counters.
func (n *Net) snapStats() netStats {
	st := n.stack.Stats()
	var s netStats
	s[mOutPkts] = n.ep.statsOutPackets.Load()
	s[mOutErr] = n.ep.statsOutErrors.Load()
	s[mInPkts] = n.ep.statsInPackets.Load()
	s[mInTCP] = n.ep.statsInTCP.Load()
	s[mInUDP] = n.ep.statsInUDP.Load()
	s[mInICMP] = n.ep.statsInICMP.Load()
	s[mInPanics] = n.ep.statsInPanics.Load()
	s[mTCPSent] = st.TCP.SegmentsSent.Value()
	s[mTCPSendErr] = st.TCP.SegmentSendErrors.Value()
	s[mTCPRetrans] = st.TCP.Retransmits.Value()
	s[mTCPResetsRcvd] = st.TCP.ResetsReceived.Value()
	s[mTCPFailedOpens] = st.TCP.FailedConnectionAttempts.Value()
	s[mTCPCurEst] = st.TCP.CurrentEstablished.Value()
	s[mUDPSent] = st.UDP.PacketsSent.Value()
	s[mUDPSendErr] = st.UDP.PacketSendErrors.Value()
	s[mUDPRcvd] = st.UDP.PacketsReceived.Value()
	s[mUDPUnknownPort] = st.UDP.UnknownPortErrors.Value()
	s[mIPSent] = st.IP.PacketsSent.Value()
	s[mIPRcvd] = st.IP.PacketsReceived.Value()
	s[mIPMalformed] = st.IP.MalformedPacketsReceived.Value()
	s[mDropped] = st.DroppedPackets.Value()
	return s
}

// sub returns the per-metric delta s - p. These are monotonic counters that
// never wrap in practice, so a plain subtraction is correct. The gauge metric
// (mTCPCurEst) is also subtracted here, but its delta is meaningless and the
// logger reads cur[mTCPCurEst] directly instead.
func (s netStats) sub(p netStats) netStats {
	var d netStats
	for i := range s {
		d[i] = s[i] - p[i]
	}
	return d
}

// statsLoggerLoop periodically logs a structured snapshot of the
// LinkEndpoint counters and key gVisor stack.Stats() fields. Designed
// to localise stuck data paths:
//
//   - Endpoint outPackets delta ≈ 0 while session outbound_ok is growing
//     → the stuck traffic is non-gVisor (e.g. keepalive only); apps
//     stopped sending through the netstack.
//   - Endpoint outPackets delta growing AND tcp_retransmits delta growing
//     → packets enter the tunnel from gVisor but aren't being acked;
//     either the wire is dropping them or the server's data path is sick.
//   - tcp_segment_send_errors > 0 → gVisor's own send path is failing;
//     usually means our WritePackets returned an error.
//   - udp_send_errors growing → ditto for UDP (DNS queries via gonet).
//   - tcp_current_established climbing without bound → endpoint leak;
//     our SOCKS5 layer isn't releasing TCP endpoints after Close.
//   - ip_packets_received delta vs endpoint inPackets delta: if endpoint
//     in is growing but IP received isn't, gVisor's IP layer is rejecting
//     the inbound (look at ip_malformed for confirmation).
func (n *Net) statsLoggerLoop() {
	defer n.statsWG.Done()
	t := time.NewTicker(statsLogPeriod)
	defer t.Stop()

	// Seed prev with a baseline snapshot taken now (at loop start the counters
	// are ~0), so the first tick logs a real first-window delta instead of
	// subtracting from a zero netStats — which would treat the cumulative gVisor
	// counters as the delta and could spuriously WARN on the very first line.
	prev := n.snapStats()
	for {
		select {
		case <-n.statsStop:
			return
		case <-t.C:
		}

		cur := n.snapStats()
		d := cur.sub(prev)
		prev = cur

		// Swap-and-reset: the next 30s window starts from 0 so the
		// reported number always means "worst single call IN THIS
		// WINDOW", which is the actionable form for tail-latency
		// regressions. Lifetime-max would freeze on the first big
		// spike and never recover.
		maxDeliverUs := n.ep.statsMaxDeliverNs.Swap(0) / 1000

		// Anything that looks like a real symptom escalates to WARN so
		// it surfaces without -v: outright errors, an elevated
		// retransmit rate, malformed packets, generic dropped packets,
		// or UDP responses landing on closed endpoints.
		//
		// `delta_tcp_resets_rcvd` is intentionally NOT included even
		// though it's surfaced in the message body for diagnosis. A
		// busy browsing session naturally produces a steady trickle
		// of RSTs because Apple/Google/Telegram services close
		// short-lived TCP via RST rather than graceful FIN, so any
		// > 0 threshold makes the line WARN on a perfectly healthy
		// tunnel. Same reasoning that retired the RST-storm watchdog
		// trigger — the metric is noise as a binary signal.
		level := slog.LevelDebug
		if d[mOutErr] > 0 || d[mTCPSendErr] > 0 || d[mUDPSendErr] > 0 ||
			d[mIPMalformed] > 0 || d[mDropped] > 0 || d[mUDPUnknownPort] > 0 {
			level = slog.LevelWarn
		}
		// TCP retransmits are a symptom only as a *fraction* of segments sent:
		// an absolute count scales with throughput, so the few tenths of a
		// percent of loss that is normal over the real internet trips an
		// absolute threshold on a perfectly healthy high-volume tunnel (the
		// same noise problem that excludes delta_tcp_resets_rcvd above).
		// Escalate only when retransmits exceed ~2% of what we sent this window,
		// with a small floor so a tiny window where one or two retransmits
		// dominate the ratio can't false-positive.
		if d[mTCPRetrans] > 10 && d[mTCPSent] > 0 && d[mTCPRetrans]*100 > d[mTCPSent]*2 {
			level = slog.LevelWarn
		}
		// A single gVisor dispatcher call eating >5 ms is the canonical
		// "fast-path back-pressure starting to bite" signal: the session
		// read loop is blocked exactly that long, and the OS UDP buffer
		// loses that many microseconds of receive headroom. 5 ms is well
		// above normal worst-case (sub-millisecond) and below typical
		// TCP RTT jitter, so it shouldn't trip on benign noise.
		if maxDeliverUs > 5_000 {
			level = slog.LevelWarn
		}
		// A recovered panic in gVisor's inbound dispatch is the most serious
		// signal: the offending packet shape can never be delivered, so a whole
		// traffic class may be silently black-holed. Escalate to ERROR (above
		// any WARN above) and attach the captured panic + stack below so the
		// condition is actionable rather than a bare counter.
		if d[mInPanics] > 0 {
			level = slog.LevelError
		}

		if n.log != nil {
			// Build the structured args from metricDefs so the snapshot, the
			// delta math, and the log keys can't drift out of sync. deltaKey →
			// per-window delta, totalKey → running total, gaugeKey → current
			// value (no delta).
			args := make([]any, 0, statsArgCap)
			for i := range numMetrics {
				m := metricDefs[i]
				if m.deltaKey != "" {
					args = append(args, m.deltaKey, d[i])
				}
				if m.totalKey != "" {
					args = append(args, m.totalKey, cur[i])
				}
				if m.gaugeKey != "" {
					args = append(args, m.gaugeKey, cur[i])
				}
			}
			// Tail-latency probe for the inbound fast path: worst single
			// DeliverNetworkPacket call (microseconds) among the
			// 1-in-deliverSampleN packets sampled this window (see
			// deliverInbound). The session read loop blocks for exactly this long
			// on the worst sampled packet — useful to spot gVisor slow paths
			// before they manifest as OS-UDP-buffer overflow.
			args = append(args, "max_deliver_us", maxDeliverUs)
			// On a recovered inbound-dispatch panic, attach the captured value +
			// stack so the ERROR line is self-contained (rare path: a realloc
			// past statsArgCap here is fine).
			if d[mInPanics] > 0 {
				if pd := n.ep.panicDetail.Load(); pd != nil {
					args = append(args, "last_panic", *pd)
				}
			}
			n.log.Log(context.Background(), level, "netstack stats", args...)
		}
	}
}

// CloseAll tears down BOTH the netstack and the tunnel (if it is an io.Closer).
func (n *Net) CloseAll() error {
	err1 := n.Close()
	err2 := closeTunnel(n.tun)
	if err1 != nil {
		return err1
	}
	return err2
}

// DialContext is suitable as a Transport.DialContext callback or net.Resolver
// Dial hook. Supports "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6". The host
// in addr must be a literal IP — the netstack package does no DNS resolution.
func (n *Net) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("netstack: bad port %q: %w", portStr, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// We deliberately do NOT do DNS resolution here — callers that need
		// it should resolve via their own resolver and call DialContext
		// with a literal IP.
		return nil, fmt.Errorf("netstack: DialContext requires literal IP, got %q", host)
	}
	// Normalise an IPv4-mapped IPv6 literal (e.g. "::ffff:10.0.0.1") to its
	// native v4 form. Without this it is treated as a v6 destination and
	// routed/bound on the v6 NIC address — which a v4-only tunnel doesn't
	// have — instead of the v4 path the operator actually meant.
	ip = ip.Unmap()

	var proto tcpip.NetworkProtocolNumber
	switch {
	case ip.Is4():
		proto = ipv4.ProtocolNumber
	case ip.Is6():
		proto = ipv6.ProtocolNumber
	default:
		return nil, fmt.Errorf("netstack: unsupported address %q", host)
	}
	// Honour an explicit address-family suffix. The protocol above is derived
	// purely from the literal, so without this a "tcp4"/"udp4" dial to an IPv6
	// literal (or "tcp6"/"udp6" to an IPv4 literal) would silently proceed on
	// the wrong family, contradicting the caller's stated intent. The check
	// runs after Unmap, so an IPv4-mapped literal counts as its native v4 form.
	switch network {
	case "tcp4", "udp4":
		if !ip.Is4() {
			return nil, &net.OpError{Op: "dial", Net: network, Err: fmt.Errorf("netstack: %s requires an IPv4 address, got %q", network, host)}
		}
	case "tcp6", "udp6":
		if !ip.Is6() {
			return nil, &net.OpError{Op: "dial", Net: network, Err: fmt.Errorf("netstack: %s requires an IPv6 address, got %q", network, host)}
		}
	}
	full := tcpip.FullAddress{NIC: nicID, Addr: netipToTCPIPAddr(ip), Port: uint16(port64)}

	// Snapshot the reconnect generation BEFORE the (potentially blocking)
	// gonet dial so finalizeDial can detect a reconnect that occurred during
	// the dial. Without this guard, an OnReconnect hook running between
	// gonet.Dial and trackConn would close every *currently-tracked* conn but
	// miss the about-to-be-tracked one — its register call arrives after
	// closeActiveOnReconnect has finished and the conn stays bound to the
	// now-stale source IP, becoming a zombie that gVisor TCP only abandons
	// after 60-120s of retransmits. The generation counter (unlike an IP
	// comparison) also fires on a same-IP reconnect.
	preGen := n.reconnectGen.Load()

	var dialed net.Conn
	switch network {
	case "tcp", "tcp4", "tcp6":
		c, err := gonet.DialContextTCP(ctx, n.stack, full, proto)
		if err != nil {
			return nil, err
		}
		dialed = c
	case "udp", "udp4", "udp6":
		// gonet.DialUDP has no Context variant; it returns immediately because
		// UDP is connectionless. We honor ctx best-effort by checking it first.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Pass an explicit local address for UDP. Without this gVisor picks
		// from the NIC's address list via route lookup; passing laddr makes
		// the bind track reconnect-driven IP changes 1:1.
		c, err := gonet.DialUDP(n.stack, n.currentLocalFullAddress(ip.Is4()), &full, proto)
		if err != nil {
			return nil, err
		}
		dialed = c
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("netstack: unsupported network")}
	}

	return n.finalizeDial(dialed, preGen, network)
}

// finalizeDial registers a freshly-dialed conn in the reconnect tracker and
// guards against a reconnect that raced the dial. preGen is the reconnect
// generation sampled before the (possibly blocking) dial; if it no longer
// matches, an OnReconfigure hook fired while we were dialing — the conn is
// bound to a now-stale tunnel session, so it is force-closed and
// ErrTunnelIPChanged returned (safe to retry; the next attempt binds to the
// fresh state).
//
// Tracking happens BEFORE the generation re-check so a hook firing in the
// [trackConn, recheck] window force-closes this conn via
// closeActiveOnReconnect; the generation re-check covers the complementary
// window where the hook's Range already ran before trackConn registered us.
// Because the hook bumps the generation BEFORE its closeActiveOnReconnect
// Range, at least one of the two mechanisms always catches the conn.
//
// The reconnect guard trips when EITHER the generation moved since preGen OR
// preGen was already odd. An odd preGen means the dial sampled it
// mid-reconfiguration (after the hook's entry bump, before its exit bump) — the
// conn may be bound to the old, about-to-be-replaced address and may have
// slipped past closeActiveOnReconnect's Range, so it is rejected even though the
// generation will not move again before this re-check.
//
// finalizeDial also rejects a dial that raced Net.Close(): Close sets n.closed
// (but does not move reconnectGen), so without this check a dial completing
// after n.closed=true could be handed back with a nil error — a conn bound to a
// stack being destroyed, plus a leaked activeConns entry Close never drains.
// Reading n.closed under closeMu serialises the two: Close either tore down
// first (we see closed and reject with net.ErrClosed, which — unlike
// ErrTunnelIPChanged — is not retryable, so callers stop) or it runs after this
// returns. The closed branch is checked first so a closing Net never reports
// the retryable ErrTunnelIPChanged.
func (n *Net) finalizeDial(dialed net.Conn, preGen uint64, network string) (net.Conn, error) {
	tracked := n.trackConn(dialed)
	n.closeMu.Lock()
	closed := n.closed
	n.closeMu.Unlock()
	if closed {
		_ = tracked.Close()
		return nil, &net.OpError{Op: "dial", Net: network, Err: net.ErrClosed}
	}
	if n.reconnectGen.Load() != preGen || preGen&1 == 1 {
		_ = tracked.Close()
		return nil, &net.OpError{Op: "dial", Net: network, Err: ErrTunnelIPChanged}
	}
	return tracked, nil
}

// ListenTCP opens a TCP listener inside the netstack on addr. The address
// family (IPv4 vs IPv6) is derived from addr.Addr(); an unspecified address
// (0.0.0.0 / ::) listens on the wildcard for that family, and a zero/invalid
// addr listens on whichever family the NIC currently has, preferring IPv4. The
// returned net.Listener is a gonet.TCPListener, so callers never touch gvisor
// types — use Stack() only for cases this and DialContext don't cover.
//
// Unlike DialContext there is no reconnect generation guard: a listener is not
// a zombie bound to a stale 4-tuple, and the OnReconfigure hook already aborts
// it only when the tunnel IP actually changes (a same-IP rekey leaves it live).
func (n *Net) ListenTCP(addr netip.AddrPort) (net.Listener, error) {
	ip := addr.Addr().Unmap()

	var proto tcpip.NetworkProtocolNumber
	var bindAddr tcpip.Address // zero value == wildcard for the chosen family

	switch {
	case ip.IsValid() && !ip.IsUnspecified():
		// Concrete address: bind it on its own family.
		if ip.Is4() {
			proto = ipv4.ProtocolNumber
		} else {
			proto = ipv6.ProtocolNumber
		}
		bindAddr = netipToTCPIPAddr(ip)
	case ip.Is4(): // 0.0.0.0 → IPv4 wildcard
		proto = ipv4.ProtocolNumber
	case ip.Is6(): // :: → IPv6 wildcard
		proto = ipv6.ProtocolNumber
	default:
		// Zero/invalid AddrPort → wildcard on whichever family the NIC has.
		switch {
		case n.HasIPv4():
			proto = ipv4.ProtocolNumber
		case n.HasIPv6():
			proto = ipv6.ProtocolNumber
		default:
			return nil, fmt.Errorf("netstack: ListenTCP on %v: stack has no IPv4 or IPv6 address", addr)
		}
	}

	full := tcpip.FullAddress{NIC: nicID, Addr: bindAddr, Port: addr.Port()}
	ln, err := gonet.ListenTCP(n.stack, full, proto)
	if err != nil {
		return nil, fmt.Errorf("netstack: ListenTCP on %v: %w", addr, err)
	}
	return ln, nil
}

// currentLocalFullAddress returns a FullAddress suitable as `laddr` for a
// gonet Dial, snapshotting the NIC's current IPv4 or IPv6 address under the
// nicMu lock. Returns nil if no address of the requested family is
// installed — gonet treats nil laddr as "auto-pick", matching the prior
// behaviour for that edge case.
func (n *Net) currentLocalFullAddress(v4 bool) *tcpip.FullAddress {
	local := n.localAddr(v4)
	if !local.IsValid() {
		return nil
	}
	return &tcpip.FullAddress{NIC: nicID, Addr: netipToTCPIPAddr(local)}
}

// netipToTCPIPAddr converts a netip.Addr into a tcpip.Address, picking the 4-
// or 16-byte form from the slice length. Centralises the conversion so every
// call site maps a netip.Addr the same way (the AddrFromSlice idiom also used
// by syncFamily/removeAddr).
func netipToTCPIPAddr(a netip.Addr) tcpip.Address {
	return tcpip.AddrFromSlice(a.AsSlice())
}

// maskPrefixLen converts a 4-byte IPv4 netmask address into a prefix length
// by counting LEADING ones (a contiguous mask is required by RFC 4632).
// Rejects non-contiguous masks by returning /32 — net.IPMask.Size reports
// (0, 0) for a non-canonical mask, which we map to /32.
func maskPrefixLen(a netip.Addr) int {
	if !a.IsValid() || !a.Is4() {
		return 32
	}
	b := a.As4()
	ones, bits := net.IPMask(b[:]).Size()
	if bits == 0 {
		return 32
	}
	return ones
}

// tcpipSubnetFromPrefix converts a netip.Prefix into a tcpip.Subnet. It masks
// off any host bits via Prefix.Masked so the resulting subnet is canonical,
// and lets AddressWithPrefix.Subnet build the gVisor value (AddrFromSlice
// picks the 4- or 16-byte address form from the slice length). An error is
// returned only for an unsupported address family.
func tcpipSubnetFromPrefix(p netip.Prefix) (tcpip.Subnet, error) {
	masked := p.Masked()
	addr := masked.Addr()
	if !addr.Is4() && !addr.Is6() {
		return tcpip.Subnet{}, fmt.Errorf("netstack: unsupported address family in prefix %s", p)
	}
	awp := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice(addr.AsSlice()),
		PrefixLen: masked.Bits(),
	}
	return awp.Subnet(), nil
}
