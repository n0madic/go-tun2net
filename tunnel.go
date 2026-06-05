// SPDX-License-Identifier: MIT

package tun2net

import (
	"io"
	"net"
	"net/netip"
)

// TunConfig is the layer-3 assignment a PacketTunnel hands to the netstack:
// the addresses, routes and MTU to install on the virtual NIC. The field set
// mirrors what VPN servers push (OpenVPN PUSH_REPLY, IKEv2 CFG payload, …) and
// is provider-agnostic. Field names match openvpn.PushReply so adapters map
// 1:1.
type TunConfig struct {
	LocalIP   netip.Addr     // assigned IPv4 address
	Netmask   netip.Addr     // IPv4 netmask (→ prefix length)
	Gateway   netip.Addr     // IPv4 default gateway (optional)
	LocalIP6  netip.Prefix   // assigned IPv6 address + prefix (optional)
	RemoteIP6 netip.Addr     // IPv6 default next-hop (optional)
	Routes    []netip.Prefix // extra IPv4 routes
	Routes6   []netip.Prefix // extra IPv6 routes
	DNS       []netip.Addr   // pushed resolvers (not used by the stack; for consumers)
	MTU       uint32         // inner MTU to apply (0 → default, then clamped)
}

// PacketTunnel is the data-plane contract the netstack runs over. Each Write on
// the outbound conn and each inbound-handler invocation carries exactly one IP
// datagram. It is implemented by adapters over concrete VPN clients
// (go-openvpn's Client, go-ipsec's ESP layer, …).
//
// A PacketTunnel that also implements io.Closer is fully torn down by
// Net.CloseAll.
type PacketTunnel interface {
	// TunnelConn returns the IP-packet pipe. One Write == one outbound IP
	// datagram (netstack → tunnel). Read yields one inbound datagram and is
	// used only when inbound fast-path delivery is not wired (legacy/testing);
	// production consumers deliver inbound via SetInbound. If the conn
	// implements SetReadDeadline it is used for clean shutdown.
	TunnelConn() net.Conn

	// Config returns the current layer-3 assignment.
	Config() TunConfig

	// SetInbound registers the fast-path handler for inbound IP datagrams
	// (tunnel → netstack) and returns a detach func. One invocation == one IP
	// datagram. The handler must not retain the slice past return.
	SetInbound(func(ip []byte)) (detach func())

	// OnReconfigure registers a hook fired whenever the layer-3 assignment
	// changes (reconnect / rekey / MOBIKE) and returns a detach func.
	OnReconfigure(func(TunConfig)) (detach func())
}

// closeTunnel closes t if it implements io.Closer; otherwise it is a no-op.
// Used by Net.CloseAll so the shared stack can fully tear down tunnels that
// own a closeable resource without depending on any concrete VPN client type.
func closeTunnel(t PacketTunnel) error {
	if c, ok := t.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
