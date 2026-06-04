// Userspace gVisor TCP/IP stack over an arbitrary packet tunnel (raw IP
// datagrams in/out). Extracted from go-openvpn/pkg/netstack so every userspace
// VPN (OpenVPN, IKEv2/IPsec, …) shares one IP-stack + DialContext/SOCKS layer.
module github.com/n0madic/go-tun2net

go 1.25.0

require gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/time v0.12.0 // indirect
)
