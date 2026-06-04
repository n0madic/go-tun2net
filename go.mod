// Userspace gVisor TCP/IP stack over an arbitrary packet tunnel (raw IP
// datagrams in/out).
module github.com/n0madic/go-tun2net

go 1.26.3

require gvisor.dev/gvisor v0.0.0-20260603223238-3694902083d5

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)
