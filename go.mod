// Userspace gVisor TCP/IP stack over an arbitrary packet tunnel (raw IP
// datagrams in/out).
module github.com/n0madic/go-tun2net

go 1.26.3

require github.com/metacubex/gvisor v0.0.0-20251227095601-261ec1326fe8

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)
