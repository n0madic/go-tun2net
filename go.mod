// Userspace gVisor TCP/IP stack over an arbitrary packet tunnel (raw IP
// datagrams in/out).
module github.com/n0madic/go-tun2net

go 1.20

require (
	github.com/metacubex/gvisor v0.0.0-20251227095601-261ec1326fe8
	golang.org/x/exp v0.0.0-20230801115018-d63ba01acd4b
)

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/time v0.7.0 // indirect
)
