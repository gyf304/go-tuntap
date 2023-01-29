package tun

import (
	"io"
	"net/netip"
)

var impls []TUNImpl

type TUN interface {
	io.ReadWriteCloser
	SetIPAddresses(addresses []netip.Prefix) error
	Sys() any // returns the underlying system object
}

type TUNImpl interface {
	Open(name string) (TUN, error)
	Name() string
}

func Register(impl TUNImpl) {
	impls = append(impls, impl)
}

func List() []TUNImpl {
	return impls
}

func Open(name string) (TUN, error) {
	for _, impl := range impls {
		return impl.Open(name)
	}
	return nil, io.EOF
}
