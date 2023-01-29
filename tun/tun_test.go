package tun_test

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gyf304/tuntap/tun"
	_ "github.com/gyf304/tuntap/tun/linux"
	_ "github.com/gyf304/tuntap/tun/wintun"
)

func TestTun(t *testing.T) {
	tun, err := tun.Open("tun0")
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	err = tun.SetIPAddresses([]netip.Prefix{netip.MustParsePrefix("192.168.42.2/24")})
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan error)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := tun.Read(buf)
			if err != nil {
				ch <- err
				return
			}
			t.Log("got pkg", buf[:n])
			if strings.Contains(string(buf[:n]), "hello") {
				close(ch)
				break
			}
		}
	}()
	// send udp packet
	s, err := net.DialUDP(
		"udp",
		&net.UDPAddr{IP: net.ParseIP("192.168.42.2"), Port: 1234},
		&net.UDPAddr{IP: net.ParseIP("192.168.42.1"), Port: 1234},
	)
	s.Write([]byte("hello"))
	s.Close()
	select {
	case err := <-ch:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}
