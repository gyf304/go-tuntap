package linuxtun

import (
	"errors"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/gyf304/go-tuntap/tun"
	"golang.org/x/sys/unix"
)

func init() {
	tun.Register(&tunLinuxImpl{})
}

type ifReq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

func ioctl(fd uintptr, request uintptr, argp uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(request), argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}

func setupFd(name string, fd uintptr) (string, error) {
	var err error
	var flags uint16 = syscall.IFF_TUN | syscall.IFF_NO_PI

	if name, err = createInterface(fd, name, flags); err != nil {
		return "", err
	}

	return name, nil
}

func createInterface(fd uintptr, ifName string, flags uint16) (createdIFName string, err error) {
	var req ifReq
	req.Flags = flags
	copy(req.Name[:], ifName)

	err = ioctl(fd, syscall.TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if err != nil {
		return
	}

	createdIFName = strings.Trim(string(req.Name[:]), "\x00")
	return
}

type tunLinuxImpl struct{}

type tunLinux struct {
	*os.File
	name string
}

type socketAddrRequest struct {
	name [unix.IFNAMSIZ]byte
	addr unix.RawSockaddrInet4
	_    [8]byte
}

type socketFlagsRequest struct {
	name  [unix.IFNAMSIZ]byte
	flags uint16
	pad   [22]byte
}

func (t *tunLinux) Sys() interface{} {
	return t.File
}

func (t *tunLinux) SetIPAddresses(addresses []netip.Prefix) error {
	if len(addresses) != 1 {
		return errors.New("tun: only one address supported")
	}
	if !addresses[0].Addr().Is4() {
		return errors.New("tun: only IPv4 supported")
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	fdUintPtr := uintptr(fd)

	var sa socketAddrRequest
	copy(sa.name[:], t.name)
	sa.addr.Family = unix.AF_INET
	addr, err := addresses[0].MarshalBinary()
	if err != nil {
		return err
	}
	copy(sa.addr.Addr[:], addr[:4])

	// set addr
	if err = ioctl(fdUintPtr, unix.SIOCSIFADDR, uintptr(unsafe.Pointer(&sa))); err != nil {
		return err
	}

	// set mask
	bits := addresses[0].Bits()
	var mask uint32
	for i := 0; i < bits; i++ {
		mask |= 1 << uint(31-i)
	}
	sa.addr.Addr[0] = byte(mask >> 24)
	sa.addr.Addr[1] = byte(mask >> 16)
	sa.addr.Addr[2] = byte(mask >> 8)
	sa.addr.Addr[3] = byte(mask)
	if err = ioctl(fdUintPtr, unix.SIOCSIFNETMASK, uintptr(unsafe.Pointer(&sa))); err != nil {
		return err
	}

	// up the interface
	var sf socketFlagsRequest
	copy(sf.name[:], t.name)
	sf.flags = unix.IFF_UP
	if err = ioctl(fdUintPtr, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&sf))); err != nil {
		return err
	}

	return nil
}

func (t *tunLinuxImpl) Name() string {
	return "tun"
}

func (t *tunLinuxImpl) Open(name string) (tun tun.TUN, err error) {
	var fdInt int
	if fdInt, err = syscall.Open(
		"/dev/net/tun", os.O_RDWR|syscall.O_NONBLOCK, 0); err != nil {
		return nil, err
	}

	name, err = setupFd(name, uintptr(fdInt))
	if err != nil {
		return nil, err
	}

	return &tunLinux{
		File: os.NewFile(uintptr(fdInt), name),
		name: name,
	}, nil
}
