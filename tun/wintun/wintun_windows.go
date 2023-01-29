package wintun

import (
	"errors"
	"net/netip"
	"sync"

	"github.com/google/uuid"
	"github.com/gyf304/go-tuntap/tun"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const netConfigKey = `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}`

type wintunWrap struct {
	session wintun.Session
	adapter *wintun.Adapter
	mutex   sync.Mutex
}

func init() {
	tun.Register(&wintunImpl{})
}

type wintunImpl struct{}

func elevated() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

func (t *wintunWrap) Read(b []byte) (int, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	pkt, err := t.session.ReceivePacket()
	for err == windows.Errno(259) {
		handle := t.session.ReadWaitEvent()
		_, err2 := windows.WaitForSingleObject(handle, windows.INFINITE)
		if err2 != nil {
			return 0, err2
		}
		pkt, err = t.session.ReceivePacket()
	}
	if err != nil {
		return 0, err
	}
	n := copy(b, pkt)
	t.session.ReleaseReceivePacket(pkt)
	return n, nil
}

func (t *wintunWrap) Write(b []byte) (int, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	buf, err := t.session.AllocateSendPacket(len(b))
	copy(buf, b)
	t.session.SendPacket(buf)
	return len(b), err
}

func (t *wintunWrap) Close() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.session.End()
	return t.adapter.Close()
}

func setAdapterName(id windows.GUID, name string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, netConfigKey+"\\"+id.String()+"\\"+"Connection", registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("Name", name)
}

func (t *wintunImpl) Name() string {
	return "Wintun"
}

func (t *wintunImpl) Open(name string) (tun tun.TUN, err error) {
	if !elevated() {
		return nil, errors.New("Wintun requires elevated privileges")
	}
	var prefix *netip.Prefix

	guid, err := windows.GenerateGUID()
	if err != nil {
		return nil, err
	}
	nameGUID, err := windows.GUIDFromString(name)
	if err == nil {
		guid = nameGUID
	} else if name != "" {
		// UUID5
		uuid := uuid.NewSHA1(uuid.Nil, []byte(name))
		guid, err = windows.GUIDFromString("{" + uuid.String() + "}")
		if err != nil {
			return nil, err
		}
	}
	adapter, err := wintun.CreateAdapter(name, "Wintun", &guid)
	if err != nil {
		return nil, err
	}
	// setAdapterName(guid, config.PlatformSpecificParams.InterfaceName)

	luid := winipcfg.LUID(adapter.LUID())
	if prefix != nil {
		err = luid.SetIPAddresses([]netip.Prefix{*prefix})
		if err != nil {
			adapter.Close()
			return nil, err
		}
	}

	sess, err := adapter.StartSession(0x400000)
	if err != nil {
		adapter.Close()
		return nil, err
	}

	return &wintunWrap{session: sess, adapter: adapter}, nil
}

func (t *wintunWrap) SetIPAddresses(addresses []netip.Prefix) error {
	luid := winipcfg.LUID(t.adapter.LUID())
	return luid.SetIPAddresses(addresses)
}

func (t *wintunWrap) Sys() any {
	return winipcfg.LUID(t.adapter.LUID())
}
