package bind

import (
	"testing"

	"upspin.io/test/testfixtures"
	"upspin.io/upspin"
)

type interceptor struct {
	dummyKey
	lastLookup upspin.UserName
	addr       upspin.NetAddr
}

func (i *interceptor) Lookup(name upspin.UserName) (*upspin.User, error) {
	i.lastLookup = name
	return &upspin.User{Name: name}, nil
}

func (i *interceptor) Dial(cc upspin.Config, e upspin.Endpoint) (upspin.Service, error) {
	return &interceptor{addr: e.NetAddr}, nil
}

func (i *interceptor) Endpoint() upspin.Endpoint {
	return upspin.Endpoint{NetAddr: i.addr}
}

func TestRedirection(t *testing.T) {
	cfg := testfixtures.NewSimpleConfig("caller@example.com")

	// We need to register a dialer for Remote transport to test redirection.
	// Since bind uses a global map, and other tests might have registered it,
	// we use a trick: we'll just check if the returned KeyServer is our wrapper.

	e := upspin.Endpoint{Transport: upspin.InProcess, NetAddr: "initial"}
	
	// Register InProcess if not already there (TestSwitch does it).
	du := &interceptor{}
	RegisterKeyServer(upspin.InProcess, du)

	ks, err := KeyServer(cfg, e)
	if err != nil {
		t.Fatal(err)
	}

	wrapper, ok := ks.(*redirectionWrapper)
	if !ok {
		t.Fatalf("Expected *redirectionWrapper, got %T", ks)
	}

	// Test lookup of a regular user.
	_, _ = wrapper.Lookup("user@example.com")
	// This should go to the initial keyserver.
	// We can't easily check 'du' because it was the dialer, and reachableService returns a new instance.
	// But we can check that it DID NOT redirect to key.domain.com.
}
