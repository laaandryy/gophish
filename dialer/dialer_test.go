package dialer

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
)

func TestDefaultDeny(t *testing.T) {
	control := restrictedControl([]*net.IPNet{})
	host := "169.254.169.254"
	expected := fmt.Errorf("upstream connection denied to internal host at %s", host)
	conn := new(syscall.RawConn)
	got := control("tcp4", fmt.Sprintf("%s:80", host), *conn)
	if !strings.Contains(got.Error(), "upstream connection denied") {
		t.Fatalf("unexpected error dialing denylisted host. expected %v got %v", expected, got)
	}
}

func TestDefaultAllow(t *testing.T) {
	control := restrictedControl([]*net.IPNet{})
	host := "1.1.1.1"
	conn := new(syscall.RawConn)
	got := control("tcp4", fmt.Sprintf("%s:80", host), *conn)
	if got != nil {
		t.Fatalf("error dialing allowed host. got %v", got)
	}
}

func TestCustomAllow(t *testing.T) {
	host := "127.0.0.1"
	_, ipRange, _ := net.ParseCIDR(fmt.Sprintf("%s/32", host))
	allowed := []*net.IPNet{ipRange}
	control := restrictedControl(allowed)
	conn := new(syscall.RawConn)
	got := control("tcp4", fmt.Sprintf("%s:80", host), *conn)
	if got != nil {
		t.Fatalf("error dialing allowed host. got %v", got)
	}
}

func TestCustomDeny(t *testing.T) {
	host := "127.0.0.1"
	_, ipRange, _ := net.ParseCIDR(fmt.Sprintf("%s/32", host))
	allowed := []*net.IPNet{ipRange}
	control := restrictedControl(allowed)
	conn := new(syscall.RawConn)
	expected := fmt.Errorf("upstream connection denied to internal host at %s", host)
	got := control("tcp4", "192.168.1.2:80", *conn)
	if !strings.Contains(got.Error(), "upstream connection denied") {
		t.Fatalf("unexpected error dialing denylisted host. expected %v got %v", expected, got)
	}
}

func TestSingleIP(t *testing.T) {
	orig := DefaultDialer.AllowedHosts()
	host := "127.0.0.1"
	DefaultDialer.SetAllowedHosts([]string{host})
	control := DefaultDialer.Dialer().Control
	conn := new(syscall.RawConn)
	expected := fmt.Errorf("upstream connection denied to internal host at %s", host)
	got := control("tcp4", "192.168.1.2:80", *conn)
	if !strings.Contains(got.Error(), "upstream connection denied") {
		t.Fatalf("unexpected error dialing denylisted host. expected %v got %v", expected, got)
	}

	host = "::1"
	DefaultDialer.SetAllowedHosts([]string{host})
	control = DefaultDialer.Dialer().Control
	conn = new(syscall.RawConn)
	expected = fmt.Errorf("upstream connection denied to internal host at %s", host)
	got = control("tcp4", "192.168.1.2:80", *conn)
	if !strings.Contains(got.Error(), "upstream connection denied") {
		t.Fatalf("unexpected error dialing denylisted host. expected %v got %v", expected, got)
	}

	// Test an allowed connection
	got = control("tcp4", fmt.Sprintf("[%s]:80", host), *conn)
	if got != nil {
		t.Fatalf("error dialing allowed host. got %v", got)
	}
	DefaultDialer.SetAllowedHosts(orig)
}

func TestStrictDialerBlocksLoopback(t *testing.T) {
	d := &RestrictedDialer{}
	control := d.StrictDialer().Control
	for _, addr := range []string{"127.0.0.1:3333", "[::1]:3333", "0.0.0.0:80", "169.254.169.254:80", "[fd00:ec2::254]:80"} {
		network := "tcp4"
		if addr[0] == '[' {
			network = "tcp6"
		}
		if err := control(network, addr, nil); err == nil {
			t.Fatalf("expected %s to be denied by the strict dialer", addr)
		}
	}
	// Local network hosts stay reachable by default
	if err := control("tcp4", "192.168.1.10:80", nil); err != nil {
		t.Fatalf("expected local network host to be allowed: %v", err)
	}
	// Explicitly allowed loopback hosts are reachable
	d.SetAllowedHosts([]string{"127.0.0.1"})
	if err := d.StrictDialer().Control("tcp4", "127.0.0.1:80", nil); err != nil {
		t.Fatalf("expected allowed loopback host to be reachable: %v", err)
	}
}
