package collect

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
)

const portsNetHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

// portsNetLine formats a /proc/net/{tcp,udp}[6] row.
func portsNetLine(sl int, local, remote, state string, inode int) string {
	return fmt.Sprintf("%4d: %s %s %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n",
		sl, local, remote, state, inode)
}

const (
	portsV4Any = "00000000:0000"
	portsV6Any = "00000000000000000000000000000000:0000"
)

func portsFixture(t *testing.T) *fixture {
	f := newFixture(t)
	f.file("/proc/net/tcp", portsNetHeader+
		portsNetLine(0, "00000000:0016", portsV4Any, "0A", 1001)+ // 0.0.0.0:22 sshd
		portsNetLine(1, "0100007F:0CEA", portsV4Any, "0A", 1002)+ // 127.0.0.1:3306 mysqld
		portsNetLine(2, "0F02000A:0016", "0101A8C0:D2F0", "01", 1010)+ // an ssh session
		portsNetLine(3, "00000000:01BB", portsV4Any, "0A", 1004)+ // 0.0.0.0:443, nginx worker 201
		portsNetLine(4, "00000000:01BB", portsV4Any, "0A", 1003)+ // the same, worker 200 (SO_REUSEPORT)
		portsNetLine(5, "0100007F:9C40", portsV4Any, "0A", 1008)) // 127.0.0.1:40000: TCP stays in the ephemeral range
	f.file("/proc/net/tcp6", portsNetHeader+
		portsNetLine(0, "00000000000000000000000000000000:0016", portsV6Any, "0A", 1005)+ // [::]:22
		portsNetLine(1, "0000000000000000FFFF00000100007F:1F90", portsV6Any, "0A", 1006)+ // ::ffff:127.0.0.1:8080
		portsNetLine(2, "B80D0120000000000000000001000000:0050", portsV6Any, "0A", 1007)) // [2001:db8::1]:80, owner gone
	f.file("/proc/net/udp", portsNetHeader+
		portsNetLine(0, "00000000:0035", portsV4Any, "07", 2001)+ // 0.0.0.0:53 dnsmasq
		portsNetLine(1, "3500007F:0035", portsV4Any, "07", 2002)+ // 127.0.0.53:53 resolved
		portsNetLine(2, "00000000:9C40", portsV4Any, "07", 2004)+ // a client socket on 40000
		portsNetLine(3, "0F02000A:9C41", "08080808:0035", "01", 2005)+ // connected
		portsNetLine(4, "00000000:CA6C", portsV4Any, "07", 0)) // WireGuard 51820, kernel
	f.file("/proc/net/udp6", portsNetHeader+
		portsNetLine(0, "00000000000000000000000000000000:EA60", portsV6Any, "07", 0)+ // kernel, ephemeral port 60000
		portsNetLine(1, "000080FE00000000FFC2A80201A8C0FE:0222", portsV6Any, "07", 2006)) // fe80::2a8:c2ff:fec0:a801:546
	f.file("/proc/sys/net/ipv4/ip_local_port_range", "32768\t60999\n")

	proc := func(pid int, comm, cgroup string, inodes ...int) {
		dir := fmt.Sprintf("/proc/%d", pid)
		f.file(dir+"/comm", comm+"\n")
		f.file(dir+"/cgroup", cgroup)
		f.link(dir+"/fd/0", "/dev/null")
		f.link(dir+"/fd/1", "pipe:[555]")
		for i, ino := range inodes {
			f.link(fmt.Sprintf("%s/fd/%d", dir, i+3), fmt.Sprintf("socket:[%d]", ino))
		}
	}
	proc(100, "sshd", "0::/system.slice/ssh.service\n", 1001, 1005)
	proc(200, "nginx", "0::/system.slice/nginx.service\n", 1003, 1004)
	proc(201, "nginx", "0::/system.slice/nginx.service\n", 1004)
	proc(202, "nginx", "0::/system.slice/nginx.service\n", 1003)
	proc(300, "mysqld", "0::/system.slice/mysql.service\n", 1002)
	proc(400, "python3", "0::/system.slice/docker-0123abcd.scope\n", 1006)
	proc(500, "dnsmasq", "0::/system.slice/dnsmasq.service\n", 2001)
	proc(600, "systemd-resolve", "0::/system.slice/systemd-resolved.service\n", 2002, 2004)
	proc(700, "dhclient", "0::/system.slice/networking.service\n", 2006)
	f.file("/proc/self/comm", "baseline-agent\n") // not a pid
	return f
}

func TestPorts(t *testing.T) {
	f := portsFixture(t)
	p, err := f.env.Ports(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []model.Listener{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Process: "sshd", PID: 100, Unit: "ssh.service"},
		{Proto: "tcp", Addr: "::", Port: 22, Process: "sshd", PID: 100, Unit: "ssh.service"},
		{Proto: "tcp", Addr: "2001:db8::1", Port: 80},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 443, Process: "nginx", PID: 200, Unit: "nginx.service"},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 3306, Process: "mysqld", PID: 300, Unit: "mysql.service"},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 8080, Process: "python3", PID: 400, Unit: "docker-0123abcd.scope"},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 40000},
		{Proto: "udp", Addr: "0.0.0.0", Port: 53, Process: "dnsmasq", PID: 500, Unit: "dnsmasq.service"},
		{Proto: "udp", Addr: "127.0.0.53", Port: 53, Process: "systemd-resolve", PID: 600, Unit: "systemd-resolved.service"},
		{Proto: "udp", Addr: "fe80::2a8:c2ff:fec0:a801", Port: 546, Process: "dhclient", PID: 700, Unit: "networking.service"},
		{Proto: "udp", Addr: "0.0.0.0", Port: 51820},
		{Proto: "udp", Addr: "::", Port: 60000},
	}
	if len(p.Listeners) != len(want) {
		t.Fatalf("got %d listeners:\n%s", len(p.Listeners), portsDump(p.Listeners))
	}
	for i := range want {
		if p.Listeners[i] != want[i] {
			t.Errorf("listener %d = %+v\nwant          %+v", i, p.Listeners[i], want[i])
		}
	}
}

func portsDump(ls []model.Listener) string {
	var b strings.Builder
	for _, l := range ls {
		fmt.Fprintf(&b, "%+v\n", l)
	}
	return b.String()
}

func TestPortsEphemeralRangeAndMissingFiles(t *testing.T) {
	// No IPv6, a narrower ephemeral range: 40000 is no longer a client port.
	f := newFixture(t)
	f.file("/proc/net/udp", portsNetHeader+portsNetLine(0, "00000000:9C40", portsV4Any, "07", 2004))
	f.file("/proc/sys/net/ipv4/ip_local_port_range", "50000 60000\n")
	p, err := f.env.Ports(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Listeners) != 1 || p.Listeners[0].Key() != "udp 0.0.0.0:40000" {
		t.Fatalf("got %s", portsDump(p.Listeners))
	}

	// Nothing to read is an empty section, not nil.
	p, err = newFixture(t).env.Ports(context.Background())
	if err != nil || p.Listeners == nil || len(p.Listeners) != 0 {
		t.Fatalf("empty: %+v %v", p, err)
	}
}

func TestParseProcNetAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F:0016":                         "127.0.0.1:22",
		"0F02000A:01BB":                         "10.0.2.15:443",
		"00000000000000000000000001000000:0035": "::1:53",
		"0000000000000000FFFF00000F02000A:0050": "10.0.2.15:80",
		"0000000000000000FFFF000000000000:0050": "0.0.0.0:80",
		"B80D0120000000000000000001000000:1F90": "2001:db8::1:8080",
	} {
		ip, port, ok := parseProcNetAddr(in)
		if got := fmt.Sprintf("%s:%d", ip, port); !ok || got != want {
			t.Errorf("%s = %s (%v), want %s", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "0100007F", "0100007G:0016", "01007F:0016", "0100007F:XYZ"} {
		if _, _, ok := parseProcNetAddr(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}
