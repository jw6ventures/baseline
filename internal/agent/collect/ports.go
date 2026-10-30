package collect

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/jw6ventures/baseline/internal/model"
)

// Ports lists listening TCP sockets and bound UDP sockets from /proc/net,
// with the process and unit that own them.
func (e *Env) Ports(ctx context.Context) (model.Ports, error) {
	out := model.Ports{Listeners: []model.Listener{}}
	lo, hi := e.ephemeralPorts()
	var socks []procSocket
	for _, src := range []struct{ file, proto string }{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp"}, {"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp"},
	} {
		raw, err := e.ReadBytes(src.file)
		if errors.Is(err, os.ErrNotExist) {
			continue // no IPv6 on this host
		}
		if err != nil {
			return out, err
		}
		for _, s := range parseProcNet(string(raw), src.proto) {
			// UDP client sockets bind ephemeral ports and churn; kernel
			// sockets (WireGuard) may sit there too and stay.
			if s.proto == "udp" && s.inode != 0 && s.port >= lo && s.port <= hi {
				continue
			}
			socks = append(socks, s)
		}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}

	want := map[uint64]bool{}
	for _, s := range socks {
		if s.inode != 0 {
			want[s.inode] = true
		}
	}
	owners := e.socketOwners(want)

	seen := map[string]int{}
	for _, s := range socks {
		l := model.Listener{Proto: s.proto, Addr: s.addr, Port: s.port}
		if pid, ok := owners[s.inode]; ok && s.inode != 0 {
			l.PID = pid
			l.Process = e.Read("/proc/" + strconv.Itoa(pid) + "/comm")
			l.Unit = e.procUnit(pid)
		}
		// SO_REUSEPORT workers each hold a socket on the same address.
		if i, ok := seen[l.Key()]; ok {
			if prev := out.Listeners[i]; prev.PID == 0 || (l.PID != 0 && l.PID < prev.PID) {
				out.Listeners[i] = l
			}
			continue
		}
		seen[l.Key()] = len(out.Listeners)
		out.Listeners = append(out.Listeners, l)
	}
	sort.Slice(out.Listeners, func(i, j int) bool {
		a, b := out.Listeners[i], out.Listeners[j]
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Addr < b.Addr
	})
	return out, nil
}

// procSocket is a row of /proc/net/{tcp,udp}[6] we keep.
type procSocket struct {
	proto string
	addr  string
	port  int
	inode uint64
}

const (
	tcpListen = "0A"
	udpClose  = "07" // unconnected: bound, not connected
)

// parseProcNet keeps the listening (TCP) and bound, unconnected (UDP) rows.
func parseProcNet(out, proto string) []procSocket {
	var socks []procSocket
	for _, line := range strings.Split(out, "\n") {
		// sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode
		f := strings.Fields(line)
		if len(f) < 10 || !strings.HasSuffix(f[0], ":") {
			continue // the header
		}
		switch {
		case proto == "tcp" && f[3] == tcpListen:
		case proto == "udp" && f[3] == udpClose && strings.Trim(f[2], "0:") == "":
		default:
			continue
		}
		ip, port, ok := parseProcNetAddr(f[1])
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if !ok || err != nil {
			continue
		}
		socks = append(socks, procSocket{proto: proto, addr: ip.String(), port: port, inode: inode})
	}
	return socks
}

// parseProcNetAddr decodes "0100007F:0016": the address is printed as 32-bit
// words in host byte order, the port as a plain number.
func parseProcNetAddr(s string) (net.IP, int, bool) {
	a, p, ok := strings.Cut(s, ":")
	if !ok || (len(a) != 8 && len(a) != 32) {
		return nil, 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return nil, 0, false
	}
	ip := make(net.IP, len(a)/2)
	for i := 0; i < len(a); i += 8 {
		w, err := strconv.ParseUint(a[i:i+8], 16, 32)
		if err != nil {
			return nil, 0, false
		}
		binary.NativeEndian.PutUint32(ip[i/2:], uint32(w))
	}
	// A v4-mapped address (a dual-stack socket bound to an IPv4 address)
	// is reported as IPv4; To4 keeps the wildcard "::" as it is.
	if v4 := ip.To4(); v4 != nil && len(ip) == net.IPv6len {
		ip = v4
	}
	return ip, int(port), true
}

// ephemeralPorts is the kernel's range for automatically bound ports.
func (e *Env) ephemeralPorts() (lo, hi int) {
	f := strings.Fields(e.Read("/proc/sys/net/ipv4/ip_local_port_range"))
	if len(f) == 2 {
		l, err1 := strconv.Atoi(f[0])
		h, err2 := strconv.Atoi(f[1])
		if err1 == nil && err2 == nil && l <= h {
			return l, h
		}
	}
	return 32768, 60999
}

// socketOwners maps socket inodes to the lowest PID holding them, from the
// /proc/<pid>/fd links. Processes come and go while we read; those that
// vanish are skipped.
func (e *Env) socketOwners(want map[uint64]bool) map[uint64]int {
	owners := map[uint64]int{}
	if len(want) == 0 {
		return owners
	}
	for _, name := range e.ReadDir("/proc") {
		pid, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		fdDir := e.path("/proc/" + name + "/fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			t, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil {
				continue
			}
			ino, ok := socketInode(t)
			if !ok || !want[ino] {
				continue
			}
			if prev, ok := owners[ino]; !ok || pid < prev {
				owners[ino] = pid
			}
		}
	}
	return owners
}

// socketInode reads "socket:[12345]".
func socketInode(link string) (uint64, bool) {
	s, ok := strings.CutPrefix(link, "socket:[")
	if !ok || !strings.HasSuffix(s, "]") {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64)
	return n, err == nil
}
