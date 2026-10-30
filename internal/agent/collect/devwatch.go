package collect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"
)

// WatchDevices calls changed whenever the kernel reports a device that
// hardware collection reads coming, going or changing (a USB device, disk,
// PCI device, NIC or display), or a NIC's link going up or down, until ctx
// ends. Events come in bursts; the caller collapses them.
func (e *Env) WatchDevices(ctx context.Context, changed func()) error {
	if e.Root != "" {
		return ErrAbsent // a fixture tree has no kernel behind it
	}
	ue, err := netlinkSocket(syscall.NETLINK_KOBJECT_UEVENT, 1) // the kernel's own uevents
	if err != nil {
		return fmt.Errorf("uevent socket: %w", err)
	}
	defer syscall.Close(ue)
	rt, err := netlinkSocket(syscall.NETLINK_ROUTE, rtmgrpLink)
	if err != nil {
		return fmt.Errorf("rtnetlink socket: %w", err)
	}
	defer syscall.Close(rt)

	errs := make(chan error, 2)
	go func() { errs <- readNetlink(ctx, ue, func(b []byte) bool { return deviceUevent(b) }, changed) }()
	go func() { errs <- readNetlink(ctx, rt, linkMessage, changed) }()
	err = <-errs
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// rtmgrpLink is the rtnetlink multicast group of link changes (RTMGRP_LINK).
const rtmgrpLink = 1

func netlinkSocket(proto, groups int) (int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		return -1, err
	}
	// Reads time out so the loop sees ctx end.
	tv := syscall.NsecToTimeval(time.Second.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: uint32(groups)}); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func readNetlink(ctx context.Context, fd int, relevant func([]byte) bool, changed func()) error {
	buf := make([]byte, 64<<10)
	for ctx.Err() == nil {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		switch {
		case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.ENOBUFS):
			// Events were dropped: something happened.
			changed()
			continue
		case err != nil:
			return err
		}
		if relevant(buf[:n]) {
			changed()
		}
	}
	return nil
}

// deviceSubsystems are the uevent subsystems hardware collection reads.
var deviceSubsystems = map[string]string{
	"usb":   "usb_device", // not its interfaces
	"block": "disk",       // not partitions
	"pci":   "",
	"net":   "",
	"drm":   "", // a connector's hotplug is a "change" on the card
}

// deviceUevent reports whether a kernel uevent ("add@/devices/...\0KEY=value\0...")
// is a device hardware collection reads coming, going or changing.
func deviceUevent(b []byte) bool {
	fields := bytes.Split(b, []byte{0})
	env := map[string]string{}
	for _, f := range fields[1:] {
		if k, v, ok := bytes.Cut(f, []byte("=")); ok {
			env[string(k)] = string(v)
		}
	}
	devtype, ok := deviceSubsystems[env["SUBSYSTEM"]]
	if !ok || (devtype != "" && env["DEVTYPE"] != devtype) {
		return false
	}
	// What hardware collection skips: a container's veth, a snap's loop.
	if name := env["INTERFACE"]; name != "" && (name == "lo" || isEphemeralNIC(name)) {
		return false
	}
	if env["SUBSYSTEM"] == "block" && skipBlock(env["DEVNAME"]) {
		return false
	}
	switch env["ACTION"] {
	case "add", "remove":
		return true
	case "change":
		return env["SUBSYSTEM"] == "drm"
	}
	return false
}

// linkMessage reports whether an rtnetlink message is about an interface
// hardware collection lists: not loopback, nor a container's or VM's.
func linkMessage(b []byte) bool {
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return true // can't tell: look
	}
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type != syscall.RTM_NEWLINK && m.Header.Type != syscall.RTM_DELLINK {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(m)
		if err != nil {
			return true
		}
		for _, a := range attrs {
			if a.Attr.Type == syscall.IFLA_IFNAME {
				name := string(bytes.TrimRight(a.Value, "\x00"))
				if name != "lo" && !isEphemeralNIC(name) {
					return true
				}
			}
		}
	}
	return false
}
