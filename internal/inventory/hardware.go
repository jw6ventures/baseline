package inventory

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// HardwareChange is a component added to, removed from or swapped in a
// host, as the hardware_change alert reports it.
type HardwareChange struct {
	Event     string `json:"event"`     // added | removed | swapped | link up | connected...
	Component string `json:"component"` // "disk sdb", "USB device 1-1.2", "NIC eno1"
	Detail    string `json:"detail,omitempty"`
}

func (c HardwareChange) String() string {
	s := c.Component + " " + c.Event
	if c.Detail != "" {
		s += " (" + c.Detail + ")"
	}
	return s
}

// component is a list in the hardware section whose items are parts of the
// machine: which fields identify the part fitted (a new serial in the same
// slot is a swap), and what describes it. Firmware, BIOS, microcode,
// filesystems and addresses are left out: they change without anyone
// touching the machine.
type component struct {
	path, label string
	swap        []string // nil: any field
	describe    []string
}

var components = []component{
	{path: "disks", label: "disk", swap: []string{"serial", "wwn", "model"}, describe: []string{"model", "serial"}},
	{path: "memory.dimms", label: "DIMM", swap: []string{"serial", "part_number", "manufacturer", "size_bytes"},
		describe: []string{"manufacturer", "part_number", "serial"}},
	{path: "nics", label: "NIC", swap: []string{"mac"}, describe: []string{"mac", "driver"}},
	{path: "pci", label: "PCI device", swap: []string{"vendor", "device"}, describe: []string{"vendor", "device"}},
	{path: "peripherals.usb", label: "USB device", describe: []string{"manufacturer", "product", "vendor_id", "product_id", "serial"}},
	{path: "peripherals.displays", label: "display connector", swap: []string{"monitor", "serial"},
		describe: []string{"status", "monitor", "serial"}},
}

// HardwareComponents picks the changes in a hardware diff that add, remove
// or swap a disk, DIMM, physical NIC, PCI or USB device, take a physical
// NIC's link up or down, or connect or disconnect a display. current is
// the section as it is now, for NIC kinds and monitor names. High security
// collection starting or stopping (peripherals and link state appearing or
// going) isn't a change.
func HardwareComponents(d Diff, current []byte) []HardwareChange {
	var hw struct {
		NICs        []struct{ Name, Kind string } `json:"nics"`
		Peripherals struct {
			Displays []struct{ Name, Monitor, Serial string } `json:"displays"`
		} `json:"peripherals"`
	}
	_ = json.Unmarshal(current, &hw)
	physical := func(name string) bool {
		return slices.ContainsFunc(hw.NICs, func(n struct{ Name, Kind string }) bool {
			return n.Name == name && n.Kind == "physical"
		})
	}
	// A display connected or disconnected brings its monitor with it: that
	// is the event, not a monitor swap.
	plugged := map[string]bool{}
	for _, ch := range d.Changed {
		if c, key, field, ok := locate(ch.Field); ok && c.path == "peripherals.displays" && field == "status" {
			plugged[key] = true
		}
	}
	monitor := func(key string) string {
		for _, x := range hw.Peripherals.Displays {
			if x.Name == key && x.Monitor != "" {
				return describe(map[string]any{"monitor": x.Monitor, "serial": x.Serial}, []string{"monitor", "serial"})
			}
		}
		// Disconnected: the monitor went with it.
		m := map[string]any{}
		for _, ch := range d.Removed {
			if c, k, field, ok := locate(ch.Field); ok && c.path == "peripherals.displays" && k == key {
				m[field] = ch.From
			}
		}
		return describe(m, []string{"monitor", "serial"})
	}

	var out []HardwareChange
	swapped := map[string]int{} // component → index in out
	item := func(c component, event string, obj any) {
		m, _ := obj.(map[string]any)
		if c.path == "nics" && m["kind"] != "physical" {
			return
		}
		out = append(out, HardwareChange{Event: event, Component: c.label + " " + identity(m), Detail: describe(m, c.describe)})
	}
	for _, x := range []struct {
		event   string
		changes []Change
	}{{"added", d.Added}, {"removed", d.Removed}, {"changed", d.Changed}} {
		for _, ch := range x.changes {
			c, key, field, ok := locate(ch.Field)
			if !ok {
				continue
			}
			event := x.event
			if key == "" && event == "changed" {
				// From or to null is the list appearing or going.
				switch {
				case ch.From == nil:
					event = "added"
				case ch.To == nil:
					event = "removed"
				}
			}
			switch {
			case key == "" && event != "changed":
				// The whole list appeared or went: each item did.
				v := ch.To
				if event == "removed" {
					v = ch.From
				}
				list, _ := v.([]any)
				for _, it := range list {
					item(c, event, it)
				}
			case key == "":
				// A list compared as a whole (items without identities):
				// it changed, but not which part.
				out = append(out, HardwareChange{Event: "swapped", Component: c.label + "s", Detail: "list changed"})
			case field == "":
				v := ch.To
				if x.event == "removed" {
					v = ch.From
				}
				item(c, x.event, v)
			case c.path == "nics" && field == "link":
				// Appearing or going is collection starting or stopping.
				if x.event == "changed" && physical(key) {
					out = append(out, HardwareChange{Event: "link " + value(ch.To), Component: "NIC " + key,
						Detail: "was " + value(ch.From)})
				}
			case c.path == "peripherals.displays" && field == "status":
				event := value(ch.To)
				if event != "connected" && event != "disconnected" {
					event = "status " + event
				}
				out = append(out, HardwareChange{Event: event, Component: c.label + " " + key, Detail: monitor(key)})
			case c.path == "peripherals.displays" && plugged[key]:
			case c.swap == nil || slices.Contains(c.swap, field):
				if c.path == "nics" && !physical(key) {
					continue
				}
				name := c.label + " " + key
				detail := fmt.Sprintf("%s %s → %s", strings.ReplaceAll(field, "_", " "), value(ch.From), value(ch.To))
				if i, ok := swapped[name]; ok {
					out[i].Detail += ", " + detail
					continue
				}
				swapped[name] = len(out)
				out = append(out, HardwareChange{Event: "swapped", Component: name, Detail: detail})
			}
		}
	}
	return out
}

// locate splits a diff path into its component, the item's key and the
// item's field: "disks[sda].serial" is disks, "sda", "serial".
func locate(path string) (c component, key, field string, ok bool) {
	for _, c := range components {
		rest, found := strings.CutPrefix(path, c.path)
		if !found {
			continue
		}
		if rest == "" {
			return c, "", "", true
		}
		rest, found = strings.CutPrefix(rest, "[")
		if !found {
			continue
		}
		key, rest, found = strings.Cut(rest, "]")
		if !found {
			continue
		}
		field, _, _ = strings.Cut(strings.TrimPrefix(rest, "."), ".")
		return c, key, field, true
	}
	return component{}, "", "", false
}

func identity(m map[string]any) string {
	for _, f := range identityFields {
		if s, ok := m[f].(string); ok && s != "" {
			return s
		}
	}
	return "?"
}

func describe(m map[string]any, fields []string) string {
	var parts []string
	for _, f := range fields {
		if v, ok := m[f]; ok && v != nil && v != "" {
			parts = append(parts, strings.ReplaceAll(f, "_", " ")+" "+value(v))
		}
	}
	return strings.Join(parts, ", ")
}

func value(v any) string {
	switch x := v.(type) {
	case nil:
		return "none"
	case string:
		if x == "" {
			return "none"
		}
		return x
	case float64: // JSON numbers: sizes in bytes
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}
