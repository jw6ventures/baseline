// Package unifitest is a fake UniFi console for tests: a UDM answering the
// Network and Protect Integration APIs and the classic API's client list.
package unifitest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Key is the API key the console accepts.
const Key = "test-api-key"

// Console is a running fake console. Its lists can be changed between
// polls.
type Console struct {
	*httptest.Server
	Fingerprint string // SHA-256 of its certificate, hex

	mu       sync.Mutex
	Devices  []map[string]any // as the device list has them; details add firmware and uplink
	Details  map[string]map[string]any
	Clients  []map[string]any
	Classic  []map[string]any // stat/sta
	Cameras  []map[string]any
	Protect  bool // Protect installed
	Requests []string
}

// Lock guards changes to the lists while the console runs.
func (c *Console) Lock()   { c.mu.Lock() }
func (c *Console) Unlock() { c.mu.Unlock() }

// New starts a console with one site ("Default"), a gateway, a switch
// uplinked to it, three wired clients and a wireless one, and a camera.
func New(t *testing.T) *Console {
	c := &Console{Protect: true,
		Devices: []map[string]any{
			{"id": "dev-gw", "name": "UDM Pro", "model": "UDM Pro", "macAddress": "F4:E2:C6:00:00:01", "ipAddress": "192.168.1.1", "state": "ONLINE", "features": []string{"switching", "gateway"}},
			{"id": "dev-sw", "name": "Rack switch", "model": "USW Pro 24", "macAddress": "f4e2c6000002", "ipAddress": "192.168.1.2", "state": "ONLINE", "features": []string{"switching"}},
		},
		Details: map[string]map[string]any{
			"dev-gw": {"firmwareVersion": "4.3.6", "firmwareUpdatable": false},
			"dev-sw": {"firmwareVersion": "7.1.26", "firmwareUpdatable": true, "uplink": map[string]any{"deviceId": "dev-gw"},
				"features": map[string]any{"switching": map[string]any{}}},
		},
		Clients: []map[string]any{
			{"type": "WIRED", "id": "cl-1", "name": "web1", "macAddress": "02:00:00:00:00:a1", "ipAddress": "192.168.1.10", "uplinkDeviceId": "dev-gw"},
			{"type": "WIRED", "id": "cl-2", "name": "printer", "macAddress": "02:00:00:00:00:a2", "ipAddress": "192.168.1.11", "uplinkDeviceId": "dev-sw"},
			{"type": "WIRED", "id": "cl-3", "name": "Front door", "macAddress": "02:00:00:00:00:c1", "ipAddress": "192.168.1.30", "uplinkDeviceId": "dev-sw"},
			{"type": "WIRELESS", "id": "cl-4", "name": "phone", "macAddress": "02:00:00:00:00:b1", "ipAddress": "192.168.1.50", "uplinkDeviceId": "dev-gw"},
		},
		Classic: []map[string]any{
			// The classic API knows web1 is really on the switch, port 7.
			{"mac": "02:00:00:00:00:a1", "is_wired": true, "sw_mac": "f4:e2:c6:00:00:02", "sw_port": 7},
			{"mac": "02:00:00:00:00:a2", "is_wired": true, "sw_mac": "f4:e2:c6:00:00:02", "sw_port": 12},
		},
		Cameras: []map[string]any{
			{"id": "cam-1", "modelKey": "camera", "name": "Front door", "mac": "0200000000C1", "state": "CONNECTED", "marketName": "G4 Doorbell Pro"},
		},
	}
	c.Server = httptest.NewTLSServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.Close)
	sum := sha256.Sum256(c.Certificate().Raw)
	c.Fingerprint = hex.EncodeToString(sum[:])
	return c
}

func (c *Console) serve(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Requests = append(c.Requests, r.URL.Path)
	if r.Header.Get("X-API-KEY") != Key {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	paged := func(items []map[string]any) any {
		off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		lim, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if lim <= 0 {
			lim = 25
		}
		// One at a time, whatever the limit, so paging is exercised.
		lim = min(lim, 1)
		end := min(off+lim, len(items))
		page := []map[string]any{}
		if off < len(items) {
			page = items[off:end]
		}
		return map[string]any{"offset": off, "limit": lim, "count": len(page), "totalCount": len(items), "data": page}
	}
	const net = "/proxy/network/integration/v1"
	const prot = "/proxy/protect/integration/v1"
	var out any
	p := r.URL.Path
	switch {
	case p == net+"/info":
		out = map[string]any{"applicationVersion": "9.4.19"}
	case p == net+"/sites":
		out = paged([]map[string]any{{"id": "site-1", "internalReference": "default", "name": "Default"}})
	case p == net+"/sites/site-1/devices":
		out = paged(c.Devices)
	case strings.HasPrefix(p, net+"/sites/site-1/devices/"):
		id := strings.TrimPrefix(p, net+"/sites/site-1/devices/")
		for _, d := range c.Devices {
			if d["id"] == id {
				full := map[string]any{}
				for k, v := range d {
					full[k] = v
				}
				for k, v := range c.Details[id] {
					full[k] = v
				}
				out = full
			}
		}
	case p == net+"/sites/site-1/clients":
		out = paged(c.Clients)
	case p == "/proxy/network/api/s/default/stat/sta":
		out = map[string]any{"meta": map[string]any{"rc": "ok"}, "data": c.Classic}
	case c.Protect && p == prot+"/meta/info":
		out = map[string]any{"applicationVersion": "6.1.79"}
	case c.Protect && p == prot+"/cameras":
		out = c.Cameras
	case c.Protect && (p == prot+"/lights" || p == prot+"/sensors" || p == prot+"/chimes" || p == prot+"/viewers"):
		out = []any{}
	}
	if out == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
