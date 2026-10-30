// Package unifi reads a UniFi console (a UDM, UCG or Cloud Key, or a
// self-hosted Network application) through its local Integration API: the
// Network application's sites, adopted devices and wired clients, and UniFi
// Protect's cameras and other devices. It only reads.
//
// The server polls a console it can reach itself; for one only a host's
// network reaches, that host's agent runs the same Poll and sends the
// result back (docs/integrations.md).
package unifi

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

// Config is how a console is reached. The API key is kept apart: the
// server stores it encrypted and only hands it over for a poll.
type Config struct {
	URL string `json:"url"` // https://192.168.1.1
	// TLSFingerprint pins the console's certificate by its SHA-256 (hex,
	// colons allowed) instead of verifying it: consoles ship self-signed.
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
	// Sites limits the poll to these sites, by name or ID; empty: all.
	Sites   []string `json:"sites,omitempty"`
	Protect bool     `json:"protect,omitempty"` // read UniFi Protect too
}

// Check validates a config as the settings form saves it, normalizing the
// URL and fingerprint.
func (c Config) Check() (Config, error) {
	c.URL = strings.TrimRight(strings.TrimSpace(c.URL), "/")
	if c.URL != "" && !strings.Contains(c.URL, "://") {
		c.URL = "https://" + c.URL
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return c, errors.New("enter the console's address, e.g. https://192.168.1.1")
	}
	if c.TLSFingerprint != "" {
		fp := NormalizeFingerprint(c.TLSFingerprint)
		if len(fp) != 64 {
			return c, errors.New("the TLS fingerprint is a SHA-256: 64 hex digits, colons allowed")
		}
		c.TLSFingerprint = fp
	}
	var sites []string
	for _, s := range c.Sites {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(sites, s) {
			sites = append(sites, s)
		}
	}
	c.Sites = sites
	return c, nil
}

// NormalizeFingerprint is a fingerprint as lower-case hex without
// separators; anything that isn't hex comes out of a different length.
func NormalizeFingerprint(s string) string {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s)))
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}

// FormatFingerprint shows a fingerprint the way browsers do.
func FormatFingerprint(fp string) string {
	var parts []string
	for i := 0; i+2 <= len(fp); i += 2 {
		parts = append(parts, strings.ToUpper(fp[i:i+2]))
	}
	return strings.Join(parts, ":")
}

// UntrustedError is a console whose certificate didn't verify. It carries
// the certificate's fingerprint, for pinning once it's confirmed to be the
// console's.
type UntrustedError struct {
	Fingerprint string
	Err         error
}

func (e *UntrustedError) Error() string {
	return fmt.Sprintf("the console's certificate isn't trusted (%v). If its SHA-256 fingerprint %s is your console's, pin it", e.Err,
		FormatFingerprint(e.Fingerprint))
}

func (e *UntrustedError) Unwrap() error { return e.Err }

const (
	pageSize = 200
	maxBody  = 32 << 20
	// maxPages bounds a paged list, in case a console keeps answering.
	maxPages = 100
)

// Client talks to one console.
type Client struct {
	cfg  Config
	key  string
	http *http.Client
}

// New makes a client. A pinned console's certificate is checked against
// the fingerprint and nothing else; otherwise it must verify normally.
func New(cfg Config, apiKey string) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if fp := NormalizeFingerprint(cfg.TLSFingerprint); fp != "" {
		tr.TLSClientConfig.InsecureSkipVerify = true // replaced by the pin below
		tr.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the console sent no certificate")
			}
			if got := certFingerprint(cs.PeerCertificates[0]); got != fp {
				return fmt.Errorf("the console's certificate changed: its fingerprint is now %s, not the pinned one", FormatFingerprint(got))
			}
			return nil
		}
	}
	return &Client{cfg: cfg, key: apiKey, http: &http.Client{Transport: tr, Timeout: time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func certFingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

// presentedFingerprint connects without verifying, only to read the
// certificate a console that failed verification presents.
func (c *Client) presentedFingerprint(ctx context.Context) string {
	u, err := url.Parse(c.cfg.URL)
	if err != nil {
		return ""
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, ServerName: u.Hostname()}} // only reads the cert
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	return certFingerprint(certs[0])
}

// statusError is a console's answer other than 200.
type statusError struct {
	Code int
	Path string
}

func (e *statusError) Error() string {
	switch e.Code {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "the console refused the API key (HTTP " + strconv.Itoa(e.Code) + ")"
	case http.StatusNotFound:
		return "the console has no " + e.Path + " (HTTP 404)"
	}
	return fmt.Sprintf("%s: HTTP %d", e.Path, e.Code)
}

func (c *Client) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.URL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-KEY", c.key)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		var unknown x509.UnknownAuthorityError
		var invalid x509.CertificateInvalidError
		var hostname x509.HostnameError
		var verify *tls.CertificateVerificationError
		if errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &hostname) || errors.As(err, &verify) {
			cause := err
			if verify != nil {
				cause = verify.Err
			}
			return &UntrustedError{Fingerprint: c.presentedFingerprint(ctx), Err: cause}
		}
		var ue *url.Error
		if errors.As(err, &ue) {
			return ue.Err // the URL is in the settings already, and the key never is
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		p, _, _ := strings.Cut(path, "?")
		return &statusError{Code: resp.StatusCode, Path: p}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// page is the Network API's paged list.
type page[T any] struct {
	Offset     int `json:"offset"`
	Count      int `json:"count"`
	TotalCount int `json:"totalCount"`
	Data       []T `json:"data"`
}

func list[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var out []T
	for range maxPages {
		var p page[T]
		if err := c.get(ctx, fmt.Sprintf("%s?offset=%d&limit=%d", path, len(out), pageSize), &p); err != nil {
			return nil, err
		}
		out = append(out, p.Data...)
		if len(p.Data) == 0 || len(out) >= p.TotalCount {
			return out, nil
		}
	}
	return out, nil
}

const (
	networkAPI = "/proxy/network/integration/v1"
	classicAPI = "/proxy/network/api"
	protectAPI = "/proxy/protect/integration/v1"
)

type apiSite struct {
	ID                string `json:"id"`
	InternalReference string `json:"internalReference"`
	Name              string `json:"name"`
}

type apiDevice struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Model             string          `json:"model"`
	MACAddress        string          `json:"macAddress"`
	IPAddress         string          `json:"ipAddress"`
	State             string          `json:"state"`
	FirmwareVersion   string          `json:"firmwareVersion"`
	FirmwareUpdatable bool            `json:"firmwareUpdatable"`
	Features          json.RawMessage `json:"features"` // a list in lists, an object in details
	Uplink            struct {
		DeviceID string `json:"deviceId"`
	} `json:"uplink"`
}

// features reads the device's features either way the API spells them.
func (d apiDevice) features() []string {
	var list []string
	if json.Unmarshal(d.Features, &list) != nil {
		var obj map[string]json.RawMessage
		if json.Unmarshal(d.Features, &obj) == nil {
			for k := range obj {
				list = append(list, k)
			}
		}
	}
	slices.Sort(list)
	return slices.Compact(list)
}

type apiClient struct {
	Type           string `json:"type"` // WIRED, WIRELESS, VPN, TELEPORT
	ID             string `json:"id"`
	Name           string `json:"name"`
	MACAddress     string `json:"macAddress"`
	IPAddress      string `json:"ipAddress"`
	UplinkDeviceID string `json:"uplinkDeviceId"`
}

// classicClient is a client as the classic API's stat/sta lists it, which
// is where the switch port is.
type classicClient struct {
	MAC     string `json:"mac"`
	IsWired bool   `json:"is_wired"`
	SwMAC   string `json:"sw_mac"`
	SwPort  int    `json:"sw_port"`
}

type protectDevice struct {
	ID         string `json:"id"`
	ModelKey   string `json:"modelKey"`
	Name       string `json:"name"`
	MAC        string `json:"mac"`
	State      string `json:"state"`
	MarketName string `json:"marketName"`
	Type       string `json:"type"`
}

// Poll reads everything the config asks for.
func Poll(ctx context.Context, cfg Config, apiKey string) (model.UniFi, error) {
	return New(cfg, apiKey).Poll(ctx)
}

func (c *Client) Poll(ctx context.Context) (model.UniFi, error) {
	var out model.UniFi
	var info struct {
		ApplicationVersion string `json:"applicationVersion"`
	}
	if err := c.get(ctx, networkAPI+"/info", &info); err != nil {
		var se *statusError
		if errors.As(err, &se) && se.Code == http.StatusNotFound {
			return out, errors.New("the console has no Integration API: UniFi Network 9.0 or newer is needed")
		}
		return out, err
	}
	out.NetworkVersion = info.ApplicationVersion
	sites, err := list[apiSite](ctx, c, networkAPI+"/sites")
	if err != nil {
		return out, err
	}
	out.Sites = []model.UniFiSite{}
	for _, s := range sites {
		if len(c.cfg.Sites) > 0 && !slices.ContainsFunc(c.cfg.Sites, func(w string) bool {
			return w == s.ID || strings.EqualFold(w, s.Name) || strings.EqualFold(w, s.InternalReference)
		}) {
			continue
		}
		site, err := c.site(ctx, s)
		if err != nil {
			return out, fmt.Errorf("site %s: %w", s.Name, err)
		}
		out.Sites = append(out.Sites, site)
	}
	if len(c.cfg.Sites) > 0 && len(out.Sites) == 0 {
		return out, fmt.Errorf("the console has none of the sites %s", strings.Join(c.cfg.Sites, ", "))
	}
	if c.cfg.Protect {
		c.protect(ctx, &out)
	}
	return out, nil
}

func (c *Client) site(ctx context.Context, s apiSite) (model.UniFiSite, error) {
	site := model.UniFiSite{ID: s.ID, Ref: s.InternalReference, Name: s.Name, Devices: []model.UniFiDevice{}, Clients: []model.UniFiClient{}}
	base := networkAPI + "/sites/" + url.PathEscape(s.ID)
	devices, err := list[apiDevice](ctx, c, base+"/devices")
	if err != nil {
		return site, err
	}
	macByID := map[string]string{}
	for _, d := range devices {
		// Firmware and uplink are only in a device's details.
		var full apiDevice
		if err := c.get(ctx, base+"/devices/"+url.PathEscape(d.ID), &full); err != nil {
			return site, err
		}
		if full.ID == "" {
			full = d
		}
		if len(full.Features) == 0 {
			full.Features = d.Features
		}
		dev := model.UniFiDevice{ID: d.ID, Name: first(full.Name, d.Name), Model: first(full.Model, d.Model),
			MAC: NormalizeMAC(first(full.MACAddress, d.MACAddress)), IP: first(full.IPAddress, d.IPAddress),
			State: first(full.State, d.State), Firmware: full.FirmwareVersion, FirmwareUpdatable: full.FirmwareUpdatable,
			Features: full.features(), UplinkID: full.Uplink.DeviceID}
		if dev.MAC == "" {
			continue // nothing to know it by
		}
		macByID[dev.ID] = dev.MAC
		site.Devices = append(site.Devices, dev)
	}
	clients, err := list[apiClient](ctx, c, base+"/clients")
	if err != nil {
		return site, err
	}
	for _, cl := range clients {
		mac := NormalizeMAC(cl.MACAddress)
		if !strings.EqualFold(cl.Type, "WIRED") || mac == "" {
			continue
		}
		site.Clients = append(site.Clients, model.UniFiClient{ID: cl.ID, Name: cl.Name, MAC: mac, IP: cl.IPAddress, UplinkID: cl.UplinkDeviceID})
	}
	// The Integration API doesn't say which port a client is on; the
	// classic API does, and takes the same key on current consoles.
	if s.InternalReference != "" && len(site.Clients) > 0 {
		var sta struct {
			Data []classicClient `json:"data"`
		}
		if err := c.get(ctx, classicAPI+"/s/"+url.PathEscape(s.InternalReference)+"/stat/sta", &sta); err != nil {
			site.PortsError = err.Error()
		} else {
			idByMAC := map[string]string{}
			for id, mac := range macByID {
				idByMAC[mac] = id
			}
			ports := map[string]classicClient{}
			for _, x := range sta.Data {
				if x.IsWired {
					ports[NormalizeMAC(x.MAC)] = x
				}
			}
			for i, cl := range site.Clients {
				if p, ok := ports[cl.MAC]; ok {
					site.Clients[i].Port = p.SwPort
					if id := idByMAC[NormalizeMAC(p.SwMAC)]; id != "" {
						site.Clients[i].UplinkID = id
					}
				}
			}
		}
	}
	slices.SortFunc(site.Devices, func(a, b model.UniFiDevice) int { return strings.Compare(a.MAC, b.MAC) })
	slices.SortFunc(site.Clients, func(a, b model.UniFiClient) int { return strings.Compare(a.MAC, b.MAC) })
	return site, nil
}

// protectKinds are the Protect device lists read, by the kind they get.
var protectKinds = []struct{ path, kind string }{
	{"/cameras", "camera"}, {"/lights", "light"}, {"/sensors", "sensor"}, {"/chimes", "chime"}, {"/viewers", "viewer"},
}

// protect reads UniFi Protect. A console without it, or a key without
// access to it, leaves a note instead of failing the poll.
func (c *Client) protect(ctx context.Context, out *model.UniFi) {
	var info struct {
		ApplicationVersion string `json:"applicationVersion"`
	}
	if err := c.get(ctx, protectAPI+"/meta/info", &info); err != nil {
		out.ProtectError = err.Error()
		return
	}
	out.ProtectVersion = info.ApplicationVersion
	out.Protect = []model.UniFiCamera{}
	for _, k := range protectKinds {
		var raw json.RawMessage
		if err := c.get(ctx, protectAPI+k.path, &raw); err != nil {
			var se *statusError
			if errors.As(err, &se) && se.Code == http.StatusNotFound {
				continue // an older Protect without this kind
			}
			out.ProtectError = err.Error()
			out.Protect = nil
			return
		}
		var devs []protectDevice
		if json.Unmarshal(raw, &devs) != nil {
			var p page[protectDevice]
			json.Unmarshal(raw, &p)
			devs = p.Data
		}
		for _, d := range devs {
			out.Protect = append(out.Protect, model.UniFiCamera{Kind: k.kind, ID: d.ID, Name: d.Name,
				Model: first(d.MarketName, d.Type), MAC: NormalizeMAC(d.MAC), State: d.State})
		}
	}
	slices.SortFunc(out.Protect, func(a, b model.UniFiCamera) int {
		return strings.Compare(a.Kind+"/"+a.ID, b.Kind+"/"+b.ID)
	})
}

// NormalizeMAC writes a MAC as lower-case hex pairs separated by colons,
// whichever way it came (F4E2C6A1B2C3, f4-e2-...); "" if it isn't one.
func NormalizeMAC(s string) string {
	h := strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(s))
	if len(h) != 12 {
		return ""
	}
	if _, err := hex.DecodeString(h); err != nil {
		return ""
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
