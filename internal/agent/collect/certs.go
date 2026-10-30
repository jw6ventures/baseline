package collect

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

// defaultCertGlobs are where certificates usually live (docs/agent.md §1.3).
var defaultCertGlobs = []string{
	"/etc/letsencrypt/live/*/fullchain.pem",
	"/etc/letsencrypt/live/*/cert.pem",
	"/etc/ssl/certs/*.pem",
	"/etc/ssl/certs/*.crt",
	"/etc/pki/tls/certs/*.pem",
	"/etc/pki/tls/certs/*.crt",
}

const (
	certMaxFileSize  = 1 << 20
	certMaxFiles     = 2000
	certProbeTimeout = 2 * time.Second
	certMaxPorts     = 64
	certProbeWorkers = 8
	certMaxSNINames  = 16
)

// Certs reports the TLS certificates in files and those served by the
// host's TCP listeners. extra are glob patterns added to the defaults.
func (e *Env) Certs(ctx context.Context, extra []string) (model.Certs, error) {
	out := model.Certs{Certs: []model.Cert{}}
	files, sans := e.certFiles(append(append([]string{}, defaultCertGlobs...), extra...))
	out.Certs = append(out.Certs, files...)

	ports, err := e.Ports(ctx)
	if err != nil {
		return out, err
	}
	probed, err := e.probeCerts(ctx, ports.Listeners, e.sniNames(sans))
	if err != nil {
		return out, err
	}
	out.Certs = append(out.Certs, probed...)
	sort.SliceStable(out.Certs, func(i, j int) bool { return out.Certs[i].Location < out.Certs[j].Location })
	return out, nil
}

// certFiles reads the leaf certificate of each matching file, and returns
// the DNS names they cover for the listener probe.
func (e *Env) certFiles(globs []string) (certs []model.Cert, sans []string) {
	seen := map[string]bool{}
	n := 0
	for _, g := range globs {
		for _, p := range e.Glob(g) {
			if seen[p] {
				continue
			}
			seen[p] = true
			if n++; n > certMaxFiles {
				return certs, sans
			}
			c := e.readCertFile(p)
			if c == nil {
				continue
			}
			certs = append(certs, certInfo(c, p))
			sans = append(sans, c.DNSNames...)
		}
	}
	return certs, sans
}

// readCertFile parses a file's first certificate (a chain lists the leaf
// first), or returns nil for anything that isn't a server certificate.
func (e *Env) readCertFile(p string) *x509.Certificate {
	st, err := os.Stat(e.path(p))
	if err != nil || !st.Mode().IsRegular() || st.Size() > certMaxFileSize {
		return nil
	}
	raw, err := e.ReadBytes(p)
	if err != nil {
		return nil
	}
	for {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		if b == nil {
			return nil
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil || isCertAuthority(c) {
			return nil
		}
		return c
	}
}

// isCertAuthority tells CA certificates (the trust store, bundles) from
// server certificates. `openssl req -x509` marks its self-signed certs
// CA:TRUE without restricting key usage; one that names hosts is still a
// server certificate (Debian's snakeoil cert).
func isCertAuthority(c *x509.Certificate) bool {
	if !c.IsCA {
		return false
	}
	names := len(c.DNSNames) + len(c.IPAddresses)
	return names == 0 || c.KeyUsage&x509.KeyUsageCertSign != 0
}

func certInfo(c *x509.Certificate, location string) model.Cert {
	var sans []string
	sans = append(sans, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, c.EmailAddresses...)
	sort.Strings(sans)
	fp := sha256.Sum256(c.Raw)
	return model.Cert{
		Location:    location,
		Subject:     c.Subject.String(),
		SANs:        sans,
		Issuer:      c.Issuer.String(),
		NotBefore:   c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:    c.NotAfter.UTC().Format(time.RFC3339),
		Serial:      c.SerialNumber.Text(16),
		Fingerprint: hex.EncodeToString(fp[:]),
		// CheckSignatureFrom would refuse a parent that isn't a CA, which
		// most self-signed server certs aren't; check the signature itself.
		SelfSigned: c.Issuer.String() == c.Subject.String() &&
			c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil,
	}
}

// sniNames are the server names to try on each TLS listener: the host's
// own name and the hosts its certificate files cover.
func (e *Env) sniNames(sans []string) []string {
	h := e.hostname()
	names := []string{e.fqdn(h), h}
	sorted := append([]string{}, sans...)
	sort.Strings(sorted)
	names = append(names, sorted...)

	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if n == "" || strings.Contains(n, "*") || seen[n] {
			continue
		}
		seen[n] = true
		if out = append(out, n); len(out) == certMaxSNINames {
			break
		}
	}
	return out
}

// certProbeTarget is a TCP port to probe and the address to dial for it.
type certProbeTarget struct {
	port int
	addr string
}

// certProbeTargets picks the TCP ports reachable from outside, once each.
func certProbeTargets(listeners []model.Listener) []certProbeTarget {
	seen := map[int]bool{}
	var out []certProbeTarget
	for _, l := range listeners {
		ip := net.ParseIP(l.Addr)
		if l.Proto != "tcp" || ip == nil || ip.IsLoopback() || seen[l.Port] {
			continue
		}
		seen[l.Port] = true
		host := l.Addr
		switch {
		case ip.IsUnspecified() && ip.To4() != nil:
			host = "127.0.0.1"
		case ip.IsUnspecified():
			host = "::1"
		}
		out = append(out, certProbeTarget{port: l.Port, addr: net.JoinHostPort(host, strconv.Itoa(l.Port))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].port < out[j].port })
	if len(out) > certMaxPorts {
		out = out[:certMaxPorts]
	}
	return out
}

// probeCerts handshakes with each listener a few at a time.
func (e *Env) probeCerts(ctx context.Context, listeners []model.Listener, names []string) ([]model.Cert, error) {
	targets := certProbeTargets(listeners)
	results := make([][]model.Cert, len(targets))
	sem := make(chan struct{}, certProbeWorkers)
	var wg sync.WaitGroup
	for i, t := range targets {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			results[i] = probeListenerCerts(ctx, t, names)
		}()
	}
	wg.Wait()
	// A probe cut short would read as certificates removed.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []model.Cert
	for _, r := range results {
		out = append(out, r...)
	}
	return out, nil
}

// probeListenerCerts records the certificate a port serves without SNI, and
// each different one it serves for a known name.
func probeListenerCerts(ctx context.Context, t certProbeTarget, names []string) []model.Cert {
	loc := "tcp:" + strconv.Itoa(t.port)
	var out []model.Cert
	seen := map[string]bool{}
	leaf, err := tlsLeafCert(ctx, t.addr, "")
	switch {
	case err == nil:
		c := certInfo(leaf, loc)
		seen[c.Fingerprint] = true
		out = append(out, c)
	case !tlsAlerted(err):
		// Not TLS, or nothing there any more. A server that answered
		// with an alert speaks TLS but wants a name (SNI-only proxies).
		return nil
	}
	for _, n := range names {
		if ctx.Err() != nil {
			break
		}
		leaf, err := tlsLeafCert(ctx, t.addr, n)
		if err != nil {
			continue
		}
		c := certInfo(leaf, loc+"/"+n)
		if !seen[c.Fingerprint] {
			seen[c.Fingerprint] = true
			out = append(out, c)
		}
	}
	return out
}

// tlsProbeSuites accepts anything: the probe reads certificates, it doesn't
// protect data, and old appliances only speak old ciphers.
var tlsProbeSuites = func() []uint16 {
	var ids []uint16
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		ids = append(ids, s.ID)
	}
	return ids
}()

// tlsLeafCert handshakes with addr and returns the server's leaf
// certificate, sending sni unless it's empty.
func tlsLeafCert(ctx context.Context, addr, sni string) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, certProbeTimeout)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // reading, not trusting
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       tlsProbeSuites,
	}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil, errors.New("no certificate")
	}
	return st.PeerCertificates[0], nil
}

// tlsAlerted reports whether a handshake failed on an alert from the
// server, which crypto/tls returns as a "remote error".
func tlsAlerted(err error) bool {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "remote error" {
		return true
	}
	var ae tls.AlertError
	return errors.As(err, &ae)
}
