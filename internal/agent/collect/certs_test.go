package collect

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

// certTestKey is a generated certificate with its key.
type certTestKey struct {
	cert *x509.Certificate
	der  []byte
	key  crypto.Signer
}

func (k certTestKey) pem() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.der}))
}

func (k certTestKey) fingerprint() string {
	fp := sha256.Sum256(k.der)
	return hex.EncodeToString(fp[:])
}

func (k certTestKey) tls() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{k.der}, PrivateKey: k.key, Leaf: k.cert}
}

var certTestSerial int64 = 0x1000

// certTestIssue signs tmpl with parent, or self-signs when parent is nil.
func certTestIssue(t *testing.T, tmpl *x509.Certificate, parent *certTestKey) certTestKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certTestSerial++
	tmpl.SerialNumber = big.NewInt(certTestSerial)
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		tmpl.NotAfter = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	signer, issuer := crypto.Signer(key), tmpl
	if parent != nil {
		signer, issuer = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certTestKey{cert: c, der: der, key: key}
}

func certTestCA(t *testing.T) certTestKey {
	return certTestIssue(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Homelab Root CA", Organization: []string{"Homelab"}},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil)
}

func certTestLeaf(t *testing.T, ca *certTestKey, cn string, names ...string) certTestKey {
	return certTestIssue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn},
		DNSNames:    names,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca)
}

func certsByLocation(cs []model.Cert) map[string]model.Cert {
	m := map[string]model.Cert{}
	for _, c := range cs {
		m[c.Location] = c
	}
	return m
}

func certLocations(cs []model.Cert) string {
	var l []string
	for _, c := range cs {
		l = append(l, c.Location)
	}
	return strings.Join(l, " ")
}

func TestCertsFiles(t *testing.T) {
	ca := certTestCA(t)
	leaf := certTestIssue(t, &x509.Certificate{
		Subject:        pkix.Name{CommonName: "example.com"},
		DNSNames:       []string{"www.example.com", "example.com", "*.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.10")},
		EmailAddresses: []string{"admin@example.com"},
		NotBefore:      time.Date(2026, 9, 1, 12, 0, 0, 0, time.FixedZone("CDT", -5*3600)),
		NotAfter:       time.Date(2026, 11, 30, 12, 0, 0, 0, time.UTC),
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}, &ca)
	// `openssl req -x509` style: self-signed, CA:TRUE, but names a host.
	snakeoil := certTestIssue(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "web1"},
		DNSNames:              []string{"web1"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}, nil)
	// A plain self-signed server cert without CA:TRUE.
	selfSigned := certTestIssue(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "app.internal"},
		DNSNames: []string{"app.internal"},
	}, nil)
	keyPEM := "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n"

	f := newFixture(t)
	f.file("/etc/letsencrypt/live/example.com/fullchain.pem", leaf.pem()+ca.pem())
	f.file("/etc/letsencrypt/live/example.com/cert.pem", leaf.pem())
	f.file("/etc/letsencrypt/live/example.com/privkey.pem", keyPEM)
	f.file("/etc/ssl/certs/Homelab_Root_CA.pem", ca.pem())
	f.file("/etc/ssl/certs/ca-certificates.crt", ca.pem()+leaf.pem())
	f.link("/etc/ssl/certs/0a1b2c3d.0", "Homelab_Root_CA.pem")
	f.file("/etc/ssl/certs/ssl-cert-snakeoil.pem", snakeoil.pem())
	f.file("/etc/pki/tls/certs/key-only.pem", keyPEM)
	f.file("/etc/pki/tls/certs/garbage.crt", "not a certificate\n")
	f.file("/etc/pki/tls/certs/huge.pem", strings.Repeat("#", certMaxFileSize+1)+leaf.pem())
	f.file("/opt/app/tls/server.crt", keyPEM+selfSigned.pem())
	f.file("/proc/sys/kernel/hostname", "web1\n")

	cs, err := f.env.Certs(context.Background(), []string{"/opt/app/*/server.crt", "/etc/ssl/certs/*.pem"})
	if err != nil {
		t.Fatal(err)
	}
	want := "/etc/letsencrypt/live/example.com/cert.pem /etc/letsencrypt/live/example.com/fullchain.pem " +
		"/etc/ssl/certs/ssl-cert-snakeoil.pem /opt/app/tls/server.crt"
	if got := certLocations(cs.Certs); got != want {
		t.Fatalf("locations = %s\nwant        %s", got, want)
	}
	m := certsByLocation(cs.Certs)
	got := m["/etc/letsencrypt/live/example.com/fullchain.pem"]
	wantLeaf := model.Cert{
		Location:    "/etc/letsencrypt/live/example.com/fullchain.pem",
		Subject:     "CN=example.com",
		SANs:        []string{"*.example.com", "192.0.2.10", "admin@example.com", "example.com", "www.example.com"},
		Issuer:      "CN=Homelab Root CA,O=Homelab",
		NotBefore:   "2026-09-01T17:00:00Z",
		NotAfter:    "2026-11-30T12:00:00Z",
		Serial:      fmt.Sprintf("%x", leaf.cert.SerialNumber),
		Fingerprint: leaf.fingerprint(),
	}
	if fmt.Sprint(got) != fmt.Sprint(wantLeaf) {
		t.Errorf("leaf = %+v\nwant   %+v", got, wantLeaf)
	}
	if c := m["/etc/letsencrypt/live/example.com/cert.pem"]; c.Fingerprint != leaf.fingerprint() {
		t.Errorf("cert.pem = %+v", c)
	}
	if c := m["/etc/ssl/certs/ssl-cert-snakeoil.pem"]; !c.SelfSigned || c.Subject != "CN=web1" {
		t.Errorf("snakeoil = %+v", c)
	}
	if c := m["/opt/app/tls/server.crt"]; !c.SelfSigned || c.Fingerprint != selfSigned.fingerprint() {
		t.Errorf("self-signed = %+v", c)
	}
}

// certTestServe serves TLS on 127.0.0.1 until the test ends, choosing the
// certificate by SNI.
func certTestServe(t *testing.T, pick func(sni string) (*tls.Certificate, error)) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	cfg := &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) { return pick(h.ServerName) }}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				tls.Server(c, cfg).Handshake()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// certTestPlain serves something that isn't TLS, like an SSH banner.
func certTestPlain(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"))
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestCertsProbe(t *testing.T) {
	ca := certTestCA(t)
	def := certTestLeaf(t, &ca, "example.com", "example.com", "www.example.com")
	app := certTestLeaf(t, &ca, "app.example.com", "app.example.com")
	host := certTestLeaf(t, &ca, "web1", "web1")
	defTLS, appTLS, hostTLS := def.tls(), app.tls(), host.tls()

	// A server with a default certificate that also serves other names.
	multi := certTestServe(t, func(sni string) (*tls.Certificate, error) {
		switch sni {
		case "app.example.com":
			return &appTLS, nil
		case "web1":
			return &hostTLS, nil
		}
		return &defTLS, nil
	})
	// An SNI-only proxy refuses a handshake without a name it knows.
	sniOnly := certTestServe(t, func(sni string) (*tls.Certificate, error) {
		if sni == "app.example.com" {
			return &appTLS, nil
		}
		return nil, errors.New("no certificate for " + sni)
	})
	plain := certTestPlain(t)
	loopbackOnly := certTestServe(t, func(string) (*tls.Certificate, error) { return &defTLS, nil })

	f := newFixture(t)
	f.file("/proc/sys/kernel/hostname", "web1\n")
	f.file("/etc/letsencrypt/live/example.com/fullchain.pem", def.pem()+ca.pem())
	// The app's cert file is how the probe learns the name to ask for.
	f.file("/etc/pki/tls/certs/app.pem", app.pem())
	hexPort := func(p int) string { return fmt.Sprintf("%04X", p) }
	f.file("/proc/net/tcp", portsNetHeader+
		portsNetLine(0, "00000000:"+hexPort(multi), portsV4Any, "0A", 0)+
		portsNetLine(1, "00000000:"+hexPort(sniOnly), portsV4Any, "0A", 0)+
		portsNetLine(2, "00000000:"+hexPort(plain), portsV4Any, "0A", 0)+
		portsNetLine(3, "0100007F:"+hexPort(loopbackOnly), portsV4Any, "0A", 0))
	// Dual-stack: the same port on :: is probed once.
	f.file("/proc/net/tcp6", portsNetHeader+
		portsNetLine(0, "00000000000000000000000000000000:"+hexPort(multi), portsV6Any, "0A", 0))

	cs, err := f.env.Certs(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := certsByLocation(cs.Certs)
	mp, sp := fmt.Sprintf("tcp:%d", multi), fmt.Sprintf("tcp:%d", sniOnly)
	for loc, fp := range map[string]string{
		mp:                      def.fingerprint(),
		mp + "/web1":            host.fingerprint(),
		mp + "/app.example.com": app.fingerprint(),
		sp + "/app.example.com": app.fingerprint(),
		"/etc/letsencrypt/live/example.com/fullchain.pem": def.fingerprint(),
		"/etc/pki/tls/certs/app.pem":                      app.fingerprint(),
	} {
		if m[loc].Fingerprint != fp {
			t.Errorf("%s: %+v", loc, m[loc])
		}
	}
	// example.com and www.example.com get the default cert again: not
	// repeated. The plain and loopback-only ports aren't there.
	if len(cs.Certs) != 6 {
		t.Errorf("locations = %s", certLocations(cs.Certs))
	}
	if c := m[mp]; c.Subject != "CN=example.com" || c.SelfSigned || c.Issuer != "CN=Homelab Root CA,O=Homelab" {
		t.Errorf("probed = %+v", c)
	}

	// A cancelled collection fails rather than reporting fewer certs.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.env.Certs(ctx, nil); err == nil {
		t.Error("expected an error when cancelled")
	}
}

func TestCertsSNINames(t *testing.T) {
	f := newFixture(t)
	f.file("/proc/sys/kernel/hostname", "web1\n")
	var sans []string
	for i := 30; i > 0; i-- {
		sans = append(sans, fmt.Sprintf("h%02d.example.com", i))
	}
	sans = append(sans, "*.example.com", "WEB1", "h01.example.com.")
	names := f.env.sniNames(sans)
	if len(names) != certMaxSNINames || names[0] != "web1" || names[1] != "h01.example.com" ||
		names[15] != "h15.example.com" {
		t.Errorf("names = %q", names)
	}
}
