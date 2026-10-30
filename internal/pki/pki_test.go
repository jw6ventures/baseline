package pki

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadCreatesThenReuses(t *testing.T) {
	dir := t.TempDir()
	a, err := Load(dir, []string{"agent.baseline.example", "10.8.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"ca.crt", "ca.key", "server.crt", "server.key", "release.key"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	if st, _ := os.Stat(filepath.Join(dir, "ca.key")); st.Mode().Perm() != 0o600 {
		t.Errorf("ca.key mode %v", st.Mode().Perm())
	}
	b, err := Load(dir, []string{"agent.baseline.example", "10.8.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.CAFingerprint(), b.CAFingerprint()) || !bytes.Equal(a.ReleasePublicKey(), b.ReleasePublicKey()) {
		t.Fatal("reload created a new CA or release key")
	}
	if !bytes.Equal(a.ServerCert().Leaf.Raw, b.ServerCert().Leaf.Raw) {
		t.Fatal("server cert reissued without reason")
	}

	// A new name forces a new server cert under the same CA.
	c, err := Load(dir, []string{"agent.new.example"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c.ServerCert().Leaf.Raw, a.ServerCert().Leaf.Raw) {
		t.Fatal("server cert not reissued for a new name")
	}
	if err := c.ServerCert().Leaf.VerifyHostname("agent.new.example"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.CAFingerprint(), a.CAFingerprint()) {
		t.Fatal("CA changed")
	}
}

func TestIssueClient(t *testing.T) {
	a, _ := Load(t.TempDir(), []string{"gw.example"})
	key, csr, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := a.IssueClient(csr, "6f1c...agent")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "6f1c...agent" {
		t.Fatalf("CN = %q", cert.Subject.CommonName)
	}
	if d := time.Until(cert.NotAfter); d < ClientLifetime-time.Hour || d > ClientLifetime {
		t.Fatalf("lifetime %v", d)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: a.ClientCAs(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("cert is not for the CSR's key")
	}
	if _, err := a.IssueClient([]byte("junk"), "x"); err == nil {
		t.Fatal("junk CSR accepted")
	}
}

func TestVerifyPinned(t *testing.T) {
	a, _ := Load(t.TempDir(), []string{"gw.example"})
	other, _ := Load(t.TempDir(), []string{"gw.example"})
	chain := a.ServerCert().Certificate

	if err := VerifyPinned(chain, a.CAFingerprint(), "gw.example"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPinned(chain, other.CAFingerprint(), "gw.example"); err == nil {
		t.Fatal("wrong fingerprint accepted")
	}
	if err := VerifyPinned(chain, a.CAFingerprint(), "evil.example"); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	// A different server presenting our CA cert but its own leaf fails.
	forged := [][]byte{other.ServerCert().Certificate[0], a.CACert().Raw}
	if err := VerifyPinned(forged, a.CAFingerprint(), "gw.example"); err == nil {
		t.Fatal("leaf from another CA accepted")
	}
}

func TestServerCertWorksInTLS(t *testing.T) {
	a, _ := Load(t.TempDir(), []string{"127.0.0.1"})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{a.ServerCert()}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	pool := x509.NewCertPool()
	pool.AddCert(a.CACert())
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestToken(t *testing.T) {
	a, _ := Load(t.TempDir(), nil)
	secret := NewTokenSecret()
	tok := FormatToken(secret, a.CAFingerprint())
	s, f, err := ParseToken(" " + tok + "\n")
	if err != nil || !bytes.Equal(s, secret) || !bytes.Equal(f, a.CAFingerprint()) {
		t.Fatalf("round trip: %v", err)
	}
	// Tokens made before the rename to Baseline still parse.
	if s, f, err := ParseToken("jcmdb1." + tok[len("baseline1."):]); err != nil || !bytes.Equal(s, secret) || !bytes.Equal(f, a.CAFingerprint()) {
		t.Fatalf("legacy token: %v", err)
	}
	for _, bad := range []string{"", "baseline1.a.b", "baseline2." + tok[len("baseline1."):], tok + ".x", "baseline1.!!!." + tok[lastDot(tok)+1:]} {
		if _, _, err := ParseToken(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func lastDot(s string) int { return bytes.LastIndexByte([]byte(s), '.') }
