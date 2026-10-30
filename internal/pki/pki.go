// Package pki is Baseline's internal certificate authority (docs/architecture.md
// §4). The server is the only verifier of agent certs, so revocation is a
// database flag checked on every connect rather than a CRL.
package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"
)

const (
	caLifetime       = 20 * 365 * 24 * time.Hour
	serverLifetime   = 365 * 24 * time.Hour
	serverRenewAhead = 30 * 24 * time.Hour
	// ClientLifetime is how long an agent cert lasts. Agents renew at two
	// thirds of it over their authenticated stream.
	ClientLifetime = 90 * 24 * time.Hour
	clockSkew      = 5 * time.Minute
)

// Authority holds the CA, the gateway's server cert and the legacy
// release-signing key (see SignRelease), all persisted under one directory (the /data/pki volume).
type Authority struct {
	dir        string
	caCert     *x509.Certificate
	caKey      *ecdsa.PrivateKey
	server     tls.Certificate
	releaseKey ed25519.PrivateKey
}

// Load opens the authority in dir, creating whatever is missing. The server
// cert is (re)issued when it is missing, close to expiry, or doesn't cover
// every name in serverNames (host names or IPs agents dial).
func Load(dir string, serverNames []string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	a := &Authority{dir: dir}
	if err := a.loadOrCreateCA(); err != nil {
		return nil, fmt.Errorf("pki: CA: %w", err)
	}
	if err := a.loadOrCreateServer(serverNames); err != nil {
		return nil, fmt.Errorf("pki: server cert: %w", err)
	}
	if err := a.loadOrCreateReleaseKey(); err != nil {
		return nil, fmt.Errorf("pki: release key: %w", err)
	}
	return a, nil
}

func (a *Authority) path(name string) string { return filepath.Join(a.dir, name) }

func (a *Authority) loadOrCreateCA() error {
	cert, key, err := readPair(a.path("ca.crt"), a.path("ca.key"))
	if err == nil {
		a.caCert, a.caKey = cert, key
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "Baseline internal CA"},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := writePair(a.path("ca.crt"), a.path("ca.key"), der, key); err != nil {
		return err
	}
	a.caCert, _ = x509.ParseCertificate(der)
	a.caKey = key
	return nil
}

func (a *Authority) loadOrCreateServer(names []string) error {
	cert, key, err := readPair(a.path("server.crt"), a.path("server.key"))
	if err == nil && cert.CheckSignatureFrom(a.caCert) == nil &&
		time.Until(cert.NotAfter) > serverRenewAhead && covers(cert, names) {
		a.server = tls.Certificate{Certificate: [][]byte{cert.Raw, a.caCert.Raw}, PrivateKey: key, Leaf: cert}
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: "Baseline agent gateway"},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(serverLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if n != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.caCert, &key.PublicKey, a.caKey)
	if err != nil {
		return err
	}
	if err := writePair(a.path("server.crt"), a.path("server.key"), der, key); err != nil {
		return err
	}
	leaf, _ := x509.ParseCertificate(der)
	// The chain includes the CA so an enrolling agent, which only knows the
	// CA's fingerprint, can find and pin it.
	a.server = tls.Certificate{Certificate: [][]byte{der, a.caCert.Raw}, PrivateKey: key, Leaf: leaf}
	return nil
}

func covers(cert *x509.Certificate, names []string) bool {
	for _, n := range names {
		if n == "" {
			continue
		}
		if ip := net.ParseIP(n); ip != nil {
			if !slices.ContainsFunc(cert.IPAddresses, ip.Equal) {
				return false
			}
		} else if !slices.Contains(cert.DNSNames, n) {
			return false
		}
	}
	return true
}

func (a *Authority) loadOrCreateReleaseKey() error {
	b, err := os.ReadFile(a.path("release.key"))
	if err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return errors.New("release.key: no PEM block")
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return err
		}
		ed, ok := k.(ed25519.PrivateKey)
		if !ok {
			return errors.New("release.key: not an ed25519 key")
		}
		a.releaseKey = ed
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeFile(a.path("release.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	a.releaseKey = key
	return nil
}

// CACert returns the CA certificate.
func (a *Authority) CACert() *x509.Certificate { return a.caCert }

// CAFingerprint is the SHA-256 of the CA cert, as carried in enrollment tokens.
func (a *Authority) CAFingerprint() []byte {
	h := sha256.Sum256(a.caCert.Raw)
	return h[:]
}

// ReleasePublicKey is the server's own release key. Agents before CI
// signing pinned it at enrollment; current agents ignore it and trust only
// the keys built into them (ReleaseKeys).
func (a *Authority) ReleasePublicKey() ed25519.PublicKey {
	return a.releaseKey.Public().(ed25519.PublicKey)
}

// SignRelease signs an agent binary's release statement with the server's
// own key. Only agents older than CI signing check this signature: it is
// what lets them install the release that brings them the CI keys.
func (a *Authority) SignRelease(version, arch, sha256hex string) []byte {
	return ed25519.Sign(a.releaseKey, ReleaseStatement(version, arch, sha256hex))
}

// ReleaseStatement is what a release signature covers: the binary's hash
// bound to its version and architecture, so a validly signed binary can't
// be passed off as another version or for another platform.
func ReleaseStatement(version, arch, sha256hex string) []byte {
	// The "jcmdb-agent" here predates the rename to Baseline. It must not
	// change: agents already installed verify updates against it.
	return []byte("jcmdb-agent release\nversion " + version + "\narch " + arch + "\nsha256 " + sha256hex + "\n")
}

// ServerCert is the gateway's TLS certificate, chain included.
func (a *Authority) ServerCert() tls.Certificate { return a.server }

// ClientCAs is the pool agent certs must chain to.
func (a *Authority) ClientCAs() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(a.caCert)
	return p
}

// IssueClient signs an agent's CSR. The CSR's own subject is ignored: the
// cert's common name is always agentID.
func (a *Authority) IssueClient(csrDER []byte, agentID string) (*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("pki: bad CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: CSR signature: %w", err)
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, errors.New("pki: CSR key must be P-256 or P-384")
		}
	case ed25519.PublicKey:
	default:
		return nil, errors.New("pki: CSR key must be ECDSA or ed25519")
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: agentID, Organization: []string{"Baseline agent"}},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(ClientLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.caCert, csr.PublicKey, a.caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// SerialHex is how cert serials are stored and compared.
func SerialHex(c *x509.Certificate) string { return fmt.Sprintf("%x", c.SerialNumber) }

// VerifyPinned checks a server's chain during enrollment, before the agent
// has the CA: some cert in the chain must hash to fingerprint, and the leaf
// must chain to it and be valid for serverName.
func VerifyPinned(rawCerts [][]byte, fingerprint []byte, serverName string) error {
	var ca *x509.Certificate
	var certs []*x509.Certificate
	for _, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		certs = append(certs, c)
		if h := sha256.Sum256(raw); bytes.Equal(h[:], fingerprint) {
			ca = c
		}
	}
	if ca == nil || len(certs) == 0 {
		return errors.New("server's CA does not match the fingerprint in the enrollment token")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err := certs[0].Verify(x509.VerifyOptions{
		DNSName:   serverName,
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

// GenerateKey makes an agent key and a CSR for it.
func GenerateKey() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "baseline-agent"}}, key)
	return key, csr, err
}

// EncodeKey and EncodeCert produce PEM for files on disk.
func EncodeKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func EncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newSerial() *big.Int {
	s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err) // crypto/rand doesn't fail on Linux
	}
	return s.Add(s, big.NewInt(1))
}

func readPair(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	cblk, _ := pem.Decode(cb)
	kblk, _ := pem.Decode(kb)
	if cblk == nil || kblk == nil {
		return nil, nil, fmt.Errorf("%s or %s: no PEM block", certPath, keyPath)
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kblk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("%s: not an ECDSA key", keyPath)
	}
	return cert, key, nil
}

func writePair(certPath, keyPath string, der []byte, key *ecdsa.PrivateKey) error {
	kp, err := EncodeKey(key)
	if err != nil {
		return err
	}
	if err := writeFile(keyPath, kp, 0o600); err != nil {
		return err
	}
	return writeFile(certPath, EncodeCert(der), 0o644)
}

// writeFile replaces path atomically.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
