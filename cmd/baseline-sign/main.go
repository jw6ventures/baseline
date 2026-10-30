// Command baseline-sign signs agent release binaries in CI (docs/agent.md §5.2).
// The release workflow runs it inside the image build with the
// RELEASE_SIGNING_KEY secret; the server only passes the signatures on.
//
// Usage:
//
//	baseline-sign -key <file> -version <version> <binary>...
//
// The key file holds one or two ed25519 private keys (PKCS #8 PEM). Each
// binary baseline-agent-linux-<arch> gets <binary>.sig with one signature per
// key over pki.ReleaseStatement. A key whose public half isn't in
// internal/pki/release-keys.pem is refused: agents wouldn't accept it.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jw6ventures/baseline/internal/pki"
	"github.com/jw6ventures/baseline/internal/release"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "baseline-sign:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("baseline-sign", flag.ContinueOnError)
	keyFile := fs.String("key", "", "file with the ed25519 signing keys (PEM)")
	version := fs.String("version", "", "release version the binaries were built with")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *version == "" || fs.NArg() == 0 {
		return errors.New("usage: baseline-sign -key <file> -version <version> <binary>...")
	}
	b, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	keys, err := pki.ParseReleaseSigningKeys(b)
	if err != nil {
		return err
	}
	trusted, err := pki.ReleaseKeys()
	if err != nil {
		return err
	}
	for _, k := range keys {
		pub := k.Public().(ed25519.PublicKey)
		if !slices.ContainsFunc(trusted, func(t ed25519.PublicKey) bool { return t.Equal(pub) }) {
			return errors.New("a signing key's public half is not in internal/pki/release-keys.pem, so agents wouldn't accept its signatures")
		}
	}
	for _, bin := range fs.Args() {
		arch, ok := strings.CutPrefix(filepath.Base(bin), release.Prefix)
		if !ok {
			return fmt.Errorf("%s: not named %s<arch>", bin, release.Prefix)
		}
		sum, err := hashFile(bin)
		if err != nil {
			return err
		}
		stmt := pki.ReleaseStatement(*version, arch, sum)
		var sigs [][]byte
		for _, k := range keys {
			sigs = append(sigs, ed25519.Sign(k, stmt))
		}
		if err := os.WriteFile(bin+release.SigSuffix, pki.FormatReleaseSignatures(sigs), 0o644); err != nil {
			return err
		}
		fmt.Printf("Signed %s %s/%s with %d key(s)\n", filepath.Base(bin), *version, arch, len(keys))
	}
	return nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
