// Package release publishes the agent binaries built into the server image
// as releases for self-update (docs/agent.md §5.2). They were signed in CI;
// the server passes those signatures on and can't make new ones.
package release

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jw6ventures/baseline/internal/pki"
	"github.com/jw6ventures/baseline/internal/store"
)

// Prefix names the agent binaries: baseline-agent-linux-<arch>.
const Prefix = "baseline-agent-linux-"

// Keep is how many versions stay published; older ones are pruned, except
// any version a host is still asked to move to.
const Keep = 5

// SigSuffix names the CI signatures shipped next to each binary
// (baseline-agent-linux-<arch>.sig, pki.FormatReleaseSignatures).
const SigSuffix = ".sig"

// Signer signs a release statement with the server's own key
// (pki.Authority), for agents older than CI signing.
type Signer interface {
	SignRelease(version, arch, sha256hex string) []byte
}

// Published is one architecture of a published release.
type Published struct {
	Arch string
	// Signed: a CI signature verifies against the trusted release keys.
	// Current agents refuse a release without one.
	Signed bool
}

// safeVersion keeps a version usable as a directory name.
var safeVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

// Publish copies the binaries in agentDir and their CI signatures to
// dataDir/releases/<version>, records them, and prunes old versions. The
// bundled binaries are built with the server's version (see the
// Dockerfile), so that is the version they are published as. keys are the
// release keys agents trust (pki.ReleaseKeys); signatures are checked
// against them only to report which architectures agents will accept.
func Publish(ctx context.Context, st *store.Store, signer Signer, keys []ed25519.PublicKey, agentDir, dataDir, version string) ([]Published, error) {
	if !safeVersion.MatchString(version) {
		return nil, fmt.Errorf("version %q can't be published", version)
	}
	names, err := filepath.Glob(filepath.Join(agentDir, Prefix+"*"))
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(dataDir, "releases", version)
	var arches []Published
	for _, src := range names {
		arch := strings.TrimPrefix(filepath.Base(src), Prefix)
		if strings.HasSuffix(arch, SigSuffix) || !safeVersion.MatchString(arch) {
			continue
		}
		sigs, err := readSignatures(src + SigSuffix)
		if err != nil {
			return nil, fmt.Errorf("publish %s: %w", filepath.Base(src), err)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		dst := filepath.Join(dir, filepath.Base(src))
		sum, size, err := copyHashed(src, dst)
		if err != nil {
			return nil, fmt.Errorf("publish %s: %w", filepath.Base(src), err)
		}
		if err := writeSignatures(dst+SigSuffix, sigs); err != nil {
			return nil, fmt.Errorf("publish %s: %w", filepath.Base(src), err)
		}
		if _, err := st.PublishRelease(ctx, store.Release{
			Version: version, Arch: arch, SHA256: sum, Signature: signer.SignRelease(version, arch, sum), Size: size, Path: dst,
		}); err != nil {
			return nil, err
		}
		arches = append(arches, Published{Arch: arch, Signed: pki.VerifyRelease(keys, version, arch, sum, sigs)})
	}
	pruned, err := st.PruneReleases(ctx, Keep)
	if err != nil {
		return arches, err
	}
	for _, r := range pruned {
		os.Remove(r.Path)
		os.Remove(r.Path + SigSuffix)
		os.Remove(filepath.Dir(r.Path)) // only once empty
	}
	return arches, nil
}

// Signatures returns the CI signatures of the published binary at path.
func Signatures(path string) ([][]byte, error) {
	return readSignatures(path + SigSuffix)
}

// readSignatures reads a .sig file; a missing one (a build without the
// signing key) is no signatures.
func readSignatures(path string) ([][]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pki.ParseReleaseSignatures(b)
}

func writeSignatures(path string, sigs [][]byte) error {
	if len(sigs) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pki.FormatReleaseSignatures(sigs), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// copyHashed copies src to dst (replacing it atomically) and returns the
// SHA-256 and size of what was written.
func copyHashed(src, dst string) (string, int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		os.Remove(tmp)
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
