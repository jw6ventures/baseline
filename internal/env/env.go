// Package env reads Baseline's environment variables. Baseline was called
// jcmdb before, and every BASELINE_<name> falls back to JCMDB_<name>, so a
// deployment's existing environment keeps working after the rename.
package env

import (
	"os"
	"sort"
	"strings"
)

const (
	Prefix       = "BASELINE_"
	LegacyPrefix = "JCMDB_"
)

// Get returns the variable key (BASELINE_<name>), or else JCMDB_<name>.
func Get(key string) string { return Fallback(os.Getenv)(key) }

// Fallback wraps getenv so that an unset or empty BASELINE_<name> reads
// JCMDB_<name> instead.
func Fallback(getenv func(string) string) func(string) string {
	return func(key string) string {
		if v := getenv(key); v != "" {
			return v
		}
		if name, ok := strings.CutPrefix(key, Prefix); ok {
			return getenv(LegacyPrefix + name)
		}
		return ""
	}
}

// Legacy lists the JCMDB_ variables set in this process's environment, so
// the server can ask for them to be renamed.
func Legacy() []string {
	var names []string
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, LegacyPrefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
