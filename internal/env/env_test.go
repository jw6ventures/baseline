package env

import "testing"

func TestFallback(t *testing.T) {
	vars := map[string]string{"BASELINE_A": "new", "JCMDB_A": "old", "JCMDB_B": "old", "OTHER": "x"}
	get := Fallback(func(k string) string { return vars[k] })
	for key, want := range map[string]string{"BASELINE_A": "new", "BASELINE_B": "old", "BASELINE_C": "", "OTHER": "x"} {
		if got := get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestLegacy(t *testing.T) {
	t.Setenv("JCMDB_TEST_LEGACY", "1")
	t.Setenv("BASELINE_TEST_LEGACY", "1")
	found := false
	for _, n := range Legacy() {
		if n == "BASELINE_TEST_LEGACY" {
			t.Fatal("BASELINE_ variable listed as legacy")
		}
		found = found || n == "JCMDB_TEST_LEGACY"
	}
	if !found {
		t.Fatal("JCMDB_TEST_LEGACY not listed")
	}
}
