package vuln

import (
	"encoding/json"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/vercmp"
)

func TestFor(t *testing.T) {
	for _, c := range []struct {
		id, ver, want string
	}{
		{"ubuntu", "24.04", "Ubuntu:24.04:LTS"}, {"ubuntu", "26.04", "Ubuntu:26.04:LTS"},
		{"ubuntu", "25.10", "Ubuntu:25.10"}, {"ubuntu", "23.04", "Ubuntu:23.04"},
		{"debian", "12", "Debian:12"}, {"rocky", "9.6", "Rocky Linux:9"}, {"rocky", "10.0", "Rocky Linux:10"},
		{"almalinux", "9.4", "AlmaLinux:9"}, {"fedora", "42", ""}, {"bazzite", "42", ""}, {"ubuntu", "", ""},
	} {
		e, ok := For(c.id, c.ver)
		if e.Name != c.want || ok != (c.want != "") {
			t.Errorf("For(%q, %q) = %q %v, want %q", c.id, c.ver, e.Name, ok, c.want)
		}
		if ok {
			if b, ok := ByName(e.Name); !ok || b.Name != e.Name || b.Base != e.Base {
				t.Errorf("ByName(%q) = %+v %v", e.Name, b, ok)
			}
		}
	}
}

func TestCVSS3(t *testing.T) {
	for _, c := range []struct {
		vec  string
		want float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.0},
		{"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4},
	} {
		got, ok := CVSS3(c.vec)
		if !ok || got != c.want {
			t.Errorf("CVSS3(%s) = %v %v, want %v", c.vec, got, ok, c.want)
		}
	}
	for _, bad := range []string{"", "CVSS:4.0/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"} {
		if _, ok := CVSS3(bad); ok {
			t.Errorf("CVSS3(%q) accepted", bad)
		}
	}
}

func TestCheck(t *testing.T) {
	r := func(evs ...Event) [][]Event { return [][]Event{evs} }
	in := func(v string) Event { return Event{Introduced: v} }
	fx := func(v string) Event { return Event{Fixed: v} }
	for _, c := range []struct {
		name   string
		ranges [][]Event
		v      string
		hit    bool
		fixed  string
	}{
		{"before fix", r(in("0"), fx("1.2-3")), "1.2-2", true, "1.2-3"},
		{"at fix", r(in("0"), fx("1.2-3")), "1.2-3", false, ""},
		{"after fix", r(in("0"), fx("1.2-3")), "1:1.0-1", false, ""},
		{"no fix", r(in("0")), "5.0", true, ""},
		{"before introduced", r(in("2.0"), fx("2.5")), "1.9", false, ""},
		{"two intervals, first", r(in("0"), fx("1.5"), in("2.0"), fx("2.5")), "1.4", true, "1.5"},
		{"two intervals, gap", r(in("0"), fx("1.5"), in("2.0"), fx("2.5")), "1.7", false, ""},
		{"two intervals, second", r(in("2.0"), fx("2.5"), in("0"), fx("1.5")), "2.1", true, "2.5"},
		{"last affected", r(in("0"), Event{LastAffected: "3.0"}), "3.0", true, ""},
		{"past last affected", r(in("0"), Event{LastAffected: "3.0"}), "3.0.1", false, ""},
		{"tilde", r(in("0"), fx("1.0")), "1.0~rc1", true, "1.0"},
	} {
		hit, fixed := Check(vercmp.Dpkg, c.ranges, c.v)
		if hit != c.hit || fixed != c.fixed {
			t.Errorf("%s: Check(%s) = %v %q, want %v %q", c.name, c.v, hit, fixed, c.hit, c.fixed)
		}
	}
}

// Shapes of real records (trimmed): an Ubuntu per-CVE record with binary
// versions, an unfixed one, a notice that duplicates them, and a Rocky
// advisory.
const (
	ubuntuFixed = `{"schema_version":"1.7.0","id":"UBUNTU-CVE-2025-15467","published":"2026-01-27T00:00:00Z",
	 "modified":"2026-10-12T14:20:24.496064664Z","upstream":["CVE-2025-15467"],"related":["USN-7980-1"],
	 "details":"Issue summary: Parsing CMS AuthEnvelopedData may crash.\nMore text.",
	 "affected":[
	  {"package":{"name":"openssl","ecosystem":"Ubuntu:24.04:LTS"},
	   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.13-0ubuntu3.7"}]}],
	   "versions":["3.0.13-0ubuntu3","3.0.13-0ubuntu3.1"],
	   "ecosystem_specific":{"ubuntu_priority":"high","binaries":[{"binary_name":"openssl","binary_version":"3.0.13-0ubuntu3.7"},
	     {"binary_name":"libssl3t64","binary_version":"3.0.13-0ubuntu3.7"}]}},
	  {"package":{"name":"openssl","ecosystem":"Ubuntu:22.04:LTS"},
	   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.2-0ubuntu1.20"}]}]}],
	 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	 "references":[{"type":"REPORT","url":"https://ubuntu.com/security/CVE-2025-15467"},{"type":"WEB","url":"ftp://x"}]}`
	ubuntuUnfixed = `{"id":"UBUNTU-CVE-2024-0001","modified":"2026-01-01T00:00:00Z","details":"Low risk thing",
	 "affected":[{"package":{"name":"bash","ecosystem":"Ubuntu:24.04:LTS"},
	   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}],"ecosystem_specific":{"ubuntu_priority":"negligible"}}]}`
	ubuntuNotice = `{"id":"USN-7980-1","modified":"2026-01-01T00:00:00Z","summary":"openssl update",
	 "affected":[{"package":{"name":"openssl","ecosystem":"Ubuntu:24.04:LTS"},
	   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.13-0ubuntu3.7"}]}]}]}`
	rockyAdvisory = `{"schema_version":"1.7.3","id":"RLSA-2025:9978","published":"2025-10-04T00:11:30.916420Z",
	 "modified":"2025-10-07T17:39:57.811960Z","upstream":["CVE-2025-32462"],"summary":"Important: sudo security update",
	 "details":"The sudo packages...","affected":[{"package":{"name":"sudo","ecosystem":"Rocky Linux:9"},
	   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0:1.9.5p2-10.el9_6.1"}]}]}],
	 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"}]}`
	withdrawn = `{"id":"RLSA-2020:1","withdrawn":"2021-01-01T00:00:00Z","modified":"2021-01-01T00:00:00Z",
	 "affected":[{"package":{"name":"sudo","ecosystem":"Rocky Linux:9"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`
)

func TestParse(t *testing.T) {
	ub := map[string]bool{"Ubuntu:24.04:LTS": true}
	v, aff, ok, err := parse([]byte(ubuntuFixed), ub)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if v.Summary != "Issue summary: Parsing CMS AuthEnvelopedData may crash." || v.Severity != "high" ||
		v.CVSSScore == nil || *v.CVSSScore != 9.8 || len(v.Aliases) != 1 || v.Aliases[0] != "CVE-2025-15467" ||
		len(v.Refs) != 1 {
		t.Fatalf("vuln: %+v", v)
	}
	if len(aff) != 1 || aff[0].Package != "openssl" || aff[0].Severity != "high" ||
		aff[0].Binaries["libssl3t64"] != "3.0.13-0ubuntu3.7" {
		t.Fatalf("affected: %+v", aff)
	}
	var ranges [][]Event
	json.Unmarshal(aff[0].Ranges, &ranges)
	if len(ranges) != 1 || ranges[0][1].Fixed != "3.0.13-0ubuntu3.7" {
		t.Fatalf("ranges: %s", aff[0].Ranges)
	}

	if _, aff, ok, _ := parse([]byte(ubuntuUnfixed), ub); !ok || aff[0].Severity != "negligible" || aff[0].Binaries != nil {
		t.Fatalf("unfixed: %v %+v", ok, aff)
	}
	for _, rec := range []string{ubuntuNotice, withdrawn} {
		if _, _, ok, err := parse([]byte(rec), map[string]bool{"Ubuntu:24.04:LTS": true, "Rocky Linux:9": true}); ok || err != nil {
			t.Errorf("kept %.40s: %v", rec, err)
		}
	}
	if _, _, ok, _ := parse([]byte(ubuntuFixed), map[string]bool{"Ubuntu:26.04:LTS": true}); ok {
		t.Error("kept a record for another release")
	}

	v, aff, ok, _ = parse([]byte(rockyAdvisory), map[string]bool{"Rocky Linux:9": true})
	if !ok || v.Severity != "high" || v.Summary != "Important: sudo security update" || *v.CVSSScore != 7.0 ||
		aff[0].Package != "sudo" || aff[0].Severity != "" {
		t.Fatalf("rocky: %+v %+v", v, aff)
	}
}

func TestMatch(t *testing.T) {
	ub, _ := For("ubuntu", "24.04")
	eco := map[string]bool{ub.Name: true}
	var affected []store.VulnAffected
	for _, rec := range []string{ubuntuFixed, ubuntuUnfixed} {
		v, aff, _, _ := parse([]byte(rec), eco)
		for i := range aff {
			aff[i].VulnSeverity = v.Severity
		}
		affected = append(affected, aff...)
	}
	pkgs := []model.Package{
		{Manager: "apt", Name: "openssl", Version: "3.0.13-0ubuntu3.5", Arch: "amd64"},
		{Manager: "apt", Name: "libssl3t64", Version: "3.0.13-0ubuntu3.5", Arch: "amd64", Source: "openssl"},
		{Manager: "apt", Name: "libssl3t64", Version: "3.0.13-0ubuntu3.5", Arch: "i386", Source: "openssl"},
		// Built from openssl but not in the record's binary list: the
		// source range decides.
		{Manager: "apt", Name: "openssl-provider-legacy", Version: "3.0.13-0ubuntu3.7", Arch: "amd64", Source: "openssl"},
		{Manager: "apt", Name: "bash", Version: "5.2.21-2ubuntu4", Arch: "amd64"},
		{Manager: "snap", Name: "openssl", Version: "1.0"},
		// Two kernel ABIs: only the newer one counts.
		{Manager: "apt", Name: "linux-headers-6.8.0-45-generic", Version: "6.8.0-45.45", Arch: "amd64", Source: "linux"},
		{Manager: "apt", Name: "linux-headers-6.8.0-50-generic", Version: "6.8.0-50.51", Arch: "amd64", Source: "linux"},
	}
	affected = append(affected, store.VulnAffected{VulnID: "UBUNTU-CVE-K", Package: "linux", VulnSeverity: "medium",
		Ranges: json.RawMessage(`[[{"introduced":"0"},{"fixed":"6.8.0-48.48"}]]`)})
	cands := map[string]string{
		CandidateKey("apt", "openssl", "amd64"):    "3.0.13-0ubuntu3.7",
		CandidateKey("apt", "libssl3t64", "amd64"): "3.0.13-0ubuntu3.6",
	}
	got := Match(ub, pkgs, cands, affected)
	want := map[string]store.HostVuln{
		"openssl/amd64":    {Fixed: "3.0.13-0ubuntu3.7", Candidate: "3.0.13-0ubuntu3.7", FixAvailable: true, Severity: "high"},
		"libssl3t64/amd64": {Fixed: "3.0.13-0ubuntu3.7", Candidate: "3.0.13-0ubuntu3.6", Severity: "high"},
		"libssl3t64/i386":  {Fixed: "3.0.13-0ubuntu3.7", Severity: "high"},
		"bash/amd64":       {Severity: "negligible"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d matches: %+v", len(got), got)
	}
	for _, m := range got {
		w, ok := want[m.Package+"/"+m.Arch]
		if !ok || m.Fixed != w.Fixed || m.Candidate != w.Candidate || m.FixAvailable != w.FixAvailable || m.Severity != w.Severity {
			t.Errorf("%s/%s: %+v, want %+v", m.Package, m.Arch, m, w)
		}
	}

	// rpm: only the newest kernel of several counts, and epochs compare.
	rocky, _ := For("rocky", "9.6")
	aff := []store.VulnAffected{{VulnID: "RLSA-1", Package: "kernel", VulnSeverity: "high",
		Ranges: json.RawMessage(`[[{"introduced":"0"},{"fixed":"0:5.14.0-570.el9"}]]`)},
		{VulnID: "RLSA-2", Package: "sudo", VulnSeverity: "high",
			Ranges: json.RawMessage(`[[{"introduced":"0"},{"fixed":"0:1.9.5p2-10.el9_6.1"}]]`)}}
	pkgs = []model.Package{
		{Manager: "dnf", Name: "kernel", Version: "5.14.0", Release: "503.el9", Arch: "x86_64"},
		{Manager: "dnf", Name: "kernel", Version: "5.14.0", Release: "570.el9", Arch: "x86_64"},
		{Manager: "dnf", Name: "sudo", Version: "1.9.5p2", Release: "10.el9_6", Arch: "x86_64"},
	}
	got = Match(rocky, pkgs, map[string]string{CandidateKey("dnf", "sudo", "x86_64"): "1.9.5p2-10.el9_6.1"}, aff)
	if len(got) != 1 || got[0].VulnID != "RLSA-2" || !got[0].FixAvailable {
		t.Fatalf("rocky: %+v", got)
	}
}

func TestTruncate(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{{"abc", 5, "abc"}, {"abcdef", 3, "abc…"}, {"a—b", 2, "a…"}, {"a—b", 3, "a…"}, {"a—b", 4, "a—…"}} {
		if got := truncate(c.in, c.n); got != c.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}
