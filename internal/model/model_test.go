package model

import (
	"encoding/json"
	"testing"
)

func TestDedupeSmart(t *testing.T) {
	yes := true
	got := DedupeSmart([]SmartDevice{
		{Name: "bus/0:megaraid,17", Serial: "S400Z25E", Passed: &yes},
		{Name: "bus/0:sat+megaraid,1", Serial: "2BJZ9T1N", Model: "WDC WD161KFGX", Passed: &yes, Reallocated: 9},
		{Name: "sdb", Serial: "2BJZ9T1N", Model: "WDC WD161KFGX", Passed: &yes, Reallocated: 9},
		{Name: "sde", Serial: "S400Z25E", Error: "smartctl couldn't read this device", Firmware: "D41A"},
		{Name: "sdf"},
		{Name: "sdg"},
	})
	if len(got) != 4 {
		t.Fatalf("%+v", got)
	}
	// The block device name is kept even when the controller path has the
	// fuller reading, which wins and fills in the firmware it lacked.
	if got[0].Name != "sdb" || got[0].Reallocated != 9 {
		t.Errorf("SATA drive = %+v", got[0])
	}
	if got[1].Name != "sde" || got[1].Firmware != "D41A" || got[1].Error != "" || got[1].Passed == nil {
		t.Errorf("SAS drive = %+v", got[1])
	}
	if got[2].Name != "sdf" || got[3].Name != "sdg" {
		t.Errorf("drives without a serial = %+v", got[2:])
	}
}

func TestStripNUL(t *testing.T) {
	for in, want := range map[string]string{
		`{"a":"b"}`:                          `{"a":"b"}`,
		`{"model":"Pine64 RockPro64\u0000"}`: `{"model":"Pine64 RockPro64"}`,
		`{"a\u0000":"\u0000x\u0000y\u0000"}`: `{"a":"xy"}`,
		`{"path":"C:\\u0000"}`:               `{"path":"C:\\u0000"}`, // an escaped backslash, then text
		`{"a":"\\\u0000"}`:                   `{"a":"\\"}`,
		`{"a":"\u00001"}`:                    `{"a":"1"}`,
	} {
		if got := string(StripNUL([]byte(in))); got != want {
			t.Errorf("StripNUL(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestEncodeDropsNUL(t *testing.T) {
	b, hash, err := Encode(System{Product: "RockPro64\x00\x00", Serial: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	var s System
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if s.Product != "RockPro64" || hash != Hash(b) {
		t.Errorf("Encode = %s, %s", b, hash)
	}
}
