package model

import "testing"

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
