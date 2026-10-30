package collect

import (
	"context"
	"math"
	"syscall"
	"testing"
	"time"
)

const smartSATA = `{
  "smartctl": {"version": [7, 4], "exit_status": 0},
  "device": {"name": "/dev/sda", "type": "sat", "protocol": "ATA"},
  "model_family": "Western Digital Red Plus",
  "model_name": "WDC WD80EFZZ-68BTXN0",
  "serial_number": "WD-CA1234567",
  "firmware_version": "81.00A81",
  "smart_status": {"passed": true},
  "ata_smart_attributes": {"table": [
    {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 8, "string": "8"}},
    {"id": 9, "name": "Power_On_Hours", "raw": {"value": 21000, "string": "21000"}},
    {"id": 194, "name": "Temperature_Celsius", "raw": {"value": 158914035744, "string": "32 (Min/Max 18/45)"}},
    {"id": 197, "name": "Current_Pending_Sector", "raw": {"value": 0, "string": "0"}},
    {"id": 198, "name": "Offline_Uncorrectable", "raw": {"value": 0, "string": "0"}}
  ]},
  "power_on_time": {"hours": 21000},
  "temperature": {"current": 32}
}`

const smartNVMe = `{
  "smartctl": {"version": [7, 4], "exit_status": 0},
  "model_name": "Samsung SSD 980 PRO 1TB",
  "serial_number": "S5GXNX0T123456",
  "firmware_version": "5B2QGXA7",
  "smart_status": {"passed": true},
  "nvme_smart_health_information_log": {"critical_warning": 0, "temperature": 41, "percentage_used": 3, "media_errors": 0, "power_on_hours": 9000},
  "power_on_time": {"hours": 9000},
  "temperature": {"current": 41}
}`

const smartStandby = `{
  "smartctl": {"version": [7, 4], "exit_status": 2,
    "messages": [{"string": "Device is in STANDBY mode, exit(2)", "severity": "information"}]}
}`

const smartVirtual = `{
  "smartctl": {"version": [7, 4], "exit_status": 4,
    "messages": [{"string": "SMART support is: Unavailable - device lacks SMART capability.", "severity": "information"}]},
  "model_name": "QEMU HARDDISK",
  "serial_number": "QM00001"
}`

func TestSMART(t *testing.T) {
	f := newFixture(t)
	f.cmds["smartctl --scan-open --json"] = `{"devices": [
		{"name": "/dev/sda", "info_name": "/dev/sda [SAT]", "type": "sat", "protocol": "ATA"},
		{"name": "/dev/nvme0", "info_name": "/dev/nvme0", "type": "nvme", "protocol": "NVMe"},
		{"name": "/dev/sdb", "info_name": "/dev/sdb", "type": "scsi", "protocol": "SCSI"}]}`
	f.cmds["smartctl --json -a -n standby -d sat /dev/sda"] = smartSATA
	f.cmds["smartctl --json -a -n standby -d nvme /dev/nvme0"] = smartNVMe
	f.cmds["smartctl --json -a -n standby -d scsi /dev/sdb"] = smartVirtual
	f.exits["smartctl --json -a -n standby -d scsi /dev/sdb"] = 4

	s := &SMART{Env: f.env}
	sec, samples, err := s.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sec.Devices) != 3 {
		t.Fatalf("%+v", sec)
	}
	nvme, sda, sdb := sec.Devices[0], sec.Devices[1], sec.Devices[2]
	if sda.Name != "sda" || sda.Model != "WDC WD80EFZZ-68BTXN0" || sda.Passed == nil || !*sda.Passed ||
		sda.Reallocated != 8 || !sda.Degrading() || sda.Failing() {
		t.Errorf("sda = %+v", sda)
	}
	if nvme.Name != "nvme0" || nvme.PercentUsed != 3 || nvme.Degrading() {
		t.Errorf("nvme = %+v", nvme)
	}
	if sdb.Passed != nil || sdb.Model != "QEMU HARDDISK" || sdb.Error != "" {
		t.Errorf("virtual disk = %+v", sdb)
	}
	got := map[string]float64{}
	for _, x := range samples {
		got[x.Instance+"/"+x.Name] = x.Value
	}
	if got["sda/temperature_c"] != 32 || got["sda/power_on_hours"] != 21000 || got["sda/reallocated"] != 8 ||
		got["nvme0/percent_used"] != 3 || got["nvme0/temperature_c"] != 41 {
		t.Errorf("samples = %v", got)
	}
	if _, ok := got["sdb/reallocated"]; ok {
		t.Error("counters reported for a disk without SMART")
	}

	// sda spins down: its last reading is kept, and it isn't woken.
	f.cmds["smartctl --json -a -n standby -d sat /dev/sda"] = smartStandby
	f.exits["smartctl --json -a -n standby -d sat /dev/sda"] = 2
	sec2, samples2, _ := s.Collect(context.Background())
	if sec2.Devices[1].Model != sda.Model || sec2.Devices[1].Reallocated != 8 {
		t.Errorf("standby device = %+v", sec2.Devices[1])
	}
	for _, x := range samples2 {
		if x.Instance == "sda" {
			t.Errorf("reading from a sleeping disk: %+v", x)
		}
	}
}

func TestSMARTAbsent(t *testing.T) {
	f := newFixture(t)
	sec, samples, err := (&SMART{Env: f.env}).Collect(context.Background())
	if err != nil || sec.Devices == nil || len(sec.Devices) != 0 || samples != nil {
		t.Fatalf("%+v %v %v", sec, samples, err)
	}
}

func TestSampler(t *testing.T) {
	f := newFixture(t)
	f.file("/proc/loadavg", "0.52 0.41 0.30 2/345 6789\n")
	f.file("/proc/meminfo", "MemTotal: 16000000 kB\nMemFree: 2000000 kB\nMemAvailable: 10000000 kB\nCached: 5000000 kB\nSReclaimable: 500000 kB\nSwapTotal: 4000000 kB\nSwapFree: 3000000 kB\n")
	f.file("/sys/block/sda/size", "1\n")
	f.file("/sys/block/loop0/size", "1\n")
	f.file("/proc/self/mountinfo", "22 1 8:2 / / rw shared:1 - ext4 /dev/sda2 rw\n")
	f.env.Statfs = func(path string, st *syscall.Statfs_t) error {
		*st = syscall.Statfs_t{Bsize: 4096, Blocks: 1000, Bfree: 400, Bavail: 300, Files: 100, Ffree: 75}
		return nil
	}
	stat := func(user, system, idle, iowait uint64) string {
		return "cpu  " + itoa(user) + " 0 " + itoa(system) + " " + itoa(idle) + " " + itoa(iowait) + " 0 0 0 0 0\ncpu0 1 2 3\n"
	}
	diskstats := func(reads, sectors, ioms uint64) string {
		return "   8       0 sda " + itoa(reads) + " 0 " + itoa(sectors) + " 0 50 0 800 0 0 " + itoa(ioms) + " 3000 0 0 0 0\n" +
			"   8       1 sda1 99 0 99 0 0 0 0 0 0 0 0\n   7       0 loop0 5 0 5 0 0 0 0 0 0 0 0\n"
	}
	netdev := func(rx uint64) string {
		return "Inter-|   Receive                            |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n" +
			"    lo: 999 9 0 0 0 0 0 0 999 9 0 0 0 0 0 0\n  eth0: " + itoa(rx) + " 10 0 0 0 0 0 0 500 5 0 0 0 0 0 0\nveth12: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n"
	}
	f.file("/proc/stat", stat(100, 50, 800, 50))
	f.file("/proc/diskstats", diskstats(1000, 8000, 100))
	f.file("/proc/net/dev", netdev(10000))

	s := &Sampler{Env: f.env}
	t0 := time.Unix(1760000000, 0)
	first := index(s.Sample(t0))
	if _, ok := first["cpu/user/"]; ok {
		t.Error("rates in the first sample")
	}
	if first["load/load1/"] != 0.52 || first["mem/used/"] != 6000000*1024 || first["mem/swap_used/"] != 1000000*1024 ||
		first["mem/cached/"] != 5500000*1024 {
		t.Errorf("gauges = %v", first)
	}
	if first["fs/used_pct//"] != 100*600.0/900 || first["fs/inodes_used_pct//"] != 25 || first["fs/used_bytes//"] != 600*4096 {
		t.Errorf("fs = %v", first)
	}

	f.file("/proc/stat", stat(130, 60, 850, 60)) // +30 user, +10 system, +50 idle, +10 iowait = 100 ticks
	f.file("/proc/diskstats", diskstats(1600, 20000, 30100))
	f.file("/proc/net/dev", netdev(70000))
	s.AddSMART([]Sample{{Kind: "smart", Name: "temperature_c", Instance: "sda", Value: 33}})
	second := index(s.Sample(t0.Add(60 * time.Second)))
	if second["cpu/user/"] != 30 || second["cpu/system/"] != 10 || second["cpu/iowait/"] != 10 || second["cpu/idle/"] != 50 {
		t.Errorf("cpu = %v", second)
	}
	if second["disk/read_iops/sda"] != 10 || second["disk/read_bps/sda"] != 12000*512/60.0 || second["disk/util/sda"] != 50 {
		t.Errorf("disk = %v", second)
	}
	if _, ok := second["disk/read_iops/sda1"]; ok {
		t.Error("partition sampled")
	}
	if second["net/rx_bps/eth0"] != 1000 || math.IsNaN(second["net/tx_bps/eth0"]) {
		t.Errorf("net = %v", second)
	}
	if _, ok := second["net/rx_bps/veth12"]; ok {
		t.Error("veth sampled")
	}
	if second["smart/temperature_c/sda"] != 33 {
		t.Error("SMART reading not passed on")
	}
	if _, ok := index(s.Sample(t0.Add(120 * time.Second)))["smart/temperature_c/sda"]; ok {
		t.Error("SMART reading sent twice")
	}
}

func index(ss []Sample) map[string]float64 {
	m := map[string]float64{}
	for _, s := range ss {
		m[s.Kind+"/"+s.Name+"/"+s.Instance] = s.Value
	}
	return m
}

func itoa(n uint64) string {
	b := []byte{}
	for {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
		if n == 0 {
			return string(b)
		}
	}
}

const smartSAS = `{
  "smartctl": {"version": [7, 2], "exit_status": 0},
  "scsi_vendor": "SAMSUNG",
  "scsi_product": "MZILS400HCGR",
  "scsi_revision": "D41A",
  "serial_number": "S400Z25E",
  "smart_status": {"passed": true},
  "scsi_grown_defect_list": 0,
  "temperature": {"current": 30}
}`

// A disk behind a MegaRAID HBA in JBOD mode is scanned twice, through the
// controller and as its block device; it is listed once.
func TestSMARTMegaRAID(t *testing.T) {
	f := newFixture(t)
	f.cmds["smartctl --scan-open --json"] = `{"devices": [
		{"name": "/dev/sda", "info_name": "/dev/sda", "type": "sat", "protocol": "ATA"},
		{"name": "/dev/sde", "info_name": "/dev/sde", "type": "scsi", "protocol": "SCSI"},
		{"name": "/dev/bus/0", "info_name": "/dev/bus/0 [megaraid_disk_00] [SAT]", "type": "sat+megaraid,0", "protocol": "ATA"},
		{"name": "/dev/bus/0", "info_name": "/dev/bus/0 [megaraid_disk_17]", "type": "megaraid,17", "protocol": "SCSI"}]}`
	f.cmds["smartctl --json -a -n standby -d sat /dev/sda"] = smartSATA
	f.cmds["smartctl --json -a -n standby -d sat+megaraid,0 /dev/bus/0"] = smartSATA
	f.cmds["smartctl --json -a -n standby -d scsi /dev/sde"] = smartSAS
	f.cmds["smartctl --json -a -n standby -d megaraid,17 /dev/bus/0"] = smartSAS

	sec, samples, err := (&SMART{Env: f.env}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sec.Devices) != 2 || sec.Devices[0].Name != "sda" || sec.Devices[1].Name != "sde" {
		t.Fatalf("%+v", sec.Devices)
	}
	if d := sec.Devices[1]; d.Model != "SAMSUNG MZILS400HCGR" || d.Firmware != "D41A" {
		t.Errorf("SAS drive = %+v", d)
	}
	for _, x := range samples {
		if x.Instance != "sda" && x.Instance != "sde" {
			t.Errorf("reading from the duplicate path: %+v", x)
		}
	}
}
