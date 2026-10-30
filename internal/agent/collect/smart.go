package collect

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/jw6ventures/baseline/internal/model"
)

// SMART reads drive health with smartctl (smartmontools 7+ for JSON). It
// remembers each drive's last reading: a drive in standby is not woken, so
// a NAS's sleeping disks keep their last known state instead of flapping
// between "asleep" and their real values.
type SMART struct {
	Env *Env

	mu   sync.Mutex
	last map[string]model.SmartDevice
}

// Collect produces the "smart" section and the drives' readings as metrics.
func (s *SMART) Collect(ctx context.Context) (model.Smart, []Sample, error) {
	e := s.Env
	out := model.Smart{Devices: []model.SmartDevice{}}
	if !e.Has("smartctl") {
		return out, nil, nil
	}
	scan, err := e.Run(ctx, "smartctl", "--scan-open", "--json")
	if err != nil && len(scan) == 0 {
		return out, nil, err
	}
	var doc struct {
		Devices []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(scan, &doc); err != nil {
		return out, nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		s.last = map[string]model.SmartDevice{}
	}
	var samples []Sample
	byDrive := map[string][]Sample{}
	seen := map[string]bool{}
	for _, d := range doc.Devices {
		name := strings.TrimPrefix(d.Name, "/dev/")
		if strings.Contains(d.Type, ",") { // behind a RAID HBA: megaraid,0
			name += ":" + d.Type
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		// Exit status is a bit mask; with --json the output is complete
		// either way, so it is read rather than the status trusted.
		raw, _ := e.Run(ctx, "smartctl", "--json", "-a", "-n", "standby", "-d", d.Type, d.Name)
		dev, readings, standby := parseSmartctl(raw)
		dev.Name, dev.Type = name, d.Type
		if standby {
			if prev, ok := s.last[name]; ok {
				dev = prev
			}
		} else {
			s.last[name] = dev
			// Both paths to a drive read the same; the first is kept.
			if k := driveKey(dev); len(byDrive[k]) == 0 {
				byDrive[k] = readings
			}
		}
		out.Devices = append(out.Devices, dev)
	}
	// One entry per drive: a disk behind a RAID HBA is seen both through
	// the controller and as its block device. Its readings become metrics
	// once, under the kept name, or temperatures would be charted twice.
	out.Devices = model.DedupeSmart(out.Devices)
	for _, d := range out.Devices {
		for _, r := range byDrive[driveKey(d)] {
			r.Kind, r.Instance = "smart", d.Name
			samples = append(samples, r)
		}
	}
	return out, samples, nil
}

// driveKey tells drives apart: by serial, which is the same on every path
// to a drive, or by name when the drive gives none.
func driveKey(d model.SmartDevice) string {
	if d.Serial != "" {
		return "serial:" + d.Serial
	}
	return d.Name
}

type smartctlDoc struct {
	Smartctl struct {
		ExitStatus int `json:"exit_status"`
		Messages   []struct {
			String   string `json:"string"`
			Severity string `json:"severity"`
		} `json:"messages"`
	} `json:"smartctl"`
	ModelName   string `json:"model_name"`
	ModelFamily string `json:"model_family"`
	// SAS drives: older smartctl gives no model_name for these.
	SCSIModel    string `json:"scsi_model_name"`
	SCSIVendor   string `json:"scsi_vendor"`
	SCSIProduct  string `json:"scsi_product"`
	SCSIRevision string `json:"scsi_revision"`
	Serial       string `json:"serial_number"`
	Firmware     string `json:"firmware_version"`
	SmartStatus  *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature *struct {
		Current *float64 `json:"current"`
	} `json:"temperature"`
	PowerOnTime *struct {
		Hours *float64 `json:"hours"`
	} `json:"power_on_time"`
	ATA *struct {
		Table []struct {
			ID  int `json:"id"`
			Raw struct {
				Value int64 `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	NVMe *struct {
		CriticalWarning int64 `json:"critical_warning"`
		PercentageUsed  int64 `json:"percentage_used"`
		MediaErrors     int64 `json:"media_errors"`
	} `json:"nvme_smart_health_information_log"`
	SCSIGrownDefects *int64 `json:"scsi_grown_defect_list"`
}

// parseSmartctl reads `smartctl --json -a`. standby is set when the drive
// was asleep and wasn't read.
func parseSmartctl(raw []byte) (dev model.SmartDevice, readings []Sample, standby bool) {
	var doc smartctlDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		dev.Error = "smartctl output unreadable"
		return dev, nil, false
	}
	for _, m := range doc.Smartctl.Messages {
		if u := strings.ToUpper(m.String); strings.Contains(u, "STANDBY") || strings.Contains(u, "SLEEP") {
			return dev, nil, true
		}
	}
	dev.Model = firstNonEmpty(doc.ModelName, doc.SCSIModel,
		strings.TrimSpace(doc.SCSIVendor+" "+doc.SCSIProduct), doc.ModelFamily)
	dev.Serial, dev.Firmware = doc.Serial, firstNonEmpty(doc.Firmware, doc.SCSIRevision)
	if doc.SmartStatus != nil {
		passed := doc.SmartStatus.Passed
		dev.Passed = &passed
	}
	// Bit 1: the device couldn't be opened or identified.
	if doc.Smartctl.ExitStatus&2 != 0 {
		for _, m := range doc.Smartctl.Messages {
			if m.Severity == "error" {
				dev.Error = m.String
				break
			}
		}
		if dev.Error == "" {
			dev.Error = "smartctl couldn't read this device"
		}
	}
	if a := doc.ATA; a != nil {
		for _, attr := range a.Table {
			// The count is in the low bytes of the 48-bit raw value; some
			// vendors pack other data into the top ones.
			v := attr.Raw.Value & 0xffffffff
			switch attr.ID {
			case 5:
				dev.Reallocated = v
			case 197:
				dev.Pending = v
			case 198:
				dev.Uncorrectable = v
			}
		}
	}
	if n := doc.NVMe; n != nil {
		dev.CriticalWarning, dev.PercentUsed, dev.MediaErrors = n.CriticalWarning, n.PercentageUsed, n.MediaErrors
	}
	if doc.SCSIGrownDefects != nil {
		dev.Reallocated = *doc.SCSIGrownDefects
	}

	add := func(name string, v float64) { readings = append(readings, Sample{Name: name, Value: v}) }
	if t := doc.Temperature; t != nil && t.Current != nil {
		add("temperature_c", *t.Current)
	}
	if p := doc.PowerOnTime; p != nil && p.Hours != nil {
		add("power_on_hours", *p.Hours)
	}
	if dev.Passed != nil {
		add("reallocated", float64(dev.Reallocated))
		add("pending", float64(dev.Pending))
		add("uncorrectable", float64(dev.Uncorrectable))
		if doc.NVMe != nil {
			add("percent_used", float64(dev.PercentUsed))
			add("media_errors", float64(dev.MediaErrors))
		}
	}
	return dev, readings, false
}
