package collect

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/jw6ventures/baseline/internal/model"
)

// Services lists systemd service units (docs/agent.md §1.5): the loaded ones
// and the installed unit files that aren't loaded.
func (e *Env) Services(ctx context.Context) (model.Services, error) {
	out := model.Services{Units: []model.Service{}}
	// systemctl may be installed in a container or on a host booted with
	// another init; only a running systemd can answer.
	if !e.Exists("/run/systemd/system") || !e.Has("systemctl") {
		return out, nil
	}
	units, err := e.systemdUnits(ctx)
	if err != nil {
		return out, err
	}
	files, err := e.systemdUnitFiles(ctx)
	if err != nil {
		return out, err
	}
	out.Units = mergeSystemdUnits(units, files)
	return out, nil
}

// systemdUnit is a row of list-units.
type systemdUnit struct {
	Unit        string `json:"unit"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
}

// systemdUnitFile is a row of list-unit-files.
type systemdUnitFile struct {
	UnitFile string `json:"unit_file"`
	State    string `json:"state"`
}

// systemctlRows runs a systemctl listing as JSON and, when this systemd
// predates JSON for it (older ones print the table regardless), as plain
// text. It reports which one it got.
func (e *Env) systemctlRows(ctx context.Context, args ...string) (out []byte, isJSON bool, err error) {
	j, err := e.Run(ctx, "systemctl", append(args[:len(args):len(args)], "--output=json", "--no-pager")...)
	if err == nil && json.Valid(j) && strings.HasPrefix(strings.TrimSpace(string(j)), "[") {
		return j, true, nil
	}
	t, err := e.Run(ctx, "systemctl", append(args[:len(args):len(args)], "--plain", "--no-legend", "--no-pager")...)
	return t, false, err
}

func (e *Env) systemdUnits(ctx context.Context) ([]systemdUnit, error) {
	raw, isJSON, err := e.systemctlRows(ctx, "list-units", "--type=service", "--all")
	if err != nil {
		return nil, err
	}
	if isJSON {
		var units []systemdUnit
		return units, json.Unmarshal(raw, &units)
	}
	return parseListUnits(string(raw))
}

func (e *Env) systemdUnitFiles(ctx context.Context) ([]systemdUnitFile, error) {
	raw, isJSON, err := e.systemctlRows(ctx, "list-unit-files", "--type=service")
	if err != nil {
		return nil, err
	}
	if isJSON {
		var files []systemdUnitFile
		return files, json.Unmarshal(raw, &files)
	}
	return parseListUnitFiles(string(raw)), nil
}

// trimUnitMarker drops the "●" (or "*" without UTF-8) that some systemd
// versions put before failed and not-found units even in plain mode.
func trimUnitMarker(line string) string {
	line = strings.TrimSpace(line)
	for _, m := range []string{"●", "*"} {
		line = strings.TrimSpace(strings.TrimPrefix(line, m))
	}
	return line
}

// parseListUnits reads "UNIT LOAD ACTIVE SUB DESCRIPTION" rows.
func parseListUnits(out string) ([]systemdUnit, error) {
	var units []systemdUnit
	for _, line := range strings.Split(out, "\n") {
		line = trimUnitMarker(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") {
			// A row we can't read means we're not reading what we think.
			return nil, errors.New("systemctl list-units: unexpected line: " + short(line, 80))
		}
		u := systemdUnit{Unit: f[0], Load: f[1], Active: f[2], Sub: f[3]}
		if len(f) > 4 {
			u.Description = strings.Join(f[4:], " ")
		}
		units = append(units, u)
	}
	return units, nil
}

// parseListUnitFiles reads "UNIT FILE STATE [PRESET]" rows.
func parseListUnitFiles(out string) []systemdUnitFile {
	var files []systemdUnitFile
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(trimUnitMarker(line))
		if len(f) < 2 || !strings.HasSuffix(f[0], ".service") {
			continue // "N unit files listed." on versions that ignore --no-legend
		}
		files = append(files, systemdUnitFile{UnitFile: f[0], State: f[1]})
	}
	return files
}

// unitTemplate is the template an instance comes from: getty@tty1.service
// -> getty@.service. It returns "" for anything that isn't an instance.
func unitTemplate(name string) string {
	at := strings.IndexByte(name, '@')
	dot := strings.LastIndexByte(name, '.')
	if at < 0 || dot < 0 || dot <= at+1 {
		return ""
	}
	return name[:at+1] + name[dot:]
}

func isUnitTemplate(name string) bool {
	return strings.HasSuffix(name, "@.service")
}

func mergeSystemdUnits(units []systemdUnit, files []systemdUnitFile) []model.Service {
	state := map[string]string{}
	for _, f := range files {
		state[f.UnitFile] = f.State
	}
	enabled := func(name string) string {
		if s, ok := state[name]; ok {
			return s
		}
		return state[unitTemplate(name)]
	}

	byName := map[string]model.Service{}
	for _, u := range units {
		if u.Unit == "" {
			continue
		}
		// A not-found unit is only a reference (a Wants= or After= to
		// something that isn't installed).
		if _, hasFile := state[u.Unit]; u.Load == "not-found" && !hasFile {
			continue
		}
		byName[u.Unit] = model.Service{Name: u.Unit, Description: u.Description, Load: u.Load,
			Active: u.Active, Sub: u.Sub, Enabled: enabled(u.Unit)}
	}
	for _, f := range files {
		// Templates aren't services until instantiated, and an alias is
		// another name for a unit already listed under its own.
		if _, ok := byName[f.UnitFile]; ok || isUnitTemplate(f.UnitFile) || f.State == "alias" {
			continue
		}
		byName[f.UnitFile] = model.Service{Name: f.UnitFile, Active: "inactive", Enabled: f.State}
	}

	svcs := make([]model.Service, 0, len(byName))
	for _, s := range byName {
		svcs = append(svcs, s)
	}
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].Name < svcs[j].Name })
	return svcs
}
