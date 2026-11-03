// Package action defines the typed actions a job runs on a host
// (docs/agent.md §5): their parameters, the capabilities they need, the
// local-policy category that can turn them off, and their risk class. The
// server validates against these definitions and the agent executes them
// (internal/agent/runner), so both sides agree on what a job means.
package action

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

const (
	PkgUpgrade       = "pkg.upgrade"
	ContainerRestart = "container.restart"
	ServiceRestart   = "service.restart"
	ServiceStart     = "service.start"
	ServiceStop      = "service.stop"
	HostReboot       = "host.reboot"
	ScriptRun        = "script.run"
	ComposePull      = "compose.pull"
	ComposeUpdate    = "compose.update"
	ComposeStart     = "compose.start"
	ComposeArchive   = "compose.archive"
	ComposeMove      = "compose.move"
	ComposeDeploy    = "compose.deploy"
	ComposeEdit      = "compose.edit"
)

// Policy categories. agent.conf's allow_actions lists the ones a host
// accepts; allow_scripts governs scripts on its own.
const (
	CategoryPatch     = "patch"
	CategoryContainer = "container"
	CategoryService   = "service"
	CategoryReboot    = "reboot"
	CategoryCompose   = "compose"
	CategoryScript    = "script"
	// CategoryKubernetes is the k8s.* actions, which only cluster agents
	// run.
	CategoryKubernetes = "kubernetes"
)

// Categories are the values allow_actions takes, in the order the UI shows
// them.
var Categories = []string{CategoryPatch, CategoryContainer, CategoryService, CategoryReboot, CategoryCompose, CategoryKubernetes}

// Capabilities an agent reports in Hello for what it can do, beside the
// tools it found (docs/agent.md §5).
const (
	// CapCompose: a Compose CLI is installed, and the agent runs
	// compose.pull and compose.update (M5).
	CapCompose = "compose"
	// CapPkgPin: the agent takes exact versions in pkg.upgrade (Versions),
	// which patch-group promotion uses (M5).
	CapPkgPin = "pkg-pin"
	// CapComposeFiles: the agent writes Compose and .env files, so it runs
	// compose.deploy and compose.edit.
	CapComposeFiles = "compose-files"
	// CapComposeRoots: compose.deploy takes the Compose root to deploy
	// under (StackFileParams.Root).
	CapComposeRoots = "compose-roots"
	// CapComposeStart: the agent runs compose.start, and lists the stacks
	// under the Compose roots it is told that aren't running.
	CapComposeStart = "compose-start"
	// CapComposeArchive: the agent runs compose.archive and compose.move.
	CapComposeArchive = "compose-archive"
	// CapComposeRootless: compose.deploy and compose.edit also take rootless
	// Podman stacks, whose files the agent writes as the stack's user.
	CapComposeRootless = "compose-rootless"
)

type Risk string

const (
	Low    Risk = "low"
	Medium Risk = "medium"
	High   Risk = "high"
)

var Risks = []Risk{Low, Medium, High}

func ParseRisk(s string) (Risk, error) {
	if r := Risk(s); slices.Contains(Risks, r) {
		return r, nil
	}
	return "", fmt.Errorf("unknown risk %q", s)
}

func (r Risk) rank() int { return slices.Index(Risks, r) }

// Spec describes one action.
type Spec struct {
	Name     string
	Label    string
	Category string
	Risk     Risk
	// Timeout bounds the job on the agent; the server gives up a little
	// later. A reboot's covers the host coming back.
	Timeout time.Duration
	// Needs lists capabilities (from Hello), any one of which the host must
	// have; empty means none.
	Needs []string
	// Sections are the inventory sections the action can change. The agent
	// collects them again when the job ends, and the server attributes their
	// changes to the job's change record.
	Sections []string
	// Typical is about how long a job takes. A maintenance window doesn't
	// start a job with less than this left (docs/change-management.md §3).
	Typical time.Duration
	// OwnForm actions carry files, so they are made from their own forms
	// (a host's or a stack's page) or the API with the files in params,
	// never from the general change form or a change model.
	OwnForm bool
}

var specs = []Spec{
	{Name: PkgUpgrade, Label: "Install updates", Category: CategoryPatch, Risk: Medium, Timeout: 2 * time.Hour,
		Needs:    []string{"apt", "dnf", "rpm-ostree", "flatpak", "snap"},
		Sections: []string{model.SectionPackages, model.SectionUpdates, model.SectionReboot, model.SectionOS, model.SectionServices},
		Typical:  30 * time.Minute},
	{Name: ServiceRestart, Label: "Restart a service", Category: CategoryService, Risk: Low, Timeout: 5 * time.Minute,
		Needs: []string{"systemd"}, Sections: []string{model.SectionServices, model.SectionPorts, model.SectionReboot},
		Typical: 2 * time.Minute},
	{Name: ServiceStart, Label: "Start a service", Category: CategoryService, Risk: Low, Timeout: 5 * time.Minute,
		Needs: []string{"systemd"}, Sections: []string{model.SectionServices, model.SectionPorts}, Typical: 2 * time.Minute},
	{Name: ServiceStop, Label: "Stop a service", Category: CategoryService, Risk: Medium, Timeout: 5 * time.Minute,
		Needs: []string{"systemd"}, Sections: []string{model.SectionServices, model.SectionPorts}, Typical: 2 * time.Minute},
	{Name: ContainerRestart, Label: "Restart a container", Category: CategoryContainer, Risk: Low, Timeout: 5 * time.Minute,
		Needs: []string{"docker", "podman"}, Sections: []string{model.SectionContainers, model.SectionPorts},
		Typical: 2 * time.Minute},
	{Name: ComposePull, Label: "Pull a Compose stack's images", Category: CategoryCompose, Risk: Low, Timeout: 30 * time.Minute,
		Needs: []string{CapCompose}, Sections: []string{model.SectionContainers}, Typical: 10 * time.Minute},
	{Name: ComposeUpdate, Label: "Update a Compose stack", Category: CategoryCompose, Risk: Medium, Timeout: 30 * time.Minute,
		Needs: []string{CapCompose}, Sections: []string{model.SectionContainers, model.SectionPorts}, Typical: 10 * time.Minute},
	{Name: ComposeStart, Label: "Start a Compose stack", Category: CategoryCompose, Risk: Low, Timeout: 30 * time.Minute,
		Needs: []string{CapComposeStart}, Sections: []string{model.SectionContainers, model.SectionPorts}, Typical: 5 * time.Minute},
	{Name: ComposeArchive, Label: "Archive a Compose stack", Category: CategoryCompose, Risk: Medium, Timeout: 15 * time.Minute,
		Needs: []string{CapComposeArchive}, Sections: []string{model.SectionContainers, model.SectionPorts}, Typical: 2 * time.Minute},
	{Name: ComposeMove, Label: "Move a Compose stack", Category: CategoryCompose, Risk: Medium, Timeout: time.Hour,
		Needs: []string{CapComposeArchive}, Sections: []string{model.SectionContainers, model.SectionPorts}, Typical: 10 * time.Minute},
	{Name: ComposeDeploy, Label: "Deploy a Compose stack", Category: CategoryCompose, Risk: Medium, Timeout: 30 * time.Minute,
		Needs: []string{CapComposeFiles}, Sections: []string{model.SectionContainers, model.SectionPorts}, Typical: 10 * time.Minute,
		OwnForm: true},
	{Name: ComposeEdit, Label: "Edit a Compose stack", Category: CategoryCompose, Risk: Medium, Timeout: 30 * time.Minute,
		Needs: []string{CapComposeFiles}, Sections: []string{model.SectionContainers, model.SectionPorts}, Typical: 10 * time.Minute,
		OwnForm: true},
	{Name: HostReboot, Label: "Reboot", Category: CategoryReboot, Risk: High, Timeout: 20 * time.Minute,
		Sections: []string{model.SectionOS, model.SectionReboot, model.SectionServices, model.SectionPorts, model.SectionContainers},
		Typical:  10 * time.Minute},
	{Name: ScriptRun, Label: "Run a script", Category: CategoryScript, Risk: Medium, Timeout: DefaultScriptTimeout,
		Sections: model.Sections, Typical: DefaultScriptTimeout},
	{Name: K8sRestart, Label: "Restart a Kubernetes workload", Category: CategoryKubernetes, Risk: Low, Timeout: 5 * time.Minute,
		Needs: []string{CapK8sActions}, Sections: []string{model.SectionK8s}, Typical: 3 * time.Minute},
	{Name: K8sScale, Label: "Scale a Kubernetes workload", Category: CategoryKubernetes, Risk: Medium, Timeout: 5 * time.Minute,
		Needs: []string{CapK8sActions}, Sections: []string{model.SectionK8s}, Typical: 3 * time.Minute},
	{Name: K8sSetImage, Label: "Change a Kubernetes workload's image", Category: CategoryKubernetes, Risk: Medium,
		Timeout: 5 * time.Minute, Needs: []string{CapK8sActions}, Sections: []string{model.SectionK8s}, Typical: 3 * time.Minute},
	{Name: K8sDeletePod, Label: "Delete a Kubernetes pod", Category: CategoryKubernetes, Risk: Low, Timeout: 3 * time.Minute,
		Needs: []string{CapK8sActions}, Sections: []string{model.SectionK8s}, Typical: time.Minute},
	{Name: K8sSuspend, Label: "Suspend a CronJob", Category: CategoryKubernetes, Risk: Low, Timeout: 2 * time.Minute,
		Needs: []string{CapK8sActions}, Sections: []string{model.SectionK8s}, Typical: time.Minute},
	{Name: K8sResume, Label: "Resume a CronJob", Category: CategoryKubernetes, Risk: Low, Timeout: 2 * time.Minute,
		Needs: []string{CapK8sActions}, Sections: []string{model.SectionK8s}, Typical: time.Minute},
	{Name: K8sTrigger, Label: "Run a CronJob now", Category: CategoryKubernetes, Risk: Low, Timeout: 2 * time.Minute,
		Needs: []string{CapK8sActions}, Sections: []string{model.SectionK8s}, Typical: time.Minute},
	{Name: K8sDeploy, Label: "Deploy a Kubernetes manifest", Category: CategoryKubernetes, Risk: Medium, Timeout: 10 * time.Minute,
		Needs: []string{CapK8sActions}, Sections: []string{model.SectionK8s}, Typical: 5 * time.Minute, OwnForm: true},
	{Name: K8sEdit, Label: "Edit a Kubernetes manifest", Category: CategoryKubernetes, Risk: Medium, Timeout: 10 * time.Minute,
		Needs: []string{CapK8sActions}, Sections: []string{model.SectionK8s}, Typical: 5 * time.Minute, OwnForm: true},
}

// Names lists every action in the order the UI offers them.
var Names = func() []string {
	var out []string
	for _, s := range specs {
		out = append(out, s.Name)
	}
	return out
}()

// Get returns an action's spec.
func Get(name string) (Spec, bool) {
	i := slices.IndexFunc(specs, func(s Spec) bool { return s.Name == name })
	if i < 0 {
		return Spec{}, false
	}
	return specs[i], true
}

// Affecting lists the actions whose jobs can change section.
func Affecting(section string) []string {
	var out []string
	for _, s := range specs {
		if slices.Contains(s.Sections, section) {
			out = append(out, s.Name)
		}
	}
	return out
}

// Supported reports whether a host with these capabilities can run the
// action, and if not, why.
func (s Spec) Supported(caps []string) (bool, string) {
	if s.Category != CategoryKubernetes && slices.Contains(caps, capK8sCluster) {
		return false, "is a Kubernetes cluster agent, which runs only Kubernetes actions"
	}
	if len(s.Needs) == 0 || slices.ContainsFunc(s.Needs, func(c string) bool { return slices.Contains(caps, c) }) {
		return true, ""
	}
	return false, "needs " + strings.Join(s.Needs, " or ")
}

// SuggestRisk is a change's risk from its actions' risk classes, one step
// higher when it touches many hosts (docs/change-management.md §2).
func SuggestRisk(risks []Risk, targets int) Risk {
	r := Low
	for _, x := range risks {
		if x.rank() > r.rank() {
			r = x
		}
	}
	if targets > 5 && r != High {
		r = Risks[r.rank()+1]
	}
	return r
}

// Parameters ------------------------------------------------------------------

// Upgrade modes and reboot policies for pkg.upgrade.
const (
	ModeAll      = "all"
	ModeSecurity = "security"
	ModeSelected = "selected"

	RebootNever      = "never"
	RebootIfRequired = "if_required"
	RebootAlways     = "always"
)

// UpgradeParams are pkg.upgrade's. A package is "name" (the system package
// manager: apt, dnf) or "manager:name" (flatpak:org.gimp.GIMP). Excludes
// are glob patterns on the name (kernel*).
type UpgradeParams struct {
	Mode     string   `json:"mode"`
	Packages []string `json:"packages,omitempty"`
	Exclude  []string `json:"exclude,omitempty"`
	Reboot   string   `json:"reboot"`
	// Versions pins packages of a selected upgrade to exact versions, keyed
	// as in Packages: apt and dnf install exactly that version
	// ([epoch:]version-release), and "rpm-ostree:<image>" deploys that image
	// version. Patch-group promotion uses it; it needs CapPkgPin.
	Versions map[string]string `json:"versions,omitempty"`
}

// ComposeParams are compose.pull's and compose.update's. A stack is named by
// engine and project as inventory reports it; the agent finds its files
// itself, so a job can't point Compose at arbitrary paths. No services means
// all of them.
type ComposeParams struct {
	Engine   string   `json:"engine"`
	Project  string   `json:"project"`
	Services []string `json:"services,omitempty"`
	// HealthTimeout (compose.update, compose.start, compose.move) is how
	// long, in seconds, the updated, started or moved containers get to be
	// running and healthy before the update is rolled back, the stack taken
	// down again, or moved back.
	HealthTimeout int `json:"health_timeout,omitempty"`
	// Dest (compose.move) is the host's Compose root the stack moves
	// under, to <dest>/<project>.
	Dest string `json:"dest,omitempty"`
}

// StackFileParams are compose.deploy's and compose.edit's. The files
// themselves travel in RunJob (StackFiles), never here: parameters are
// stored, listed and audited, and the .env holds secrets. Revision names the
// server's record of the files.
type StackFileParams struct {
	Engine   string `json:"engine"`
	Project  string `json:"project"`
	Revision string `json:"revision"`
	// Root (compose.deploy) is the host's Compose root the stack goes
	// under, in <root>/<project>; "" is the agent's own compose_root.
	Root string `json:"root,omitempty"`
	// ComposeSHA256 is the new Compose file's SHA-256; "" when an edit
	// leaves the file alone. BaseSHA256 (compose.edit) is the hash of the
	// file on the host the edit was made from: the agent refuses the edit
	// if the file changed since.
	ComposeSHA256 string `json:"compose_sha256,omitempty"`
	BaseSHA256    string `json:"base_sha256,omitempty"`
	// Env writes the .env sent with the job; false leaves the .env alone.
	// No plain hash of it goes here: parameters are stored, and a hash of
	// short secrets helps guess them.
	Env bool `json:"env,omitempty"`
	// HealthTimeout is how long, in seconds, the stack's containers get to
	// be running and healthy before the change is undone.
	HealthTimeout int `json:"health_timeout,omitempty"`
}

const (
	DefaultHealthTimeout = 120
	MaxHealthTimeout     = 1800
)

// UnitParams are service.restart's, service.start's and service.stop's.
type UnitParams struct {
	Unit string `json:"unit"`
}

// ContainerParams name a container the way inventory does: by engine and
// name, which survive Compose recreating it.
type ContainerParams struct {
	Engine string `json:"engine"`
	Name   string `json:"name"`
}

// RebootParams are host.reboot's.
type RebootParams struct {
	DelaySeconds int `json:"delay_s"`
}

// ScriptParams are script.run's. The body travels in RunJob, not here.
type ScriptParams struct {
	ScriptID string            `json:"script_id"`
	Name     string            `json:"name"`
	Version  int               `json:"version"`
	Args     map[string]string `json:"args,omitempty"`
	Timeout  int               `json:"timeout_s,omitempty"`
}

const (
	DefaultRebootDelay   = 10 // seconds: the agent reports before it goes
	DefaultScriptTimeout = 10 * time.Minute
	MaxScriptTimeout     = 4 * time.Hour
)

var (
	// Names that reach a command line never start with "-", so they can't
	// be taken for options.
	reUnit      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9@._:\\-]{0,254}$`)
	reContainer = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
	reEngine    = regexp.MustCompile(`^(docker|podman)(:[a-z_][a-z0-9_.-]{0,63})?$`)
	reUUID      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reSHA256    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rePackage   = regexp.MustCompile(`^([a-z-]+:)?[A-Za-z0-9][A-Za-z0-9+._@/:~-]{0,255}$`)
	reGlob      = regexp.MustCompile(`^[A-Za-z0-9*?\[][A-Za-z0-9+._@/:~*?\[\]!-]{0,255}$`)
	reVersion   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:~-]{0,127}$`)
	// Compose project names are lowercase (Compose normalizes them).
	reProject = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	reService = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
)

// Validate checks an action's parameters and returns them normalized
// (defaults filled in), as JSON.
func Validate(name string, raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	var v any
	switch name {
	case PkgUpgrade:
		var p UpgradeParams
		if err := strictJSON(raw, &p); err != nil {
			return nil, err
		}
		if p.Mode == "" {
			p.Mode = ModeAll
		}
		if p.Reboot == "" {
			p.Reboot = RebootNever
		}
		if !slices.Contains([]string{ModeAll, ModeSecurity, ModeSelected}, p.Mode) {
			return nil, fmt.Errorf("mode must be all, security or selected")
		}
		if !slices.Contains([]string{RebootNever, RebootIfRequired, RebootAlways}, p.Reboot) {
			return nil, fmt.Errorf("reboot must be never, if_required or always")
		}
		if p.Mode == ModeSelected && len(p.Packages) == 0 {
			return nil, errors.New("pick at least one package to upgrade")
		}
		if p.Mode != ModeSelected && len(p.Packages) > 0 {
			return nil, errors.New("packages are only listed in selected mode")
		}
		if len(p.Packages) > 1000 || len(p.Exclude) > 100 {
			return nil, errors.New("too many packages")
		}
		for _, pk := range p.Packages {
			// The manager prefix is optional, so check what follows each
			// ":" too: "flatpak:--help" must not reach a command line.
			if !rePackage.MatchString(pk) || strings.Contains(pk, ":-") {
				return nil, fmt.Errorf("%q isn't a package name", pk)
			}
		}
		for _, g := range p.Exclude {
			if _, err := path.Match(g, ""); err != nil || !reGlob.MatchString(g) {
				return nil, fmt.Errorf("%q isn't a package name or pattern", g)
			}
		}
		if len(p.Versions) > 0 && p.Mode != ModeSelected {
			return nil, errors.New("versions are only pinned in selected mode")
		}
		for pk, ver := range p.Versions {
			if !slices.Contains(p.Packages, pk) {
				return nil, fmt.Errorf("version pinned for %q, which isn't listed", pk)
			}
			if strings.HasPrefix(pk, "flatpak:") || strings.HasPrefix(pk, "snap:") {
				return nil, fmt.Errorf("%q: flatpak and snap versions can't be pinned", pk)
			}
			if !reVersion.MatchString(ver) {
				return nil, fmt.Errorf("%q isn't a version", ver)
			}
		}
		v = p
	case ServiceRestart, ServiceStart, ServiceStop:
		var p UnitParams
		if err := strictJSON(raw, &p); err != nil {
			return nil, err
		}
		if !reUnit.MatchString(p.Unit) {
			return nil, fmt.Errorf("%q isn't a unit name", p.Unit)
		}
		if !strings.Contains(p.Unit, ".") {
			p.Unit += ".service"
		}
		if !strings.HasSuffix(p.Unit, ".service") {
			return nil, errors.New("only .service units can be started, stopped or restarted")
		}
		v = p
	case ContainerRestart:
		var p ContainerParams
		if err := strictJSON(raw, &p); err != nil {
			return nil, err
		}
		if !reEngine.MatchString(p.Engine) || !reContainer.MatchString(p.Name) {
			return nil, errors.New("container needs an engine and a name")
		}
		v = p
	case ComposePull, ComposeUpdate, ComposeStart, ComposeArchive, ComposeMove:
		var p ComposeParams
		if err := strictJSON(raw, &p); err != nil {
			return nil, err
		}
		if !reEngine.MatchString(p.Engine) || !reProject.MatchString(p.Project) {
			return nil, errors.New("a Compose stack needs an engine and a project name")
		}
		if len(p.Services) > 100 {
			return nil, errors.New("too many services")
		}
		for _, sv := range p.Services {
			if !reService.MatchString(sv) {
				return nil, fmt.Errorf("%q isn't a service name", sv)
			}
		}
		p.Services = uniqSorted(p.Services)
		if name == ComposeStart && len(p.Services) > 0 {
			return nil, errors.New("starting a stack starts all of it")
		}
		if (name == ComposeArchive || name == ComposeMove) && len(p.Services) > 0 {
			return nil, errors.New("a stack is archived or moved as a whole")
		}
		if name == ComposeMove {
			if p.Dest == "" {
				return nil, errors.New("pick the Compose root to move the stack to")
			}
			if err := CheckComposeRoot(p.Dest); err != nil {
				return nil, err
			}
		} else if p.Dest != "" {
			return nil, errors.New("dest is compose.move's")
		}
		if name == ComposePull || name == ComposeArchive {
			if p.HealthTimeout != 0 {
				return nil, errors.New("health_timeout is compose.update's, compose.start's and compose.move's")
			}
		} else {
			if p.HealthTimeout == 0 {
				p.HealthTimeout = DefaultHealthTimeout
			}
			if p.HealthTimeout < 10 || p.HealthTimeout > MaxHealthTimeout {
				return nil, fmt.Errorf("the health timeout must be between 10 seconds and %d minutes", MaxHealthTimeout/60)
			}
		}
		v = p
	case ComposeDeploy, ComposeEdit:
		var p StackFileParams
		if err := strictJSON(raw, &p); err != nil {
			return nil, err
		}
		if !reEngine.MatchString(p.Engine) || !reProject.MatchString(p.Project) {
			return nil, errors.New("a Compose stack needs an engine and a project name")
		}
		if !reUUID.MatchString(p.Revision) {
			return nil, errors.New("the stack's files are missing")
		}
		for _, h := range []string{p.ComposeSHA256, p.BaseSHA256} {
			if h != "" && !reSHA256.MatchString(h) {
				return nil, errors.New("a file hash isn't a SHA-256")
			}
		}
		if name == ComposeDeploy {
			if p.ComposeSHA256 == "" {
				return nil, errors.New("a new stack needs a Compose file")
			}
			if p.BaseSHA256 != "" {
				return nil, errors.New("a new stack has nothing to edit")
			}
			if p.Root != "" {
				if err := CheckComposeRoot(p.Root); err != nil {
					return nil, err
				}
			}
		} else {
			if p.ComposeSHA256 == "" && !p.Env {
				return nil, errors.New("change the Compose file, the .env, or both")
			}
			if p.Root != "" {
				return nil, errors.New("an edit stays where the stack is")
			}
			if (p.ComposeSHA256 == "") != (p.BaseSHA256 == "") {
				return nil, errors.New("an edited Compose file goes with the hash of the file it replaces")
			}
		}
		if p.HealthTimeout == 0 {
			p.HealthTimeout = DefaultHealthTimeout
		}
		if p.HealthTimeout < 10 || p.HealthTimeout > MaxHealthTimeout {
			return nil, fmt.Errorf("the health timeout must be between 10 seconds and %d minutes", MaxHealthTimeout/60)
		}
		v = p
	case HostReboot:
		var p RebootParams
		p.DelaySeconds = DefaultRebootDelay
		if err := strictJSON(raw, &p); err != nil {
			return nil, err
		}
		if p.DelaySeconds < 5 || p.DelaySeconds > 3600 {
			return nil, errors.New("the reboot delay must be between 5 seconds and an hour")
		}
		v = p
	case K8sRestart, K8sScale, K8sSetImage, K8sDeletePod, K8sSuspend, K8sResume, K8sTrigger:
		var err error
		if v, err = validateK8s(name, raw); err != nil {
			return nil, err
		}
	case K8sDeploy, K8sEdit:
		var err error
		if v, err = validateK8sManifest(name, raw); err != nil {
			return nil, err
		}
	case ScriptRun:
		var p ScriptParams
		if err := strictJSON(raw, &p); err != nil {
			return nil, err
		}
		if p.ScriptID == "" || p.Version < 1 {
			return nil, errors.New("pick a script version")
		}
		// Checked in seconds: a huge value would overflow a Duration.
		if p.Timeout < 0 || p.Timeout > int(MaxScriptTimeout/time.Second) {
			return nil, fmt.Errorf("the timeout must be at most %v", MaxScriptTimeout)
		}
		v = p
	default:
		return nil, fmt.Errorf("unknown action %q", name)
	}
	return json.Marshal(v)
}

func uniqSorted(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	s = slices.Clone(s)
	slices.Sort(s)
	return slices.Compact(s)
}

func strictJSON(raw []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("parameters: %w", err)
	}
	return nil
}

// Timeout is how long a job of this action may run with these parameters.
func Timeout(name string, params []byte) time.Duration {
	s, ok := Get(name)
	if !ok {
		return DefaultScriptTimeout
	}
	switch name {
	case ScriptRun:
		var p ScriptParams
		if json.Unmarshal(params, &p) == nil && p.Timeout > 0 {
			return time.Duration(p.Timeout) * time.Second
		}
	case PkgUpgrade:
		var p UpgradeParams
		if json.Unmarshal(params, &p) == nil && p.Reboot != RebootNever {
			return s.Timeout + MustGet(HostReboot).Timeout
		}
	case ComposeUpdate, ComposeStart, ComposeMove:
		var p ComposeParams
		if json.Unmarshal(params, &p) == nil {
			return s.Timeout + time.Duration(p.HealthTimeout)*time.Second
		}
	case ComposeDeploy, ComposeEdit:
		var p StackFileParams
		if json.Unmarshal(params, &p) == nil {
			return s.Timeout + time.Duration(p.HealthTimeout)*time.Second
		}
	case K8sRestart, K8sScale, K8sSetImage:
		var p K8sParams
		if json.Unmarshal(params, &p) == nil {
			// A failed image change rolls back, which waits again.
			n := 1 + boolInt(name == K8sSetImage)
			return s.Timeout + time.Duration(n*p.HealthTimeout)*time.Second
		}
	case K8sDeploy, K8sEdit:
		var p K8sManifestParams
		if json.Unmarshal(params, &p) == nil {
			return s.Timeout + time.Duration(2*p.HealthTimeout)*time.Second
		}
	}
	return s.Timeout
}

// Expected is about how long a job of this action takes with these
// parameters: a maintenance window doesn't start it with less time left.
func Expected(name string, params []byte) time.Duration {
	s, ok := Get(name)
	if !ok {
		return DefaultScriptTimeout
	}
	switch name {
	case ScriptRun:
		return Timeout(name, params)
	case PkgUpgrade:
		var p UpgradeParams
		if json.Unmarshal(params, &p) == nil && p.Reboot != RebootNever {
			return s.Typical + MustGet(HostReboot).Typical
		}
	case ComposeUpdate, ComposeStart, ComposeMove:
		var p ComposeParams
		if json.Unmarshal(params, &p) == nil {
			return s.Typical + time.Duration(p.HealthTimeout)*time.Second
		}
	case ComposeDeploy, ComposeEdit:
		var p StackFileParams
		if json.Unmarshal(params, &p) == nil {
			return s.Typical + time.Duration(p.HealthTimeout)*time.Second
		}
	case K8sRestart, K8sScale, K8sSetImage:
		var p K8sParams
		if json.Unmarshal(params, &p) == nil {
			return s.Typical + time.Duration(p.HealthTimeout)*time.Second
		}
	case K8sDeploy, K8sEdit:
		var p K8sManifestParams
		if json.Unmarshal(params, &p) == nil {
			return s.Typical + time.Duration(p.HealthTimeout)*time.Second
		}
	}
	return s.Typical
}

// NeedsPin reports whether pkg.upgrade parameters pin versions, which only
// agents with CapPkgPin understand.
func NeedsPin(name string, params []byte) bool {
	if name != PkgUpgrade {
		return false
	}
	var p UpgradeParams
	return json.Unmarshal(params, &p) == nil && len(p.Versions) > 0
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// MustGet is Get for names known to exist.
func MustGet(name string) Spec {
	s, ok := Get(name)
	if !ok {
		panic("unknown action " + name)
	}
	return s
}

// Describe is a one-line summary of a job for lists: "Install security
// updates, reboot if required".
func Describe(name string, params []byte) string {
	switch name {
	case PkgUpgrade:
		var p UpgradeParams
		json.Unmarshal(params, &p)
		var s string
		switch p.Mode {
		case ModeSecurity:
			s = "Install security updates"
		case ModeSelected:
			s = "Upgrade " + strings.Join(p.Packages, ", ")
			if len(p.Packages) > 3 {
				s = fmt.Sprintf("Upgrade %d packages", len(p.Packages))
			}
			if len(p.Versions) > 0 {
				s += " to validated versions"
			}
		default:
			s = "Install all updates"
		}
		if len(p.Exclude) > 0 {
			s += " except " + strings.Join(p.Exclude, ", ")
		}
		switch p.Reboot {
		case RebootIfRequired:
			s += ", reboot if required"
		case RebootAlways:
			s += ", then reboot"
		}
		return s
	case ServiceRestart, ServiceStart, ServiceStop:
		var p UnitParams
		json.Unmarshal(params, &p)
		verb := strings.TrimPrefix(name, "service.")
		return strings.ToUpper(verb[:1]) + verb[1:] + " " + p.Unit
	case ContainerRestart:
		var p ContainerParams
		json.Unmarshal(params, &p)
		return "Restart container " + p.Name
	case ComposeArchive:
		var p ComposeParams
		json.Unmarshal(params, &p)
		return "Archive stack " + p.Project
	case ComposeMove:
		var p ComposeParams
		json.Unmarshal(params, &p)
		return "Move stack " + p.Project + " to " + path.Join(p.Dest, p.Project)
	case ComposePull, ComposeUpdate, ComposeStart:
		var p ComposeParams
		json.Unmarshal(params, &p)
		verb := "Update"
		switch name {
		case ComposePull:
			verb = "Pull images of"
		case ComposeStart:
			verb = "Start"
		}
		s := verb + " stack " + p.Project
		if len(p.Services) > 0 {
			s += " (" + strings.Join(p.Services, ", ") + ")"
		}
		return s
	case ComposeDeploy:
		var p StackFileParams
		json.Unmarshal(params, &p)
		if p.Root != "" {
			return "Deploy stack " + p.Project + " to " + path.Join(p.Root, p.Project)
		}
		return "Deploy stack " + p.Project
	case ComposeEdit:
		var p StackFileParams
		json.Unmarshal(params, &p)
		var what string
		switch {
		case p.ComposeSHA256 != "" && p.Env:
			what = "the Compose file and .env of"
		case p.ComposeSHA256 != "":
			what = "the Compose file of"
		default:
			what = "the .env of"
		}
		return "Edit " + what + " stack " + p.Project
	case K8sRestart, K8sScale, K8sSetImage, K8sDeletePod, K8sSuspend, K8sResume, K8sTrigger:
		var p K8sParams
		json.Unmarshal(params, &p)
		return describeK8s(name, p)
	case K8sDeploy, K8sEdit:
		var p K8sManifestParams
		json.Unmarshal(params, &p)
		return describeK8sManifest(name, p)
	case HostReboot:
		return "Reboot"
	case ScriptRun:
		var p ScriptParams
		json.Unmarshal(params, &p)
		return fmt.Sprintf("Run script %s v%d", p.Name, p.Version)
	}
	return name
}

// Local policy ------------------------------------------------------------------

// Policy is a host's agent-local policy from agent.conf (docs/architecture.md
// §5.3). The server can't override it; the agent reports it in Hello so the
// UI can grey out what a host refuses.
type Policy struct {
	// Jobs is false for agents that run no jobs at all: ones too old to,
	// and Kubernetes cluster agents.
	Jobs         bool `json:"jobs"`
	AllowScripts bool `json:"allow_scripts"`
	// AllowActions lists the categories the host accepts; nil means all.
	AllowActions []string `json:"allow_actions"` // null for all; [] for none, so no omitempty
	// SelfUpdateOff is agent.conf's self_update = off: the agent ignores
	// UpdateAgent and is updated only by running install.sh again. Stored
	// negated so agents that don't report it read as accepting updates.
	SelfUpdateOff bool `json:"self_update_off,omitempty"`
}

// AllActions reports whether every action category is allowed.
func (p Policy) AllActions() bool { return p.AllowActions == nil }

// Allows reports whether the policy lets an action run, and if not, why.
func (p Policy) Allows(name string) (bool, string) {
	s, ok := Get(name)
	switch {
	case !p.Jobs:
		return false, "this agent runs no jobs (it is too old to, or a Kubernetes cluster agent)"
	case !ok:
		return false, "unknown action"
	case s.Category == CategoryScript:
		if !p.AllowScripts {
			return false, "scripts are turned off in this host's agent.conf (allow_scripts)"
		}
	case s.Category == CategoryKubernetes && p.AllowActions != nil && !slices.Contains(p.AllowActions, s.Category):
		return false, "Kubernetes actions are turned off on this cluster agent (BASELINE_ALLOW_ACTIONS)"
	case p.AllowActions != nil && !slices.Contains(p.AllowActions, s.Category):
		return false, "\"" + s.Category + "\" actions are turned off in this host's agent.conf (allow_actions)"
	}
	return true, ""
}

// ParseAllowActions reads agent.conf's allow_actions: a comma-separated list
// of categories, "all", or "none" (or empty) for no actions at all.
func ParseAllowActions(v string) ([]string, error) {
	v = strings.TrimSpace(v)
	switch v {
	case "all", "*":
		return nil, nil
	case "", "none":
		return []string{}, nil
	}
	out := []string{}
	for _, c := range strings.Split(v, ",") {
		c = strings.TrimSpace(c)
		if !slices.Contains(Categories, c) {
			return nil, fmt.Errorf("unknown action category %q (known: %s)", c, strings.Join(Categories, ", "))
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// Results -----------------------------------------------------------------------

// StackFileResult is compose.deploy's and compose.edit's: where the stack's
// files are, the services it runs afterwards, and whether a failure was
// undone (the stack taken down again, or put back on its previous files).
type StackFileResult struct {
	WorkingDir  string   `json:"working_dir,omitempty"`
	ComposeFile string   `json:"compose_file,omitempty"`
	Services    []string `json:"services,omitempty"`
	RolledBack  bool     `json:"rolled_back,omitempty"`
}

// UpgradeResult is pkg.upgrade's structured result. Versions are read back
// from the package database after the run, not parsed from tool output.
type UpgradeResult struct {
	Changed  []PackageChange `json:"changed,omitempty"`
	Added    []PackageChange `json:"added,omitempty"`
	Removed  []PackageChange `json:"removed,omitempty"`
	Managers []string        `json:"managers,omitempty"` // the ones that ran
	Warnings []string        `json:"warnings,omitempty"`
	// RebootRequired is the host's state after the upgrade.
	RebootRequired bool     `json:"reboot_required,omitempty"`
	RebootReasons  []string `json:"reboot_reasons,omitempty"`
	Rebooting      bool     `json:"rebooting,omitempty"`
}

// ComposeResult is compose.pull's and compose.update's structured result.
type ComposeResult struct {
	Services []ComposeService `json:"services,omitempty"`
	// Current: the pull brought no new image, so nothing was restarted.
	Current bool `json:"current,omitempty"`
	// RolledBack: the updated containers didn't come up healthy, and the
	// previous images were put back (job state "rolled_back").
	RolledBack bool     `json:"rolled_back,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// ComposeService is one service's image before and after.
type ComposeService struct {
	Service string `json:"service"`
	Image   string `json:"image"`          // the reference it runs
	From    string `json:"from,omitempty"` // image ID before
	To      string `json:"to,omitempty"`   // image ID after the pull
	Changed bool   `json:"changed,omitempty"`
}

// PackageChange is one package's version before and after.
type PackageChange struct {
	Manager string `json:"manager"`
	Name    string `json:"name"`
	Arch    string `json:"arch,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
}

// ValidProject reports whether a Compose project name is one Baseline takes.
func ValidProject(name string) bool { return reProject.MatchString(name) }

// systemDirs are where no Compose root may be, or lie under: the system's
// own files, and the kernel's and runtime's file systems.
var systemDirs = []string{"/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32",
	"/proc", "/run", "/sbin", "/sys", "/usr", "/var/run"}

// CheckComposeRoot says why a directory can't be a Compose root, the
// directory on a host that compose.deploy puts stacks under: it must be
// an absolute, clean path, and not / or a system directory.
func CheckComposeRoot(dir string) error {
	switch {
	case dir == "":
		return errors.New("a Compose root needs a path")
	case len(dir) > 1024:
		return errors.New("a Compose root's path is at most 1024 characters")
	case !strings.HasPrefix(dir, "/"):
		return fmt.Errorf("%s isn't an absolute path", dir)
	case strings.ContainsFunc(dir, func(r rune) bool { return r < ' ' || r == 0x7f }):
		return errors.New("a Compose root's path can't hold control characters")
	case path.Clean(dir) != dir:
		return fmt.Errorf("write %s as %s", dir, path.Clean(dir))
	case dir == "/":
		return errors.New("/ can't be a Compose root")
	}
	for _, d := range systemDirs {
		if dir == d || strings.HasPrefix(dir, d+"/") {
			return fmt.Errorf("%s is a system directory; pick one outside %s", dir, d)
		}
	}
	return nil
}
