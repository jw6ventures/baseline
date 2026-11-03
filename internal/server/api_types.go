package server

import (
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/registry"
	"github.com/jw6ventures/baseline/internal/store"
)

// The API's response types. Field names are snake_case, times are RFC 3339
// and absent when unset, and lists are never null. Store types are
// converted rather than encoded directly so the API is a contract of its
// own: a store column can change without the API changing with it.

// ts turns a zero time into an absent field.
func ts(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func raw(b json.RawMessage) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("null")
	}
	return b
}

func strs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ref names something by ID with a label, for lists of related objects.
type ref struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func refs(ids, names []string) []ref {
	out := make([]ref, 0, len(ids))
	for i, id := range ids {
		r := ref{ID: id}
		if i < len(names) {
			r.Name = names[i]
		}
		out = append(out, r)
	}
	return out
}

// Hosts -------------------------------------------------------------------------

type hostJSON struct {
	ID                string        `json:"id"`
	AgentID           string        `json:"agent_id"`
	Hostname          string        `json:"hostname"`
	FQDN              string        `json:"fqdn"`
	OSID              string        `json:"os_id"`
	OSVersion         string        `json:"os_version"`
	OSPretty          string        `json:"os_pretty"`
	Kernel            string        `json:"kernel"`
	Arch              string        `json:"arch"`
	AgentVersion      string        `json:"agent_version"`
	AgentArch         string        `json:"agent_arch"`
	ClusterAgent      bool          `json:"cluster_agent"`
	Connected         bool          `json:"connected"`
	LastSeen          *time.Time    `json:"last_seen,omitempty"`
	LastConnect       *time.Time    `json:"last_connect,omitempty"`
	EnrolledAt        *time.Time    `json:"enrolled_at,omitempty"`
	Revoked           bool          `json:"revoked"`
	DuplicateIdentity bool          `json:"duplicate_identity"`
	HighSecurity      bool          `json:"high_security"`
	HighSecuritySince *time.Time    `json:"high_security_since,omitempty"`
	Groups            []ref         `json:"groups"`
	PackageCount      int           `json:"package_count"`
	Updates           int           `json:"updates"`
	SecurityUpdates   int           `json:"security_updates"`
	UpdatesAt         *time.Time    `json:"updates_at,omitempty"`
	DisksFailing      int           `json:"disks_failing"`
	DisksDegrading    int           `json:"disks_degrading"`
	RebootRequired    bool          `json:"reboot_required"`
	RebootReasons     []string      `json:"reboot_reasons"`
	FailedServices    int           `json:"failed_services"`
	Containers        int           `json:"containers"`
	ContainersUp      int           `json:"containers_running"`
	ContainerUpdates  int           `json:"container_updates"`
	CertsExpiring     int           `json:"certs_expiring"`
	OpenJobs          int           `json:"open_jobs"`
	VulnEcosystem     string        `json:"vuln_ecosystem"`
	VulnsAt           *time.Time    `json:"vulns_at,omitempty"`
	FixableVulns      int           `json:"fixable_vulns"`
	AgentUpdateTarget string        `json:"agent_update_target,omitempty"`
	AgentUpdateAt     *time.Time    `json:"agent_update_at,omitempty"`
	AgentUpdateError  string        `json:"agent_update_error,omitempty"`
	Policy            action.Policy `json:"policy"`
	Capabilities      []string      `json:"capabilities"`
	MachineID         string        `json:"machine_id"`
	DMIUUID           string        `json:"dmi_uuid"`
	BootID            string        `json:"boot_id"`
	BootTime          *time.Time    `json:"boot_time,omitempty"`
	CertNotAfter      *time.Time    `json:"cert_not_after,omitempty"`
}

func hostToJSON(h store.Host) hostJSON {
	return hostJSON{
		ID: h.ID, AgentID: h.AgentID, Hostname: h.Hostname, FQDN: h.FQDN, OSID: h.OSID, OSVersion: h.OSVersion,
		OSPretty: h.OSPretty, Kernel: h.Kernel, Arch: h.Arch, AgentVersion: h.AgentVersion, AgentArch: h.AgentArch,
		ClusterAgent: h.ClusterAgent(), Connected: h.Connected, LastSeen: ts(h.LastSeen), LastConnect: ts(h.LastConnect),
		EnrolledAt: ts(h.EnrolledAt), Revoked: h.Revoked, DuplicateIdentity: h.DuplicateIdentity,
		HighSecurity: h.HighSecurity, HighSecuritySince: ts(h.HighSecuritySince), Groups: refs(h.GroupIDs, h.GroupNames),
		PackageCount: h.PackageCount, Updates: h.Updates, SecurityUpdates: h.SecurityUpdates, UpdatesAt: ts(h.UpdatesAt),
		DisksFailing: h.DisksFailing, DisksDegrading: h.DisksDegrading, RebootRequired: h.RebootRequired,
		RebootReasons: strs(h.RebootReasons), FailedServices: h.FailedServices, Containers: h.Containers,
		ContainersUp: h.ContainersUp, ContainerUpdates: h.ContainerUpdates, CertsExpiring: h.CertsExpiring,
		OpenJobs: h.OpenJobs, VulnEcosystem: h.VulnEcosystem, VulnsAt: ts(h.VulnsAt), FixableVulns: h.FixableVulns,
		AgentUpdateTarget: h.AgentUpdateTarget, AgentUpdateAt: ts(h.AgentUpdateAt), AgentUpdateError: h.AgentUpdateError,
		Policy: h.Policy, Capabilities: strs(h.Capabilities), MachineID: h.MachineID, DMIUUID: h.DMIUUID, BootID: h.BootID,
		BootTime: ts(h.BootTime), CertNotAfter: ts(h.CertNotAfter),
	}
}

func hostsToJSON(hs []store.Host) []hostJSON {
	out := make([]hostJSON, 0, len(hs))
	for _, h := range hs {
		out = append(out, hostToJSON(h))
	}
	return out
}

type hostGroupJSON struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
}

type sectionJSON struct {
	Section     string          `json:"section"`
	CollectedAt *time.Time      `json:"collected_at,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
}

type historyJSON struct {
	ID        int64           `json:"id"`
	At        time.Time       `json:"at"`
	Actor     string          `json:"actor"`
	ChangeID  string          `json:"change_id,omitempty"`
	ChangeRef string          `json:"change_ref,omitempty"`
	Section   string          `json:"section"`
	Diff      json.RawMessage `json:"diff"`
}

func historyToJSON(es []store.HistoryEntry) []historyJSON {
	out := make([]historyJSON, 0, len(es))
	for _, e := range es {
		h := historyJSON{ID: e.ID, At: e.At, Actor: e.Actor, ChangeID: e.ChangeID, Section: e.Section, Diff: raw(e.Diff)}
		if e.ChangeID != "" {
			h.ChangeRef = store.ChangeRef(e.ChangeNumber)
		}
		out = append(out, h)
	}
	return out
}

type hostUpdateJSON struct {
	model.Update
	FirstSeen *time.Time `json:"first_seen,omitempty"`
}

type packageUpdateJSON struct {
	Manager    string     `json:"manager"`
	Name       string     `json:"name"`
	Candidates []string   `json:"candidates"`
	Security   bool       `json:"security"`
	Image      bool       `json:"image"`
	Hosts      []ref      `json:"hosts"`
	FirstSeen  *time.Time `json:"first_seen,omitempty"`
}

type certJSON struct {
	CIID        string     `json:"ci_id"`
	CIName      string     `json:"ci_name"`
	CIType      string     `json:"ci_type"`
	Location    string     `json:"location"`
	Source      string     `json:"source"`
	Subject     string     `json:"subject"`
	SANs        []string   `json:"sans"`
	Issuer      string     `json:"issuer"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
	Serial      string     `json:"serial"`
	Fingerprint string     `json:"fingerprint"`
	SelfSigned  bool       `json:"self_signed"`
	Error       string     `json:"error,omitempty"`
	CheckedAt   *time.Time `json:"checked_at,omitempty"`
}

func certsToJSON(cs []store.CertRow) []certJSON {
	out := make([]certJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, certJSON{CIID: c.CIID, CIName: c.CIName, CIType: c.CIType, Location: c.Location, Source: c.Source,
			Subject: c.Subject, SANs: strs(c.SANs), Issuer: c.Issuer, NotBefore: ts(c.NotBefore), NotAfter: ts(c.NotAfter),
			Serial: c.Serial, Fingerprint: c.Fingerprint, SelfSigned: c.SelfSigned, Error: c.Error, CheckedAt: ts(c.CheckedAt)})
	}
	return out
}

// Containers, VMs, Kubernetes --------------------------------------------------

type containerJSON struct {
	model.Container
	CIID          string     `json:"ci_id"`
	HostID        string     `json:"host_id"`
	Hostname      string     `json:"hostname"`
	HostConnected bool       `json:"host_connected"`
	StackCI       string     `json:"stack_ci,omitempty"`
	CheckRef      string     `json:"check_ref,omitempty"`
	ImageDigests  []string   `json:"image_digests"`
	LatestDigest  string     `json:"latest_digest,omitempty"`
	CheckedAt     *time.Time `json:"checked_at,omitempty"`
	CheckError    string     `json:"check_error,omitempty"`
	Drift         bool       `json:"drift"`
	Pinned        bool       `json:"pinned"`
	// Rule is the semver rule that applies (the container's own, or its
	// Compose service's); AdvisedTag the newest tag it allows, if newer.
	Rule       *registry.Rule `json:"rule,omitempty"`
	AdvisedTag string         `json:"advised_tag,omitempty"`
	HasUpdate  bool           `json:"has_update"`
}

func containerToJSON(c containerView) containerJSON {
	return containerJSON{Container: c.Container, CIID: c.CIID, HostID: c.HostID, Hostname: c.Hostname,
		HostConnected: c.HostConnected, StackCI: c.StackCI, CheckRef: c.CheckRef, ImageDigests: strs(c.ImageDigests),
		LatestDigest: c.LatestDigest, CheckedAt: ts(c.CheckedAt), CheckError: c.CheckError, Drift: c.Drift, Pinned: c.Pinned,
		Rule: c.Rule, AdvisedTag: c.Advice, HasUpdate: c.HasUpdate()}
}

func containersToJSON(cs []containerView) []containerJSON {
	out := make([]containerJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, containerToJSON(c))
	}
	return out
}

type stackJSON struct {
	CIID        string         `json:"ci_id"`
	HostID      string         `json:"host_id"`
	Hostname    string         `json:"hostname"`
	Engine      string         `json:"engine"`
	Project     string         `json:"project"`
	WorkingDir  string         `json:"working_dir"`
	ConfigFiles []string       `json:"config_files"`
	CLI         string         `json:"cli"`
	Orphaned    bool           `json:"orphaned"`
	Stopped     bool           `json:"stopped"`
	Present     bool           `json:"present"`
	AutoUpdate  bool           `json:"auto_update"`
	Pinned      bool           `json:"pinned"`
	SemverRules map[string]any `json:"semver_rules"`
	Containers  int            `json:"containers"`
	Running     int            `json:"running"`
	Drift       int            `json:"drift"`
	Status      string         `json:"status"`
	ModelID     string         `json:"model_id,omitempty"`
	ModelName   string         `json:"model_name,omitempty"`
	ModelState  string         `json:"model_state,omitempty"`
	WindowID    string         `json:"window_id,omitempty"`
	WindowName  string         `json:"window_name,omitempty"`
	Environment string         `json:"environment"`
	Category    string         `json:"category"`
	Visibility  string         `json:"visibility"`
}

func stackToJSON(st store.Stack) stackJSON {
	rules := map[string]any{}
	for svc, r := range st.SemverRules {
		rules[svc] = r
	}
	return stackJSON{CIID: st.CIID, HostID: st.HostID, Hostname: st.Hostname, Engine: st.Engine, Project: st.Project,
		WorkingDir: st.WorkingDir, ConfigFiles: strs(st.ConfigFiles), CLI: st.CLI, Orphaned: st.Orphaned, Stopped: st.Stopped, Present: st.Present,
		AutoUpdate: st.AutoUpdate, Pinned: st.Pinned, SemverRules: rules, Containers: st.Containers, Running: st.Running,
		Drift: st.Drift, Status: st.Status, ModelID: st.ModelID, ModelName: st.ModelName, ModelState: st.ModelState,
		WindowID: st.WindowID, WindowName: st.WindowName, Environment: st.Environment, Category: st.Category,
		Visibility: st.Visibility}
}

func stacksToJSON(sts []store.Stack) []stackJSON {
	out := make([]stackJSON, 0, len(sts))
	for _, st := range sts {
		out = append(out, stackToJSON(st))
	}
	return out
}

type guestJSON struct {
	model.Guest
	CIID          string `json:"ci_id"`
	Status        string `json:"status"`
	Present       bool   `json:"present"`
	HostID        string `json:"host_id"`
	Hostname      string `json:"hostname"`
	HostConnected bool   `json:"host_connected"`
	AgentHostID   string `json:"agent_host_id,omitempty"`
	AgentHostname string `json:"agent_hostname,omitempty"`
}

func guestToJSON(g store.Guest) guestJSON {
	return guestJSON{Guest: g.Guest, CIID: g.CIID, Status: g.Status, Present: g.Present, HostID: g.HostID,
		Hostname: g.Hostname, HostConnected: g.HostConnected, AgentHostID: g.AgentHostID, AgentHostname: g.AgentHostname}
}

type clusterJSON struct {
	CIID       string `json:"ci_id"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Version    string `json:"version"`
	Platform   string `json:"platform"`
	Status     string `json:"status"`
	HostID     string `json:"host_id"`
	Connected  bool   `json:"connected"`
	Nodes      int    `json:"nodes"`
	NodesReady int    `json:"nodes_ready"`
	Workloads  int    `json:"workloads"`
	Degraded   int    `json:"degraded"`
}

func clusterToJSON(c store.Cluster) clusterJSON {
	return clusterJSON{CIID: c.CIID, Name: c.Name, UID: c.UID, Version: c.Version, Platform: c.Platform, Status: c.Status,
		HostID: c.HostID, Connected: c.Connected, Nodes: c.Nodes, NodesReady: c.NodesReady, Workloads: c.Workloads,
		Degraded: c.Degraded}
}

type k8sObjectJSON struct {
	CIID      string             `json:"ci_id"`
	Kind      string             `json:"kind"`
	Namespace string             `json:"namespace,omitempty"`
	Name      string             `json:"name"`
	Present   bool               `json:"present"`
	Status    string             `json:"status"`
	Node      *model.K8sNodeInfo `json:"node,omitempty"`
	Workload  *model.K8sWorkload `json:"workload,omitempty"`
	HostID    string             `json:"host_id,omitempty"`
	Hostname  string             `json:"hostname,omitempty"`
}

func k8sObjectToJSON(o store.K8sObject) k8sObjectJSON {
	j := k8sObjectJSON{CIID: o.CIID, Kind: o.Kind, Namespace: o.Namespace, Name: o.Name, Present: o.Present,
		Status: o.Status, HostID: o.HostID, Hostname: o.Hostname}
	if o.Kind == "Node" {
		n := o.Node
		j.Node = &n
	} else {
		w := o.Workload
		j.Workload = &w
	}
	return j
}

// CIs --------------------------------------------------------------------------

type ciJSON struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	TypeLabel     string         `json:"type_label"`
	Name          string         `json:"name"`
	Status        string         `json:"status"`
	Source        string         `json:"source"`
	Owner         string         `json:"owner"`
	Description   string         `json:"description"`
	Tags          []string       `json:"tags"`
	Attrs         map[string]any `json:"attrs"`
	FirstSeen     *time.Time     `json:"first_seen,omitempty"`
	LastSeen      *time.Time     `json:"last_seen,omitempty"`
	UpdatedAt     *time.Time     `json:"updated_at,omitempty"`
	HostID        string         `json:"host_id,omitempty"`
	Relationships int            `json:"relationships"`
}

func ciToJSON(c store.CI) ciJSON {
	attrs := c.Attrs
	if attrs == nil {
		attrs = map[string]any{}
	}
	return ciJSON{ID: c.ID, Type: c.Type, TypeLabel: c.TypeLabel, Name: c.Name, Status: c.Status, Source: c.Source,
		Owner: c.Owner, Description: c.Description, Tags: strs(c.Tags), Attrs: attrs, FirstSeen: ts(c.FirstSeen),
		LastSeen: ts(c.LastSeen), UpdatedAt: ts(c.UpdatedAt), HostID: c.HostID, Relationships: c.Relation}
}

func cisToJSON(cs []store.CI) []ciJSON {
	out := make([]ciJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, ciToJSON(c))
	}
	return out
}

type ciTypeJSON struct {
	Key    string          `json:"key"`
	Label  string          `json:"label"`
	Fields []store.CIField `json:"fields"`
}

type relationshipJSON struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Source   string `json:"source"`
	Outgoing bool   `json:"outgoing"`
	Other    ciJSON `json:"other"`
}

func relationshipsToJSON(rels []store.Relationship) []relationshipJSON {
	out := make([]relationshipJSON, 0, len(rels))
	for _, r := range rels {
		out = append(out, relationshipJSON{ID: r.ID, Kind: r.Kind, Source: r.Source, Outgoing: r.Outgoing, Other: ciToJSON(r.Other)})
	}
	return out
}

// Changes, jobs, scripts, schedule ------------------------------------------------

type changeJSON struct {
	ID                string           `json:"id"`
	Number            int64            `json:"number"`
	Ref               string           `json:"ref"`
	Kind              string           `json:"kind"`
	Title             string           `json:"title"`
	Description       string           `json:"description"`
	Justification     string           `json:"justification"`
	Risk              string           `json:"risk"`
	Impact            string           `json:"impact"`
	BackoutPlan       string           `json:"backout_plan"`
	TestPlan          string           `json:"test_plan"`
	State             string           `json:"state"`
	Outcome           string           `json:"outcome,omitempty"`
	RequestedBy       string           `json:"requested_by,omitempty"`
	RequestedByName   string           `json:"requested_by_name"`
	RequiredApprovals int              `json:"required_approvals"`
	Approvals         int              `json:"approval_count"`
	SelfApproved      bool             `json:"self_approved"`
	Concurrency       int              `json:"concurrency"`
	StopOnFailure     bool             `json:"stop_on_failure"`
	Plan              []store.PlanStep `json:"plan"`
	Hosts             []ref            `json:"hosts"`
	CreatedAt         time.Time        `json:"created_at"`
	SubmittedAt       *time.Time       `json:"submitted_at,omitempty"`
	ApprovedAt        *time.Time       `json:"approved_at,omitempty"`
	PlannedStart      *time.Time       `json:"planned_start,omitempty"`
	PlannedEnd        *time.Time       `json:"planned_end,omitempty"`
	ActualStart       *time.Time       `json:"actual_start,omitempty"`
	ActualEnd         *time.Time       `json:"actual_end,omitempty"`
	ClosedAt          *time.Time       `json:"closed_at,omitempty"`
	ModelID           string           `json:"model_id,omitempty"`
	ModelName         string           `json:"model_name,omitempty"`
	WindowID          string           `json:"window_id,omitempty"`
	WindowName        string           `json:"window_name,omitempty"`
	WindowEndsAt      *time.Time       `json:"window_ends_at,omitempty"`
	OnWindowEnd       string           `json:"on_window_end"`
	ScheduleNote      string           `json:"schedule_note,omitempty"`
	ReviewNotes       string           `json:"review_notes,omitempty"`
	ReviewedBy        string           `json:"reviewed_by,omitempty"`
	Jobs              jobCountsJSON    `json:"jobs"`
}

type jobCountsJSON struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Open      int `json:"open"`
	Queued    int `json:"queued"`
}

func changeToJSON(c store.Change) changeJSON {
	plan := c.Plan
	if plan == nil {
		plan = []store.PlanStep{}
	}
	return changeJSON{ID: c.ID, Number: c.Number, Ref: c.Ref(), Kind: c.Kind, Title: c.Title, Description: c.Description,
		Justification: c.Justification, Risk: c.Risk, Impact: c.Impact, BackoutPlan: c.BackoutPlan, TestPlan: c.TestPlan,
		State: c.State, Outcome: c.Outcome, RequestedBy: c.RequestedBy, RequestedByName: c.RequestedByName,
		RequiredApprovals: c.RequiredApprovals, Approvals: c.Approvals, SelfApproved: c.SelfApproved,
		Concurrency: c.Concurrency, StopOnFailure: c.StopOnFailure, Plan: plan, Hosts: refs(c.HostIDs, c.HostNames),
		CreatedAt: c.CreatedAt, SubmittedAt: ts(c.SubmittedAt), ApprovedAt: ts(c.ApprovedAt), PlannedStart: ts(c.PlannedStart),
		PlannedEnd: ts(c.PlannedEnd), ActualStart: ts(c.ActualStart), ActualEnd: ts(c.ActualEnd), ClosedAt: ts(c.ClosedAt),
		ModelID: c.ModelID, ModelName: c.ModelName, WindowID: c.WindowID, WindowName: c.WindowName,
		WindowEndsAt: ts(c.WindowEndsAt), OnWindowEnd: c.OnWindowEnd, ScheduleNote: c.ScheduleNote,
		ReviewNotes: c.ReviewNotes, ReviewedBy: c.ReviewedBy,
		Jobs: jobCountsJSON{Total: c.Jobs, Succeeded: c.JobsOK, Failed: c.JobsFailed, Open: c.JobsOpen, Queued: c.JobsQueued}}
}

func changesToJSON(cs []store.Change) []changeJSON {
	out := make([]changeJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, changeToJSON(c))
	}
	return out
}

type approvalJSON struct {
	Approver     string    `json:"approver"`
	ApproverName string    `json:"approver_name"`
	Decision     string    `json:"decision"`
	Comment      string    `json:"comment"`
	SelfApproved bool      `json:"self_approved"`
	At           time.Time `json:"at"`
}

type patchCycleJSON struct {
	ID           string                   `json:"id"`
	GroupID      string                   `json:"group_id"`
	GroupName    string                   `json:"group_name"`
	ChangeID     string                   `json:"change_id,omitempty"`
	ChangeRef    string                   `json:"change_ref,omitempty"`
	ChangeState  string                   `json:"change_state,omitempty"`
	ScheduledFor *time.Time               `json:"scheduled_for,omitempty"`
	StartedAt    *time.Time               `json:"started_at,omitempty"`
	FinishedAt   *time.Time               `json:"finished_at,omitempty"`
	Result       string                   `json:"result"`
	Reason       string                   `json:"reason,omitempty"`
	Hosts        int                      `json:"hosts"`
	Succeeded    int                      `json:"succeeded"`
	Planned      []store.PlannedHost      `json:"planned"`
	Validated    []store.ValidatedPackage `json:"validated"`
}

func patchCycleToJSON(c store.PatchCycle) patchCycleJSON {
	j := patchCycleJSON{ID: c.ID, GroupID: c.GroupID, GroupName: c.GroupName, ChangeID: c.ChangeID, ChangeState: c.ChangeState,
		ScheduledFor: ts(c.ScheduledFor), StartedAt: ts(c.StartedAt), FinishedAt: ts(c.FinishedAt), Result: c.Result,
		Reason: c.Reason, Hosts: c.Hosts, Succeeded: c.Succeeded, Planned: c.Planned, Validated: c.Validated}
	if c.ChangeID != "" {
		j.ChangeRef = store.ChangeRef(c.ChangeNumber)
	}
	if j.Planned == nil {
		j.Planned = []store.PlannedHost{}
	}
	if j.Validated == nil {
		j.Validated = []store.ValidatedPackage{}
	}
	return j
}

type changeModelJSON struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Action          string          `json:"action"`
	Params          json.RawMessage `json:"params"`
	ScriptID        string          `json:"script_id,omitempty"`
	ScriptVersion   int             `json:"script_version,omitempty"`
	Risk            string          `json:"risk"`
	State           string          `json:"state"`
	RequestedBy     string          `json:"requested_by,omitempty"`
	RequestedByName string          `json:"requested_by_name"`
	ApprovedByName  string          `json:"approved_by_name,omitempty"`
	ApprovedAt      *time.Time      `json:"approved_at,omitempty"`
	SelfApproved    bool            `json:"self_approved"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	Changes         int             `json:"changes"`
	PatchGroups     int             `json:"patch_groups"`
	Stacks          int             `json:"stacks"`
}

func changeModelToJSON(m store.ChangeModel) changeModelJSON {
	return changeModelJSON{ID: m.ID, Name: m.Name, Description: m.Description, Action: m.Action, Params: raw(m.Params),
		ScriptID: m.ScriptID, ScriptVersion: m.ScriptVersion, Risk: m.Risk, State: m.State, RequestedBy: m.RequestedBy,
		RequestedByName: m.RequestedByName, ApprovedByName: m.ApprovedByName, ApprovedAt: ts(m.ApprovedAt),
		SelfApproved: m.SelfApproved, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt, Changes: m.Changes,
		PatchGroups: m.PatchGroups, Stacks: m.Stacks}
}

type jobJSON struct {
	ID              string          `json:"id"`
	ChangeID        string          `json:"change_id"`
	ChangeRef       string          `json:"change_ref"`
	ChangeTitle     string          `json:"change_title"`
	ChangeState     string          `json:"change_state"`
	Seq             int             `json:"seq"`
	HostID          string          `json:"host_id"`
	AgentID         string          `json:"agent_id"`
	Hostname        string          `json:"hostname"`
	Action          string          `json:"action"`
	Params          json.RawMessage `json:"params"`
	ScriptID        string          `json:"script_id,omitempty"`
	ScriptVersion   int             `json:"script_version,omitempty"`
	TimeoutS        int             `json:"timeout_s"`
	State           string          `json:"state"`
	Final           bool            `json:"final"`
	AwaitingReboot  bool            `json:"awaiting_reboot"`
	QueuedAt        *time.Time      `json:"queued_at,omitempty"`
	DispatchedAt    *time.Time      `json:"dispatched_at,omitempty"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
	ExitCode        *int64          `json:"exit_code,omitempty"`
	Result          json.RawMessage `json:"result"`
	Error           string          `json:"error,omitempty"`
	OutputBytes     int             `json:"output_bytes"`
	RequestedByName string          `json:"requested_by_name"`
}

func jobToJSON(j store.Job) jobJSON {
	out := jobJSON{ID: j.ID, ChangeID: j.ChangeID, ChangeRef: store.ChangeRef(j.ChangeNumber), ChangeTitle: j.ChangeTitle,
		ChangeState: j.ChangeState, Seq: j.Seq, HostID: j.HostID, AgentID: j.AgentID, Hostname: j.Hostname, Action: j.Action,
		Params: raw(j.Params), ScriptID: j.ScriptID, ScriptVersion: j.ScriptVersion, TimeoutS: j.TimeoutS, State: j.State,
		Final: j.Final(), AwaitingReboot: j.AwaitingReboot, QueuedAt: ts(j.QueuedAt), DispatchedAt: ts(j.DispatchedAt),
		StartedAt: ts(j.StartedAt), FinishedAt: ts(j.FinishedAt), Result: raw(j.Result), Error: j.Error,
		OutputBytes: j.OutputBytes, RequestedByName: j.RequestedByName}
	if j.ExitCode.Valid {
		code := j.ExitCode.Int64
		out.ExitCode = &code
	}
	return out
}

func jobsToJSON(js []store.Job) []jobJSON {
	out := make([]jobJSON, 0, len(js))
	for _, j := range js {
		out = append(out, jobToJSON(j))
	}
	return out
}

type outputChunkJSON struct {
	ID     int64     `json:"id"`
	Seq    int64     `json:"seq"`
	Stream string    `json:"stream"`
	At     time.Time `json:"at"`
	Chunk  string    `json:"chunk"`
}

type scriptJSON struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Archived    bool       `json:"archived"`
	CreatedAt   time.Time  `json:"created_at"`
	Latest      int        `json:"latest"`
	LatestAt    *time.Time `json:"latest_at,omitempty"`
	Risk        string     `json:"risk"`
	Interpreter string     `json:"interpreter"`
	Runs        int        `json:"runs"`
}

func scriptToJSON(sc store.Script) scriptJSON {
	return scriptJSON{ID: sc.ID, Name: sc.Name, Description: sc.Description, Archived: sc.Archived, CreatedAt: sc.CreatedAt,
		Latest: sc.Latest, LatestAt: ts(sc.LatestAt), Risk: sc.Risk, Interpreter: sc.Interpreter, Runs: sc.Runs}
}

type scriptVersionJSON struct {
	ScriptID    string               `json:"script_id"`
	ScriptName  string               `json:"script_name"`
	Version     int                  `json:"version"`
	Interpreter string               `json:"interpreter"`
	Params      []action.ScriptParam `json:"params"`
	Risk        string               `json:"risk"`
	Body        string               `json:"body,omitempty"`
	SHA256      string               `json:"sha256"`
	Notes       string               `json:"notes"`
	CreatedBy   string               `json:"created_by"`
	CreatedAt   time.Time            `json:"created_at"`
}

func scriptVersionToJSON(v store.ScriptVersion, body bool) scriptVersionJSON {
	j := scriptVersionJSON{ScriptID: v.ScriptID, ScriptName: v.ScriptName, Version: v.Version, Interpreter: v.Interpreter,
		Params: v.Params, Risk: v.Risk, SHA256: v.SHA256, Notes: v.Notes, CreatedBy: v.CreatedBy, CreatedAt: v.CreatedAt}
	if j.Params == nil {
		j.Params = []action.ScriptParam{}
	}
	if body {
		j.Body = v.Body
	}
	return j
}

type windowJSON struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Kind        string    `json:"kind"`
	Cron        string    `json:"cron"`
	DurationS   int       `json:"duration_s"`
	TZ          string    `json:"tz"`
	Scope       []ref     `json:"scope"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func windowToJSON(w store.MaintenanceWindow) windowJSON {
	return windowJSON{ID: w.ID, Name: w.Name, Description: w.Description, Kind: w.Kind, Cron: w.Cron,
		DurationS: int(w.Duration / time.Second), TZ: w.TZ, Scope: refs(w.ScopeGroups, w.ScopeNames), Active: w.Active,
		CreatedAt: w.CreatedAt, UpdatedAt: w.UpdatedAt}
}

type calendarItemJSON struct {
	Kind   string     `json:"kind"`
	Name   string     `json:"name"`
	Detail string     `json:"detail,omitempty"`
	Start  time.Time  `json:"start"`
	End    *time.Time `json:"end,omitempty"`
}

type patchGroupJSON struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	HostGroupID      string          `json:"host_group_id"`
	HostGroupName    string          `json:"host_group_name"`
	Cron             string          `json:"cron"`
	TZ               string          `json:"tz"`
	WindowID         string          `json:"window_id,omitempty"`
	WindowName       string          `json:"window_name,omitempty"`
	ModelID          string          `json:"model_id"`
	ModelName        string          `json:"model_name"`
	ModelState       string          `json:"model_state"`
	BlockedBy        []ref           `json:"blocked_by"`
	SoakS            int             `json:"soak_s"`
	SuccessThreshold int             `json:"success_threshold"`
	PromoteValidated bool            `json:"promote_validated"`
	Concurrency      int             `json:"concurrency"`
	StopOnFailure    bool            `json:"stop_on_failure"`
	Enabled          bool            `json:"enabled"`
	LastRunAt        *time.Time      `json:"last_run_at,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	Hosts            int             `json:"hosts"`
	LastCycle        *patchCycleJSON `json:"last_cycle,omitempty"`
}

func patchGroupToJSON(g store.PatchGroup) patchGroupJSON {
	j := patchGroupJSON{ID: g.ID, Name: g.Name, Description: g.Description, HostGroupID: g.HostGroupID,
		HostGroupName: g.HostGroupName, Cron: g.Cron, TZ: g.TZ, WindowID: g.WindowID, WindowName: g.WindowName,
		ModelID: g.ModelID, ModelName: g.ModelName, ModelState: g.ModelState, BlockedBy: refs(g.BlockedBy, g.BlockedByNames),
		SoakS: int(g.Soak / time.Second), SuccessThreshold: g.SuccessThreshold, PromoteValidated: g.PromoteValidated,
		Concurrency: g.Concurrency, StopOnFailure: g.StopOnFailure, Enabled: g.Enabled, LastRunAt: ts(g.LastRunAt),
		CreatedAt: g.CreatedAt, Hosts: g.Hosts}
	if g.Last != nil {
		c := patchCycleToJSON(*g.Last)
		j.LastCycle = &c
	}
	return j
}

// Vulnerabilities, alerts, audit -------------------------------------------------

type vulnRowJSON struct {
	ID           string     `json:"id"`
	Aliases      []string   `json:"aliases"`
	Summary      string     `json:"summary"`
	Severity     string     `json:"severity"`
	CVSSScore    *float64   `json:"cvss_score,omitempty"`
	Published    *time.Time `json:"published,omitempty"`
	Hosts        int        `json:"hosts"`
	FixableHosts int        `json:"fixable_hosts"`
	Packages     []string   `json:"packages"`
	FirstSeen    *time.Time `json:"first_seen,omitempty"`
}

type hostVulnJSON struct {
	HostID       string     `json:"host_id"`
	Hostname     string     `json:"hostname"`
	VulnID       string     `json:"vuln_id"`
	Package      string     `json:"package"`
	Arch         string     `json:"arch,omitempty"`
	Source       string     `json:"source,omitempty"`
	Installed    string     `json:"installed"`
	Fixed        string     `json:"fixed,omitempty"`
	Candidate    string     `json:"candidate,omitempty"`
	FixAvailable bool       `json:"fix_available"`
	Severity     string     `json:"severity"`
	FirstSeen    *time.Time `json:"first_seen,omitempty"`
	Summary      string     `json:"summary"`
	Aliases      []string   `json:"aliases"`
	CVSSScore    *float64   `json:"cvss_score,omitempty"`
}

func hostVulnsToJSON(ms []store.HostVuln) []hostVulnJSON {
	out := make([]hostVulnJSON, 0, len(ms))
	for _, m := range ms {
		out = append(out, hostVulnJSON{HostID: m.HostID, Hostname: m.Hostname, VulnID: m.VulnID, Package: m.Package,
			Arch: m.Arch, Source: m.Source, Installed: m.Installed, Fixed: m.Fixed, Candidate: m.Candidate,
			FixAvailable: m.FixAvailable, Severity: m.Severity, FirstSeen: ts(m.FirstSeen), Summary: m.Summary,
			Aliases: strs(m.Aliases), CVSSScore: m.CVSSScore})
	}
	return out
}

type vulnJSON struct {
	ID         string             `json:"id"`
	Aliases    []string           `json:"aliases"`
	Summary    string             `json:"summary"`
	Details    string             `json:"details"`
	Severity   string             `json:"severity"`
	CVSSScore  *float64           `json:"cvss_score,omitempty"`
	CVSSVector string             `json:"cvss_vector,omitempty"`
	Published  *time.Time         `json:"published,omitempty"`
	Modified   *time.Time         `json:"modified,omitempty"`
	Refs       []store.VulnRef    `json:"refs"`
	Affected   []vulnAffectedJSON `json:"affected"`
	Hosts      int                `json:"hosts"`
	Fixable    int                `json:"fixable_hosts"`
	Matches    []hostVulnJSON     `json:"matches"`
}

type vulnAffectedJSON struct {
	Ecosystem string            `json:"ecosystem"`
	Package   string            `json:"package"`
	Severity  string            `json:"severity,omitempty"`
	Ranges    json.RawMessage   `json:"ranges"`
	Binaries  map[string]string `json:"binaries,omitempty"`
}

type vulnSourceJSON struct {
	Ecosystem string     `json:"ecosystem"`
	Dump      string     `json:"dump"`
	Cursor    *time.Time `json:"cursor,omitempty"`
	FullAt    *time.Time `json:"full_at,omitempty"`
	SyncedAt  *time.Time `json:"synced_at,omitempty"`
	TriedAt   *time.Time `json:"tried_at,omitempty"`
	Error     string     `json:"error,omitempty"`
	Vulns     int        `json:"vulns"`
}

type alertJSON struct {
	ID          string         `json:"id"`
	RuleID      string         `json:"rule_id"`
	RuleName    string         `json:"rule_name"`
	RuleKind    string         `json:"rule_kind"`
	CIID        string         `json:"ci_id,omitempty"`
	Subject     string         `json:"subject"`
	Key         string         `json:"key"`
	Link        string         `json:"link"`
	GroupIDs    []string       `json:"group_ids"`
	Severity    string         `json:"severity"`
	State       string         `json:"state"`
	Summary     string         `json:"summary"`
	Details     map[string]any `json:"details"`
	FirstAt     *time.Time     `json:"first_at,omitempty"`
	FiredAt     *time.Time     `json:"fired_at,omitempty"`
	LastAt      *time.Time     `json:"last_at,omitempty"`
	ResolvedAt  *time.Time     `json:"resolved_at,omitempty"`
	NotifiedAt  *time.Time     `json:"notified_at,omitempty"`
	SilenceID   string         `json:"silence_id,omitempty"`
	SilenceEnds *time.Time     `json:"silence_ends,omitempty"`
	AckedBy     string         `json:"acked_by,omitempty"`
	AckedByName string         `json:"acked_by_name,omitempty"`
	AckedAt     *time.Time     `json:"acked_at,omitempty"`
	AckComment  string         `json:"ack_comment,omitempty"`
}

func alertToJSON(a store.Alert) alertJSON {
	details := a.Details
	if details == nil {
		details = map[string]any{}
	}
	return alertJSON{ID: a.ID, RuleID: a.RuleID, RuleName: a.RuleName, RuleKind: a.RuleKind, CIID: a.CIID, Subject: a.Subject,
		Key: a.Key, Link: a.Link, GroupIDs: strs(a.GroupIDs), Severity: a.Severity, State: a.State, Summary: a.Summary,
		Details: details, FirstAt: ts(a.FirstAt), FiredAt: ts(a.FiredAt), LastAt: ts(a.LastAt), ResolvedAt: ts(a.ResolvedAt),
		NotifiedAt: ts(a.NotifiedAt), SilenceID: a.SilenceID, SilenceEnds: ts(a.SilenceEnds), AckedBy: a.AckedBy,
		AckedByName: a.AckedByName, AckedAt: ts(a.AckedAt), AckComment: a.AckComment}
}

type alertRuleJSON struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Kind           string            `json:"kind"`
	Params         store.AlertParams `json:"params"`
	Scope          []ref             `json:"scope"`
	Severity       string            `json:"severity"`
	Channels       []ref             `json:"channels"`
	ForS           int               `json:"for_s"`
	RepeatS        int               `json:"repeat_s"`
	NotifyResolved bool              `json:"notify_resolved"`
	Enabled        bool              `json:"enabled"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	Firing         int               `json:"firing"`
}

func alertRuleToJSON(r store.AlertRule) alertRuleJSON {
	return alertRuleJSON{ID: r.ID, Name: r.Name, Kind: r.Kind, Params: r.Params, Scope: refs(r.ScopeGroups, r.ScopeNames),
		Severity: r.Severity, Channels: refs(r.Channels, r.ChannelNames), ForS: int(r.For / time.Second),
		RepeatS: int(r.Repeat / time.Second), NotifyResolved: r.NotifyResolved, Enabled: r.Enabled, CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt, Firing: r.Firing}
}

type silenceJSON struct {
	ID          string    `json:"id"`
	RuleID      string    `json:"rule_id,omitempty"`
	RuleName    string    `json:"rule_name,omitempty"`
	CIID        string    `json:"ci_id,omitempty"`
	CIName      string    `json:"ci_name,omitempty"`
	HostGroupID string    `json:"host_group_id,omitempty"`
	GroupName   string    `json:"group_name,omitempty"`
	Key         string    `json:"key,omitempty"`
	Starts      time.Time `json:"starts"`
	Ends        time.Time `json:"ends"`
	Comment     string    `json:"comment"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatorName string    `json:"creator_name"`
	CreatedAt   time.Time `json:"created_at"`
	Muting      int       `json:"muting"`
}

func silenceToJSON(sl store.Silence) silenceJSON {
	return silenceJSON{ID: sl.ID, RuleID: sl.RuleID, RuleName: sl.RuleName, CIID: sl.CIID, CIName: sl.CIName,
		HostGroupID: sl.HostGroupID, GroupName: sl.GroupName, Key: sl.Key, Starts: sl.Starts, Ends: sl.Ends,
		Comment: sl.Comment, CreatedBy: sl.CreatedBy, CreatorName: sl.CreatorName, CreatedAt: sl.CreatedAt, Muting: sl.Muting}
}

type auditJSON struct {
	ID         int64           `json:"id"`
	At         time.Time       `json:"at"`
	Actor      string          `json:"actor"`
	ActorName  string          `json:"actor_name,omitempty"`
	ActorIP    string          `json:"actor_ip,omitempty"`
	Action     string          `json:"action"`
	ObjectType string          `json:"object_type,omitempty"`
	ObjectID   string          `json:"object_id,omitempty"`
	Details    json.RawMessage `json:"details"`
	PrevHash   string          `json:"prev_hash"`
	Hash       string          `json:"hash"`
}

func auditToJSON(e store.AuditEntry) auditJSON {
	details := json.RawMessage(e.Details)
	if !json.Valid(details) {
		details, _ = json.Marshal(e.Details)
	}
	return auditJSON{ID: e.ID, At: e.At, Actor: e.Actor, ActorName: e.ActorName, ActorIP: e.ActorIP, Action: e.Action,
		ObjectType: e.ObjectType, ObjectID: e.ObjectID, Details: details, PrevHash: hex.EncodeToString(e.PrevHash),
		Hash: hex.EncodeToString(e.Hash)}
}

// Me, actions, dashboard ----------------------------------------------------------

type meJSON struct {
	User   userJSON     `json:"user"`
	Token  tokenJSON    `json:"token"`
	Global []rbac.Role  `json:"global_roles"`
	Scoped []scopedJSON `json:"scoped_roles"`
	Groups []string     `json:"idp_groups"`
}

type userJSON struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Subject string `json:"subject"`
}

type tokenJSON struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Roles     []rbac.Role `json:"roles"`
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt *time.Time  `json:"expires_at,omitempty"`
}

type scopedJSON struct {
	GroupID   string      `json:"group_id"`
	GroupName string      `json:"group_name"`
	Roles     []rbac.Role `json:"roles"`
}

type actionJSON struct {
	Name     string   `json:"name"`
	Label    string   `json:"label"`
	Category string   `json:"category"`
	Risk     string   `json:"risk"`
	TimeoutS int      `json:"timeout_s"`
	Needs    []string `json:"needs"`
	Sections []string `json:"sections"`
}

type dashboardJSON struct {
	Fleet            fleetJSON        `json:"fleet"`
	HostsWithUpdates int              `json:"hosts_with_updates"`
	Updates          int              `json:"updates"`
	SecurityUpdates  int              `json:"security_updates"`
	DisksFailing     int              `json:"disks_failing"`
	DisksDegrading   int              `json:"disks_degrading"`
	Attention        []ref            `json:"attention"`
	AgentsOutdated   int              `json:"agents_outdated"`
	Containers       int              `json:"containers"`
	ContainerUpdates int              `json:"container_updates"`
	Guests           int              `json:"guests"`
	GuestsRunning    int              `json:"guests_running"`
	Clusters         int              `json:"clusters"`
	NodesNotReady    int              `json:"nodes_not_ready"`
	RebootRequired   int              `json:"reboot_required"`
	FailedServices   int              `json:"failed_services"`
	ExpiringCerts    []certJSON       `json:"expiring_certs"`
	Changes          changeCountsJSON `json:"changes"`
	UpcomingWindows  []upcomingJSON   `json:"upcoming_windows"`
	Alerts           alertCountsJSON  `json:"alerts"`
	Vulns            vulnTotalsJSON   `json:"vulnerabilities"`
}

type fleetJSON struct {
	Total     int `json:"total"`
	Online    int `json:"online"`
	Offline   int `json:"offline"`
	Duplicate int `json:"duplicate"`
}

type changeCountsJSON struct {
	AwaitingApproval int `json:"awaiting_approval"`
	Scheduled        int `json:"scheduled"`
	InProgress       int `json:"in_progress"`
	AwaitingReview   int `json:"awaiting_review"`
}

type upcomingJSON struct {
	Name  string    `json:"name"`
	Kind  string    `json:"kind"`
	Scope []string  `json:"scope"`
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Open  bool      `json:"open"`
}

type alertCountsJSON struct {
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
	Pending  int `json:"pending"`
}

type vulnTotalsJSON struct {
	Total         int `json:"total"`
	Fixable       int `json:"fixable"`
	FixableSevere int `json:"fixable_severe"`
	HostsFixable  int `json:"hosts_fixable"`
	Uncovered     int `json:"hosts_uncovered"`
}

func dashboardToJSON(v dashboardView) dashboardJSON {
	d := dashboardJSON{
		Fleet:            fleetJSON{Total: v.Fleet.Total, Online: v.Fleet.Online, Offline: v.Fleet.Offline, Duplicate: v.Fleet.Duplicate},
		HostsWithUpdates: v.HostsWithUpdates, Updates: v.Updates, SecurityUpdates: v.SecurityUpdates,
		DisksFailing: v.DisksFailing, DisksDegrading: v.DisksDegrading, Attention: []ref{}, AgentsOutdated: v.AgentsOutdated,
		Containers: v.Containers, ContainerUpdates: v.ContainerUpdates, Guests: v.Guests, GuestsRunning: v.GuestsRunning,
		Clusters: v.Clusters, NodesNotReady: v.NodesNotReady, RebootRequired: v.RebootRequired,
		FailedServices: v.FailedServices, ExpiringCerts: certsToJSON(v.Expiring),
		Changes: changeCountsJSON{AwaitingApproval: v.Changes.AwaitingApproval, Scheduled: v.Changes.Scheduled,
			InProgress: v.Changes.InProgress, AwaitingReview: v.Changes.AwaitingReview},
		UpcomingWindows: []upcomingJSON{},
		Alerts:          alertCountsJSON{Critical: v.Alerts.Critical, Warning: v.Alerts.Warning, Info: v.Alerts.Info, Pending: v.Alerts.Pending},
		Vulns: vulnTotalsJSON{Total: v.Vulns, Fixable: v.Fixable, FixableSevere: v.FixableSevere, HostsFixable: v.HostsFixable,
			Uncovered: v.VulnsUncovered},
	}
	for _, h := range v.Attention {
		d.Attention = append(d.Attention, ref{ID: h.ID, Name: h.DisplayName()})
	}
	for _, w := range v.Upcoming {
		d.UpcomingWindows = append(d.UpcomingWindows, upcomingJSON{Name: w.Name, Kind: w.Kind, Scope: strs(w.Scope),
			Start: w.Start, End: w.End, Open: w.Open})
	}
	return d
}

// stackRevisionJSON is the files a compose.deploy or compose.edit writes.
// The .env's values never appear: GET /stacks/{id}/files?env=1 reads the
// stack's current one.
type stackRevisionJSON struct {
	ID            string   `json:"id"`
	HostID        string   `json:"host_id"`
	Engine        string   `json:"engine"`
	Project       string   `json:"project"`
	Action        string   `json:"action"`
	Compose       *string  `json:"compose,omitempty"` // left out when an edit keeps the file
	ComposeSHA256 string   `json:"compose_sha256,omitempty"`
	BaseSHA256    string   `json:"base_sha256,omitempty"`
	Env           bool     `json:"env"` // writes a .env
	EnvKeys       []string `json:"env_keys"`
	EnvHash       string   `json:"env_hash,omitempty"`
}

// manifestRevisionJSON is a revision of a Kubernetes manifest bundle.
type manifestRevisionJSON struct {
	ID             string   `json:"id"`
	ClusterCI      string   `json:"cluster_ci"`
	Bundle         string   `json:"bundle"`
	Namespace      string   `json:"namespace"`
	Action         string   `json:"action"`
	Manifest       string   `json:"manifest"`
	ManifestSHA256 string   `json:"manifest_sha256"`
	Objects        []string `json:"objects"`
	BaseRevision   string   `json:"base_revision,omitempty"`
	Applied        bool     `json:"applied"`
}

func manifestRevisionToJSON(m store.Manifest) manifestRevisionJSON {
	if m.Objects == nil {
		m.Objects = []string{}
	}
	return manifestRevisionJSON{ID: m.ID, ClusterCI: m.ClusterCI, Bundle: m.Bundle, Namespace: m.Namespace, Action: m.Action,
		Manifest: m.Manifest, ManifestSHA256: m.ManifestSHA256, Objects: m.Objects, BaseRevision: m.BaseRevision,
		Applied: m.Applied()}
}

func stackRevisionToJSON(rev store.ComposeRevision) stackRevisionJSON {
	out := stackRevisionJSON{ID: rev.ID, HostID: rev.HostID, Engine: rev.Engine, Project: rev.Project, Action: rev.Action,
		ComposeSHA256: rev.ComposeSHA256, BaseSHA256: rev.BaseSHA256, Env: rev.HasEnv, EnvKeys: strs(rev.EnvKeys), EnvHash: rev.EnvHash}
	if rev.HasCompose {
		out.Compose = &rev.Compose
	}
	return out
}
