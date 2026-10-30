package change

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/store"
)

const (
	// retryFailed is how long auto-update leaves a stack alone after an
	// update of it failed or was rolled back.
	retryFailed = 24 * time.Hour
	// settle is how long after an update a stack's drift is trusted again:
	// the new containers and their image checks take a moment to arrive.
	settle = 30 * time.Minute
)

// ModelParams checks the parameters of a change model for action. A
// compose.* model leaves the stack out (it's chosen per change), so it is
// checked with a stand-in stack and stored without one.
func ModelParams(act string, raw []byte) ([]byte, error) {
	switch act {
	case action.ComposePull, action.ComposeUpdate:
		var p action.ComposeParams
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &p); err != nil {
				return nil, fmt.Errorf("parameters: %w", err)
			}
		}
		if p.Engine != "" || p.Project != "" || len(p.Services) > 0 {
			return nil, errors.New("a Compose model applies to any stack; leave the stack out")
		}
		p.Engine, p.Project = "docker", "stack"
		b, _ := json.Marshal(p)
		norm, err := action.Validate(act, b)
		if err != nil {
			return nil, err
		}
		json.Unmarshal(norm, &p)
		p.Engine, p.Project = "", ""
		return json.Marshal(p)
	}
	return action.Validate(act, raw)
}

// StackParams are the parameters of a compose.* change on a stack, from a
// model's (or none).
func StackParams(act string, model []byte, st store.Stack, services []string) ([]byte, error) {
	var p action.ComposeParams
	if len(model) > 0 {
		if err := json.Unmarshal(model, &p); err != nil {
			return nil, err
		}
	}
	p.Engine, p.Project, p.Services = st.Engine, st.Project, services
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return action.Validate(act, b)
}

// AutoUpdate updates the stacks set to update themselves whose images
// drifted (docs/change-management.md §5): a Standard change under the
// stack's model, inside the stack's window, or else the first window that
// covers its host, or at once when none does. It never applies semver
// advisories. It returns how many changes it created.
func (m *Manager) AutoUpdate(ctx context.Context, now time.Time) (int, error) {
	stacks, err := m.St.AutoUpdateStacks(ctx)
	if err != nil {
		return 0, err
	}
	if len(stacks) == 0 {
		return 0, nil
	}
	cal, err := m.LoadCalendar(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, st := range stacks {
		h, known := cal.Hosts[st.HostID]
		if ok, _ := st.Updatable(); !ok || !known || st.Pinned || st.Drift == 0 || st.ModelState != store.ModelApproved ||
			!h.Connected || h.Revoked {
			continue
		}
		if ok, _ := h.Policy.Allows(action.ComposeUpdate); !ok {
			continue
		}
		if ok, _ := action.MustGet(action.ComposeUpdate).Supported(h.Capabilities); !ok {
			continue
		}
		recent, err := m.St.ListChanges(ctx, store.ChangeFilter{CIID: st.CIID, Limit: 10})
		if err != nil {
			return n, err
		}
		if slices.ContainsFunc(recent, func(c store.Change) bool { return busy(c, now) }) {
			continue
		}
		model, err := m.St.GetChangeModel(ctx, st.ModelID)
		if err != nil {
			return n, err
		}
		params, err := StackParams(action.ComposeUpdate, model.Params, st, nil)
		if err != nil {
			m.logf(jw6_utils.Warn, "Stack %s on %s: %v", st.Project, st.Hostname, err)
			continue
		}
		window := st.WindowID
		if window == "" {
			if w, ok := cal.WindowFor(st.HostID, now); ok {
				window = w.ID
			}
		}
		c, err := m.St.CreateChange(ctx, store.System, store.NewChange{
			Kind: store.KindStandard, ModelID: model.ID,
			Title: fmt.Sprintf("Auto-update stack %s on %s", st.Project, st.Hostname),
			Justification: fmt.Sprintf("The registry has newer images behind the tags of %s, and the stack is set to update itself",
				plural(st.Drift, "container")),
			Risk: action.Risk(model.Risk), Concurrency: 1, StopOnFailure: true, WindowID: window,
			Steps: []store.PlanStep{{Action: action.ComposeUpdate, Params: params,
				Summary: action.Describe(action.ComposeUpdate, params), HostIDs: []string{st.HostID}}},
			CIs: []string{st.CIID},
		})
		if err != nil {
			m.errorf(ctx, "auto-update stack %s on %s: %v", st.Project, st.Hostname, err)
			continue
		}
		m.logf(jw6_utils.Info, "Stack %s on %s: %s auto-updates it", st.Project, st.Hostname, c.Ref())
		n++
	}
	return n, nil
}

// busy reports whether a change on a stack keeps auto-update off it: one
// still open, one that ended moments ago, or a failed one within a day.
func busy(c store.Change, now time.Time) bool {
	switch {
	case c.Open():
		return true
	case !c.ActualEnd.IsZero() && now.Sub(c.ActualEnd) < settle:
		return true
	case c.Outcome != "success" && c.Outcome != "cancelled" && c.Outcome != "" && now.Sub(c.CreatedAt) < retryFailed:
		return true
	}
	return false
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
