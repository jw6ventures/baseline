package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/stackenv"
	"github.com/jw6ventures/baseline/internal/store"
)

// Editing the files of a compose.deploy or compose.edit change before it
// starts (docs/change-management.md §2.1): its Compose file and .env, in
// place, rather than cancelling it and making a new one. The deploy's
// host, engine, project and root stay as they are.

// changeFilesView is the stack files part of a change's edit form.
type changeFilesView struct {
	Revision store.ComposeRevision
	Deploy   bool
	// CanEdit: the editor is an operator of the host, who may read and
	// write its stacks' files.
	CanEdit bool
}

// changeRevision is the revision of the change's stack files, or nil when
// it writes none.
func (s *Server) changeRevision(ctx context.Context, c store.Change) (*store.ComposeRevision, error) {
	revs, err := s.store.ChangeRevisions(ctx, c.ID)
	if err != nil || len(revs) != 1 {
		return nil, err
	}
	return &revs[0], nil
}

// endLine ends non-empty text with a newline, as the files are written.
func endLine(s string) string {
	if s != "" && !strings.HasSuffix(s, "\n") {
		return s + "\n"
	}
	return s
}

// lineDiff counts the lines added and removed from a to b, as a multiset:
// enough for a history line, not a diff.
func lineDiff(a, b string) (added, removed int) {
	n := map[string]int{}
	for _, l := range strings.Split(strings.TrimSuffix(a, "\n"), "\n") {
		n[l]++
	}
	for _, l := range strings.Split(strings.TrimSuffix(b, "\n"), "\n") {
		if n[l] > 0 {
			n[l]--
		} else {
			added++
		}
	}
	for _, k := range n {
		removed += k
	}
	return added, removed
}

// filesEdit builds the edit of the files rev writes: compose and env are
// the new Compose file and .env, nil to keep one. A deploy's .env left
// empty writes none. An edit change (compose.edit) changes the files it
// writes, not which: to also write the other one, it is cancelled and made
// again. It returns nil when the files stay as they are.
func (s *Server) filesEdit(r *http.Request, c store.Change, rev store.ComposeRevision, compose, env *string) (*store.FilesEdit, error) {
	deploy := rev.Action == action.ComposeDeploy
	var oldEnv string
	if rev.HasEnv {
		text, err := s.openEnv(r, rev, "edit compare")
		if err != nil {
			return nil, err
		}
		oldEnv = string(text)
	}
	newCompose, newEnv, hasEnv := rev.Compose, oldEnv, rev.HasEnv
	if compose != nil {
		if !rev.HasCompose {
			return nil, store.EditError("this change leaves the stack's Compose file alone; to change it too, cancel the change and make a new one")
		}
		newCompose = endLine(*compose)
	}
	if env != nil {
		if !deploy && !rev.HasEnv {
			return nil, store.EditError("this change leaves the stack's .env alone; to change it too, cancel the change and make a new one")
		}
		newEnv = endLine(*env)
		if deploy {
			hasEnv = strings.TrimSpace(newEnv) != ""
			if !hasEnv {
				newEnv = ""
			}
		}
	}
	composeChanged := rev.HasCompose && newCompose != rev.Compose
	envChanged := hasEnv != rev.HasEnv || newEnv != oldEnv
	if !composeChanged && !envChanged {
		return nil, nil
	}
	if composeChanged && !deploy {
		if strings.Contains(newCompose, composeMask) {
			return nil, store.EditError("the Compose file still holds masked values (" + composeMask + "); put the real values back, or move them into the .env as ${VARIABLES}")
		}
		if stackenv.SHA256([]byte(newCompose)) == rev.BaseSHA256 {
			return nil, store.EditError("that Compose file is the one the host has already; cancel the change if it should change nothing")
		}
	}

	var step *store.PlanStep
	for i, p := range c.Plan {
		var x action.StackFileParams
		if (p.Action == action.ComposeDeploy || p.Action == action.ComposeEdit) && json.Unmarshal(p.Params, &x) == nil && x.Revision == rev.ID {
			step = &c.Plan[i]
		}
	}
	if step == nil {
		return nil, errors.New("the change has no step for its stack files")
	}
	var params action.StackFileParams
	if err := json.Unmarshal(step.Params, &params); err != nil {
		return nil, err
	}
	next := rev
	if err := s.sealFiles(&next, &params, newCompose, newEnv, rev.HasCompose, hasEnv); err != nil {
		return nil, store.EditError(sentence(err))
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	norm, err := action.Validate(step.Action, raw)
	if err != nil {
		return nil, store.EditError(sentence(err))
	}
	f := &store.FilesEdit{Revision: next, WasComposeSHA256: rev.ComposeSHA256, WasEnvHash: rev.EnvHash,
		Params: norm, Summary: action.Describe(step.Action, norm)}
	if composeChanged {
		added, removed := lineDiff(rev.Compose, next.Compose)
		f.Compose = map[string]any{"from": rev.ComposeSHA256, "to": next.ComposeSHA256, "added": added, "removed": removed}
	}
	if envChanged {
		added, removed, changed, err := stackenv.Diff([]byte(oldEnv), []byte(newEnv))
		if err != nil {
			return nil, store.EditError("the .env: " + err.Error())
		}
		f.Env = map[string]any{"added": nonNilStrings(added), "removed": nonNilStrings(removed),
			"changed": nonNilStrings(changed), "had": rev.HasEnv, "has": hasEnv}
	}
	return f, nil
}

// filesHistory is the history lines of a files edit's audit details.
func filesHistory(changes map[string]any) []string {
	var out []string
	if c, ok := changes["compose"].(map[string]any); ok {
		from, _ := c["from"].(string)
		to, _ := c["to"].(string)
		added, _ := c["added"].(float64)
		removed, _ := c["removed"].(float64)
		out = append(out, "Compose file: sha256 "+shortHash(from)+" → "+shortHash(to)+
			" ("+plural(int(added), "line", "lines")+" added, "+plural(int(removed), "line", "lines")+" removed)")
	}
	if e, ok := changes["env"].(map[string]any); ok {
		had, _ := e["had"].(bool)
		has, _ := e["has"].(bool)
		names := func(k string) string {
			v, _ := e[k].([]any)
			var s []string
			for _, x := range v {
				if n, ok := x.(string); ok {
					s = append(s, n)
				}
			}
			return strings.Join(s, ", ")
		}
		var parts []string
		switch {
		case !had && has:
			parts = append(parts, "written now")
		case had && !has:
			parts = append(parts, "not written any more")
		}
		for _, x := range []struct{ key, label string }{{"added", "added"}, {"changed", "new value for"}, {"removed", "removed"}} {
			if n := names(x.key); n != "" {
				parts = append(parts, x.label+" "+n)
			}
		}
		if len(parts) == 0 {
			parts = append(parts, "comments or layout changed")
		}
		out = append(out, ".env: "+strings.Join(parts, "; "))
	}
	return out
}

func shortHash(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "none"
	}
	return s
}
