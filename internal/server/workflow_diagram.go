package server

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"

	"github.com/jw6ventures/baseline/internal/store"
)

// The workflow diagram (docs/data-model.md §14): a version's statuses as
// boxes and its transitions as arrows, drawn by web/static/wfmap.js on the
// workflow page. On a draft, statuses can be moved, transitions drawn
// between them and statuses added; changes other than moves go through the
// page's forms.

// wfDiagram is what the page script draws, embedded in the page as JSON.
type wfDiagram struct {
	Draft       bool          `json:"draft"`
	Categories  []mapOption   `json:"categories"`
	Statuses    []wfDiaStatus `json:"statuses"`
	Transitions []wfDiaTrans  `json:"transitions"`
}

type wfDiaStatus struct {
	ID       string   `json:"id"`
	Key      string   `json:"key"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Initial  bool     `json:"initial"`
	X        *float64 `json:"x"`
	Y        *float64 `json:"y"`
}

type wfDiaTrans struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	From     string `json:"from"` // "": from any status
	To       string `json:"to"`
	Who      string `json:"who"`
	Requires string `json:"requires"`
	Then     string `json:"then"`
	Asks     string `json:"asks"`
}

func diagramOf(v store.WorkflowVersion) wfDiagram {
	d := wfDiagram{Draft: v.Draft(), Statuses: []wfDiaStatus{}, Transitions: []wfDiaTrans{}}
	for _, c := range store.StatusCategories {
		d.Categories = append(d.Categories, mapOption{Key: c, Label: itemStatusLabel(c)})
	}
	for _, st := range v.Statuses {
		d.Statuses = append(d.Statuses, wfDiaStatus{ID: st.ID, Key: st.Key, Name: st.Name, Category: st.Category,
			Initial: st.Initial, X: st.X, Y: st.Y})
	}
	for _, t := range v.Transitions {
		req := ruleTexts(t.Validators)
		if t.ToCategory == store.StatusDone {
			if req != "" {
				req += ", "
			}
			req += "a resolution"
		}
		d.Transitions = append(d.Transitions, wfDiaTrans{ID: t.ID, Name: t.Name, From: t.FromID, To: t.ToID,
			Who: ruleTexts(t.Conditions), Requires: req, Then: ruleTexts(t.PostFunctions), Asks: ruleTexts(t.Screen)})
	}
	return d
}

// statusLayout saves where the draft's statuses sit on the diagram. The
// body is {"<status id>": [x, y], ...}. It answers 204, or 409 when there is
// no draft any more.
func (s *Server) statusLayout(w http.ResponseWriter, r *http.Request) {
	f, ok := s.loadWorkflow(w, r)
	if !ok {
		return
	}
	var in map[string][]float64
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		http.Error(w, "bad positions", http.StatusBadRequest)
		return
	}
	at := make(map[string]store.StatusPoint, len(in))
	for id, p := range in {
		if len(p) != 2 || math.IsNaN(p[0]+p[1]) || math.IsInf(p[0]+p[1], 0) {
			http.Error(w, "bad positions", http.StatusBadRequest)
			return
		}
		at[id] = store.StatusPoint{X: p[0], Y: p[1]}
	}
	if f.DraftID == "" {
		http.Error(w, "no draft", http.StatusConflict)
		return
	}
	err := s.store.PlaceStatuses(r.Context(), f.DraftID, at)
	switch {
	case errors.Is(err, store.ErrNotDraft), errors.Is(err, store.ErrNotFound):
		http.Error(w, "no draft", http.StatusConflict)
	case err != nil:
		s.serverError(w, r, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
