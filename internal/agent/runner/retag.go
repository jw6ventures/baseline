package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/agent/collect"
	"github.com/jw6ventures/baseline/internal/composefile"
)

// retag writes compose.update's new tag (p.Tag) into the image references
// of the services it names, in the Compose file that sets each one's image,
// keeping the file before as <file>.baseline-prev, and checks the files
// with `config --quiet`. It updates res.Services to the new references. It
// returns how to put the files back, or why it didn't change anything.
func (r *Runner) retag(ctx context.Context, st collect.Stack, p action.ComposeParams, res *action.ComposeResult,
	out *output) (func() error, string) {
	if why := fileRefusal(st); why != "" {
		return nil, why
	}
	fsys := r.files(ctx, st)
	type file struct {
		old, data []byte
		mode      os.FileMode
	}
	files := map[string]*file{}
	var order []string
	for i := range res.Services {
		s := &res.Services[i]
		found := ""
		for _, cf := range st.ConfigFiles {
			f, ok := files[cf.Path]
			if !ok {
				data, mode, err := fsys.read(cf.Path)
				if err != nil {
					return nil, err.Error()
				}
				f = &file{old: data, data: data, mode: mode}
				files[cf.Path] = f
				order = append(order, cf.Path)
			}
			data, old, err := composefile.SetTag(f.data, s.Service, p.Tag)
			if errors.Is(err, composefile.ErrNoImage) {
				continue
			}
			if err != nil {
				return nil, fmt.Sprintf("%s: %v", cf.Path, err)
			}
			if found != "" {
				return nil, fmt.Sprintf("both %s and %s set the image of %s; Baseline changes a tag written in one place", found, cf.Path, s.Service)
			}
			found, f.data = cf.Path, data
			ref := composefile.WithTag(old, p.Tag)
			if s.Image == ref {
				continue
			}
			out.info("%s: %s → %s in %s\n", s.Service, old, ref, cf.Path)
			s.Retagged, s.Image = s.Image, ref
			if s.Retagged == "" {
				s.Retagged = old
			}
		}
		if found == "" {
			return nil, fmt.Sprintf("no Compose file of %s sets an image for %s", st.Project, s.Service)
		}
	}
	restore := func() error {
		var errs []string
		for _, path := range order {
			if f := files[path]; string(f.data) != string(f.old) {
				if err := fsys.write(path, f.old, f.mode); err != nil {
					errs = append(errs, err.Error())
				}
			}
		}
		if len(errs) > 0 {
			return errors.New(strings.Join(errs, "; "))
		}
		return nil
	}
	wrote := false
	for _, path := range order {
		f := files[path]
		if string(f.data) == string(f.old) {
			continue
		}
		fsys.write(path+prevSuffix, f.old, f.mode)
		out.info("Writing %s\n", path)
		if err := fsys.write(path, f.data, f.mode); err != nil {
			restore()
			return nil, err.Error()
		}
		wrote = true
	}
	if !wrote {
		out.info("The Compose files already say tag %s.\n", p.Tag)
		return nil, ""
	}
	if why := r.composeCheck(ctx, st, out); why != "" {
		if err := restore(); err != nil {
			return nil, fmt.Sprintf("%s; putting the previous files back failed too: %v", why, err)
		}
		return nil, why
	}
	return restore, ""
}
