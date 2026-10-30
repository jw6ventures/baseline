package action

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Interpreters are the ones a library script may declare
// (docs/change-management.md §6).
var Interpreters = []string{"/bin/sh", "/bin/bash", "/usr/bin/python3"}

// ScriptParam declares one parameter of a script version.
type ScriptParam struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // string | int | bool
	Required bool   `json:"required,omitempty"`
	// Pattern is a regular expression the whole value must match.
	Pattern string `json:"pattern,omitempty"`
	Help    string `json:"help,omitempty"`
}

var (
	reParamName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	paramTypes  = []string{"string", "int", "bool"}
)

const maxArgLen = 4096

// ParseScriptParams reads the parameter list an admin writes, one per line:
//
//	name type [required] [/pattern/] [# help]
//
// e.g. "days int required # keep this many days of logs".
func ParseScriptParams(text string) ([]ScriptParam, error) {
	var out []ScriptParam
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var p ScriptParam
		// The pattern comes first: it may contain "#". It ends at the last
		// "/" followed by nothing, "required" or the help (which may
		// contain "/").
		hash := strings.Index(line, "#")
		if i := strings.Index(line, "/"); i >= 0 && (hash < 0 || i < hash) {
			j := -1
			for k := len(line) - 1; k > i; k-- {
				rest := strings.TrimSpace(line[k+1:])
				if r, ok := strings.CutPrefix(rest, "required"); ok && (r == "" || r[0] == ' ' || r[0] == '#') {
					rest = strings.TrimSpace(r)
				}
				if line[k] == '/' && (rest == "" || rest[0] == '#') {
					j = k
					break
				}
			}
			if j < 0 {
				return nil, fmt.Errorf("line %d: a pattern is written /like this/", n+1)
			}
			p.Pattern, line = line[i+1:j], strings.TrimSpace(line[:i]+" "+line[j+1:])
		}
		if i := strings.Index(line, "#"); i >= 0 {
			p.Help, line = strings.TrimSpace(line[i+1:]), strings.TrimSpace(line[:i])
		}
		f := strings.Fields(line)
		if len(f) < 2 || len(f) > 3 || (len(f) == 3 && f[2] != "required") {
			return nil, fmt.Errorf("line %d: expected \"name type [required] [/pattern/] [# help]\"", n+1)
		}
		p.Name, p.Type, p.Required = f[0], f[1], len(f) == 3
		out = append(out, p)
	}
	return out, ValidateScriptParams(out)
}

// FormatScriptParams is the inverse of ParseScriptParams.
func FormatScriptParams(ps []ScriptParam) string {
	var b strings.Builder
	for _, p := range ps {
		b.WriteString(p.Name + " " + p.Type)
		if p.Required {
			b.WriteString(" required")
		}
		if p.Pattern != "" {
			b.WriteString(" /" + p.Pattern + "/")
		}
		if p.Help != "" {
			b.WriteString(" # " + p.Help)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ValidateScriptParams checks a parameter list.
func ValidateScriptParams(ps []ScriptParam) error {
	seen := map[string]bool{}
	for _, p := range ps {
		if !reParamName.MatchString(p.Name) {
			return fmt.Errorf("parameter %q: names are lowercase letters, digits and _", p.Name)
		}
		if seen[p.Name] {
			return fmt.Errorf("parameter %q is declared twice", p.Name)
		}
		seen[p.Name] = true
		if !slices.Contains(paramTypes, p.Type) {
			return fmt.Errorf("parameter %q: type must be string, int or bool", p.Name)
		}
		if p.Pattern != "" {
			// Compiled as ScriptArgs uses it: alone, "\Qa" would pass but
			// quote the anchors around it.
			if _, err := anchored(p.Pattern); err != nil {
				return fmt.Errorf("parameter %q: bad pattern: %v", p.Name, err)
			}
		}
	}
	if len(ps) > 32 {
		return errors.New("at most 32 parameters")
	}
	return nil
}

// ScriptArgs checks values against a script's parameters. It returns the
// positional arguments in declared order ("" for an optional one left out)
// and the same values as environment variables, BASELINE_PARAM_<NAME> and
// JCMDB_PARAM_<NAME> (its name before the rename to Baseline).
func ScriptArgs(ps []ScriptParam, values map[string]string) ([]string, map[string]string, error) {
	for k := range values {
		if !slices.ContainsFunc(ps, func(p ScriptParam) bool { return p.Name == k }) {
			return nil, nil, fmt.Errorf("the script has no parameter %q", k)
		}
	}
	args := make([]string, 0, len(ps))
	env := map[string]string{}
	for _, p := range ps {
		v := values[p.Name]
		switch {
		case v == "" && p.Required:
			return nil, nil, fmt.Errorf("%s is required", p.Name)
		case len(v) > maxArgLen:
			return nil, nil, fmt.Errorf("%s is too long", p.Name)
		case strings.ContainsRune(v, 0):
			return nil, nil, fmt.Errorf("%s contains a NUL byte", p.Name)
		case v == "":
		case p.Type == "int":
			if _, err := strconv.ParseInt(v, 10, 64); err != nil {
				return nil, nil, fmt.Errorf("%s must be a whole number", p.Name)
			}
		case p.Type == "bool":
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, nil, fmt.Errorf("%s must be true or false", p.Name)
			}
			v = strconv.FormatBool(b)
		}
		if v != "" && p.Pattern != "" {
			re, err := anchored(p.Pattern)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: bad pattern: %v", p.Name, err)
			}
			if !re.MatchString(v) {
				return nil, nil, fmt.Errorf("%s doesn't match /%s/", p.Name, p.Pattern)
			}
		}
		args = append(args, v)
		env["BASELINE_PARAM_"+strings.ToUpper(p.Name)] = v
		env["JCMDB_PARAM_"+strings.ToUpper(p.Name)] = v // for scripts written before the rename
	}
	return args, env, nil
}

// anchored compiles a parameter pattern to match whole values.
func anchored(pattern string) (*regexp.Regexp, error) {
	if strings.Contains(pattern, `\Q`) {
		return nil, errors.New(`\Q isn't supported`)
	}
	return regexp.Compile(`^(?:` + pattern + `)$`)
}
