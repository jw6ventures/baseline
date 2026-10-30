package vuln

import (
	"math"
	"strings"
)

// CVSS3 computes the base score of a CVSS v3.0 or v3.1 vector, as the
// specification's equations do (first.org/cvss/v3.1/specification-document
// §7.1). It returns false for a vector it can't read.
func CVSS3(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || !strings.HasPrefix(parts[0], "CVSS:3.") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, false
		}
		m[k] = v
	}
	weight := func(metric string, w map[string]float64) (float64, bool) {
		v, ok := w[m[metric]]
		return v, ok
	}
	changed := m["S"] == "C"
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	av, ok1 := weight("AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac, ok2 := weight("AC", map[string]float64{"L": 0.77, "H": 0.44})
	prv, ok3 := weight("PR", pr)
	ui, ok4 := weight("UI", map[string]float64{"N": 0.85, "R": 0.62})
	c, ok5 := weight("C", cia)
	i, ok6 := weight("I", cia)
	a, ok7 := weight("A", cia)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) || (m["S"] != "U" && m["S"] != "C") {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * prv * ui
	if changed {
		return roundUp(min(1.08*(impact+exploitability), 10)), true
	}
	return roundUp(min(impact+exploitability, 10)), true
}

// roundUp is the specification's Roundup: the smallest number with one
// decimal place that is not less than x, robust to floating-point error.
func roundUp(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}
