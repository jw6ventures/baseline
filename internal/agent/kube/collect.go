package kube

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

// Collector produces the "k8s" section from the API server. It reads
// configuration only: never environment variables, annotations,
// ConfigMaps or Secrets, and no labels except node roles and service
// selectors.
type Collector struct {
	Client      *Client
	ClusterName string
	// DenyNamespaces are reported for the UI (Manager.DenyNamespaces).
	DenyNamespaces []string
}

// Collect produces the "k8s" section. Failing to read the kube-system
// namespace, which identifies the cluster, or the version, which every
// account may read, fails the section; a list that fails (forbidden, or an
// API the cluster doesn't serve) is reported in Errors and the rest is
// still collected.
func (c *Collector) Collect(ctx context.Context) (model.K8s, error) {
	out := model.K8s{
		Nodes:      []model.K8sNodeInfo{},
		Namespaces: []string{},
		Workloads:  []model.K8sWorkload{},
		Services:   []model.K8sService{},
		Ingresses:  []model.K8sIngress{},
	}
	if len(c.DenyNamespaces) > 0 {
		out.DenyNamespaces = slicesSorted(c.DenyNamespaces)
	}
	var ks struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := c.Client.Get(ctx, "/api/v1/namespaces/kube-system", &ks); err != nil {
		return out, err
	}
	if ks.Metadata.UID == "" {
		return out, errors.New("/api/v1/namespaces/kube-system: no uid")
	}
	out.Cluster = model.K8sCluster{UID: ks.Metadata.UID, Name: c.ClusterName}
	var ver struct {
		GitVersion string `json:"gitVersion"`
		Platform   string `json:"platform"`
	}
	if err := c.Client.Get(ctx, "/version", &ver); err != nil {
		return out, err
	}
	out.Cluster.Version, out.Cluster.Platform = ver.GitVersion, ver.Platform

	fail := func(resource string, err error) {
		out.Errors = append(out.Errors, model.K8sError{Resource: resource, Error: errText(err)})
	}

	if nodes, err := List[node](ctx, c.Client, "/api/v1/nodes"); err != nil {
		fail("nodes", err)
	} else {
		for _, n := range nodes {
			out.Nodes = append(out.Nodes, n.info())
		}
	}
	if nss, err := List[objectRef](ctx, c.Client, "/api/v1/namespaces"); err != nil {
		fail("namespaces", err)
	} else {
		for _, ns := range nss {
			out.Namespaces = append(out.Namespaces, ns.Metadata.Name)
		}
	}
	if ds, err := List[deployment](ctx, c.Client, "/apis/apps/v1/deployments"); err != nil {
		fail("deployments", err)
	} else {
		for _, d := range ds {
			out.Workloads = append(out.Workloads, d.workload("Deployment"))
		}
	}
	if ss, err := List[deployment](ctx, c.Client, "/apis/apps/v1/statefulsets"); err != nil {
		fail("statefulsets", err)
	} else {
		for _, s := range ss {
			out.Workloads = append(out.Workloads, s.workload("StatefulSet"))
		}
	}
	if ds, err := List[daemonSet](ctx, c.Client, "/apis/apps/v1/daemonsets"); err != nil {
		fail("daemonsets", err)
	} else {
		for _, d := range ds {
			out.Workloads = append(out.Workloads, d.workload())
		}
	}
	if cjs, err := List[cronJob](ctx, c.Client, "/apis/batch/v1/cronjobs"); err != nil {
		fail("cronjobs", err)
	} else {
		for _, cj := range cjs {
			out.Workloads = append(out.Workloads, cj.workload())
		}
	}
	if pods, err := List[pod](ctx, c.Client, "/api/v1/pods"); err != nil {
		fail("pods", err)
	} else {
		for _, p := range pods {
			// A controller's pods come and go; it is reported instead.
			if len(p.Metadata.OwnerReferences) == 0 {
				out.Workloads = append(out.Workloads, p.workload())
			}
		}
	}
	if svcs, err := List[service](ctx, c.Client, "/api/v1/services"); err != nil {
		fail("services", err)
	} else {
		for _, s := range svcs {
			out.Services = append(out.Services, s.service())
		}
	}
	if ings, err := List[ingress](ctx, c.Client, "/apis/networking.k8s.io/v1/ingresses"); err != nil {
		fail("ingresses", err)
	} else {
		for _, i := range ings {
			out.Ingresses = append(out.Ingresses, i.ingress())
		}
	}
	// A cancelled collection would otherwise look like every list failing.
	if ctx.Err() != nil {
		return out, ctx.Err()
	}

	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].Name < out.Nodes[j].Name })
	sort.Strings(out.Namespaces)
	sort.Slice(out.Workloads, func(i, j int) bool {
		a, b := out.Workloads[i], out.Workloads[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
	sort.Slice(out.Services, func(i, j int) bool {
		a, b := out.Services[i], out.Services[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	sort.Slice(out.Ingresses, func(i, j int) bool {
		a, b := out.Ingresses[i], out.Ingresses[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	sort.Slice(out.Errors, func(i, j int) bool { return out.Errors[i].Resource < out.Errors[j].Resource })
	return out, nil
}

// errText is an error as the UI shows it.
func errText(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Short()
	}
	s := err.Error()
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// The types below decode only what the section reports; the decoder skips
// everything else (environment, annotations, managed fields) without
// keeping it.

type objectRef struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
}

type meta struct {
	Name              string `json:"name"`
	Namespace         string `json:"namespace"`
	CreationTimestamp string `json:"creationTimestamp"`
}

type podSpec struct {
	NodeName       string      `json:"nodeName"`
	Containers     []container `json:"containers"`
	InitContainers []container `json:"initContainers"`
}

type container struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

// containers are the pod's containers, then its init containers.
func (s podSpec) containers() []model.K8sContainer {
	var out []model.K8sContainer
	for _, c := range s.Containers {
		out = append(out, model.K8sContainer{Name: c.Name, Image: c.Image})
	}
	for _, c := range s.InitContainers {
		out = append(out, model.K8sContainer{Name: c.Name, Image: c.Image, Init: true})
	}
	return out
}

type podTemplate struct {
	Spec podSpec `json:"spec"`
}

// images are the sorted, unique images of a pod's containers and init
// containers.
func (s podSpec) images() []string {
	var out []string
	for _, cs := range [][]container{s.Containers, s.InitContainers} {
		for _, c := range cs {
			if c.Image != "" {
				out = append(out, c.Image)
			}
		}
	}
	return sortedUnique(out)
}

type node struct {
	Metadata struct {
		meta
		Labels map[string]string `json:"labels"` // only roles are kept
	} `json:"metadata"`
	Spec struct {
		Unschedulable bool `json:"unschedulable"`
		Taints        []struct {
			Key    string `json:"key"`
			Value  string `json:"value"`
			Effect string `json:"effect"`
		} `json:"taints"`
	} `json:"spec"`
	Status struct {
		Capacity   map[string]string `json:"capacity"`
		Conditions []condition       `json:"conditions"`
		Addresses  []struct {
			Type    string `json:"type"`
			Address string `json:"address"`
		} `json:"addresses"`
		NodeInfo struct {
			MachineID               string `json:"machineID"`
			SystemUUID              string `json:"systemUUID"`
			KernelVersion           string `json:"kernelVersion"`
			OSImage                 string `json:"osImage"`
			ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
			KubeletVersion          string `json:"kubeletVersion"`
			Architecture            string `json:"architecture"`
		} `json:"nodeInfo"`
	} `json:"status"`
}

type condition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

func conditionTrue(cs []condition, typ string) bool {
	for _, c := range cs {
		if c.Type == typ {
			return c.Status == "True"
		}
	}
	return false
}

func (n node) info() model.K8sNodeInfo {
	ni := n.Status.NodeInfo
	out := model.K8sNodeInfo{
		Name:             n.Metadata.Name,
		Ready:            conditionTrue(n.Status.Conditions, "Ready"),
		Unschedulable:    n.Spec.Unschedulable,
		KubeletVersion:   ni.KubeletVersion,
		ContainerRuntime: ni.ContainerRuntimeVersion,
		OSImage:          ni.OSImage,
		KernelVersion:    ni.KernelVersion,
		Arch:             ni.Architecture,
		MachineID:        ni.MachineID,
		SystemUUID:       strings.ToLower(ni.SystemUUID),
		CPU:              n.Status.Capacity["cpu"],
		Created:          timestamp(n.Metadata.CreationTimestamp),
	}
	var roles []string
	for k, v := range n.Metadata.Labels {
		if r, ok := strings.CutPrefix(k, "node-role.kubernetes.io/"); ok && r != "" {
			roles = append(roles, r)
		} else if k == "kubernetes.io/role" && v != "" {
			roles = append(roles, v)
		}
	}
	out.Roles = sortedUnique(roles)
	for _, a := range n.Status.Addresses {
		if a.Type == "InternalIP" {
			out.InternalIPs = append(out.InternalIPs, a.Address)
		}
	}
	out.InternalIPs = sortedUnique(out.InternalIPs)
	if m, ok := ParseQuantity(n.Status.Capacity["memory"]); ok {
		out.MemoryBytes = m
	}
	for _, t := range n.Spec.Taints {
		s := t.Key
		if t.Value != "" {
			s += "=" + t.Value
		}
		out.Taints = append(out.Taints, s+":"+t.Effect)
	}
	out.Taints = sortedUnique(out.Taints)
	return out
}

// deployment also decodes a StatefulSet, which has the same fields.
type deployment struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Replicas *int        `json:"replicas"`
		Template podTemplate `json:"template"`
	} `json:"spec"`
	Status struct {
		ReadyReplicas int `json:"readyReplicas"`
	} `json:"status"`
}

func (d deployment) workload(kind string) model.K8sWorkload {
	replicas := 1 // the API's default
	if d.Spec.Replicas != nil {
		replicas = *d.Spec.Replicas
	}
	return model.K8sWorkload{Kind: kind, Namespace: d.Metadata.Namespace, Name: d.Metadata.Name,
		Replicas: replicas, Ready: d.Status.ReadyReplicas, Images: d.Spec.Template.Spec.images(),
		Containers: d.Spec.Template.Spec.containers(), Created: timestamp(d.Metadata.CreationTimestamp)}
}

type daemonSet struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Template podTemplate `json:"template"`
	} `json:"spec"`
	Status struct {
		DesiredNumberScheduled int `json:"desiredNumberScheduled"`
		NumberReady            int `json:"numberReady"`
	} `json:"status"`
}

func (d daemonSet) workload() model.K8sWorkload {
	return model.K8sWorkload{Kind: "DaemonSet", Namespace: d.Metadata.Namespace, Name: d.Metadata.Name,
		Replicas: d.Status.DesiredNumberScheduled, Ready: d.Status.NumberReady, Images: d.Spec.Template.Spec.images(),
		Containers: d.Spec.Template.Spec.containers(), Created: timestamp(d.Metadata.CreationTimestamp)}
}

type cronJob struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Schedule    string `json:"schedule"`
		Suspend     bool   `json:"suspend"`
		JobTemplate struct {
			Spec struct {
				Template podTemplate `json:"template"`
			} `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
}

func (c cronJob) workload() model.K8sWorkload {
	return model.K8sWorkload{Kind: "CronJob", Namespace: c.Metadata.Namespace, Name: c.Metadata.Name,
		Images: c.Spec.JobTemplate.Spec.Template.Spec.images(), Containers: c.Spec.JobTemplate.Spec.Template.Spec.containers(),
		Schedule: c.Spec.Schedule, Suspend: c.Spec.Suspend, Created: timestamp(c.Metadata.CreationTimestamp)}
}

type pod struct {
	Metadata struct {
		meta
		OwnerReferences []struct {
			Kind string `json:"kind"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec   podSpec `json:"spec"`
	Status struct {
		Conditions []condition `json:"conditions"`
	} `json:"status"`
}

func (p pod) workload() model.K8sWorkload {
	w := model.K8sWorkload{Kind: "Pod", Namespace: p.Metadata.Namespace, Name: p.Metadata.Name,
		Replicas: 1, Images: p.Spec.images(), Containers: p.Spec.containers(), Node: p.Spec.NodeName,
		Created: timestamp(p.Metadata.CreationTimestamp)}
	if conditionTrue(p.Status.Conditions, "Ready") {
		w.Ready = 1
	}
	return w
}

type service struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Type         string            `json:"type"`
		ClusterIP    string            `json:"clusterIP"`
		ExternalIPs  []string          `json:"externalIPs"`
		ExternalName string            `json:"externalName"`
		Selector     map[string]string `json:"selector"`
		Ports        []struct {
			Protocol   string      `json:"protocol"`
			Port       int         `json:"port"`
			TargetPort intOrString `json:"targetPort"`
			NodePort   int         `json:"nodePort"`
		} `json:"ports"`
	} `json:"spec"`
	Status struct {
		LoadBalancer struct {
			Ingress []struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			} `json:"ingress"`
		} `json:"loadBalancer"`
	} `json:"status"`
}

func (s service) service() model.K8sService {
	out := model.K8sService{Namespace: s.Metadata.Namespace, Name: s.Metadata.Name, Type: s.Spec.Type,
		ClusterIP: s.Spec.ClusterIP, ExternalName: s.Spec.ExternalName}
	if out.Type == "" {
		out.Type = "ClusterIP"
	}
	if len(s.Spec.Selector) > 0 {
		out.Selector = s.Spec.Selector
	}
	ext := append([]string(nil), s.Spec.ExternalIPs...)
	for _, i := range s.Status.LoadBalancer.Ingress {
		if i.IP != "" {
			ext = append(ext, i.IP)
		}
		if i.Hostname != "" {
			ext = append(ext, i.Hostname)
		}
	}
	out.ExternalIPs = sortedUnique(ext)
	for _, p := range s.Spec.Ports {
		proto := p.Protocol
		if proto == "" {
			proto = "TCP"
		}
		port := strconv.Itoa(p.Port)
		if p.NodePort != 0 {
			port += ":" + strconv.Itoa(p.NodePort)
		}
		target := string(p.TargetPort)
		if target == "" || target == "0" {
			target = strconv.Itoa(p.Port) // the API's default
		}
		out.Ports = append(out.Ports, port+"/"+proto+"→"+target)
	}
	sort.Strings(out.Ports)
	return out
}

// intOrString is a port given as a number or a name, kept as text.
type intOrString string

func (v *intOrString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*v = intOrString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*v = intOrString(n.String())
	return nil
}

type ingress struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		IngressClassName string          `json:"ingressClassName"`
		DefaultBackend   *ingressBackend `json:"defaultBackend"`
		TLS              []struct {
			Hosts []string `json:"hosts"`
		} `json:"tls"`
		Rules []struct {
			Host string `json:"host"`
			HTTP *struct {
				Paths []struct {
					Path    string         `json:"path"`
					Backend ingressBackend `json:"backend"`
				} `json:"paths"`
			} `json:"http"`
		} `json:"rules"`
	} `json:"spec"`
}

type ingressBackend struct {
	Service *struct {
		Name string `json:"name"`
		Port struct {
			Name   string `json:"name"`
			Number int    `json:"number"`
		} `json:"port"`
	} `json:"service"`
	Resource *struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"resource"`
}

// String is "service:port" (a port number or name), or "Kind/name" for a
// resource backend.
func (b ingressBackend) String() string {
	switch {
	case b.Service != nil:
		port := b.Service.Port.Name
		if b.Service.Port.Number != 0 {
			port = strconv.Itoa(b.Service.Port.Number)
		}
		return b.Service.Name + ":" + port
	case b.Resource != nil:
		return b.Resource.Kind + "/" + b.Resource.Name
	}
	return "?"
}

func (i ingress) ingress() model.K8sIngress {
	out := model.K8sIngress{Namespace: i.Metadata.Namespace, Name: i.Metadata.Name,
		Class: i.Spec.IngressClassName, TLS: len(i.Spec.TLS) > 0}
	var hosts, backends []string
	for _, r := range i.Spec.Rules {
		host := r.Host
		if host != "" {
			hosts = append(hosts, host)
		} else {
			host = "*"
		}
		if r.HTTP == nil {
			continue
		}
		for _, p := range r.HTTP.Paths {
			path := p.Path
			if path == "" {
				path = "/"
			}
			backends = append(backends, host+path+" → "+p.Backend.String())
		}
	}
	if b := i.Spec.DefaultBackend; b != nil {
		backends = append(backends, "* → "+b.String())
	}
	out.Hosts = sortedUnique(hosts)
	out.Backends = sortedUnique(backends)
	return out
}

// timestamp normalizes an API timestamp to RFC 3339 in UTC; "" stays "".
func timestamp(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}

func slicesSorted(s []string) []string {
	return sortedUnique(append([]string(nil), s...))
}

func sortedUnique(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	sort.Strings(s)
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

var quantitySuffixes = map[string]*big.Rat{
	"": big.NewRat(1, 1), "m": big.NewRat(1, 1000),
	"k": pow(10, 3), "M": pow(10, 6), "G": pow(10, 9), "T": pow(10, 12), "P": pow(10, 15), "E": pow(10, 18),
	"Ki": pow(2, 10), "Mi": pow(2, 20), "Gi": pow(2, 30), "Ti": pow(2, 40), "Pi": pow(2, 50), "Ei": pow(2, 60),
}

func pow(base, exp int64) *big.Rat {
	return new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(base), big.NewInt(exp), nil))
}

// ParseQuantity reads a Kubernetes resource quantity ("16Gi", "8044176Ki",
// "1.5G", "128974848000m", "1e9") as a whole number, rounded up as
// Kubernetes does. ok is false for anything else, or a value that doesn't
// fit in an int64.
func ParseQuantity(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	i := 0
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	num, suffix := s[:i], s[i:]
	if num == "" || num == "+" || num == "-" {
		return 0, false
	}
	v, ok := new(big.Rat).SetString(num)
	if !ok {
		return 0, false
	}
	if mult, known := quantitySuffixes[suffix]; known {
		v.Mul(v, mult)
	} else if len(suffix) > 1 && (suffix[0] == 'e' || suffix[0] == 'E') {
		exp, err := strconv.Atoi(suffix[1:])
		if err != nil || exp < -30 || exp > 30 {
			return 0, false
		}
		m := pow(10, int64(abs(exp)))
		if exp < 0 {
			m.Inv(m)
		}
		v.Mul(v, m)
	} else {
		return 0, false
	}
	// Round up (towards +infinity).
	q, r := new(big.Int).QuoRem(v.Num(), v.Denom(), new(big.Int))
	if r.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsInt64() {
		return 0, false
	}
	return q.Int64(), true
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
