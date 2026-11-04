package store

import (
	"maps"
	"slices"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
)

func TestIngressHosts(t *testing.T) {
	ings := []model.K8sIngress{
		{Namespace: "shop", Name: "web", Hosts: []string{"Shop.Lab", "api.lab"}, TLS: true, Backends: []string{
			"Shop.Lab/ → web:http", "api.lab/v1 → api:80", "api.lab/files → StorageBucket/static", "* → fallback:80"}},
		{Namespace: "blog", Name: "blog", Hosts: []string{"*.blog.lab"}, Backends: []string{"*.blog.lab/ → blog:80"}},
	}
	svcs := []model.K8sService{
		{Namespace: "shop", Name: "web", Workloads: []string{"Deployment/shop/web"}},
		{Namespace: "shop", Name: "api", Workloads: []string{"Deployment/shop/api", "StatefulSet/shop/api-cache"}},
		{Namespace: "shop", Name: "fallback", Workloads: []string{"Pod/shop/oops"}},
		{Namespace: "other", Name: "blog", Workloads: []string{"Deployment/other/blog"}}, // another namespace's
	}
	got := map[string][]string{}
	for _, h := range ingressHosts(ings, svcs) {
		got[h.name] = slices.Sorted(maps.Keys(h.workloads))
	}
	want := map[string][]string{
		"shop.lab":   {"Deployment/shop/web", "Pod/shop/oops"},
		"api.lab":    {"Deployment/shop/api", "Pod/shop/oops", "StatefulSet/shop/api-cache"},
		"*.blog.lab": {},
	}
	if len(got) != len(want) {
		t.Fatalf("hosts: %v", got)
	}
	for k, w := range want {
		if !slices.Equal(got[k], w) {
			t.Errorf("%s: workloads %v, want %v", k, got[k], w)
		}
	}
}
