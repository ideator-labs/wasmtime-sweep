package main

import "testing"

func TestVerdictBoundaries(t *testing.T) {
	cases := []struct {
		ver, arch        string
		want889, want893 Status
	}{
		{"36.0.18", "x86_64", Affected, NotThisArch},
		{"36.0.19", "aarch64", NotAffected, NotAffected},
		{"42.0.0", "x86_64", Affected, NotThisArch},
		{"43.0.0", "aarch64", NotAffected, Affected},
		{"48.0.6", "aarch64", NotAffected, Affected},
		{"48.0.7", "aarch64", NotAffected, NotAffected},
		{"49.0.3", "aarch64", NotAffected, Affected},
		{"49.0.4", "aarch64", NotAffected, NotAffected},
		{"50.0.0", "aarch64", NotAffected, NotAffected},
	}
	for _, c := range cases {
		v := judge(Finding{Engine: c.ver, Arch: []string{c.arch}, HasCranelift: true})
		if v[0].Status != c.want889 || v[1].Status != c.want893 {
			t.Errorf("%s %s: got %s/%s want %s/%s", c.ver, c.arch, v[0].Status, v[1].Status, c.want889, c.want893)
		}
	}
	if v := judge(Finding{Arch: []string{"aarch64"}, HasCranelift: true}); v[0].Status != Unknown || v[1].Status != Unknown {
		t.Errorf("no version: got %v", v)
	}
}
