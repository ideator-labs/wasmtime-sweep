package main

import (
	"strconv"
	"strings"
)

// Range is a half-open version interval [Min, Max). An empty Min means no lower bound.
type Range struct{ Min, Max string }

type Advisory struct {
	CVE, GHSA, RustSec string
	ARM64Only          bool
	Affected           []Range
}

// Copied from the two Oct 19 2026 advisories. Check them again before trusting a verdict:
// https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-897f-g5gm-fmxm
// https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-mghf-wjfp-p5xm
var advisories = []Advisory{
	{
		CVE: "CVE-2026-115889", GHSA: "GHSA-897f-g5gm-fmxm", RustSec: "RUSTSEC-2026-0380",
		Affected: []Range{{"", "36.0.19"}, {"37.0.0", "43.0.0"}},
	},
	{
		CVE: "CVE-2026-115893", GHSA: "GHSA-mghf-wjfp-p5xm", RustSec: "RUSTSEC-2026-0379",
		ARM64Only: true,
		Affected:  []Range{{"", "36.0.19"}, {"37.0.0", "48.0.7"}, {"49.0.0", "49.0.4"}},
	},
}

type Status string

const (
	Affected    Status = "affected"
	NotAffected Status = "ok"
	NotThisArch Status = "ok-arch"
	NoCompiler  Status = "no-cranelift"
	Unknown     Status = "unknown"
)

type Verdict struct {
	CVE    string `json:"cve"`
	Status Status `json:"status"`
}

func judge(f Finding) []Verdict {
	out := make([]Verdict, 0, len(advisories))
	for _, a := range advisories {
		out = append(out, Verdict{a.CVE, judgeOne(a, f)})
	}
	return out
}

func judgeOne(a Advisory, f Finding) Status {
	if !f.HasCranelift {
		return NoCompiler
	}
	if a.ARM64Only && !f.hasArch("aarch64") {
		return NotThisArch
	}
	v := f.Version()
	if v == "" {
		return Unknown
	}
	for _, r := range a.Affected {
		if (r.Min == "" || cmpVersion(v, r.Min) >= 0) && cmpVersion(v, r.Max) < 0 {
			return Affected
		}
	}
	return NotAffected
}

func cmpVersion(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		x, y := part(pa, i), part(pb, i)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func part(p []string, i int) int {
	if i >= len(p) {
		return 0
	}
	n, _ := strconv.Atoi(p[i])
	return n
}
