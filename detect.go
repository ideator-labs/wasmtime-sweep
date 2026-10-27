package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"regexp"
)

// Finding is one native binary that contains a Wasmtime engine.
type Finding struct {
	Path         string    `json:"path"`
	Format       string    `json:"format"`
	Arch         []string  `json:"arch"`
	Engine       string    `json:"engine_version,omitempty"`
	EngineFrom   string    `json:"engine_from,omitempty"`
	Package      string    `json:"package,omitempty"`
	PackageVer   string    `json:"package_version,omitempty"`
	HasCranelift bool      `json:"has_cranelift"`
	Verdicts     []Verdict `json:"verdicts"`
}

// Version is the engine version read from the binary, else the version its package claims.
func (f Finding) Version() string {
	if f.Engine != "" {
		return f.Engine
	}
	return f.PackageVer
}

func (f Finding) hasArch(a string) bool {
	for _, x := range f.Arch {
		if x == a {
			return true
		}
	}
	return false
}

var (
	// Wasmtime's panic hook text. Seen in 48.0.2, 49.0.0, 49.0.3, 49.0.4 and 50.0.0 builds.
	panicHook = regexp.MustCompile(`version: (\d+\.\d+\.\d+)\n\nThis is a bug in Wasmtime`)
	// The CLI's --version banner, present in older CLI builds that lack the panic hook.
	cliBanner = regexp.MustCompile(`Wasmtime WebAssembly Runtime(\d+\.\d+\.\d+) \(`)
)

// fingerprint returns ok=false when data is not a native binary or has no Wasmtime engine in it.
func fingerprint(data []byte) (f Finding, ok bool) {
	format, arch := nativeArch(data)
	if format == "" {
		return f, false
	}
	f.Format, f.Arch = format, arch
	f.HasCranelift = bytes.Count(data, []byte("cranelift-codegen")) >= 5
	switch {
	case panicHook.Match(data):
		f.Engine, f.EngineFrom = string(panicHook.FindSubmatch(data)[1]), "panic-hook"
	case cliBanner.Match(data):
		f.Engine, f.EngineFrom = string(cliBanner.FindSubmatch(data)[1]), "cli-banner"
	case f.HasCranelift && bytes.Contains(data, []byte("wasmtime")):
	default:
		return f, false
	}
	return f, true
}

func nativeArch(data []byte) (string, []string) {
	r := bytes.NewReader(data)
	switch {
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		if e, err := elf.NewFile(r); err == nil {
			return "elf", []string{elfArch(e.Machine)}
		}
	case bytes.HasPrefix(data, []byte("MZ")):
		if p, err := pe.NewFile(r); err == nil {
			return "pe", []string{peArch(p.Machine)}
		}
	case bytes.HasPrefix(data, []byte{0xcf, 0xfa, 0xed, 0xfe}):
		if m, err := macho.NewFile(r); err == nil {
			return "macho", []string{machoArch(m.Cpu)}
		}
	case bytes.HasPrefix(data, []byte{0xca, 0xfe, 0xba, 0xbe}):
		if fat, err := macho.NewFatFile(r); err == nil {
			var arches []string
			for _, a := range fat.Arches {
				arches = append(arches, machoArch(a.Cpu))
			}
			return "macho-fat", arches
		}
	}
	return "", nil
}

func elfArch(m elf.Machine) string {
	switch m {
	case elf.EM_X86_64:
		return "x86_64"
	case elf.EM_AARCH64:
		return "aarch64"
	}
	return m.String()
}

func peArch(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x86_64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "aarch64"
	}
	return "pe-machine-unknown"
}

func machoArch(c macho.Cpu) string {
	switch c {
	case macho.CpuAmd64:
		return "x86_64"
	case macho.CpuArm64:
		return "aarch64"
	}
	return c.String()
}
