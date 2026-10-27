// Command wasmtime-sweep finds Wasmtime engines embedded in native binaries and
// reports which of the Oct 2026 Cranelift sandbox-escape CVEs apply to each copy.
package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const maxDepth = 4

type scanner struct {
	byName   bool
	findings []Finding
	errs     []string
}

func main() {
	jsonOut := flag.Bool("json", false, "print findings as JSON lines")
	byName := flag.Bool("by-name", false, "naive mode: only look at files whose name contains \"wasmtime\"")
	allowUnknown := flag.Bool("allow-unknown", false, "exit 0 when the only problems are copies with an unknown version")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wasmtime-sweep [-json] [-by-name] [-allow-unknown] PATH...")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(3)
	}
	s := &scanner{byName: *byName}
	for _, root := range flag.Args() {
		if err := filepath.WalkDir(root, s.visit); err != nil {
			fmt.Fprintln(os.Stderr, "wasmtime-sweep:", err)
			os.Exit(3)
		}
	}
	for _, e := range s.errs {
		fmt.Fprintln(os.Stderr, "warn:", e)
	}
	affected, unknown := 0, 0
	for i := range s.findings {
		f := &s.findings[i]
		f.Verdicts = judge(*f)
		switch worst(f.Verdicts) {
		case Affected:
			affected++
		case Unknown:
			unknown++
		}
		if *jsonOut {
			b, _ := json.Marshal(f)
			fmt.Println(string(b))
		} else {
			printText(*f)
		}
	}
	if !*jsonOut {
		fmt.Printf("summary: %d wasmtime copies, %d affected, %d unknown version\n", len(s.findings), affected, unknown)
	}
	if affected > 0 || (unknown > 0 && !*allowUnknown) {
		os.Exit(1)
	}
}

func worst(vs []Verdict) Status {
	w := NotAffected
	for _, v := range vs {
		if v.Status == Affected {
			return Affected
		}
		if v.Status == Unknown {
			w = Unknown
		}
	}
	return w
}

func printText(f Finding) {
	ver := f.Engine
	if ver == "" {
		ver = "?"
	}
	from := f.EngineFrom
	if f.Engine == "" && f.PackageVer != "" {
		from = "package-metadata:" + f.PackageVer
	}
	pkg := f.Package
	if pkg == "" {
		pkg = "-"
	} else {
		pkg += "@" + f.PackageVer
	}
	cols := []string{strings.ToUpper(string(worst(f.Verdicts))), f.Path, strings.Join(f.Arch, ","), ver, from, pkg}
	for _, v := range f.Verdicts {
		cols = append(cols, v.CVE+"="+string(v.Status))
	}
	fmt.Println(strings.Join(cols, "\t"))
}

func (s *scanner) visit(p string, d fs.DirEntry, err error) error {
	if err != nil {
		s.errs = append(s.errs, err.Error())
		return nil
	}
	if !d.Type().IsRegular() {
		return nil
	}
	if !s.sniffFile(p) {
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		s.errs = append(s.errs, err.Error())
		return nil
	}
	pkg, ver := packageNear(p)
	s.scanBlob(p, data, 0, pkg, ver)
	return nil
}

// sniffFile reads the header so we only load files we know how to look inside.
func (s *scanner) sniffFile(p string) bool {
	fh, err := os.Open(p)
	if err != nil {
		return false
	}
	defer fh.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(fh, head)
	k := kindOf(head[:n])
	if k == "" {
		return false
	}
	if s.byName && k == "native" && !strings.Contains(strings.ToLower(filepath.Base(p)), "wasmtime") {
		return false
	}
	return true
}

func kindOf(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("\x7fELF")), bytes.HasPrefix(b, []byte("MZ")),
		bytes.HasPrefix(b, []byte{0xcf, 0xfa, 0xed, 0xfe}), bytes.HasPrefix(b, []byte{0xca, 0xfe, 0xba, 0xbe}):
		return "native"
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		return "zip"
	case bytes.HasPrefix(b, []byte{0x1f, 0x8b}):
		return "gzip"
	case len(b) >= 262 && string(b[257:262]) == "ustar":
		return "tar"
	}
	return ""
}

func (s *scanner) scanBlob(name string, data []byte, depth int, pkg, ver string) {
	if depth > maxDepth {
		return
	}
	switch kindOf(data) {
	case "native":
		if s.byName && !strings.Contains(strings.ToLower(path.Base(name)), "wasmtime") {
			return
		}
		if f, ok := fingerprint(data); ok {
			f.Path, f.Package, f.PackageVer = name, pkg, ver
			s.findings = append(s.findings, f)
		}
	case "zip":
		s.scanZip(name, data, depth)
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			s.errs = append(s.errs, name+": "+err.Error())
			return
		}
		raw, err := io.ReadAll(zr)
		if err != nil {
			s.errs = append(s.errs, name+": "+err.Error())
			return
		}
		s.scanBlob(name+"!gunzip", raw, depth+1, pkg, ver)
	case "tar":
		s.scanTar(name, data, depth)
	}
}

func (s *scanner) scanZip(name string, data []byte, depth int) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		s.errs = append(s.errs, name+": "+err.Error())
		return
	}
	pkg, ver := zipPackage(zr)
	for _, m := range zr.File {
		if m.FileInfo().IsDir() {
			continue
		}
		rc, err := m.Open()
		if err != nil {
			continue
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		s.scanBlob(name+"!"+m.Name, b, depth+1, pkg, ver)
	}
}

func (s *scanner) scanTar(name string, data []byte, depth int) {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if err != nil {
			if err != io.EOF {
				s.errs = append(s.errs, name+": "+err.Error())
			}
			return
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return
		}
		s.scanBlob(name+"!"+h.Name, b, depth+1, "", "")
	}
}

var (
	metaVersion  = regexp.MustCompile(`(?m)^Version: (\S+)`)
	nuspecID     = regexp.MustCompile(`<id>\s*Wasmtime\s*</id>`)
	nuspecVer    = regexp.MustCompile(`<version>\s*([^<\s]+)\s*</version>`)
	distInfoName = regexp.MustCompile(`^wasmtime-[^/]+\.dist-info/METADATA$`)
)

// zipPackage reads the PyPI wheel METADATA or the NuGet .nuspec at the archive root.
func zipPackage(zr *zip.Reader) (string, string) {
	for _, m := range zr.File {
		if distInfoName.MatchString(m.Name) || (strings.HasSuffix(strings.ToLower(m.Name), ".nuspec") && !strings.Contains(m.Name, "/")) {
			rc, err := m.Open()
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(rc)
			rc.Close()
			if pkg, ver := parseMeta(m.Name, b); pkg != "" {
				return pkg, ver
			}
		}
	}
	return "", ""
}

func parseMeta(name string, b []byte) (string, string) {
	if strings.HasSuffix(name, "METADATA") {
		if m := metaVersion.FindSubmatch(b); m != nil {
			return "pypi:wasmtime", string(m[1])
		}
	}
	if strings.HasSuffix(strings.ToLower(name), ".nuspec") && nuspecID.Match(b) {
		if m := nuspecVer.FindSubmatch(b); m != nil {
			return "nuget:Wasmtime", string(m[1])
		}
	}
	return "", ""
}

// packageNear looks up to four directories above an unpacked library for the
// package metadata that shipped it (site-packages/wasmtime-X.dist-info, or a NuGet cache dir).
func packageNear(p string) (string, string) {
	dir := filepath.Dir(p)
	for i := 0; i < 4; i++ {
		cands, _ := filepath.Glob(filepath.Join(dir, "wasmtime-*.dist-info", "METADATA"))
		more, _ := filepath.Glob(filepath.Join(dir, "*.nuspec"))
		for _, c := range append(cands, more...) {
			b, err := readSmall(c)
			if err != nil {
				continue
			}
			if pkg, ver := parseMeta(c, b); pkg != "" {
				return pkg, ver
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", ""
}

func readSmall(p string) ([]byte, error) {
	fh, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return io.ReadAll(io.LimitReader(bufio.NewReader(fh), 1<<20))
}
