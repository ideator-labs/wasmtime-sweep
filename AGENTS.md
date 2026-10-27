# AGENTS.md

Handoff for a coding agent that starts with no context.

## What this is

wasmtime-sweep is a Go CLI that finds every Wasmtime engine embedded in native binaries under a path, reads the engine version and CPU architecture out of the binary itself, and says which of the two October 2026 Cranelift sandbox escapes applies to each copy:

- CVE-2026-115889 (GHSA-897f-g5gm-fmxm, RUSTSEC-2026-0380). Any architecture. Affected `<36.0.19` and `>=37.0.0, <43.0.0`.
- CVE-2026-115893 (GHSA-mghf-wjfp-p5xm, RUSTSEC-2026-0379). aarch64 only. Affected `<36.0.19`, `>=37.0.0, <48.0.7`, `>=49.0.0, <49.0.4`.

It looks inside directories, zip files (Python wheels, NuGet packages), gzip and tar (release tarballs, container layer tarballs), nested up to 4 levels.

The claim: Wasmtime usually ships as a native library inside some other package (a PyPI wheel, a NuGet package, a Go module, a Rust binary like Spin, a vendored `.so`). Lockfile and SBOM tools match a package name in an ecosystem. The Oct 19 advisories are filed against the crates.io `wasmtime` crate only, so those copies have nothing to match. Fingerprinting the engine in the binary finds them anyway, including copies that were renamed.

## Status

Real:
- Every fixture is a real published artifact, downloaded by `fetch-fixtures.sh` and checked against a pinned sha256: PyPI `wasmtime` 49.0.0 and 50.0.1 (manylinux2014_aarch64) and 42.0.0 (manylinux1_x86_64), NuGet `Wasmtime` 48.0.2, Spin v4.2.3 linux-aarch64, Wasmtime CLI v42.0.0 and v50.0.0 x86_64-linux.
- Versions and architectures in the output come from the bytes of those binaries (ELF, PE, Mach-O headers via Go's `debug/*` packages).

Not built:
- No live advisory feed. The two advisories are a table in `advisories.go`, copied by hand on 2026-10-27.
- No OCI registry pulls. Point it at an exported rootfs, a `docker save` tarball or layer tarballs.
- No Go-module (`wasmtime-go`) fixture. It would need a cgo build. The detector is the same native fingerprint, so it should work, but it is not tested.
- No model calls, no cloud account, no network except fixture downloads.

`bash demo.sh` passes 9/9 on a fresh clone. `bash demo.sh --break` fails checks 1, 5 and 6. `go test ./...` passes.

## Data shape

One `Finding` per native binary that contains a Wasmtime engine (`detect.go`):

```json
{"path":"tree/spin/spin-v4.2.3-linux-aarch64.tar.gz!gunzip!spin","format":"elf","arch":["aarch64"],
 "engine_version":"49.0.3","engine_from":"panic-hook","package":"","package_version":"",
 "has_cranelift":true,
 "verdicts":[{"cve":"CVE-2026-115889","status":"ok"},{"cve":"CVE-2026-115893","status":"affected"}]}
```

- `path`. File path, with `!member` for each archive level.
- `engine_from`. `panic-hook` (the text `version: X.Y.Z\n\nThis is a bug in Wasmtime`, seen in 48.0.2, 49.0.0, 49.0.3, 49.0.4, 50.0.0 builds) or `cli-banner` (`Wasmtime WebAssembly RuntimeX.Y.Z (`, older CLI builds). Empty when neither is present.
- `package`, `package_version`. From the wheel `METADATA` or `.nuspec` in the same archive, or from `wasmtime-*.dist-info` or `*.nuspec` up to four directories above an unpacked library. Used for the verdict only when `engine_version` is empty.
- `status` is one of `affected`, `ok`, `ok-arch` (aarch64-only CVE on another arch), `no-cranelift` (runtime-only build such as `wasmtime-min`, cannot compile Wasm), `unknown` (Wasmtime present but no version found).

Text output is one tab-separated line per finding: worst status, path, arch, engine version, source, package@version, then `CVE=status` per advisory, then a summary line. `-json` prints JSON lines instead. Exit 1 when any copy is affected or unknown (`-allow-unknown` relaxes unknown), 0 when clean, 3 on usage errors.

## Repo map

- `main.go`. Flags, directory walk, archive recursion (zip, gzip, tar), package metadata lookup, output, exit codes.
- `detect.go`. `Finding`, the presence and version fingerprints, ELF/PE/Mach-O arch.
- `advisories.go`. The advisory table, version compare, verdicts.
- `advisories_test.go`. Boundary versions for both CVEs.
- `fetch-fixtures.sh`. Downloads the seven pinned artifacts into `.fixtures/` (about 150 MB, gitignored).
- `demo.sh`. Builds `work/tree` from the fixtures, scans it, runs 9 checks.

## Setup, run, verify (fresh clone)

Needs Go 1.24+, curl, unzip, tar with xz, sha256sum, bash. Tested with Go 1.27.3 on x86_64 Linux.

```bash
git clone https://github.com/ideator-labs/wasmtime-sweep && cd wasmtime-sweep
go test ./...
bash demo.sh            # expect "mode=normal: 9 passed, 0 failed", exit 0
bash demo.sh --break    # expect checks 1, 5, 6 FAIL, exit 1
bash demo.sh            # passes again
go build -o bin/wasmtime-sweep . && ./bin/wasmtime-sweep /path/to/rootfs   # your own tree
```

The first `demo.sh` run downloads the fixtures. Later runs reuse them after a sha256 check. A run takes about 5 s after that.

## Design decisions

- Fingerprint the binary, not the name. `--break` turns on `-by-name` (only files whose name contains "wasmtime") to show what a name-based inventory misses: Spin and a renamed `libplugin_engine.so`.
- Trust the engine version over the package version. The PyPI 50.0.1 wheel's library reports engine 50.0.0. The verdict uses what is compiled in.
- Presence needs a strong signal (panic hook, CLI banner, or at least 5 `cranelift-codegen` strings plus `wasmtime`). The demo copies the scanner's own binary into the tree as a negative control, because it contains those words as literals.
- `has_cranelift` needs at least 5 `cranelift-codegen` strings. Real engines measured 7 to 87. `wasmtime-min` has 0.
- Whole files are read into memory. Simple, fine for libraries and layers up to a few hundred MB.
- Standard library only.

## Known limits

- Builds before about 48 have no panic hook. The 36.0.0, 42.0.0 and 44.0.0 wheel libraries have neither the panic hook nor the banner (36.0.0 does have the version next to `serialization.rs`, see next step 2), so the version comes from package metadata or is `unknown`. `wasmtime-min` 42.0.0 has neither a version nor Cranelift and is not reported at all.
- Stripped or LTO'd custom embedders may drop the panic hook text. Not measured.
- The advisory table is hand-copied. A new advisory needs a code change.
- Measured on 2026-10-27, not re-checked by the demo: OSV lists both advisories under crates.io `wasmtime` only. PyPI `wasmtime` has 11 OSV entries, newest published 2026-04-09. `wasmtime-go` and NuGet `Wasmtime` have none. PyPI has no 48.0.7 or 49.0.4. NuGet's newest `Wasmtime` is 48.0.2. These facts will change.
- No Windows or macOS host testing. The PE and Mach-O fixtures are scanned on Linux.

## Next steps (prioritized)

1. OSV-backed table. Fetch `RUSTSEC-2026-0379`/`0380` style records from api.osv.dev and build `advisories` from them, with the hand table as the offline fallback. Done when: `-osv` produces the same 9/9 demo result and a unit test feeds a recorded OSV JSON response.
2. Version signature for pre-48 builds. Find a stable string near `CARGO_PKG_VERSION` in 36.x to 47.x libraries (try `serialization.rs` neighbours). Done when: the 42.0.0 wheel library reports `engine_from` other than empty without package metadata, checked in `demo.sh`.
3. OCI image input. Accept an OCI layout dir or `docker save` tar and report the image digest per finding. Done when: a `docker save` of an image with the 49.0.0 wheel installed reports the wheel's library with the image digest.
4. wasmtime-go fixture. Build a tiny cgo program against `wasmtime-go/v49` and scan it. Done when: demo check reports `49.0.0` for that binary on x86_64 (`ok-arch`) and for an aarch64 cross build (`affected`).
5. GitHub Action and SARIF output. Done when: a workflow on a sample repo fails on the 49.0.0 wheel and shows the finding in code scanning.

## Working rules

- Verify against real artifacts. Every new fixture is a published file with a pinned sha256 in `fetch-fixtures.sh`.
- Keep `demo.sh` the source of truth. Every new claim gets a check, and `--break` must still fail at least one check.
- Never edit the advisory table from memory. Copy from the advisory page and cite it.
- Commit as `danielgerlag <daniel@gerlag.ca>`.
- No em-dashes in prose.

## Context and sources

- Advisories: https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-897f-g5gm-fmxm and https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-mghf-wjfp-p5xm
- The Hacker News, Oct 26 2026 (version table, Dependabot gap, "updating the command-line tool does not fix them"): https://thehackernews.com/2026/10/two-critical-wasmtime-flaws-could-let.html
- "rebuild every embedded copy": https://rushcommerce.dev/blog/wasmtime-cranelift-sandbox-escape-cve-2026-115889-115893-rebuild-every-embedded-copy
- Inventory gap ("A name missing from that tree does not prove a downloaded native library or a supplier binary is absent"): https://www.plexicus.ai/blog/application-security/wasmtime-embedded-runtime-patch-validation/
- Wasmtime releases: https://github.com/bytecodealliance/wasmtime/releases
- OSV queries used for the measurement: `POST https://api.osv.dev/v1/query` with `{"package":{"name":"wasmtime","ecosystem":"PyPI"}}`, and `GET https://api.osv.dev/v1/vulns/RUSTSEC-2026-0380`.
