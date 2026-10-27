# wasmtime-sweep

Find every Wasmtime engine hiding in your binaries, wheels, NuGet packages and container layers, and see which of the October 2026 Cranelift sandbox escapes (CVE-2026-115889, CVE-2026-115893) applies to each one.

Wasmtime usually ships inside something else. The advisories are filed against the crates.io crate, so a PyPI wheel, a NuGet package or a vendored `.so` gives Dependabot and SBOM scanners nothing to match. wasmtime-sweep reads the engine version and CPU arch out of the binary itself.

```
$ wasmtime-sweep ./rootfs
AFFECTED  spin-v4.2.3-linux-aarch64.tar.gz!gunzip!spin  aarch64  49.0.3  panic-hook  -  CVE-2026-115889=ok  CVE-2026-115893=affected
...
summary: 14 wasmtime copies, 8 affected, 0 unknown version
```

Try it on real published artifacts:

```bash
bash demo.sh          # 9/9 checks on PyPI, NuGet, Spin and Wasmtime CLI downloads
bash demo.sh --break  # name-based scanning misses Spin and a renamed lib, checks fail
```

This is a proof of concept. The advisory table is hand-copied and builds before about 48.0 often have no readable version. Read [AGENTS.md](AGENTS.md) for the data shape, design, limits and next steps.

MIT licensed.
