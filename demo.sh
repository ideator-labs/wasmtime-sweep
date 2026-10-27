#!/usr/bin/env bash
# End-to-end proof on real published artifacts. Usage: bash demo.sh [--break]
# --break scans by file name only (what a name-based inventory does); checks must fail.
set -uo pipefail
cd "$(dirname "$0")"

MODE=normal
[ "${1:-}" = "--break" ] && MODE=break

./fetch-fixtures.sh >/dev/null || { echo "FAIL could not fetch fixtures"; exit 1; }
go build -o bin/wasmtime-sweep . || { echo "FAIL build"; exit 1; }

F=.fixtures
W=work
rm -rf "$W"
mkdir -p "$W/tree/pypi" "$W/tree/nuget" "$W/tree/spin" "$W/tree/cli" "$W/tree/neg" \
  "$W/tree/rootfs/usr/lib/python3/site-packages" "$W/layer/opt/plugin-host/lib"

cp "$F"/wasmtime-49.0.0-py3-none-manylinux2014_aarch64.whl "$F"/wasmtime-50.0.1-py3-none-manylinux2014_aarch64.whl "$W/tree/pypi/"
unzip -q "$F/wasmtime-42.0.0-py3-none-manylinux1_x86_64.whl" -d "$W/tree/rootfs/usr/lib/python3/site-packages"
cp "$F/wasmtime.48.0.2.nupkg" "$W/tree/nuget/"
cp "$F/spin-v4.2.3-linux-aarch64.tar.gz" "$W/tree/spin/"
tar -xJf "$F/wasmtime-v42.0.0-x86_64-linux.tar.xz" -C "$W/tree/cli"
tar -xJf "$F/wasmtime-v50.0.0-x86_64-linux.tar.xz" -C "$W/tree/cli"
unzip -q -p "$F/wasmtime.48.0.2.nupkg" runtimes/linux-arm64/native/libwasmtime.so > "$W/layer/opt/plugin-host/lib/libplugin_engine.so"
tar -czf "$W/tree/vendor-layer.tar.gz" -C "$W/layer" opt
cp bin/wasmtime-sweep "$W/tree/neg/wasmtime-sweep-copy"
cp /bin/ls "$W/tree/neg/ls"

FLAGS=()
[ "$MODE" = break ] && FLAGS=(-by-name)
./bin/wasmtime-sweep "${FLAGS[@]}" "$W/tree" > "$W/out.tsv"
FULL_EXIT=$?
./bin/wasmtime-sweep "${FLAGS[@]}" "$W/tree/pypi/wasmtime-50.0.1-py3-none-manylinux2014_aarch64.whl" "$W/tree/cli/wasmtime-v50.0.0-x86_64-linux" > "$W/clean.tsv"
CLEAN_EXIT=$?

echo "--- scanner output (work/out.tsv)"
sed "s#$W/tree/##" "$W/out.tsv"
echo "---"

pass=0; fail=0
check() {
  if eval "$2"; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1"; fail=$((fail+1)); fi
}
row() { grep -F -- "$1" "$W/out.tsv" | grep -v -F -- "${2:-@@none@@}"; }
copies=$(grep -vc '^summary' "$W/out.tsv")

check "1 finds all 14 embedded copies and neither negative control (got $copies)" \
  '[ "$copies" = 14 ] && ! grep -q "/neg/" "$W/out.tsv"'
check "2 PyPI wasmtime 49.0.0 aarch64 wheel: engine 49.0.0 read from the binary, CVE-2026-115893 affected" \
  'row "wasmtime-49.0.0-py3-none-manylinux2014_aarch64.whl!" | grep -q "aarch64	49.0.0	panic-hook	pypi:wasmtime@49.0.0	CVE-2026-115889=ok	CVE-2026-115893=affected"'
check "3 PyPI wasmtime 50.0.1 wheel: binary says engine 50.0.0, package says 50.0.1, both CVEs ok" \
  'row "wasmtime-50.0.1-py3" | grep -q "^OK	.*aarch64	50.0.0	panic-hook	pypi:wasmtime@50.0.1	CVE-2026-115889=ok	CVE-2026-115893=ok$"'
check "4 NuGet Wasmtime 48.0.2 (newest on nuget.org): 3 arm64 libs affected, 3 x64 libs ok-arch" \
  '[ "$(row "wasmtime.48.0.2.nupkg!" | grep -c "aarch64	48.0.2.*CVE-2026-115893=affected")" = 3 ] && [ "$(row "wasmtime.48.0.2.nupkg!" | grep -c "x86_64	48.0.2.*CVE-2026-115893=ok-arch")" = 3 ]'
check "5 Spin 4.2.3 linux-aarch64 inside its release tar.gz embeds 49.0.3, CVE-2026-115893 affected" \
  'row "spin-v4.2.3-linux-aarch64.tar.gz!gunzip!spin" | grep -q "^AFFECTED	.*aarch64	49.0.3	panic-hook	-	.*CVE-2026-115893=affected"'
check "6 renamed vendored lib inside a layer tarball (libplugin_engine.so) is still found and affected" \
  'row "vendor-layer.tar.gz!gunzip!opt/plugin-host/lib/libplugin_engine.so" | grep -q "^AFFECTED	.*aarch64	48.0.2	panic-hook"'
check "7 pre-48 builds: CLI 42.0.0 via banner and site-packages 42.0.0 via dist-info, CVE-2026-115889 affected" \
  'row "wasmtime-v42.0.0-x86_64-linux/wasmtime	" | grep -q "42.0.0	cli-banner	-	CVE-2026-115889=affected" && row "site-packages/wasmtime/linux-x86_64/_libwasmtime.so" | grep -q "	?	package-metadata:42.0.0	pypi:wasmtime@42.0.0	CVE-2026-115889=affected"'
check "8 wasmtime 50.0.0 CLI is ok and wasmtime-min 50.0.0 has no Cranelift to attack" \
  'row "wasmtime-v50.0.0-x86_64-linux/wasmtime	" | grep -q "^OK	" && row "wasmtime-v50.0.0-x86_64-linux/wasmtime-min" | grep -q "CVE-2026-115889=no-cranelift	CVE-2026-115893=no-cranelift"'
check "9 exit code 1 on the full tree, 0 on a clean subset (got $FULL_EXIT and $CLEAN_EXIT)" \
  '[ "$FULL_EXIT" = 1 ] && [ "$CLEAN_EXIT" = 0 ] && grep -q "summary: 3 wasmtime copies, 0 affected" "$W/clean.tsv"'

echo "mode=$MODE: $pass passed, $fail failed"
[ "$fail" = 0 ]
