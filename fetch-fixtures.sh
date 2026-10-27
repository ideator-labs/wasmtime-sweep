#!/usr/bin/env bash
# Downloads real published Wasmtime artifacts into .fixtures/ and checks their sha256.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .fixtures
cd .fixtures

GH=https://github.com
PY=https://files.pythonhosted.org/packages
while read -r sha name url; do
  if [ -f "$name" ] && echo "$sha  $name" | sha256sum -c --quiet - 2>/dev/null; then
    continue
  fi
  echo "fetch $name"
  curl -fsSL -o "$name.part" "$url"
  echo "$sha  $name.part" | sha256sum -c --quiet -
  mv "$name.part" "$name"
done <<LIST
263b924576d9519c43d5a1acff50a03ab03209d16d26c53543c9ab9a409fb93f wasmtime-49.0.0-py3-none-manylinux2014_aarch64.whl $PY/9c/f4/7889eb2fdbb11423e61f442af218441e0ae5749452bf8d2c1ade4ce630c5/wasmtime-49.0.0-py3-none-manylinux2014_aarch64.whl
675484e525c028dc02762b777f1db4477ea70caa3fec6775426daff4d64edfb1 wasmtime-50.0.1-py3-none-manylinux2014_aarch64.whl $PY/8e/c4/58709b73e613e5366e4783537e2a861272d95f500c43fddf9b378d98415a/wasmtime-50.0.1-py3-none-manylinux2014_aarch64.whl
ca12269ee88aac6b1f64b5f324abf3c6370ff853338d991292f10cb17b906667 wasmtime-42.0.0-py3-none-manylinux1_x86_64.whl $PY/44/54/a774313c19c1c0ae2c1897af697c12178904d67911f42c4a9bdddba68640/wasmtime-42.0.0-py3-none-manylinux1_x86_64.whl
7672c89e28338de4f838951e5cddfab0eb68cfa86031cb4520390bc71f770951 wasmtime.48.0.2.nupkg https://api.nuget.org/v3-flatcontainer/wasmtime/48.0.2/wasmtime.48.0.2.nupkg
146929021a80aabf4dc6dfc8154a06ab2fd556fd229d621cddf26af91401547b spin-v4.2.3-linux-aarch64.tar.gz $GH/spinframework/spin/releases/download/v4.2.3/spin-v4.2.3-linux-aarch64.tar.gz
191174efa60ac4497c684e7b83cac6fee4330cdbfba2f7db7dda4250b389eea9 wasmtime-v42.0.0-x86_64-linux.tar.xz $GH/bytecodealliance/wasmtime/releases/download/v42.0.0/wasmtime-v42.0.0-x86_64-linux.tar.xz
77c19ee0437991f9ac7837b9c269d9c7076744f85dad263fea5214cc2723c7ff wasmtime-v50.0.0-x86_64-linux.tar.xz $GH/bytecodealliance/wasmtime/releases/download/v50.0.0/wasmtime-v50.0.0-x86_64-linux.tar.xz
LIST
echo "fixtures ok: $(ls | wc -l) files in .fixtures/"
