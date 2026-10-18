#!/usr/bin/env bash
# 本机（macOS/Docker Desktop）一键运行 Seam A 拓扑：构建 topo 镜像并在特权容器内执行 topo.sh。
# CI 里由 .github/workflows/seam-a.yml 直接构建镜像并 docker run，不经过本脚本。
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
IMAGE="${HZMN_TOPO_IMAGE:-hertzmesh-topo:latest}"
CARGO_CACHE="${HZMN_CARGO_CACHE:-/Users/lixin/Develop/.hmn-cache/cargo}"
VOL_TGT=hz-topo-target
VOL_BIN=hz-topo-bin

docker build -t "$IMAGE" -f "$ROOT/scripts/test/Dockerfile.topo" "$ROOT/scripts/test"

docker volume create "$VOL_TGT" >/dev/null
docker volume create "$VOL_BIN" >/dev/null

exec docker run --rm --privileged \
  -v "$ROOT:/src" -v "$CARGO_CACHE:/usr/local/cargo/registry" \
  -v "$VOL_TGT:/target" -v "$VOL_BIN:/out" \
  -e CARGO_TARGET_DIR=/target -e HZ_TOPO_CARGO_TARGET_DIR=/target \
  -w /src "$IMAGE" bash scripts/test/topo/topo.sh "$@"
