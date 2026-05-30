#!/usr/bin/env bash
# WSL 入口：全部在 Docker 内完成构建、单元/集成测试、E2E 冒烟。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/deploy"

# 修复 Windows CRLF
for f in "$ROOT"/deploy/*.sh "$ROOT"/scripts/test/*.sh "$ROOT"/scripts/benchmark/*.sh; do
  [ -f "$f" ] && sed -i 's/\r$//' "$f" || true
done

echo "==> docker version"
docker version
docker compose version

echo ""
echo "==> building images (cargo test runs inside builder stage) ..."
docker compose -f docker-compose.test.yml build --progress=plain

echo ""
echo "==> running E2E: server + test-runner container ..."
docker compose -f docker-compose.test.yml up --abort-on-container-exit --exit-code-from test-runner

echo ""
echo "==> cleanup"
docker compose -f docker-compose.test.yml down -v

echo ""
echo "==> ALL DOCKER TESTS PASSED"
