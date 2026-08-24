#!/usr/bin/env bash
# 本地 CI：build + vet + test + race（本机不支持则跳过）+ 覆盖率门禁 + 可选 PG 真库用例。
# 用法:
#   scripts/ci.sh                        # 全套
#   CI_COVER_THRESHOLD=90 scripts/ci.sh  # 自定义覆盖率门禁
#   PG_TEST_DSN=... scripts/ci.sh        # 启用 PG 门控用例
set -euo pipefail
cd "$(dirname "$0")/.."

THRESHOLD="${CI_COVER_THRESHOLD:-85.0}"
FAIL=0

step() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }

step "build ./..."
go build ./...

step "vet ./..."
go vet ./...

step "test ./... (-count=1)"
go test -count=1 ./...

step "test -race ./..."
if go test -race -count=1 ./cache/ >/tmp/race_probe 2>&1; then
  go test -race -count=1 ./...
else
  if grep -q "unsupported VMA range" /tmp/race_probe; then
    echo "SKIP: -race 本机不可用（arm64 ASLR 熵 39bit，TSan 需 <=32）；CI 环境应启用此步"
  else
    echo "WARN: -race 探测失败（非 VMA 限制）:"
    cat /tmp/race_probe
    FAIL=1
  fi
fi

step "coverage gate (>= ${THRESHOLD}%)"
go test -coverprofile=/tmp/pki-db-lib.cover -count=1 ./... >/dev/null
TOTAL=$(go tool cover -func=/tmp/pki-db-lib.cover | tail -1 | awk '{print $3}' | tr -d '%')
echo "total: ${TOTAL}% (gate ${THRESHOLD}%)"
if awk -v t="$TOTAL" -v g="$THRESHOLD" 'BEGIN{exit !(t < g)}'; then
  echo "FAIL: 覆盖率低于门禁"; FAIL=1
fi

if [ -n "${PG_TEST_DSN:-}" ]; then
  step "PostgreSQL 真库用例（PG_TEST_DSN 已设置）"
  go test -tags postgres ./db/ -run 'TestPGConnect|TestPGAdvisoryLockReal|TestPGTransferToReal' -count=1
fi

if [ -n "${MYSQL_TEST_DSN:-}" ]; then
  step "MariaDB 真库用例（MYSQL_TEST_DSN 已设置）"
  go test -tags mysql ./db/ -run 'TestMySQLConnect|TestMySQLCertRoundtrip|TestMySQLBulkInsert|TestMySQLTransferTo' -count=1
fi

step "结果"
if [ "$FAIL" -ne 0 ]; then
  echo "CI 未通过（见上方 WARN/FAIL）"
  exit 1
fi
echo "全部通过"
