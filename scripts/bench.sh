#!/usr/bin/env bash
# 运行全部基准并输出表格，供 README「基准」表重测对比。
# 用法: scripts/bench.sh            # recordbuffer/cache/engine（快）
#       scripts/bench.sh all       # 加 db 包（TF 卡上很慢）
#       scripts/bench.sh -count=1  # 自定义次数
set -euo pipefail

cd "$(dirname "$0")/.."

ARGS=(-benchtime=300ms)
DIRS=(recordbuffer cache engine)
for a in "$@"; do
  case "$a" in
    all) DIRS=(recordbuffer cache engine db) ;;
    *) ARGS+=("$a") ;;
  esac
done

run_pkg() {
  local pkg="$1"
  local out
  out=$(go test "./$pkg/" -bench . -benchmem -run '^$' "${ARGS[@]:-}" 2>/dev/null || true)
  if ! echo "$out" | grep -q '^Benchmark'; then
    echo "[$pkg] 无基准输出或失败"
    return
  fi
  echo "==== $pkg ===="
  # engine 的慢 flush 基准会把日志插入结果行，导致名字与数字分两行，这里合并还原
  echo "$out" | awk '
    /^Benchmark/ && /ns\/op/ { print $1, $3; next }
    /^Benchmark/ {
      name = $1
      while (getline > 0) {
        if ($0 ~ /ns\/op/) { print name, $2; break }
      }
    }'
  echo
}

for d in "${DIRS[@]}"; do
  run_pkg "$d"
done
