#!/usr/bin/env bash
# 快速验证 MVP 端点与 HEAD 回退
set -euo pipefail

BASE_URL=${BASE_URL:-${1:-http://127.0.0.1:8080}}
NAME=${NAME:-${2:-alice}}
MAX_TIME=${MAX_TIME:-8}

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
ok() { printf "  [OK ] %s\n" "$*"; }
err() { printf "  [ERR] %s\n" "$*"; }

host_from_url() {
  printf "%s" "$1" | sed -E 's|^[a-z]+://||; s|/.*$||'
}

expect_status() {
  local method=$1; shift
  local url=$1; shift
  local expect=$1; shift
  # 额外 curl 参数（如 -H ...），在 set -u 下需安全展开
  local -a extra
  if [[ $# -gt 0 ]]; then
    extra=("$@")
  else
    extra=()
  fi
  local code
  if [[ "$method" == HEAD ]]; then
    code=$(curl -sS -I --max-time "$MAX_TIME" -o /dev/null -w "%{http_code}" "${url}") || code=000
  else
    if [[ ${#extra[@]} -gt 0 ]]; then
      code=$(curl -sS --max-time "$MAX_TIME" -o /dev/null -w "%{http_code}" "${extra[@]}" "${url}") || code=000
    else
      code=$(curl -sS --max-time "$MAX_TIME" -o /dev/null -w "%{http_code}" "${url}") || code=000
    fi
  fi
  if [[ "$code" == "$expect" ]]; then ok "$method $url -> $code"; else err "$method $url -> $code (expect $expect)"; fi
}

expect_ct() {
  local url=$1; shift
  local expect=$1; shift
  local ct
  # 使用 GET 获取响应头，避免 HEAD 回退导致无 Content-Type
  ct=$(curl -sS --max-time "$MAX_TIME" -D - -o /dev/null "$url" | awk -F': ' 'tolower($1)=="content-type"{print tolower($2)}' | tr -d '\r') || ct=""
  if printf "%s" "$ct" | grep -qi "$expect"; then ok "CT $url -> $ct"; else err "CT $url -> $ct (expect ~$expect)"; fi
}

bold "Verifying MVP endpoints on: $BASE_URL"
HOST=$(host_from_url "$BASE_URL")

# health
expect_status GET  "$BASE_URL/health" 200
expect_status HEAD "$BASE_URL/health" 200

# webfinger
WF_URL="$BASE_URL/.well-known/webfinger?resource=acct:${NAME}@${HOST}"
expect_status GET  "$WF_URL" 200
expect_ct "$WF_URL" "application/jrd+json"
expect_status HEAD "$BASE_URL/.well-known/webfinger" 200

# host-meta
expect_status GET  "$BASE_URL/.well-known/host-meta" 200
expect_status HEAD "$BASE_URL/.well-known/host-meta" 200

# nodeinfo
expect_status GET  "$BASE_URL/.well-known/nodeinfo" 200
expect_status HEAD "$BASE_URL/.well-known/nodeinfo" 200
expect_status GET  "$BASE_URL/nodeinfo/2.1" 200
expect_status HEAD "$BASE_URL/nodeinfo/2.1" 200

# actor profile
expect_status GET  "$BASE_URL/users/$NAME" 200 -H "Accept: application/activity+json"
expect_ct "$BASE_URL/users/$NAME" "application/activity+json"
expect_status HEAD "$BASE_URL/users/$NAME" 200

# outbox
expect_status GET  "$BASE_URL/users/$NAME/outbox" 200 -H "Accept: application/activity+json"
expect_ct "$BASE_URL/users/$NAME/outbox" "application/activity+json"
expect_status HEAD "$BASE_URL/users/$NAME/outbox" 200

bold "Done."
