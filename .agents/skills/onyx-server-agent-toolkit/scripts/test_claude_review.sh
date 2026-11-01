#!/usr/bin/env bash
# Prove the reviewer reads a private snapshot during a transient live symlink swap.
set -euo pipefail

project_root="$(git rev-parse --show-toplevel)"
launcher="$project_root/tools/claude-review.sh"
stub="$project_root/.agents/skills/onyx-server-agent-toolkit/scripts/claude_review_stub.py"
review_tmp_base="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)"
test_root="$(mktemp -d "$review_tmp_base/onyx-claude-review-test.XXXXXX")"
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT

repo="$test_root/repo"
mkdir -p -- "$repo/.claude/agents" "$test_root/bin"
git -C "$repo" init -q
printf '%s\n' \
  '---' \
  'name: onyx-fast-auditor' \
  'description: Test reviewer' \
  'tools: Read' \
  'model: claude-haiku-4-5-20251001' \
  'effort: low' \
  '---' \
  'ORIGINAL_AGENT_BYTES' \
  > "$repo/.claude/agents/onyx-fast-auditor.md"
ln -s -- "$stub" "$test_root/bin/claude"
printf '%s\n' 'ORIGINAL_REVIEW_BYTES' > "$repo/scope.txt"
printf '%s\n' 'OUTSIDE_SENTINEL_BYTES' > "$test_root/sentinel.txt"
printf '%s\n' 'OUTSIDE_AGENT_SENTINEL_BYTES' > "$test_root/agent-sentinel.md"
touch "$test_root/hold"

(
  cd "$repo"
  PATH="$test_root/bin:$PATH" \
    CLAUDE_STUB_READY="$test_root/ready" \
    CLAUDE_STUB_HOLD="$test_root/hold" \
    CLAUDE_STUB_OBSERVED="$test_root/observed" \
    CLAUDE_STUB_RESULT_MODE=fenced \
    "$launcher" fast --file scope.txt -- 'Exercise snapshot isolation.' \
    > "$test_root/result.json" 2> "$test_root/review.err"
) &
review_pid="$!"

for _ in $(seq 1 1000); do
  [ -e "$test_root/ready" ] && break
  kill -0 "$review_pid" 2>/dev/null || {
    wait "$review_pid" || true
    cat "$test_root/review.err" >&2
    exit 1
  }
  sleep 0.01
done
[ -e "$test_root/ready" ] || {
  echo "review stub never became ready" >&2
  exit 1
}

mv -- "$repo/scope.txt" "$repo/scope.saved"
ln -s -- "$test_root/sentinel.txt" "$repo/scope.txt"
mv -- "$repo/.claude/agents/onyx-fast-auditor.md" "$repo/.claude/agents/agent.saved"
ln -s -- "$test_root/agent-sentinel.md" \
  "$repo/.claude/agents/onyx-fast-auditor.md"
sleep 0.1
rm -- "$repo/scope.txt"
mv -- "$repo/scope.saved" "$repo/scope.txt"
rm -- "$repo/.claude/agents/onyx-fast-auditor.md"
mv -- "$repo/.claude/agents/agent.saved" \
  "$repo/.claude/agents/onyx-fast-auditor.md"
rm -- "$test_root/hold"
wait "$review_pid" || {
  cat "$test_root/review.err" >&2
  exit 1
}

jq -e '.verdict == "pass" and (.findings | length) == 0' \
  "$test_root/result.json" >/dev/null
grep -F 'ORIGINAL_REVIEW_BYTES' "$test_root/observed" >/dev/null
grep -F 'ORIGINAL_AGENT_BYTES' "$test_root/observed" >/dev/null
if grep -F 'OUTSIDE_SENTINEL_BYTES' "$test_root/observed" >/dev/null; then
  echo "reviewer observed transient out-of-scope symlink target" >&2
  exit 1
fi
if grep -F 'OUTSIDE_AGENT_SENTINEL_BYTES' "$test_root/observed" >/dev/null; then
  echo "reviewer observed transient agent-definition symlink target" >&2
  exit 1
fi
grep -F "cwd=$review_tmp_base/onyx-claude-snapshot." "$test_root/observed" >/dev/null
[ "$(grep -c '^cwd=' "$test_root/observed")" -eq 1 ]
review_snapshot="$(sed -n 's/^cwd=//p' "$test_root/observed")"
if [ -e "$review_snapshot" ] || [ -L "$review_snapshot" ]; then
  echo "review snapshot survived launcher cleanup" >&2
  exit 1
fi

set +e
(
  cd "$repo"
  "$launcher" fast --file $'scope.txt\nsecond.txt' -- 'Reject ambiguous scope.'
) > /dev/null 2> "$test_root/control-path.err"
control_status="$?"
set -e
[ "$control_status" -eq 2 ]
grep -F 'scope paths cannot contain control separators' \
  "$test_root/control-path.err" >/dev/null

set +e
printf '%s\n' 'AMBIGUOUS_PATH_BYTES' > "$repo/scope,txt"
(
  cd "$repo"
  "$launcher" fast --file 'scope,txt' -- 'Reject ambiguous permission rule.'
) > /dev/null 2> "$test_root/metachar-path.err"
metachar_status="$?"
set -e
[ "$metachar_status" -eq 2 ]
grep -F 'scope path contains unsupported permission-rule characters' \
  "$test_root/metachar-path.err" >/dev/null
echo "snapshot isolation regression passed"
