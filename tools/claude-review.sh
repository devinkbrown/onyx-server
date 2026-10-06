#!/usr/bin/env bash
# Run a bounded, read-only Claude Code review and reject ungrounded JSON.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: tools/claude-review.sh <fast|integration|security> \
  [--agent <review-agent>] --file <repo-relative-path> [--file <path> ...] -- \
  <review prompt>

Examples:
  tools/claude-review.sh fast --file src/proto/foo.zig -- 'Check codec bounds.'
  tools/claude-review.sh security --agent onyx-server-helix-reviewer \
    --file src/daemon/helix/live.zig --file src/daemon/server.zig -- \
    'Try to falsify transactional current-version adoption.'
EOF
  exit 2
}

frontmatter_value() {
  local file="$1"
  local key="$2"
  awk -v key="$key" '
    { sub(/\r$/, "") }
    $0 == "---" { section += 1; next }
    section == 1 && index($0, key ":") == 1 {
      sub("^[^:]+:[[:space:]]*", "")
      print
    }
    section >= 2 { exit }
  ' "$file"
}

[ "$#" -ge 5 ] || usage

lane="$1"
shift

case "$lane" in
  fast)
    default_agent="onyx-fast-auditor"
    max_scope=4
    timeout_seconds=300
    max_budget_usd=0.75
    ;;
  integration)
    default_agent="onyx-integration-reviewer"
    max_scope=10
    timeout_seconds=900
    max_budget_usd=3.00
    ;;
  security)
    default_agent="onyx-security-reviewer"
    max_scope=12
    timeout_seconds=1200
    max_budget_usd=6.00
    ;;
  *)
    usage
    ;;
esac

agent="$default_agent"
declare -a requested_files=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --agent)
      [ "$#" -ge 2 ] || usage
      agent="$2"
      shift 2
      ;;
    --file)
      [ "$#" -ge 2 ] || usage
      requested_files+=("$2")
      shift 2
      ;;
    --)
      shift
      break
      ;;
    *)
      usage
      ;;
  esac
done

[ "$#" -eq 1 ] || usage
[ "${#requested_files[@]}" -gt 0 ] || usage
prompt="$1"
[ -n "$prompt" ] || usage

# The structured review path accepts review-only agents. Writer prompts are
# intentionally excluded: they are broader, slower, and can fight the JSON
# contract even when the CLI tool surface itself is read-only.
case "$lane:$agent" in
  fast:onyx-fast-auditor|\
  integration:onyx-integration-reviewer|\
  integration:onyx-reviewer|\
  security:onyx-security-reviewer|\
  security:onyx-reviewer)
    ;;
  *)
    echo "agent $agent is not a bounded read-only reviewer for lane $lane" >&2
    exit 2
    ;;
esac

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

raw_file=""
snapshot_root=""
cleanup_review() {
  local status="$?"
  if [ -n "$snapshot_root" ]; then
    case "$snapshot_root" in
      /tmp/onyx-claude-snapshot.*)
        chmod -R u+w -- "$snapshot_root" 2>/dev/null || true
        rm -rf -- "$snapshot_root"
        ;;
    esac
  fi
  if [ -n "$raw_file" ] && [ -e "$raw_file" ]; then
    if [ "$status" -eq 0 ]; then
      rm -f -- "$raw_file"
    else
      echo "Claude review failed; raw output preserved at $raw_file" >&2
    fi
  fi
}
trap cleanup_review EXIT

declare -a files=()
for requested in "${requested_files[@]}"; do
  case "$requested" in
    /*)
      echo "scope paths must be repository-relative: $requested" >&2
      exit 2
      ;;
    *$'\n'*|*$'\r'*|*$'\t'*)
      echo "scope paths cannot contain control separators" >&2
      exit 2
      ;;
  esac
  canonical="$(realpath -e -- "$requested")" || {
    echo "scope file does not exist: $requested" >&2
    exit 2
  }
  case "$canonical" in
    "$repo_root"/*) ;;
    *)
      echo "scope path escapes the repository: $requested" >&2
      exit 2
      ;;
  esac
  [ -f "$canonical" ] || {
    echo "scope path is not a regular file: $requested" >&2
    exit 2
  }
  relative="${canonical#"$repo_root"/}"
  [[ "$relative" =~ ^[A-Za-z0-9._/@%+-]+$ ]] || {
    echo "scope path contains unsupported permission-rule characters: $requested" >&2
    exit 2
  }
  files+=("$relative")
done
mapfile -t files < <(printf '%s\n' "${files[@]}" | LC_ALL=C sort -u)
if [ "${#files[@]}" -gt "$max_scope" ]; then
  echo "$lane reviews accept at most $max_scope files; split the review into bounded seams" >&2
  exit 2
fi

agent_file=".claude/agents/$agent.md"
[ -f "$agent_file" ] && [ ! -L "$agent_file" ] || {
  echo "review agent definition is missing or is a symlink: $agent_file" >&2
  exit 2
}
agent_canonical="$(realpath -e -- "$agent_file")"
[ "$agent_canonical" = "$repo_root/$agent_file" ] || {
  echo "review agent definition escapes the repository: $agent_file" >&2
  exit 2
}
agent_lines="$(wc -l < "$agent_file")"
agent_hash="$(sha256sum -- "$agent_file" | cut -d' ' -f1)"
routing_file=".claude/agents/$default_agent.md"
[ -f "$routing_file" ] && [ ! -L "$routing_file" ] || {
  echo "lane routing definition is missing or is a symlink: $routing_file" >&2
  exit 2
}
routing_canonical="$(realpath -e -- "$routing_file")"
[ "$routing_canonical" = "$repo_root/$routing_file" ] || {
  echo "lane routing definition escapes the repository: $routing_file" >&2
  exit 2
}
mapfile -t model_values < <(frontmatter_value "$routing_file" model)
mapfile -t effort_values < <(frontmatter_value "$routing_file" effort)
[ "${#model_values[@]}" -eq 1 ] && [ -n "${model_values[0]}" ] &&
  [ "${#effort_values[@]}" -eq 1 ] && [ -n "${effort_values[0]}" ] || {
    echo "lane routing definition must contain exactly one model and effort" >&2
    exit 2
  }
model="${model_values[0]}"
effort="${effort_values[0]}"
routing_lines="$(wc -l < "$routing_file")"
routing_hash="$(sha256sum -- "$routing_file" | cut -d' ' -f1)"

review_nonce="$(
  {
    printf '%s\0%s\0%s\0%s\0%s\0%s\0%s\0' \
      "$lane" "$agent" "$agent_hash" "$routing_hash" "$model" "$effort" "$prompt"
    printf '%s\0' "${files[@]}"
    date +%s%N
    printf '%s' "$$"
  } | sha256sum | cut -d' ' -f1
)"

declare -A starting_lines=()
declare -A starting_hashes=()
declare -a manifest_lines=()
declare -a read_rules=()
declare -a permission_rules=("StructuredOutput")
snapshot_root="$(mktemp -d /tmp/onyx-claude-snapshot.XXXXXX)"
git -C "$snapshot_root" init -q
mkdir -p -- "$snapshot_root/.claude/agents"
cp -- "$agent_file" "$snapshot_root/$agent_file"
[ "$(wc -l < "$snapshot_root/$agent_file")" = "$agent_lines" ] &&
  [ "$(sha256sum -- "$snapshot_root/$agent_file" | cut -d' ' -f1)" = "$agent_hash" ] || {
    echo "review agent definition changed while snapshotting: $agent_file" >&2
    exit 1
  }
for file in "${files[@]}"; do
  canonical="$(realpath -e -- "$file")" || {
    echo "scope file disappeared while snapshotting: $file" >&2
    exit 1
  }
  [ "$canonical" = "$repo_root/$file" ] || {
    echo "scope file changed identity while snapshotting: $file" >&2
    exit 1
  }
  line_count="$(wc -l < "$file")"
  file_hash="$(sha256sum -- "$file" | cut -d' ' -f1)"
  starting_lines["$file"]="$line_count"
  starting_hashes["$file"]="$file_hash"
  mkdir -p -- "$snapshot_root/$(dirname -- "$file")"
  cp -- "$file" "$snapshot_root/$file"
  [ "$(wc -l < "$snapshot_root/$file")" = "$line_count" ] &&
    [ "$(sha256sum -- "$snapshot_root/$file" | cut -d' ' -f1)" = "$file_hash" ] || {
      echo "scope file changed while snapshotting: $file" >&2
      exit 1
    }
  manifest_lines+=("$(printf '%s\tread_path=%s/%s\tlines=%s\tsha256=%s' \
    "$file" "$snapshot_root" "$file" "$line_count" "$file_hash")")
  # Claude permission syntax uses `//` for an absolute filesystem path. The
  # manifest's normal `/tmp/...` read_path therefore becomes `Read(//tmp/...)`.
  read_rules+=("Read(/$file)" "Read(/$snapshot_root/$file)")
done
permission_rules+=("${read_rules[@]}")
chmod -R a-w -- "$snapshot_root"
scope_manifest="$(printf '%s\n' "${manifest_lines[@]}")"
settings_json="$(jq -cn --args \
  '{permissions: {defaultMode: "dontAsk", allow: $ARGS.positional}}' \
  "${permission_rules[@]}")"

schema='{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "review_nonce": {"type": "string", "minLength": 64, "maxLength": 64},
    "verdict": {"type": "string", "enum": ["pass", "findings"]},
    "summary": {"type": "string", "minLength": 8},
    "reviewed_files": {
      "type": "array",
      "minItems": 1,
      "uniqueItems": true,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "file": {"type": "string", "minLength": 1},
          "line": {"type": "integer", "minimum": 1},
          "anchor": {"type": "string", "minLength": 1, "maxLength": 200}
        },
        "required": ["file", "line", "anchor"]
      }
    },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "severity": {"type": "string", "enum": ["P0", "P1", "P2", "P3"]},
          "title": {"type": "string", "minLength": 8},
          "file": {"type": "string", "minLength": 1},
          "line": {"type": "integer", "minimum": 1},
          "evidence": {"type": "string", "minLength": 1, "maxLength": 200},
          "counterexample": {"type": "string", "minLength": 8},
          "impact": {"type": "string", "minLength": 8},
          "fix": {"type": "string", "minLength": 8},
          "test": {"type": "string", "minLength": 8}
        },
        "required": ["severity", "title", "file", "line", "evidence", "counterexample", "impact", "fix", "test"]
      }
    }
  },
  "required": ["review_nonce", "verdict", "summary", "reviewed_files", "findings"]
}'

full_prompt="$(printf '%s\n\nReview nonce: %s\nReviewer definition SHA-256: %s\nLane routing: %s model=%s effort=%s SHA-256=%s\n\nExact review scope (path, snapshot line count, snapshot SHA-256):\n%s\n\n%s\n\n%s\n\n%s' \
  'Read every scoped file from this immutable snapshot. In each Read call, use the exact absolute read_path printed for that file; never prepend a slash to the report path. Report the first manifest field as file. Review only these files and the behavior named below. Do not edit anything. Do not report style preferences. Findings must be reachable and independently evidenced.' \
  "$review_nonce" \
  "$agent_hash" \
  "$default_agent" \
  "$model" \
  "$effort" \
  "$routing_hash" \
  "$scope_manifest" \
  'Return the nonce verbatim. For every scoped file, include exactly one reviewed_files record with a nonblank source line and an exact, distinctive substring from that current line as anchor. Every finding must cite a scoped file and include an exact substring from its cited current line as evidence. Never emit examples or placeholders. If there is no concrete issue, return verdict pass with an empty findings array.' \
  'Return only one JSON object with exactly these top-level keys: review_nonce, verdict, summary, reviewed_files, findings. Do not wrap JSON in Markdown. Verdict must be exactly pass or findings, never fail. Severity must be exactly P0, P1, P2, or P3, never high/medium/low. Each reviewed_files item has file, line, anchor. Each findings item has severity, title, file, line, evidence, counterexample, impact, fix, test.' \
  "$prompt")"

raw_file="$(mktemp /tmp/onyx-claude-review.XXXXXX.json)"

(
  cd "$snapshot_root"
  timeout --signal=TERM --kill-after=10s "${timeout_seconds}s" claude -p "$full_prompt" \
    --agent "$agent" \
    --model "$model" \
    --effort "$effort" \
    --max-budget-usd "$max_budget_usd" \
    --permission-mode dontAsk \
    --settings "$settings_json" \
    --setting-sources project,local \
    --disable-slash-commands \
    --strict-mcp-config \
    --mcp-config '{"mcpServers":{}}' \
    --no-chrome \
    --no-session-persistence \
    --output-format json \
    --json-schema "$schema" \
    --tools Read StructuredOutput
) > "$raw_file"
raw="$(<"$raw_file")"

# The reviewer reads only the private immutable copy. Reject its result when
# the live path no longer identifies the snapshotted file at validation time.
agent_canonical="$(realpath -e -- "$agent_file")" || {
  echo "review agent definition disappeared during review: $agent_file" >&2
  exit 1
}
[ "$agent_canonical" = "$repo_root/$agent_file" ] &&
  [ "$(wc -l < "$agent_file")" = "$agent_lines" ] &&
  [ "$(sha256sum -- "$agent_file" | cut -d' ' -f1)" = "$agent_hash" ] || {
    echo "review agent definition changed during review: $agent_file" >&2
    exit 1
  }
routing_canonical="$(realpath -e -- "$routing_file")" || {
  echo "lane routing definition disappeared during review: $routing_file" >&2
  exit 1
}
[ "$routing_canonical" = "$repo_root/$routing_file" ] &&
  [ "$(wc -l < "$routing_file")" = "$routing_lines" ] &&
  [ "$(sha256sum -- "$routing_file" | cut -d' ' -f1)" = "$routing_hash" ] || {
    echo "lane routing definition changed during review: $routing_file" >&2
    exit 1
  }
for file in "${files[@]}"; do
  canonical="$(realpath -e -- "$file")" || {
    echo "scoped file disappeared during review: $file" >&2
    exit 1
  }
  [ "$canonical" = "$repo_root/$file" ] || {
    echo "scoped file changed identity during review: $file" >&2
    exit 1
  }
  [ "$(wc -l < "$file")" = "${starting_lines[$file]}" ] || {
    echo "scoped file changed line count during review: $file" >&2
    exit 1
  }
  [ "$(sha256sum -- "$file" | cut -d' ' -f1)" = "${starting_hashes[$file]}" ] || {
    echo "scoped file changed content during review: $file" >&2
    exit 1
  }
done

fail_validation() {
  echo "Claude review failed grounding validation" >&2
  exit 1
}

structured="$(printf '%s\n' "$raw" | jq -ce '
  if .is_error != false then
    error("Claude reported an error")
  elif .structured_output != null then
    .structured_output
  elif (.result | type) == "string" then
    (.result as $result |
      try ($result | fromjson)
      catch (
        $result |
        capture("(?s)^\\s*```(?:json)?\\s*(?<body>\\{.*\\})\\s*```\\s*$").body |
        fromjson
      ))
  else
    error("Claude returned neither structured_output nor a JSON result")
  end
')" || fail_validation

printf '%s\n' "$structured" | jq -e --arg nonce "$review_nonce" '
  type == "object" and
  (keys | sort) == (["findings", "review_nonce", "reviewed_files", "summary", "verdict"] | sort) and
  .review_nonce == $nonce and
  (.summary | type) == "string" and (.summary | length) >= 8 and
  (.reviewed_files | type) == "array" and (.reviewed_files | length) > 0 and
  all(.reviewed_files[];
    type == "object" and
    (keys | sort) == (["anchor", "file", "line"] | sort) and
    (.file | type) == "string" and (.file | length) > 0 and
    (.line | type) == "number" and .line >= 1 and (.line | floor) == .line and
    (.anchor | type) == "string" and (.anchor | length) > 0 and (.anchor | length) <= 200
  ) and
  (.findings | type) == "array" and
  all(.findings[];
    type == "object" and
    (keys | sort) == (["counterexample", "evidence", "file", "fix", "impact", "line", "severity", "test", "title"] | sort) and
    (.severity == "P0" or .severity == "P1" or .severity == "P2" or .severity == "P3") and
    (.file | type) == "string" and (.file | length) > 0 and
    (.line | type) == "number" and .line >= 1 and (.line | floor) == .line and
    (.evidence | type) == "string" and (.evidence | length) > 0 and (.evidence | length) <= 200 and
    (.title | type) == "string" and (.title | length) >= 8 and
    (.counterexample | type) == "string" and (.counterexample | length) >= 8 and
    (.impact | type) == "string" and (.impact | length) >= 8 and
    (.fix | type) == "string" and (.fix | length) >= 8 and
    (.test | type) == "string" and (.test | length) >= 8
  ) and
  ((.verdict == "pass" and (.findings | length) == 0) or
   (.verdict == "findings" and (.findings | length) > 0))
' >/dev/null || fail_validation

mapfile -t reported_files < <(
  printf '%s\n' "$structured" | jq -r '.reviewed_files[].file' | LC_ALL=C sort
)
if [ "${#reported_files[@]}" -ne "${#files[@]}" ] ||
   [ "$(printf '%s\n' "${reported_files[@]}")" != "$(printf '%s\n' "${files[@]}")" ]; then
  fail_validation
fi

is_scoped_file() {
  local candidate="$1"
  local expected
  for expected in "${files[@]}"; do
    [ "$candidate" = "$expected" ] && return 0
  done
  return 1
}

validate_anchor_records() {
  local jq_path="$1"
  local evidence_key="$2"
  local encoded record file line evidence source_line
  while IFS= read -r encoded; do
    record="$(printf '%s' "$encoded" | base64 --decode)"
    file="$(printf '%s' "$record" | jq -r '.file')"
    line="$(printf '%s' "$record" | jq -r '.line')"
    evidence="$(printf '%s' "$record" | jq -r --arg key "$evidence_key" '.[$key]')"
    is_scoped_file "$file" || return 1
    source_line="$(sed -n "${line}p" -- "$snapshot_root/$file")"
    [ -n "$source_line" ] || return 1
    case "$source_line" in
      *"$evidence"*) ;;
      *) return 1 ;;
    esac
  done < <(printf '%s\n' "$structured" | jq -r "$jq_path | @base64")
}

validate_anchor_records '.reviewed_files[]' anchor || fail_validation
validate_anchor_records '.findings[]' evidence || fail_validation

printf '%s\n' "$structured" | jq .
