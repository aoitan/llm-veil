#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
fixture_tmp_dir=""

cleanup_fixture_tmp_dir() {
    if [[ -n "${fixture_tmp_dir}" && -d "${fixture_tmp_dir}" ]]; then
        rm -rf -- "${fixture_tmp_dir}"
    fi
}

trap cleanup_fixture_tmp_dir EXIT

usage() {
    cat <<'EOF'
Usage: scripts/design_lint.sh <fast|full|advisory>

Run the repository design-lint checks from the repository root.

 Profiles (registered design-policy checks are blocking; P1 and unsuitable
 module-graph diagnostics are report-only):
  fast  Tool versions, rustfmt, all-target Cargo tests, strict contract verification,
        repository-wide all-target Clippy baseline (-D warnings), acceptance coverage,
        expectation inventory,
        P1 lint report, DL-001/DL-002/DL-003/DL-004/DL-006/DL-007 production
        boundary lint, exception-scope checks, and design fixtures.
  full  The fast checks plus deterministic cargo-deny bans/licenses/sources,
        cargo-machete unused-dependency detection, Cargo metadata/check, the
        advisory cargo-modules acyclic diagnostic, storage spike tests, and
        Python syntax verification for the verification scripts.
  advisory  The RustSec advisory database check only. This profile is
            blocking by default; CI makes it report-only for pull requests.

The dependency tools have exact versions in design-lint-tools.json. The fast
profile verifies only the Rust toolchain it uses; full additionally verifies
every required dependency tool. The advisory profile verifies only cargo-deny.
The full
profile blocks on the deterministic dependency policy and unused-dependency
checks; the current cargo-modules graph is report-only until its output is
suitable for enforcing the architectural layer rule. cargo-geiger and Dylint
remain separate follow-up concerns.

The script may be invoked from any working directory. Local runs and CI should
call this same entrypoint with the appropriate profile.
EOF
}

print_command() {
    printf '[design-lint] command:'
    printf ' %q' "$@"
    printf '\n'
}

run_check() {
    local name="$1"
    shift
    local started_at=$SECONDS
    local status

    printf '\n[design-lint] START check=%s\n' "$name"
    print_command "$@"

    if "$@"; then
        status=0
    else
        status=$?
    fi

    local duration=$((SECONDS - started_at))
    if ((status == 0)); then
        printf '[design-lint] PASS check=%s duration=%ss\n' "$name" "$duration"
        return 0
    fi

    printf '[design-lint] FAIL check=%s duration=%ss exit=%s reason=command failed\n' \
        "$name" "$duration" "$status" >&2
    return "$status"
}

run_report_only_check() {
    local name="$1"
    shift
    local started_at=$SECONDS
    local status

    printf '\n[design-lint] START report-only=%s\n' "$name"
    print_command "$@"

    if "$@"; then
        status=0
    else
        status=$?
    fi

    local duration=$((SECONDS - started_at))
    if ((status == 0)); then
        printf '[design-lint] PASS report-only=%s duration=%ss\n' "$name" "$duration"
    else
        printf '[design-lint] ADVISORY report-only=%s duration=%ss exit=%s reason=report-failed\n' \
            "$name" "$duration" "$status" >&2
    fi

    # P1 is intentionally observable without making an otherwise unrelated
    # change unmergeable. Scheduled/CI policy can promote this report later.
    return 0
}

run_toolchain_checks() {
    run_check 'tool-cargo-version' cargo --version || return $?
    run_check 'tool-rustc-version' rustc --version || return $?
    run_check 'tool-rustfmt-version' cargo fmt --version || return $?
    run_check 'tool-python-version' python3 --version || return $?
    run_check 'tool-version-policy' check_tool_versions --toolchain-only || return $?
    run_check 'tool-version-policy-self-test' check_tool_version_policy_self_test --toolchain-only || return $?
}

check_tool_versions() {
    python3 - "${repo_root}" "${DESIGN_LINT_TOOLS_MANIFEST:-${repo_root}/design-lint-tools.json}" "$@" <<'PY'
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
manifest_path = Path(sys.argv[2])
tool_scope = set(sys.argv[3:])
toolchain_only = "--toolchain-only" in tool_scope
tool_scope.discard("--toolchain-only")
if not manifest_path.is_absolute():
    manifest_path = repo_root / manifest_path

version_pattern = re.compile(r"(?<![0-9A-Za-z])(\d+\.\d+\.\d+)(?![0-9A-Za-z])")
errors = []

try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    print(f"[design-lint] tool-version-error: cannot read {manifest_path}: {error}", file=sys.stderr)
    raise SystemExit(1)

if manifest.get("schema_version") != "1.0":
    errors.append(f"manifest-schema expected=1.0 actual={manifest.get('schema_version')!r}")

toolchain = manifest.get("toolchain")
if not isinstance(toolchain, dict):
    errors.append("manifest-toolchain missing or not an object")
    toolchain = {}

def run_version_check(name, command, expected):
    executable = shutil.which(command[0])
    if executable is None:
        errors.append(f"tool-missing: {name} command={command[0]}")
        return

    try:
        result = subprocess.run(
            [executable, *command[1:]],
            cwd=repo_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError as error:
        errors.append(f"tool-exec-error: {name} command={executable}: {error}")
        return

    output = result.stdout or ""
    if result.returncode != 0:
        errors.append(f"tool-version-command-failed: {name} exit={result.returncode}")
        return

    match = version_pattern.search(output)
    actual = match.group(1) if match else None
    if actual != expected:
        errors.append(f"tool-version-mismatch: {name} expected={expected} actual={actual or 'unknown'}")
        return

    print(f"[design-lint] tool version verified: {name}={actual} path={executable}")

required_toolchain = {
    "cargo": ["cargo", "--version"],
    "rustc": ["rustc", "--version"],
    "rustfmt": ["cargo", "fmt", "--version"],
}
for name, command in required_toolchain.items():
    expected = toolchain.get(name)
    if not isinstance(expected, str) or not version_pattern.fullmatch(expected):
        errors.append(f"manifest-version-invalid: {name} value={expected!r}")
        continue
    run_version_check(name, command, expected)

toolchain_file = repo_root / "rust-toolchain.toml"
try:
    toolchain_text = toolchain_file.read_text(encoding="utf-8")
except OSError as error:
    errors.append(f"toolchain-file-error: {error}")
else:
    channel_match = re.search(r"(?m)^\s*channel\s*=\s*[\"']([^\"']+)[\"']\s*$", toolchain_text)
    expected_channel = toolchain.get("channel")
    if channel_match is None:
        errors.append("toolchain-channel-missing: rust-toolchain.toml")
    elif channel_match.group(1) != expected_channel:
        errors.append(
            f"toolchain-channel-mismatch: expected={expected_channel} actual={channel_match.group(1)}"
        )

tools = manifest.get("tools")
if not isinstance(tools, list):
    errors.append("manifest-tools missing or not an array")
    tools = []

seen_names = set()
for tool in tools:
    if not isinstance(tool, dict):
        errors.append("manifest-tool-invalid: entry is not an object")
        continue

    name = tool.get("name")
    binary = tool.get("binary")
    expected = tool.get("version")
    required = tool.get("required")
    if not isinstance(name, str) or name in seen_names:
        errors.append(f"manifest-tool-name-invalid: {name!r}")
        continue
    seen_names.add(name)
    if toolchain_only:
        continue
    if tool_scope and name not in tool_scope:
        continue
    if not isinstance(binary, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", binary):
        errors.append(f"manifest-binary-invalid: {name}")
        continue
    if not isinstance(expected, str) or not version_pattern.fullmatch(expected):
        errors.append(f"manifest-version-invalid: {name} value={expected!r}")
        continue
    if not isinstance(required, bool):
        errors.append(f"manifest-required-invalid: {name}")
        continue

    executable = shutil.which(binary)
    if executable is None:
        if required:
            errors.append(f"tool-missing: {name} command={binary}")
        else:
            print(f"[design-lint] optional tool absent: {name} (expected={expected})")
        continue
    run_version_check(name, [binary, "--version"], expected)

if errors:
    for error in errors:
        print(f"[design-lint] tool-version-error: {error}", file=sys.stderr)
    raise SystemExit(1)

print(f"[design-lint] tool version policy verified: {manifest_path}")
PY
}

check_tool_version_policy_self_test() {
    local -a scope=("$@")
    local manifest_tmp
    local log_file
    manifest_tmp="$(mktemp)"
    log_file="$(mktemp)"

    python3 - "${repo_root}/design-lint-tools.json" "${manifest_tmp}" <<'PY'
import json
import sys

source_path, destination_path = sys.argv[1:]
manifest = json.loads(open(source_path, encoding="utf-8").read())
manifest["toolchain"]["cargo"] = "0.0.0"
with open(destination_path, "w", encoding="utf-8") as output:
    json.dump(manifest, output)
PY

    if DESIGN_LINT_TOOLS_MANIFEST="${manifest_tmp}" check_tool_versions "${scope[@]}" >"${log_file}" 2>&1; then
        cat -- "${log_file}" >&2
        rm -f -- "${manifest_tmp}" "${log_file}"
        printf '[design-lint] version policy self-test failed: mutated manifest was accepted\n' >&2
        return 1
    fi

    if ! grep -Fq 'tool-version-mismatch: cargo' "${log_file}"; then
        cat -- "${log_file}" >&2
        rm -f -- "${manifest_tmp}" "${log_file}"
        printf '[design-lint] version policy self-test failed: mismatch was not diagnosed\n' >&2
        return 1
    fi

    rm -f -- "${manifest_tmp}" "${log_file}"
    printf '[design-lint] version policy self-test detected an exact-version mismatch\n'
}

check_design_lint_policy() {
    python3 - "${repo_root}" <<'PY'
import json
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
manifest_path = repo_root / "design-lint-manifest.json"
source_path = repo_root / "src/main.rs"
clippy_path = repo_root / "clippy.toml"
entrypoint_path = repo_root / "scripts/design_lint.sh"

expected_rules = {
    "DL-001": {"level": "deny", "lints": ["unsafe_code"]},
    "DL-002": {
        "level": "deny",
        "lints": ["clippy::disallowed_methods", "clippy::disallowed_types"],
    },
    "DL-003": {"level": "deny", "lints": ["clippy::disallowed_methods"]},
    "DL-004": {"level": "deny", "lints": ["clippy::disallowed_macros"]},
    "DL-005": {"level": "deny", "lints": []},
    "DL-006": {"level": "deny", "lints": []},
    "DL-007": {"level": "deny", "lints": ["clippy::disallowed_methods"]},
    "DL-008": {"level": "warn", "lints": ["unreachable_pub"]},
    "DL-009": {"level": "advisory", "lints": []},
    "DL-010": {
        "level": "warn",
        "lints": ["clippy::unwrap_used", "clippy::expect_used"],
    },
    "DL-011": {"level": "advisory", "lints": ["clippy::too_many_arguments"]},
}

failures = []

if not manifest_path.is_file():
    failures.append(f"manifest-missing: {manifest_path}")
    manifest = {}
else:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        failures.append(f"manifest-invalid: {error}")
        manifest = {}

if isinstance(manifest, dict) and manifest.get("schema_version") != "1.0":
    failures.append(
        f"manifest-schema-mismatch: expected=1.0 actual={manifest.get('schema_version')}"
    )

rules = manifest.get("rules") if isinstance(manifest, dict) else None
if not isinstance(rules, list):
    failures.append("manifest-rules-missing")
    rules = []

records = {}
for index, rule in enumerate(rules):
    if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
        failures.append(f"rule-invalid: index={index}")
        continue
    identifier = rule["id"]
    if identifier in records:
        failures.append(f"rule-duplicate: {identifier}")
    records[identifier] = rule

if set(records) != set(expected_rules):
    missing = sorted(set(expected_rules) - set(records))
    extra = sorted(set(records) - set(expected_rules))
    if missing:
        failures.append(f"rule-missing: {','.join(missing)}")
    if extra:
        failures.append(f"rule-unregistered: {','.join(extra)}")

for identifier, expected in expected_rules.items():
    rule = records.get(identifier)
    if rule is None:
        continue
    actual_level = rule.get("level")
    actual_lints = rule.get("lints")
    if actual_level != expected["level"]:
        failures.append(
            f"rule-level-mismatch: {identifier} expected={expected['level']} actual={actual_level}"
        )
    if actual_lints != expected["lints"]:
        failures.append(
            f"rule-lints-mismatch: {identifier} expected={','.join(expected['lints']) or 'none'} "
            f"actual={','.join(actual_lints) if isinstance(actual_lints, list) else actual_lints}"
        )

exception_manifest = manifest.get("exception_manifest", {})
if not isinstance(exception_manifest, dict):
    failures.append("exception-manifest-invalid")
else:
    exception_path_text = exception_manifest.get("path")
    if not isinstance(exception_path_text, str) or not exception_path_text:
        failures.append("exception-manifest-path-missing")
    else:
        if exception_path_text != "clippy-baseline.txt":
            failures.append(
                "exception-manifest-path-mismatch: expected=clippy-baseline.txt "
                f"actual={exception_path_text}"
            )
        exception_path = (repo_root / exception_path_text).resolve()
        try:
            exception_path.relative_to(repo_root)
        except ValueError:
            failures.append(f"exception-manifest-outside-repository: {exception_path_text}")
        if not exception_path.is_file():
            failures.append(f"exception-manifest-missing: {exception_path_text}")
    if exception_manifest.get("scope") != "item":
        failures.append(
            f"exception-scope-mismatch: expected=item actual={exception_manifest.get('scope')}"
        )
    if exception_manifest.get("forbid_crate_scope") is not True:
        failures.append("exception-policy-must-forbid-crate-scope")
    if exception_manifest.get("forbid_blanket_allow") is not True:
        failures.append("exception-policy-must-forbid-blanket-allow")

source = source_path.read_text(encoding="utf-8") if source_path.is_file() else ""
attribute = re.compile(
    r"#!\[(?P<level>deny|warn|allow|forbid)\((?P<body>[^\]]*)\)\]",
    re.DOTALL,
)
declared = {}
for match in attribute.finditer(source):
    for lint in re.findall(
        r"(?:clippy::[A-Za-z0-9_]+|unreachable_pub|unsafe_code|unfulfilled_lint_expectations)",
        match.group("body"),
    ):
        declared.setdefault(lint, set()).add(match.group("level"))

required_source_levels = {
    "unsafe_code": "deny",
    "unreachable_pub": "warn",
    "clippy::unwrap_used": "warn",
    "clippy::expect_used": "warn",
    "clippy::too_many_arguments": "warn",
    "unfulfilled_lint_expectations": "deny",
}
for lint, expected_level in required_source_levels.items():
    levels = declared.get(lint, set())
    if levels != {expected_level}:
        failures.append(
            f"source-lint-level-mismatch: {lint} expected={expected_level} "
            f"actual={','.join(sorted(levels)) or 'missing'}"
        )

clippy = clippy_path.read_text(encoding="utf-8") if clippy_path.is_file() else ""
required_clippy_entries = {
    "DL-002": ["std::process::Command::new", "std::process::Command"],
    "DL-003": [
        "std::fs::canonicalize",
        "std::path::Path::canonicalize",
        "std::fs::read",
        "std::fs::read_to_string",
        "std::fs::read_dir",
        "std::fs::File::open",
        "std::fs::OpenOptions::open",
    ],
    "DL-004": ["std::print", "std::println", "std::eprint", "std::eprintln"],
    "DL-007": [
        "std::env::var",
        "std::env::var_os",
        "std::env::vars",
        "std::env::vars_os",
        "std::env::current_dir",
    ],
}
for identifier, entries in required_clippy_entries.items():
    for entry in entries:
        if entry not in clippy:
            failures.append(f"clippy-policy-missing: {identifier} entry={entry}")

entrypoint = entrypoint_path.read_text(encoding="utf-8") if entrypoint_path.is_file() else ""
for lint in (
    "clippy::disallowed_methods",
    "clippy::disallowed_types",
    "clippy::disallowed_macros",
    "unsafe_code",
    "clippy::undocumented_unsafe_blocks",
    "unfulfilled_lint_expectations",
):
    if f"-D {lint}" not in entrypoint:
        failures.append(f"blocking-enforcement-missing: {lint}")

for lint in (
    "unreachable_pub",
    "clippy::unwrap_used",
    "clippy::expect_used",
    "clippy::too_many_arguments",
):
    if f"-W {lint}" not in entrypoint:
        failures.append(f"p1-report-enforcement-missing: {lint}")
    if f"--force-warn {lint}" not in entrypoint:
        failures.append(f"p1-baseline-enforcement-missing: {lint}")

if failures:
    for failure in failures:
        print(f"[design-lint] policy error: {failure}")
    sys.exit(1)

print(
    "[design-lint] policy verified: DL-001..DL-007=deny, "
    "DL-008/DL-010=warn, DL-009/DL-011=advisory"
)
PY
}

check_clippy_expectation_inventory() {
    local scan_root="$1"

    python3 - "${repo_root}" "${scan_root}" <<'PY'
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
scan_root = Path(sys.argv[2]).resolve()
manifest_path = repo_root / "clippy-baseline.txt"

def source_files_for(path):
    if path.is_file():
        return [path] if path.suffix == ".rs" else []
    if path == repo_root:
        return sorted((repo_root / "src").rglob("*.rs")) + sorted(
            (repo_root / "tests").glob("*.rs")
        )
    return sorted(path.rglob("*.rs"))

def report(message):
    print(f"[design-lint] clippy expectation error: {message}")

records = {}
manifest_failed = False
if not manifest_path.is_file():
    report(f"inventory-missing: {manifest_path}")
    manifest_failed = True
else:
    for line_number, line in enumerate(
        manifest_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split("|")
        if len(fields) != 4 or any(not field.strip() for field in fields):
            report(f"inventory-malformed: {manifest_path}:{line_number}")
            manifest_failed = True
            continue

        identifier, lint_field, relative_file, item = (
            field.strip() for field in fields
        )
        if identifier in records:
            report(f"inventory-duplicate-id: {identifier}")
            manifest_failed = True
            continue

        expected_file = (repo_root / relative_file).resolve()
        if not expected_file.is_file() or expected_file.suffix != ".rs":
            report(f"inventory-file-missing: {identifier} file={relative_file}")
            manifest_failed = True

        lints = tuple(sorted(set(lint.strip() for lint in lint_field.split(","))))
        if any(
            lint not in {"dead_code", "unsafe_code", "unreachable_pub"}
            and not lint.startswith("clippy::")
            for lint in lints
        ):
            report(f"inventory-lint-invalid: {identifier} lints={lint_field}")
            manifest_failed = True
        records[identifier] = {
            "lints": set(lints),
            "file": expected_file,
            "relative_file": relative_file,
            "item": item,
        }

attribute = re.compile(
    r"(?P<inner>#!)?\[(?P<kind>allow|expect)\((?P<body>[^\]]*?)\)\]",
    re.DOTALL,
)
lint_name = re.compile(
    r"(?:clippy::[A-Za-z0-9_]+|dead_code|unsafe_code|unreachable_pub)"
)
inventory_id = re.compile(r"\bWB-\d+-\d{3}\b")
delegated_id = re.compile(r"\bDL-\d{3}\b")
tracked_blanket = re.compile(
    r"(?:\bclippy::(?:all|pedantic|restriction|nursery|cargo)\b|"
    r"\b(?:warnings|unused)\b|\bdead_code\b|\bunsafe_code\b|"
    r"\b(?:unreachable_pub|clippy::(?:unwrap_used|expect_used|too_many_arguments))\b|"
    r"\bclippy::disallowed_[A-Za-z0-9_]+\b)"
)
blanket_expect_group = re.compile(
    r"\b(?:clippy::(?:all|pedantic|restriction|nursery|cargo)|warnings|unused)\b"
)
seen = {}
failed = manifest_failed

for path in source_files_for(scan_root):
    text = path.read_text(encoding="utf-8")
    for match in attribute.finditer(text):
        body = match.group("body")
        kind = match.group("kind")
        line = text.count("\n", 0, match.start()) + 1
        location = f"{path}:{line}"

        if kind == "allow":
            if tracked_blanket.search(body):
                report(f"blanket suppression: {location}")
                failed = True
            continue

        if match.group("inner"):
            report(f"broad expectation: {location}")
            failed = True
        if blanket_expect_group.search(body):
            report(f"broad expectation group: {location}")
            failed = True

        reason_match = re.search(r'reason\s*=\s*"([^"]*)"', body)
        reason = reason_match.group(1) if reason_match else ""
        baseline_ids = inventory_id.findall(reason)
        delegated_ids = delegated_id.findall(reason)
        if len(baseline_ids) > 1 or (baseline_ids and delegated_ids):
            report(f"reason-id-ambiguous: {location}")
            failed = True
            continue
        if len(baseline_ids) == 1:
            identifier = baseline_ids[0]
            record = records.get(identifier)
            if record is None:
                report(f"inventory-not-registered: {location} id={identifier}")
                failed = True
                continue

            relative_file = path.relative_to(repo_root).as_posix()
            if record["file"] != path.resolve():
                report(
                    f"inventory-file-mismatch: {location} id={identifier} "
                    f"expected={record['relative_file']} actual={relative_file}"
                )
                failed = True

            actual_lints = set(lint_name.findall(body))
            if actual_lints != record["lints"]:
                report(
                    f"inventory-lint-mismatch: {location} id={identifier} "
                    f"expected={','.join(sorted(record['lints']))} "
                    f"actual={','.join(sorted(actual_lints)) or 'none'}"
                )
                failed = True

            item_pattern = re.compile(rf"\b{re.escape(record['item'])}\b")
            if not item_pattern.search(text[match.end() : match.end() + 768]):
                report(
                    f"inventory-item-mismatch: {location} id={identifier} "
                    f"item={record['item']}"
                )
                failed = True

            if identifier in seen:
                report(f"inventory-id-repeated: {location} id={identifier}")
                failed = True
            else:
                seen[identifier] = location
        elif len(delegated_ids) == 1:
            # DL-001..DL-007 expectations are checked by their dedicated
            # boundary/unsafe-island scope validators.
            if delegated_ids[0] not in {f"DL-{number:03d}" for number in range(1, 8)}:
                report(f"delegated-rule-unknown: {location} id={delegated_ids[0]}")
                failed = True
            else:
                continue
        else:
            report(
                f"expectation-without-inventory-id: {location} "
                "reason must contain one WB-NNN-NNN or delegated DL-NNN id"
            )
            failed = True

for identifier in sorted(records):
    if identifier not in seen:
        report(f"inventory-id-unused: {identifier}")
        failed = True

if failed:
    sys.exit(1)

print(
    f"[design-lint] Clippy expectation inventory verified: "
    f"{len(records)} local baseline entries"
)
PY
}

run_clippy_expectation_inventory_self_test() {
    local fixture
    local expected_marker
    local log_file

    while read -r fixture expected_marker; do
        log_file="$(mktemp)"
        if check_clippy_expectation_inventory \
            "${repo_root}/tests/design_lints/exception_scope/${fixture}" \
            >"${log_file}" 2>&1; then
            rm -f -- "${log_file}"
            printf '[design-lint] FAIL fixture=clippy-expectation-inventory-self-test file=%s reason=invalid-expectation-accepted\n' \
                "${fixture}" >&2
            return 1
        fi
        if ! grep -Fq -- "${expected_marker}" "${log_file}"; then
            print_fixture_output "${log_file}"
            rm -f -- "${log_file}"
            printf '[design-lint] FAIL fixture=clippy-expectation-inventory-self-test file=%s reason=expected-marker-missing marker=%s\n' \
                "${fixture}" "${expected_marker}" >&2
            return 1
        fi
        rm -f -- "${log_file}"
        printf '[design-lint] PASS fixture=clippy-expectation-inventory-self-test file=%s marker=%s\n' \
            "${fixture}" "${expected_marker}"
    done <<'EOF'
broad_expect.rs broad expectation
unregistered_baseline_expect.rs inventory-not-registered
unregistered_p1_expect.rs inventory-not-registered
unregistered_p1_allow.rs blanket suppression
EOF
}

print_fixture_output() {
    local log_file="$1"

    if [[ -s "${log_file}" ]]; then
        sed -n '1,160p' "${log_file}" >&2
    fi
}

run_fixture_success() {
    local name="$1"
    local log_file="$2"
    shift 2

    printf '\n[design-lint] START fixture=%s\n' "${name}"
    print_command "$@"

    local status
    if "$@" >"${log_file}" 2>&1; then
        printf '[design-lint] PASS fixture=%s\n' "${name}"
        return 0
    else
        status=$?
    fi

    printf '[design-lint] FAIL fixture=%s exit=%s reason=unexpected-command-failure\n' \
        "${name}" "${status}" >&2
    print_fixture_output "${log_file}"
    return "${status}"
}

run_fixture_failure_with_marker() {
    local name="$1"
    local marker="$2"
    local log_file="$3"
    shift 3

    printf '\n[design-lint] START fixture=%s expected-marker=%s\n' "${name}" "${marker}"
    print_command "$@"

    local status
    if "$@" >"${log_file}" 2>&1; then
        printf '[design-lint] FAIL fixture=%s reason=unexpected-success\n' \
            "${name}" >&2
        return 1
    else
        status=$?
    fi

    if ! grep -Fq -- "${marker}" "${log_file}"; then
        printf '[design-lint] FAIL fixture=%s exit=%s reason=expected-marker-missing marker=%s\n' \
            "${name}" "${status}" "${marker}" >&2
        print_fixture_output "${log_file}"
        return 1
    fi

    printf '[design-lint] PASS fixture=%s marker=%s exit=%s\n' \
        "${name}" "${marker}" "${status}"
    return 0
}

check_boundary_exception_scope() {
    local scan_root="$1"

    python3 - "${repo_root}" "${scan_root}" <<'PY'
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
scan_root = Path(sys.argv[2]).resolve()
allowed = {
    (repo_root / "src/path_io.rs").resolve(): {
        "new": {"clippy::disallowed_methods": "DL-003"},
        "resolve_existing": {"clippy::disallowed_methods": "DL-003"},
        "read_file": {"clippy::disallowed_methods": "DL-003"},
        "scan_root_directory": {"clippy::disallowed_methods": "DL-003"},
        "scan_child_directory": {"clippy::disallowed_methods": "DL-003"},
        "scan_file": {"clippy::disallowed_methods": "DL-003"},
        "resolves_and_reads_existing_file_without_reopening_raw_spelling": {
            "clippy::disallowed_methods": "DL-003"
        },
    },
    (repo_root / "src/config.rs").resolve(): {
        "load_config": {"clippy::disallowed_methods": "DL-003"},
    },
    (repo_root / "src/stats.rs").resolve(): {
        "load_stats": {"clippy::disallowed_methods": "DL-003"},
        "load_last_stats": {"clippy::disallowed_methods": "DL-003"},
        "test_save_stats_redacts_secret_command_before_json_persistence": {
            "clippy::disallowed_methods": "DL-003"
        },
    },
    (repo_root / "src/path_guard.rs").resolve(): {
        "matching_rule": {"clippy::disallowed_methods": "DL-003"},
    },
    (repo_root / "src/persistence.rs").resolve(): {
        "temp_root": {"clippy::disallowed_methods": "DL-003"},
        "facade_persists_only_sanitized_content": {
            "clippy::disallowed_methods": "DL-003"
        },
    },
    (repo_root / "src/storage.rs").resolve(): {
        "default_root": {"clippy::disallowed_methods": "DL-003"},
        "usage": {"clippy::disallowed_methods": "DL-003"},
        "purge": {"clippy::disallowed_methods": "DL-003"},
        "sweep_expired": {"clippy::disallowed_methods": "DL-003"},
        "status": {"clippy::disallowed_methods": "DL-003"},
        "open_private_file": {"clippy::disallowed_methods": "DL-003"},
        "write_private_file": {"clippy::disallowed_methods": "DL-003"},
        "sync_directory": {"clippy::disallowed_methods": "DL-003"},
        "safe_storage_parent": {"clippy::disallowed_methods": "DL-003"},
        "temp_root": {"clippy::disallowed_methods": "DL-003"},
        "canonical_system_temp_parent_is_safe": {
            "clippy::disallowed_methods": "DL-003"
        },
        "storage_round_trip_preserves_streams_and_bounded_lines": {
            "clippy::disallowed_methods": "DL-003"
        },
    },
    (repo_root / "src/platform.rs").resolve(): {
        "value": {"clippy::disallowed_methods": "DL-007"},
        "variables": {"clippy::disallowed_methods": "DL-007"},
        "current_dir": {"clippy::disallowed_methods": "DL-007"},
        "spawn": {
            "clippy::disallowed_methods": "DL-002",
            "clippy::disallowed_types": "DL-002",
        },
    },
}

if scan_root.is_file():
    source_files = [scan_root] if scan_root.suffix == ".rs" else []
else:
    source_files = sorted(scan_root.rglob("*.rs"))

attribute = re.compile(
    r"#!?\[(?P<kind>allow|expect)\((?P<body>[^\]]*?)\)\]", re.DOTALL
)
function_after_attribute = re.compile(
    r"\s*(?:#\[[^\]]*\]\s*)*"
    r"(?:(?:pub(?:\([^)]*\))?|async|unsafe|const)\s+)*"
    r"fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*<[^()\n]*>)?\s*\(",
    re.DOTALL,
)
failed = False
tracked_lints = {
    "clippy::disallowed_methods",
    "clippy::disallowed_types",
}

for path in source_files:
    text = path.read_text(encoding="utf-8")
    for match in attribute.finditer(text):
        body = match.group("body")
        if "clippy::disallowed_methods" not in body and "clippy::disallowed_types" not in body:
            continue

        line = text.count("\n", 0, match.start()) + 1
        location = f"{path}:{line}"
        if match.group("kind") == "allow":
            print(f"[design-lint] disallowed exception error: broad suppression: {location}")
            failed = True
            continue

        lint_names = {lint for lint in tracked_lints if lint in body}
        if path not in allowed:
            print(f"[design-lint] disallowed exception error: scope-not-allowlisted: {location}")
            failed = True
            continue

        function_match = function_after_attribute.match(text[match.end():])
        function = function_match.group("name") if function_match else None
        expected = allowed[path].get(function)
        if expected is None:
            print(
                "[design-lint] disallowed exception error: "
                f"item-not-allowlisted: {location} function={function or 'unknown'}"
            )
            failed = True
            continue

        expected_lints = set(expected)
        if not lint_names.issubset(expected_lints):
            unexpected_lints = ",".join(sorted(lint_names - expected_lints))
            print(
                "[design-lint] disallowed exception error: "
                f"lint-not-allowlisted: {location} lints={unexpected_lints}"
            )
            failed = True

        reason_match = re.search(r'reason\s*=\s*"([^"]*)"', body)
        reason_ids = set(
            re.findall(r"\bDL-\d{3}\b", reason_match.group(1))
            if reason_match
            else []
        )
        expected_ids = set(expected.values())
        if not reason_ids:
            print(
                f"[design-lint] disallowed exception error: missing-reason: {location}"
            )
            failed = True
        elif reason_ids != expected_ids:
            print(
                "[design-lint] disallowed exception error: "
                f"wrong-rule: {location} expected={','.join(sorted(expected_ids))} "
                f"actual={','.join(sorted(reason_ids))}"
            )

sys.exit(1 if failed else 0)
PY
}

run_boundary_exception_scope_self_test() {
    local fixture
    local expected_marker
    local log_file

    while read -r fixture expected_marker; do
        log_file="$(mktemp)"
        if check_boundary_exception_scope "${repo_root}/tests/design_lints/exception_scope/${fixture}" >"${log_file}" 2>&1; then
            rm -f -- "${log_file}"
            printf '[design-lint] FAIL fixture=dl003-exception-scope-self-test file=%s reason=invalid-exception-accepted\n' \
                "${fixture}" >&2
            return 1
        fi
        if ! grep -Fq -- "${expected_marker}" "${log_file}"; then
            print_fixture_output "${log_file}"
            rm -f -- "${log_file}"
            printf '[design-lint] FAIL fixture=dl003-exception-scope-self-test file=%s reason=expected-marker-missing marker=%s\n' \
                "${fixture}" "${expected_marker}" >&2
            return 1
        fi
        rm -f -- "${log_file}"
        printf '[design-lint] PASS fixture=dl003-exception-scope-self-test file=%s marker=%s\n' \
            "${fixture}" "${expected_marker}"
    done <<'EOF'
broad_allow.rs broad suppression
broad_type_allow.rs broad suppression
unregistered_expect.rs scope-not-allowlisted
EOF
}

check_unsafe_island_scope() {
    local scan_root="$1"

    python3 - "${repo_root}" "${scan_root}" <<'PY'
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
scan_root = Path(sys.argv[2]).resolve()
allowed_file = (repo_root / "src/platform.rs").resolve()
allowed_functions = {
    "install_shutdown_signal_handlers",
    "terminate_child",
    "raise_signal_for_test",
    "effective_user_id",
    "rename_noreplace",
}

if scan_root.is_file():
    source_files = [scan_root] if scan_root.suffix == ".rs" else []
else:
    source_files = sorted(scan_root.rglob("*.rs"))

attribute = re.compile(
    r"#!?\[(?P<kind>allow|expect)\((?P<body>[^\]]*?)\)\]", re.DOTALL
)
function = re.compile(r"\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
unsafe_block = re.compile(r"\bunsafe\s*\{")
unsafe_function = re.compile(r"\bunsafe\s+fn\b")
failed = False

for path in source_files:
    text = path.read_text(encoding="utf-8")
    resolved_path = path.resolve()

    for match in attribute.finditer(text):
        body = match.group("body")
        if "unsafe_code" not in body:
            continue

        line = text.count("\n", 0, match.start()) + 1
        location = f"{path}:{line}"
        if match.group("kind") == "allow":
            print(f"[design-lint] unsafe exception error: broad suppression: {location}")
            failed = True
            continue

        if resolved_path != allowed_file:
            print(f"[design-lint] unsafe exception error: scope-not-allowlisted: {location}")
            failed = True
            continue

        function_match = re.match(
            r"\s*(?:#\[[^\]]*\]\s*)*"
            r"(?:(?:pub(?:\([^)]*\))?|async|unsafe|const)\s+)*"
            r"fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
            text[match.end():],
            re.DOTALL,
        )
        function_name = function_match.group("name") if function_match else None
        if function_name not in allowed_functions:
            print(
                "[design-lint] unsafe exception error: "
                f"item-not-allowlisted: {location} function={function_name or 'unknown'}"
            )
            failed = True

        reason_match = re.search(r'reason\s*=\s*"([^"]*)"', body)
        reason_ids = set(
            re.findall(r"\bDL-\d{3}\b", reason_match.group(1))
            if reason_match
            else []
        )
        if reason_ids != {"DL-001"}:
            print(
                "[design-lint] unsafe exception error: "
                f"wrong-rule: {location} expected=DL-001 actual={','.join(sorted(reason_ids)) or 'none'}"
            )
            failed = True

    function_matches = list(function.finditer(text))
    for unsafe_match in unsafe_block.finditer(text):
        line = text.count("\n", 0, unsafe_match.start()) + 1
        location = f"{path}:{line}"
        if resolved_path != allowed_file:
            print(f"[design-lint] unsafe block error: outside-island: {location}")
            failed = True
            continue

        enclosing = None
        for candidate in function_matches:
            if candidate.start() <= unsafe_match.start():
                enclosing = candidate.group("name")
            else:
                break
        if enclosing not in allowed_functions:
            print(
                "[design-lint] unsafe block error: "
                f"function-not-allowlisted: {location} function={enclosing or 'unknown'}"
            )
            failed = True

        prior_lines = text[:unsafe_match.start()].splitlines()
        safety_comment = any("SAFETY:" in prior for prior in prior_lines[-4:])
        if not safety_comment:
            print(f"[design-lint] unsafe block error: missing-safety-comment: {location}")
            failed = True

    for unsafe_match in unsafe_function.finditer(text):
        line = text.count("\n", 0, unsafe_match.start()) + 1
        print(
            "[design-lint] unsafe function error: "
            f"unsafe-functions-are-not-allowed: {path}:{line}"
        )
        failed = True

sys.exit(1 if failed else 0)
PY
}

run_unsafe_island_scope_self_test() {
    local fixture
    local expected_marker
    local log_file

    while read -r fixture expected_marker; do
        log_file="$(mktemp)"
        if check_unsafe_island_scope "${repo_root}/tests/design_lints/exception_scope/${fixture}" >"${log_file}" 2>&1; then
            printf '[design-lint] FAIL fixture=dl001-unsafe-scope-self-test file=%s reason=invalid-exception-accepted\n' \
                "${fixture}" >&2
            return 1
        fi
        if ! grep -Fq -- "${expected_marker}" "${log_file}"; then
            print_fixture_output "${log_file}"
            printf '[design-lint] FAIL fixture=dl001-unsafe-scope-self-test file=%s reason=expected-marker-missing marker=%s\n' \
                "${fixture}" "${expected_marker}" >&2
            return 1
        fi
        printf '[design-lint] PASS fixture=dl001-unsafe-scope-self-test file=%s marker=%s\n' \
            "${fixture}" "${expected_marker}"
    done <<'EOF'
broad_unsafe_allow.rs broad suppression
EOF
}

check_dl006_persistence_api() {
    python3 - "${repo_root}" <<'PY'
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
source = {
    "main": (repo_root / "src/main.rs").read_text(encoding="utf-8"),
    "persistence": (repo_root / "src/persistence.rs").read_text(encoding="utf-8"),
    "safety": (repo_root / "src/safety.rs").read_text(encoding="utf-8"),
    "storage": (repo_root / "src/storage.rs").read_text(encoding="utf-8"),
}
failures = []

if "PersistencePolicy" in source["main"] or "PersistencePolicy" in source["storage"]:
    failures.append("legacy PersistencePolicy API is still present")

if not re.search(
    r"pub\(crate\)\s+fn\s+store\s*\([^)]*content\s*:\s*&SanitizedStoredContent",
    source["persistence"],
    re.DOTALL,
):
    failures.append("Persistence::store must accept &SanitizedStoredContent")

if not re.search(
    r"pub\(crate\)\s+fn\s+commit\s*\([^)]*content\s*:\s*&SanitizedStoredContent",
    source["storage"],
    re.DOTALL,
):
    failures.append("RunStore::commit must accept &SanitizedStoredContent")

if re.search(
    r"fn\s+(?:store|commit)\s*\([^)]*content\s*:\s*SanitizedStoredContent\b",
    source["persistence"] + "\n" + source["storage"],
    re.DOTALL,
):
    failures.append("storage content must not cross the boundary by value")

if re.search(
    r"^\s*pub(?:\([^)]*\))?\s+(?:stdout|stderr)\s*:",
    source["safety"],
    re.MULTILINE,
):
    failures.append("SanitizedStoredContent fields must remain private")

if "persistence.store(" not in source["main"]:
    failures.append("application handlers must call Persistence::store")
if re.search(r"\bpersistence\.commit\s*\(", source["main"]):
    failures.append("application handlers must not call a raw persistence commit")

if failures:
    for failure in failures:
        print(f"[design-lint] DL-006 persistence API error: {failure}")
    sys.exit(1)

print("[design-lint] DL-006 persistence API: typed facade and private content fields verified")
PY
}

check_acceptance_coverage() {
    python3 - "${repo_root}" "${repo_root}/scripts/design_lint.sh" <<'PY'
import json
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
script_path = Path(sys.argv[2]).resolve()
manifest_path = repo_root / "design-lint-manifest.json"
failures = []

try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    print(f"[design-lint] acceptance coverage error: manifest unreadable: {error}")
    raise SystemExit(1)

raw_rules = manifest.get("rules", []) if isinstance(manifest, dict) else []
if not isinstance(raw_rules, list):
    print("[design-lint] acceptance coverage error: manifest rules are not an array")
    raise SystemExit(1)
rules = {
    rule.get("id"): rule
    for rule in raw_rules
    if isinstance(rule, dict) and isinstance(rule.get("id"), str)
}
adopted = {f"DL-{number:03d}" for number in range(1, 8)}
# The complete rule-set check belongs to check_design_lint_policy. This check
# only makes the adopted P0 set explicit for the evidence mapping.
for identifier in sorted(adopted):
    rule = rules.get(identifier)
    if rule is None:
        failures.append(f"manifest-rule-missing: {identifier}")
    elif rule.get("level") != "deny":
        failures.append(
            f"manifest-rule-not-blocking: {identifier} level={rule.get('level')}"
        )

script = script_path.read_text(encoding="utf-8")
function_pattern = re.compile(
    r"(?ms)^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\(\) \{\n"
    r"(?P<body>.*?)(?=^[A-Za-z_][A-Za-z0-9_]*\(\) \{\n|\Z)"
)
functions = {
    match.group("name"): match.group("body")
    for match in function_pattern.finditer(script)
}

# Each entry is intentionally tied to the concrete runner label in the
# entrypoint. The runtime entries are shared test/contract gates; their
# rule-specific test names and invariants are recorded in WB-20 notes.
coverage = {
    "DL-001": {
        "positive": [("run_clippy_fixtures", "clippy-unsafe-positive")],
        "negative": [
            ("run_clippy_fixtures", "clippy-unsafe-negative"),
            ("run_clippy_fixtures", "clippy-unsafe-undocumented"),
        ],
        "runtime": [
            ("run_fast_checks", "run_check 'tests'"),
            ("run_fast_checks", "run_check 'strict-contract'"),
            ("run_fast_checks", "run_check 'unsafe-island-scope'"),
        ],
    },
    "DL-002": {
        "positive": [("run_clippy_fixtures", "clippy-process-positive")],
        "negative": [
            ("run_clippy_fixtures", "clippy-negative-disallowed-method"),
            ("run_clippy_fixtures", "clippy-negative-disallowed-type"),
        ],
        "runtime": [
            ("run_fast_checks", "run_check 'tests'"),
            ("run_fast_checks", "run_check 'strict-contract'"),
        ],
    },
    "DL-003": {
        "positive": [
            ("run_rustc_fixtures", "rustc-path-io-positive"),
            ("run_clippy_fixtures", "clippy-path-io-positive"),
        ],
        "negative": [
            ("run_rustc_fixtures", "rustc-path-io-raw-argument"),
            ("run_rustc_fixtures", "rustc-path-io-private-fields"),
            ("run_rustc_fixtures", "rustc-path-io-no-unchecked-conversion"),
            ("run_clippy_fixtures", "clippy-path-io-negative"),
        ],
        "runtime": [
            ("run_fast_checks", "run_check 'tests'"),
            ("run_fast_checks", "run_check 'strict-contract'"),
            ("run_fast_checks", "run_check 'boundary-exception-scope'"),
        ],
    },
    "DL-004": {
        "positive": [("run_rustc_fixtures", "rustc-output-render-positive")],
        "negative": [
            ("run_rustc_fixtures", "rustc-output-render-private-fields"),
            ("run_clippy_fixtures", "clippy-output-negative-disallowed-macro"),
        ],
        "runtime": [
            ("run_fast_checks", "run_check 'tests'"),
            ("run_fast_checks", "run_check 'strict-contract'"),
        ],
    },
    "DL-005": {
        "positive": [
            ("run_rustc_fixtures", "rustc-output-render-positive"),
            ("run_rustc_fixtures", "rustc-storage-content-positive"),
        ],
        "negative": [
            ("run_clippy_fixtures", "clippy-output-negative-disallowed-macro"),
            ("run_rustc_fixtures", "rustc-storage-content-raw-argument"),
        ],
        "runtime": [
            ("run_fast_checks", "run_check 'tests'"),
            ("run_fast_checks", "run_check 'strict-contract'"),
            ("run_fast_checks", "run_check 'dl006-persistence-api'"),
        ],
    },
    "DL-006": {
        "positive": [("run_rustc_fixtures", "rustc-storage-content-positive")],
        "negative": [
            ("run_rustc_fixtures", "rustc-storage-content-private-fields"),
            ("run_rustc_fixtures", "rustc-storage-content-raw-argument"),
            ("run_rustc_fixtures", "rustc-storage-content-no-unchecked-conversion"),
        ],
        "runtime": [
            ("run_fast_checks", "run_check 'tests'"),
            ("run_fast_checks", "run_check 'strict-contract'"),
            ("run_fast_checks", "run_check 'dl006-persistence-api'"),
            ("run_full_checks", "run_check 'storage-spike'"),
        ],
    },
    "DL-007": {
        "positive": [("run_clippy_fixtures", "clippy-environment-positive")],
        "negative": [
            ("run_clippy_fixtures", "clippy-environment-negative"),
            ("run_clippy_fixtures", "clippy-current-dir-negative"),
        ],
        "runtime": [
            ("run_fast_checks", "run_check 'tests'"),
            ("run_fast_checks", "run_check 'strict-contract'"),
        ],
    },
}

for identifier in sorted(adopted):
    evidence = coverage.get(identifier)
    if evidence is None:
        failures.append(f"coverage-rule-missing: {identifier}")
        continue
    for kind in ("positive", "negative", "runtime"):
        entries = evidence.get(kind, [])
        if not entries:
            failures.append(f"coverage-kind-missing: {identifier} kind={kind}")
            continue
        for function_name, marker in entries:
            body = functions.get(function_name)
            if body is None:
                failures.append(
                    f"coverage-runner-missing: {identifier} kind={kind} function={function_name}"
                )
            elif marker not in body:
                failures.append(
                    f"coverage-marker-missing: {identifier} kind={kind} "
                    f"function={function_name} marker={marker}"
                )

if failures:
    for failure in failures:
        print(f"[design-lint] acceptance coverage error: {failure}")
    raise SystemExit(1)

print(
    "[design-lint] acceptance coverage verified: "
    "DL-001..DL-007 each have positive, negative, and runtime runners"
)
PY
}

run_rustc_fixtures() {
    local fixture_dir="${repo_root}/tests/design_lints/rustc"
    local forge_fixture="${repo_root}/prototype/forge_workspace_path.rs"
    local library_path
    local library_log
    local positive_log
    local negative_log
    local self_test_log
    local path_positive_log
    local path_raw_log
    local path_forge_log
    local path_conversion_log
    local output_positive_log
    local output_forge_log
    local storage_positive_log
    local storage_forge_log
    local storage_raw_log
    local storage_conversion_log

    fixture_tmp_dir="$(mktemp -d)"
    library_path="${fixture_tmp_dir}/libworkspace_path_spike.rlib"
    library_log="${fixture_tmp_dir}/rustc-library.log"
    positive_log="${fixture_tmp_dir}/rustc-positive.log"
    negative_log="${fixture_tmp_dir}/rustc-negative.log"
    self_test_log="${fixture_tmp_dir}/rustc-self-test.log"
    path_positive_log="${fixture_tmp_dir}/rustc-path-positive.log"
    path_raw_log="${fixture_tmp_dir}/rustc-path-raw.log"
    path_forge_log="${fixture_tmp_dir}/rustc-path-forge.log"
    path_conversion_log="${fixture_tmp_dir}/rustc-path-conversion.log"
    output_positive_log="${fixture_tmp_dir}/rustc-output-positive.log"
    output_forge_log="${fixture_tmp_dir}/rustc-output-forge.log"
    storage_positive_log="${fixture_tmp_dir}/rustc-storage-positive.log"
    storage_forge_log="${fixture_tmp_dir}/rustc-storage-forge.log"
    storage_raw_log="${fixture_tmp_dir}/rustc-storage-raw.log"
    storage_conversion_log="${fixture_tmp_dir}/rustc-storage-conversion.log"

    run_fixture_success 'rustc-library' "${library_log}" \
        rustc --edition=2024 --crate-name workspace_path_spike --crate-type=lib \
        "${fixture_dir}/workspace_path_spike.rs" --out-dir "${fixture_tmp_dir}" || return $?

    run_fixture_success 'rustc-positive-workspace-path' "${positive_log}" \
        rustc --edition=2024 --emit=metadata --out-dir "${fixture_tmp_dir}" \
        "${fixture_dir}/positive_workspace_path.rs" \
        --extern "workspace_path_spike=${library_path}" || return $?

    run_fixture_failure_with_marker 'rustc-negative-private-field' 'E0451' "${negative_log}" \
        rustc --edition=2024 --emit=metadata --out-dir "${fixture_tmp_dir}" \
        "${forge_fixture}" --extern "workspace_path_spike=${library_path}" || return $?

    if run_fixture_failure_with_marker 'rustc-self-test-unrelated-failure' 'E0451' "${self_test_log}" \
        rustc --edition=2024 --emit=metadata --out-dir "${fixture_tmp_dir}" \
        "${fixture_dir}/unrelated_compile_failure.rs"; then
        printf '[design-lint] FAIL fixture=rustc-self-test reason=marker-mismatch-accepted\n' >&2
        return 1
    fi

    printf '[design-lint] PASS fixture=rustc-self-test reason=unrelated-failure-rejected\n'

    run_fixture_success 'rustc-path-io-positive' "${path_positive_log}" \
        rustc --edition=2024 --emit=metadata --out-dir "${fixture_tmp_dir}" \
        "${fixture_dir}/path_io_positive.rs" || return $?

    run_fixture_failure_with_marker 'rustc-path-io-raw-argument' 'E0308' "${path_raw_log}" \
        rustc --edition=2024 --emit=metadata --out-dir "${fixture_tmp_dir}" \
        "${fixture_dir}/path_io_raw_argument.rs" || return $?

    run_fixture_failure_with_marker 'rustc-path-io-private-fields' 'E0451' "${path_forge_log}" \
        rustc --edition=2024 --emit=metadata --out-dir "${fixture_tmp_dir}" \
        "${fixture_dir}/path_io_forge.rs" || return $?

    run_fixture_failure_with_marker 'rustc-path-io-no-unchecked-conversion' 'E0277' \
        "${path_conversion_log}" \
        rustc --edition=2024 --emit=metadata --out-dir "${fixture_tmp_dir}" \
        "${fixture_dir}/path_io_unchecked_conversion.rs" || return $?

    run_fixture_success 'rustc-output-render-positive' "${output_positive_log}" \
        rustc --edition=2024 --emit=metadata --out-dir "${fixture_tmp_dir}" \
        "${fixture_dir}/output_render_positive.rs" || return $?

    run_fixture_failure_with_marker 'rustc-output-render-private-fields' 'E0451' \
        "${output_forge_log}" \
        rustc --edition=2024 --emit=metadata --out-dir "${fixture_tmp_dir}" \
        "${fixture_dir}/output_render_forge.rs" || return $?

    run_fixture_success 'rustc-storage-content-positive' "${storage_positive_log}" \
        rustc --edition=2024 --emit=metadata --out-dir "${fixture_tmp_dir}" \
        "${fixture_dir}/storage_content_positive.rs" || return $?

    run_fixture_failure_with_marker 'rustc-storage-content-private-fields' 'E0451' \
        "${storage_forge_log}" \
        rustc --edition=2024 --emit=metadata --out-dir "${fixture_tmp_dir}" \
        "${fixture_dir}/storage_content_forge.rs" || return $?

    run_fixture_failure_with_marker 'rustc-storage-content-raw-argument' 'E0308' \
        "${storage_raw_log}" \
        rustc --edition=2024 --emit=metadata --out-dir "${fixture_tmp_dir}" \
        "${fixture_dir}/storage_content_raw_argument.rs" || return $?

    run_fixture_failure_with_marker 'rustc-storage-content-no-unchecked-conversion' 'E0277' \
        "${storage_conversion_log}" \
        rustc --edition=2024 --emit=metadata --out-dir "${fixture_tmp_dir}" \
        "${fixture_dir}/storage_content_unchecked_conversion.rs" || return $?
}

run_clippy_fixtures() {
    local manifest="${repo_root}/tests/design_lints/clippy/Cargo.toml"
    local target_dir="${fixture_tmp_dir}/clippy-target"
    local positive_log="${fixture_tmp_dir}/clippy-positive.log"
    local negative_log="${fixture_tmp_dir}/clippy-negative.log"
    local process_positive_log="${fixture_tmp_dir}/clippy-process-positive.log"
    local type_negative_log="${fixture_tmp_dir}/clippy-type-negative.log"
    local environment_positive_log="${fixture_tmp_dir}/clippy-environment-positive.log"
    local environment_negative_log="${fixture_tmp_dir}/clippy-environment-negative.log"
    local current_dir_negative_log="${fixture_tmp_dir}/clippy-current-dir-negative.log"
    local path_positive_log="${fixture_tmp_dir}/clippy-path-positive.log"
    local path_negative_log="${fixture_tmp_dir}/clippy-path-negative.log"
    local output_negative_log="${fixture_tmp_dir}/clippy-output-negative.log"
    local unsafe_positive_log="${fixture_tmp_dir}/clippy-unsafe-positive.log"
    local unsafe_negative_log="${fixture_tmp_dir}/clippy-unsafe-negative.log"
    local unsafe_undocumented_log="${fixture_tmp_dir}/clippy-unsafe-undocumented.log"
    local clippy_args=(
        cargo
        clippy
        --manifest-path "${manifest}"
        --target-dir "${target_dir}"
        --offline
        --locked
        --no-deps
    )

    mkdir -p "${target_dir}"

    run_fixture_success 'clippy-positive' "${positive_log}" \
        "${clippy_args[@]}" --bin positive -- \
        -D clippy::disallowed_methods -D clippy::disallowed_types || return $?

    run_fixture_success 'clippy-process-positive' "${process_positive_log}" \
        "${clippy_args[@]}" --bin process_positive -- \
        -D clippy::disallowed_methods -D clippy::disallowed_types \
        -D unfulfilled_lint_expectations || return $?

    run_fixture_failure_with_marker 'clippy-negative-disallowed-method' \
        'clippy::disallowed-methods' "${negative_log}" \
        "${clippy_args[@]}" --bin negative -- \
        -D clippy::disallowed_methods -D clippy::disallowed_types || return $?

    run_fixture_failure_with_marker 'clippy-negative-disallowed-type' \
        'clippy::disallowed-types' "${type_negative_log}" \
        "${clippy_args[@]}" --bin type_negative -- \
        -D clippy::disallowed_types || return $?

    run_fixture_success 'clippy-environment-positive' "${environment_positive_log}" \
        "${clippy_args[@]}" --bin environment_positive -- \
        -D clippy::disallowed_methods -D unfulfilled_lint_expectations || return $?

    run_fixture_failure_with_marker 'clippy-environment-negative' \
        'clippy::disallowed-methods' "${environment_negative_log}" \
        "${clippy_args[@]}" --bin environment_negative -- \
        -D clippy::disallowed_methods || return $?

    run_fixture_failure_with_marker 'clippy-current-dir-negative' \
        'clippy::disallowed-methods' "${current_dir_negative_log}" \
        "${clippy_args[@]}" --bin current_dir_negative -- \
        -D clippy::disallowed_methods || return $?

    run_fixture_success 'clippy-path-io-positive' "${path_positive_log}" \
        "${clippy_args[@]}" --bin path_io_positive -- \
        -D clippy::disallowed_methods -D unfulfilled_lint_expectations || return $?

    run_fixture_failure_with_marker 'clippy-path-io-negative' \
        'clippy::disallowed-methods' "${path_negative_log}" \
        "${clippy_args[@]}" --bin path_io_negative -- \
        -D clippy::disallowed_methods || return $?

    run_fixture_failure_with_marker 'clippy-output-negative-disallowed-macro' \
        'clippy::disallowed-macros' "${output_negative_log}" \
        "${clippy_args[@]}" --bin output_negative -- \
        -D clippy::disallowed_macros || return $?

    run_fixture_success 'clippy-unsafe-positive' "${unsafe_positive_log}" \
        "${clippy_args[@]}" --bin unsafe_positive -- \
        -D unsafe_code -D clippy::undocumented_unsafe_blocks \
        -D unfulfilled_lint_expectations || return $?

    run_fixture_failure_with_marker 'clippy-unsafe-negative' \
        'unsafe_code' "${unsafe_negative_log}" \
        "${clippy_args[@]}" --bin unsafe_negative -- \
        -D unsafe_code -D clippy::undocumented_unsafe_blocks || return $?

    run_fixture_failure_with_marker 'clippy-unsafe-undocumented' \
        'clippy::undocumented-unsafe-blocks' "${unsafe_undocumented_log}" \
        "${clippy_args[@]}" --bin unsafe_undocumented -- \
        -D clippy::undocumented_unsafe_blocks -D unfulfilled_lint_expectations || return $?
}

run_production_boundary_clippy() {
    run_check 'dl001-dl002-dl003-dl004-dl007-production-clippy' cargo clippy --locked --all-features --no-deps \
        --bin veil -- -D clippy::disallowed_methods -D clippy::disallowed_macros \
        -D clippy::disallowed_types \
        -D unsafe_code -D clippy::undocumented_unsafe_blocks \
        -D unfulfilled_lint_expectations
}

run_module_dependency_check() {
    local module_args=(
        cargo-modules
        dependencies
        --manifest-path "${repo_root}/Cargo.toml"
        --bin veil
        --no-externs
        --no-sysroot
        --no-fns
        --no-types
        --no-traits
        --acyclic
    )
    local started_at=$SECONDS
    local output
    local status

    printf '\n[design-lint] START report-only=cargo-modules-acyclic\n'
    print_command "${module_args[@]}"

    if output=$("${module_args[@]}" 2>&1); then
        status=0
    else
        status=$?
    fi

    if [[ -n "${output}" ]]; then
        printf '%s\n' "${output}"
    fi

    local duration=$((SECONDS - started_at))
    if ((status == 0)); then
        printf '[design-lint] PASS report-only=cargo-modules-acyclic duration=%ss status=acyclic\n' \
            "${duration}"
        return 0
    fi

    # cargo-modules currently models method/type ownership as graph edges and
    # reports a cycle in the existing binary. Keep that diagnostic visible but
    # advisory until the output is shown to be a reliable layer-policy signal.
    if ((status == 1)) && grep -Fq 'circular dependency between' <<<"${output}"; then
        printf '[design-lint] ADVISORY report-only=cargo-modules-acyclic duration=%ss ' \
            "${duration}"
        printf 'reason=graph-output-not-suitable-for-blocking\n'
        return 0
    fi

    printf '[design-lint] FAIL check=cargo-modules-acyclic duration=%ss exit=%s '
        "${duration}" "${status}" >&2
    printf 'reason=unexpected-module-tool-failure\n' >&2
    return "${status}"
}

run_dependency_checks() {
    run_check 'cargo-deny-deterministic-policy' \
        cargo-deny --manifest-path "${repo_root}/Cargo.toml" --locked \
        check bans licenses sources || return $?
    run_check 'cargo-machete-unused-dependencies' \
        cargo-machete --with-metadata --skip-target-dir || return $?
    run_module_dependency_check || return $?
}

run_advisory_checks() {
    run_check 'tool-version-policy-advisory' check_tool_versions cargo-deny || return $?
    run_check 'cargo-deny-advisories' \
        cargo-deny --manifest-path "${repo_root}/Cargo.toml" --locked \
        check advisories || return $?
}

run_fast_checks() {
    run_toolchain_checks || return $?
    run_check 'format' cargo fmt --all -- --check || return $?
    run_check 'tests' cargo test --locked --all-targets || return $?
    run_check 'strict-contract' python3 scripts/verify_contract.py --strict-coverage || return $?
    run_check 'tool-clippy-version' cargo clippy --version || return $?
    run_check 'design-lint-policy' check_design_lint_policy || return $?
    run_check 'acceptance-coverage' check_acceptance_coverage || return $?
    run_check 'clippy-expectation-inventory' check_clippy_expectation_inventory "${repo_root}" || return $?
    run_check 'clippy-expectation-inventory-self-test' run_clippy_expectation_inventory_self_test || return $?
    run_check 'clippy-baseline' cargo clippy --locked --all-targets --all-features \
        --message-format=short -- -D warnings \
        --force-warn unreachable_pub --force-warn clippy::unwrap_used \
        --force-warn clippy::expect_used \
        --force-warn clippy::too_many_arguments || return $?
    run_report_only_check 'p1-clippy-advisory' cargo clippy --locked --all-features --no-deps \
        --bin veil --message-format=short -- \
        -W unreachable_pub -W clippy::unwrap_used -W clippy::expect_used \
        -W clippy::too_many_arguments || return $?
    run_check 'dl006-persistence-api' check_dl006_persistence_api || return $?
    run_check 'boundary-exception-scope' check_boundary_exception_scope "${repo_root}/src" || return $?
    run_check 'boundary-exception-scope-self-test' run_boundary_exception_scope_self_test || return $?
    run_check 'unsafe-island-scope' check_unsafe_island_scope "${repo_root}/src" || return $?
    run_check 'unsafe-island-scope-self-test' run_unsafe_island_scope_self_test || return $?
    run_production_boundary_clippy || return $?
    run_check 'rustc-fixtures' run_rustc_fixtures || return $?
    run_check 'clippy-fixtures' run_clippy_fixtures || return $?
}

run_full_checks() {
    run_fast_checks || return $?
    run_check 'tool-version-policy-dependencies' \
        check_tool_versions cargo-deny cargo-machete cargo-modules || return $?
    run_check 'cargo-metadata' cargo metadata --locked --no-deps --format-version 1 || return $?
    run_dependency_checks || return $?
    run_check 'cargo-check' cargo check --locked --all-targets || return $?
    run_check 'storage-spike' cargo test --locked --test level2_storage_spike -- --nocapture || return $?
    run_check 'verification-script-syntax' \
        python3 -m py_compile scripts/verify_contract.py scripts/verify_meta.py || return $?
}

run_profile() {
    local profile="$1"

    printf '[design-lint] profile=%s repo=%s\n' "$profile" "$repo_root"

    case "$profile" in
        fast)
            run_fast_checks
            ;;
        full)
            run_full_checks
            ;;
        advisory)
            run_advisory_checks
            ;;
        *)
            printf '[design-lint] ERROR profile=%s reason=unknown profile\n' "$profile" >&2
            usage >&2
            return 2
            ;;
    esac
}

main() {
    if (($# != 1)); then
        printf '[design-lint] ERROR reason=expected exactly one profile argument\n' >&2
        usage >&2
        return 2
    fi

    case "$1" in
        -h|--help)
            usage
            return 0
            ;;
        fast|full|advisory)
            ;;
        *)
            printf '[design-lint] ERROR profile=%s reason=unknown profile\n' "$1" >&2
            usage >&2
            return 2
            ;;
    esac

    cd -- "$repo_root"

    if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
        export CARGO_TARGET_DIR="${repo_root}/target/design-lint"
        printf '[design-lint] cargo-target-dir=%s (isolated default)\n' "$CARGO_TARGET_DIR"
    else
        printf '[design-lint] cargo-target-dir=%s (from environment)\n' "$CARGO_TARGET_DIR"
    fi

    local status
    if run_profile "$1"; then
        printf '\n[design-lint] PASS profile=%s\n' "$1"
        return 0
    else
        status=$?
    fi

    printf '\n[design-lint] FAIL profile=%s exit=%s\n' "$1" "$status" >&2
    return "$status"
}

main "$@"
