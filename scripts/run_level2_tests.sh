#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
compose_file="${repo_root}/compose.test.yaml"
build_image=true

usage() {
    cat <<'EOF'
Usage: scripts/run_level2_tests.sh [--build|--no-build] [-- COMMAND ...]

Run the Level 2 Rust/Python verification suite in the Linux test container.

Options:
  --build       Rebuild the image before running (default).
  --no-build    Reuse the existing image for a faster rerun.
  -h, --help    Show this help.

Arguments after `--` replace the container's default test command.
EOF
}

while (($# > 0)); do
    case "$1" in
        --build)
            build_image=true
            shift
            ;;
        --no-build)
            build_image=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *)
            printf 'unknown option: %s\n\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

compose_args=(--file "${compose_file}" run --rm)
if [[ "${build_image}" == true ]]; then
    compose_args+=(--build)
fi

exec docker compose "${compose_args[@]}" level2-test "$@"
