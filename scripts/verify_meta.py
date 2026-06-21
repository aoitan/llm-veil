#!/usr/bin/env python3
"""Meta-verification for the safety gate contract checker.

This script intentionally corrupts one contract snapshot expectation and checks
that scripts/verify_contract.py rejects it with exit code 1.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFY_CONTRACT = REPO_ROOT / "scripts" / "verify_contract.py"
SNAPSHOT = REPO_ROOT / "tests" / "fixtures" / "contract_observations.json"


def load_snapshot() -> dict[str, object]:
    with SNAPSHOT.open(encoding="utf-8") as f:
        return json.load(f)


def corrupt_one_expectation(snapshot: dict[str, object]) -> dict[str, object]:
    observations = snapshot.get("contract_observations")
    if not isinstance(observations, list):
        raise ValueError("snapshot is missing contract_observations list")

    for observation in observations:
        if (
            isinstance(observation, dict)
            and observation.get("name") == "cat .env"
            and observation.get("reason") == "path_blocked"
        ):
            observation["reason"] = "secret_detected"
            return snapshot

    raise ValueError("negative test could not find the cat .env path_blocked observation")


def main() -> int:
    snapshot = corrupt_one_expectation(load_snapshot())

    with tempfile.TemporaryDirectory(prefix="llm-veil-contract-meta-") as tmp:
        mismatched_snapshot = Path(tmp) / "contract_observations.json"
        with mismatched_snapshot.open("w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, sort_keys=True)
            f.write("\n")

        env = os.environ.copy()
        env["LLM_VEIL_CONTRACT_SNAPSHOT"] = str(mismatched_snapshot)
        output = subprocess.run(
            [sys.executable, str(VERIFY_CONTRACT), "--strict-coverage"],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    if output.returncode != 1:
        sys.stderr.write(
            "mismatched contract snapshot did not fail with exit code 1\n"
            f"status: {output.returncode}\n"
            f"stdout:\n{output.stdout}\n"
            f"stderr:\n{output.stderr}\n"
        )
        return 1

    expected_fragments = [
        "contract observations changed from previous run",
        "previous contract observations",
        "current contract observations",
        '"reason": "secret_detected"',
        '"reason": "path_blocked"',
    ]
    missing = [fragment for fragment in expected_fragments if fragment not in output.stderr]
    if missing:
        sys.stderr.write(
            "snapshot mismatch failure did not include the expected diff\n"
            f"missing: {missing}\n"
            f"stdout:\n{output.stdout}\n"
            f"stderr:\n{output.stderr}\n"
        )
        return 1

    print("meta verification passed: snapshot mismatch failed with exit code 1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
