# Development Workflow

Before committing or merging changes that affect `llm-veil`, run the Safety
Gate contract verification in strict coverage mode:

```bash
python3 scripts/verify_contract.py --strict-coverage
```

The change is not ready if this command fails. Strict coverage mode keeps
Safety Gate contract cases, including blocked-path handling, redaction-only
handling, and mixed block/redact policy cases, inside the required development
flow instead of treating uncovered cases as complete.

For `run`, blocked-path preflight is intentionally scoped to direct argv
entries. The block detail is a structured stdout record; stderr is reserved for
normal stats/errors and does not carry block details for this preflight failure.
Shell-embedded strings and program-internal path strings are outside the current
contract unless a future change adds a parser for those command languages.
