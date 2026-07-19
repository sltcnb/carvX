# Contributing to carvX

Thanks for your interest in improving carvX. This document covers how to set up
a development environment, the project's ground rules, and how to submit
changes.

## Design constraints

carvX has one hard rule: the runtime is **pure Python 3.10+, standard library
only**. Do not add mandatory third-party dependencies. Optional accelerators
(e.g. `cryptography`, `Pillow`, `pyewf`, `pyahocorasick`) are allowed **only**
if the feature degrades gracefully to a stdlib implementation when the package
is absent. Keep imports of optional packages local (inside the function that
uses them) and guarded by `try`/`except ImportError`.

## Development setup

```sh
git clone https://github.com/sltcnb/BreadCrumb
cd BreadCrumb
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
pip install pytest ruff pre-commit
pre-commit install
```

## Running checks

```sh
ruff check .          # lint
ruff format .         # format
pytest -q             # test suite (169+ tests)
```

All of the above run in CI on every push and pull request. Please make sure
they pass locally before opening a PR.

## Adding a new file-type signature

Signatures live in `carvx/signatures.py`; end-of-file detection logic lives in
`carvx/handlers.py`. When adding a type:

1. Add the magic bytes and a reasonable `max_size` in `signatures.py`.
2. If the format has a determinable length, add a handler in `handlers.py`.
3. Add a builder + test in `tests/` that carves a synthetic sample and
   verifies the recovered bytes hash-match the original.
4. Feed truncated, corrupted, and pure-noise input through the handler to
   confirm it never crashes and never emits a false-positive `validated` carve.

## Pull requests

- Keep changes focused; one logical change per PR where practical.
- Use [Conventional Commits](https://www.conventionalcommits.org/) style for
  commit messages (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `ci:`, ...).
- Include tests for new behaviour and bug fixes.
- Never commit real evidence data, disk images, or recovered files — the
  `.gitignore` blocks common image extensions, but double-check.

## Reporting bugs

Open an issue with the carvX version/commit, your OS and Python version, the
command you ran, and — for parsing bugs — a **synthetic** reproducer image
(never real evidence). Security issues should follow [SECURITY.md](SECURITY.md)
instead.
