# Contributing to Clay Seal Identity

Thanks for your interest in contributing! Clay Seal Identity (`clayseal-identity`)
is layer 1 of Clay Seal: cryptographically attested agent identity and Biscuit
capability tokens. This guide covers how to set up a dev environment, run the
tests, and submit changes.

Because this is security-critical identity software, please also read
[SECURITY.md](SECURITY.md) before reporting anything that looks like a
vulnerability — do **not** file it as a public issue or PR.

By participating in this project you are expected to uphold our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Development Environment

We recommend a virtual environment on **Python 3.13** (the project supports
3.11–3.13).

```bash
git clone https://github.com/clayseal/clayseal-identity.git
cd clayseal-identity
python3.13 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,server]"
```

The `dev` extra installs the test tooling; the `server` extra installs the
FastAPI backend and its heavier dependencies. Every dependency resolves from
public PyPI — no private packages are needed to develop or test this repo.

## Running the Tests

Tests live in `backend/tests/` and `sdk/python/tests/` and run with `pytest`:

```bash
pytest backend/tests sdk/python/tests -q
```

SQLite is the zero-config default for development and tests, so no external
database is required to run the suite.

## Code Style

We use [ruff](https://docs.astral.sh/ruff/) for formatting and linting and
[mypy](https://mypy.readthedocs.io/) for type checking. These checks are being
added to CI, so please run them locally before opening a PR:

```bash
ruff format .
ruff check .
mypy .
```

Keep changes clean and typed; new code should pass `ruff check` and `mypy`
without new errors.

## Commit and Pull Request Conventions

- **Keep PRs small and focused.** One logical change per PR is much easier to
  review than a large mixed diff.
- **Include tests.** New behavior and bug fixes should come with tests. The full
  suite must pass.
- **Run the style checks.** `ruff format`, `ruff check`, and `mypy` should be
  clean.
- **Update the changelog.** Add a note to `CHANGELOG.md` under the `Unreleased`
  section describing user-visible changes (added/changed/fixed).
- **Update docs** when you change behavior, configuration, or public APIs.
- **Write clear commit messages.** A short imperative subject line (e.g.
  "Add offline JWKS verification"), with a body explaining the why when useful.
- **Security-relevant changes** should reference the
  [threat model](docs/THREAT_MODEL.md) and explain how the change affects it.

## Licensing and Sign-off

This project is licensed under the [MIT License](LICENSE). **By contributing,
you agree that your contributions will be licensed under the MIT License** and
that you have the right to submit them.

Please sign off your commits to certify the
[Developer Certificate of Origin](https://developercertificate.org/) by adding a
`Signed-off-by` line with your real name:

```bash
git commit -s -m "Your message"
```

This adds a line like `Signed-off-by: Your Name <you@example.com>` to the commit
message.

## Reporting Bugs and Requesting Features

Use the GitHub issue templates (Bug report / Feature request). For anything
security-sensitive, use the private reporting flow described in
[SECURITY.md](SECURITY.md) instead of a public issue.
