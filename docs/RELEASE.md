# Releasing to PyPI

## The distribution name is not the import name

```
pip install sentinelcore-ai        →        import sentinelcore
```

**PyPI refuses the name `sentinelcore`.** An unrelated project, [`sentinel-core`](https://pypi.org/project/sentinel-core/) (a RAG knowledge-graph library, 8 releases, Nov 2025 – Jan 2026), already exists, and PyPI's similarity check compares names after deleting `.` `_` `-` and folding the confusable characters `l`/`I`/`1` and `O`/`0`. Both names collapse to `sentlnelcore`, so the form is rejected with *"This project name is too similar to an existing project."*

This is stricter than PEP 503 normalization, which only collapses runs of `-_.` into a single `-`. Under PEP 503 alone the two names are distinct, which is why `pypi.org/simple/sentinelcore/` returns 404 — the name is **unregistered but unregisterable**, by anyone.

**TestPyPI accepted `sentinelcore`, and that told us nothing.** TestPyPI is a separate database; `sentinel-core` is not in it, so there was no collision to detect. A name that works on TestPyPI can still be refused by PyPI, and a successful TestPyPI publish is not evidence about the real index.

Two consequences worth remembering:

- Since the import name is unchanged, no code, example or API changed. Only `project.name`, the self-referential `all` extra, and install instructions.
- **A hyphen typo — `pip install sentinel-core` — installs someone else's package.** For a security tool that is worth stating in the README rather than discovering later.

`sentinelcore-ai` was verified available against the full PyPI index (894,169 projects) under the same ultranormalization rule, not just against the JSON API.

## The one thing that cannot be undone

**PyPI version numbers are immutable.** You cannot re-upload `0.4.0` after publishing it, even if it is broken — only yank it and publish `0.4.1`. A yanked version still occupies the number and is still installable by exact pin.

So: **TestPyPI first, every time.** It costs one command and it is the only chance to catch a packaging error before it is permanent.

## Why trusted publishing rather than an API token

The release workflow uses PyPI Trusted Publishing (OIDC). GitHub proves the workflow's identity to PyPI directly, so **no long-lived API token exists anywhere** — not in repository secrets, not on a laptop, not in a chat log. For a tool whose own detectors flag credentials in text, a release pipeline that depends on a stored secret is the wrong default.

## One-time setup

1. Create the PyPI account and enable 2FA.
2. On PyPI: **Your projects → Publishing → Add a pending publisher**

   | Field | Value |
   |---|---|
   | PyPI project name | `sentinelcore-ai` ← the **distribution** name |
   | Owner | `jaisurya93945` |
   | Repository name | `sentinelcore` ← the **GitHub repo**, still unrenamed |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

   The first two rows differ on purpose and are the easiest thing here to get wrong.

3. Repeat on **test.pypi.org** with environment name `testpypi`.

   **A publisher created before the rename is stale.** It names the project `sentinelcore`, and the workflow now uploads `sentinelcore-ai` — a different project as far as the index is concerned — so the publish is rejected as unauthorized. Add a second pending publisher for `sentinelcore-ai`. The old one is harmless; a pending publisher reserves nothing and expires on its own.
4. In GitHub: **Settings → Environments** → create `pypi` and `testpypi`. Add a required reviewer on `pypi` so a release cannot happen by accident.

No secrets are added in either place. That is the point.

## Releasing

```bash
# 0. Preconditions. A publish cannot be undone, so confirm all three first:
#      - the code is pushed and the CI workflow is GREEN
#      - GitHub → Settings → Environments contains `pypi` and `testpypi`
#        (OIDC fails if the environment named in the job does not exist)
#      - the pending publisher on each index names the DISTRIBUTION,
#        `sentinelcore-ai`, and the REPOSITORY, `sentinelcore`

# 1. Check the wheel BEFORE it leaves the machine. A packaging defect
#    caught here costs nothing; the same defect caught after upload costs
#    a version number permanently.
python -m build && python scripts/verify_published.py --index local

# 2. TestPyPI
#    GitHub → Actions → "Release to PyPI" → Run workflow → target: testpypi

# 3. Verify what you actually published
python scripts/verify_published.py --index testpypi

# 4. Only then, the real thing
git tag v0.4.0 && git push origin v0.4.0

# 5. Verify the real index too. Step 3 proved a TestPyPI artifact worked;
#    it says nothing about the one that just went out.
python scripts/verify_published.py --index pypi
```

### Verify with the script, not by hand

The hand-written version of steps 3 and 5 used to be in this file, and it
was wrong in the direction that reports success:

```bash
python -m venv /tmp/verify && /tmp/verify/bin/pip install ... sentinelcore-ai
/tmp/verify/bin/python -c "import sentinelcore; print(sentinelcore.__version__)"
```

Run from a clone of this repository — the obvious place to run it — `python
-c` puts the working directory first on `sys.path`, so `import sentinelcore`
resolves to `./sentinelcore/` in the source tree and never touches the
virtualenv. **An empty virtualenv passes that check.** A published wheel
missing every data file would pass it too.

`scripts/verify_published.py` builds the environment outside the repository,
runs every check with `-P` and a foreign working directory, and asserts the
imported module's `__file__` is inside the virtualenv — so shadowing is
impossible rather than merely unlikely. It also checks the version, the
runtime-loaded data files and the console script, and exits non-zero on any
failure.

The tag triggers the release. The workflow will refuse to publish if the tag does not match the version in `pyproject.toml`, and will not reach the publish step at all unless the full suite passes on Python 3.11, 3.12 and 3.13 and the wheel imports from a clean virtualenv.

Re-running step 1 on an already-published version is safe: the TestPyPI job sets `skip-existing`, so a rehearsal can be repeated without bumping the version. The real PyPI job deliberately does not, because there an existing version must stop the release rather than be skipped over.

## Before the first release, decide these

**Version.** `0.4.0` matches this project's internal history but will be the first version on PyPI. That is fine and honest — the alpha classifier is already set. Do not start at `1.0.0`; this software has no production deployments and `1.0` implies a stability commitment that is not yet true.

**What the README promises.** It is the PyPI landing page. It currently states measured operating points with confidence intervals and says plainly that over-defense is unmeasured. Keep that. A security package whose front page overstates its coverage is worse than one nobody installs.

**Yank policy.** If a published version turns out to have a security-relevant defect, yank it and say why in `CHANGELOG.md`. Do not quietly replace it.
