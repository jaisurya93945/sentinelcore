# Releasing to PyPI

**`sentinelcore` is available on PyPI** (checked against the index). Note that **`sentinel-core` is taken by an unrelated project** — a hyphen typo lands a user on someone else's package, which is worth knowing for a security tool.

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
   | PyPI project name | `sentinelcore` |
   | Owner | `jaisurya93945` |
   | Repository name | `sentinelcore` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

3. Repeat on **test.pypi.org** with environment name `testpypi`.
4. In GitHub: **Settings → Environments** → create `pypi` and `testpypi`. Add a required reviewer on `pypi` so a release cannot happen by accident.

No secrets are added in either place. That is the point.

## Releasing

```bash
# 1. TestPyPI — always first
#    GitHub → Actions → "Release to PyPI" → Run workflow → target: testpypi

# 2. Verify what you actually published, in a clean environment
python -m venv /tmp/verify && /tmp/verify/bin/pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ sentinelcore
/tmp/verify/bin/python -c "import sentinelcore; print(sentinelcore.__version__)"
/tmp/verify/bin/sentinel doctor

# 3. Only then, the real thing
git tag v0.4.0 && git push origin v0.4.0
```

The tag triggers the release. The workflow will refuse to publish if the tag does not match the version in `pyproject.toml`, and will not reach the publish step at all unless the full suite passes on Python 3.11, 3.12 and 3.13 and the wheel imports from a clean virtualenv.

## Before the first release, decide these

**Version.** `0.4.0` matches this project's internal history but will be the first version on PyPI. That is fine and honest — the alpha classifier is already set. Do not start at `1.0.0`; this software has no production deployments and `1.0` implies a stability commitment that is not yet true.

**What the README promises.** It is the PyPI landing page. It currently states measured operating points with confidence intervals and says plainly that over-defense is unmeasured. Keep that. A security package whose front page overstates its coverage is worse than one nobody installs.

**Yank policy.** If a published version turns out to have a security-relevant defect, yank it and say why in `CHANGELOG.md`. Do not quietly replace it.
