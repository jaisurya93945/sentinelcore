"""Single source of truth for the version.

Deliberately imports nothing. `core.config` needs the version at import
time, and `sentinelcore/__init__.py` imports `core.config` transitively --
so config reading the version from the package root is a circular import
that silently degrades to "unknown". A leaf module with no imports cannot
participate in a cycle.

pyproject.toml carries the same literal; test_packaging.py asserts all
three stay equal, so drift fails CI rather than shipping an API that
advertises a version the package has not been for two milestones.
"""

__version__ = "0.4.0"
