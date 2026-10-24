"""Single source of truth for the version.

Read by __main__ for the --version flag and the startup banner, and by
pyproject.toml if packaging is ever added. A user asked which version they are
running should be able to answer from the log alone, without inspecting files.
"""

__version__ = "0.5.0"
