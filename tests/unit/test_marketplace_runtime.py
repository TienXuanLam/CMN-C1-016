"""Dependency checks for the Marketplace container entrypoint."""

from importlib.util import find_spec


def test_marketplace_database_driver_is_installed() -> None:
    """cli.py imports the Marketplace DB runner before invoking the graph."""
    assert find_spec("asyncpg") is not None
