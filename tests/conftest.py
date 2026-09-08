"""Shared pytest fixtures for OptiGate's Tier-1 (no-Docker) suite.

Every component in this repo is deployed as a *flat* directory in its
container (see the Dockerfiles): common/*.py, the proxy helpers, and
defaults/seed_defaults.py are all copied into /opt/parental-proxy/, and
common/*.py + dashboard.py are copied into /app/ for the dashboard image.
Every module therefore does bare imports like ``import db`` or
``import cr_api``, not ``from common import db``. To exercise the real code
unmodified, this conftest puts each source directory directly on
sys.path (flat, no package layer) instead of using a src-layout/PYTHONPATH
trick that would require touching the modules under test.

``controller/`` (the Phase 3 interception-controller, see RoadMap.md
Milestone 3) has no Dockerfile yet -- it isn't deployed anywhere yet --
but follows the same flat-import convention (``from ipc_client import
Target``, not ``from controller import ipc_client``) so it's included
here on the same basis, ready for whenever it does get containerized.

No Docker, no network, no external services -- see the autouse
``block_network`` fixture below.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for sub in ("common", "proxy", "dashboard", "defaults", "controller"):
    p = str(REPO_ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

# db.py reads PP_DB_PATH once, at its own import time, and stores it in a
# module-level Path. Set it to something harmless *before* anything imports
# db, so a stray import elsewhere in the session never touches a real
# /config/parental_proxy.db path, or writes anywhere inside the repo.
# Individual tests still isolate themselves by monkeypatching db.DB_PATH
# directly (see the `conn` fixture) -- this is just a safe default for
# whichever import happens first.
os.environ.setdefault(
    "PP_DB_PATH", str(Path(tempfile.gettempdir()) / "parental_proxy_pytest_default.db")
)

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    """No test in this suite may make a real network call. The only network
    entry point anywhere in this codebase is cr_api._OPENER.open (everything
    else goes through the shared SQLite file) -- patch that directly rather
    than the stdlib `socket` module: replacing socket.socket globally breaks
    `ssl.py`'s `class SSLSocket(socket):` the moment anything imports ssl for
    the first time, which raises a confusing TypeError instead of a clean
    failure. Anything exercising cr_api must monkeypatch this (or
    cr_api.SeriesResolver._get_json / cr_api.series_title) explicitly."""
    import cr_api

    def _blocked(*args, **kwargs):
        raise RuntimeError(
            "Network access attempted during a Tier-1 test. Mock the call "
            "instead (see cr_api._OPENER.open / SeriesResolver._get_json)."
        )

    monkeypatch.setattr(cr_api._OPENER, "open", _blocked)


@pytest.fixture
def conn(monkeypatch, tmp_path):
    """A fresh, isolated SQLite connection (schema applied, no data) per
    test. Monkeypatches db.DB_PATH directly -- db.get_conn() reads that
    module attribute on every call, so this is enough for full isolation
    even though db.py itself is only ever imported once per test session."""
    import db

    db_file = tmp_path / "test.db"
    monkeypatch.setattr(db, "DB_PATH", db_file)
    connection = db.get_conn()
    db.init_db(connection)
    yield connection
    connection.close()
