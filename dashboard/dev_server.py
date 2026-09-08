"""Local dev-only launcher: sets env vars an in-process run needs, then starts
the real dashboard. Not used by Docker (entrypoint there is `dashboard.py`
directly, configured via docker-compose's environment: block) -- this exists
purely so the dashboard can be previewed outside a container while working
on it. Not referenced by any Dockerfile."""
import os
import sys
import tempfile
from pathlib import Path

# common/*.py only ends up next to dashboard.py inside the Docker image
# (Dockerfile COPYs them flat into /app); locally they live in ../common,
# so it needs to go on sys.path before `import dashboard` pulls them in.
sys.path.insert(0, str(Path(__file__).parent.parent / "common"))

tmp_dir = Path(tempfile.gettempdir()) / "optigate_dashboard_dev"
tmp_dir.mkdir(exist_ok=True)

os.environ.setdefault("OG_DB_PATH", str(tmp_dir / "dev.db"))
os.environ.setdefault("OG_CA_CERT_PATH", str(tmp_dir / "ca_cert.pem"))
os.environ.setdefault("DASHBOARD_USER", "admin")
os.environ.setdefault("DASHBOARD_PASSWORD", "devpassword123")
os.environ.setdefault("DASHBOARD_HOST", "127.0.0.1")
os.environ.setdefault("DASHBOARD_PORT", "8787")
os.environ.setdefault("LOCAL_NETWORK", "")

import dashboard  # noqa: E402  (env vars above must be set first)

dashboard.main()
