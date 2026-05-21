import os
import tempfile

import pytest


@pytest.fixture(scope="module")
def temp_db():
    fd, tmpfile = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    old_val = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = f"sqlite:///{tmpfile}"

    from devsecops_radar.core.database import save_scan, get_all_scans, get_findings_paginated  # noqa: E402

    yield tmpfile, save_scan, get_all_scans, get_findings_paginated

    os.unlink(tmpfile)
    if old_val is None:
        del os.environ["DATABASE_URL"]
    else:
        os.environ["DATABASE_URL"] = old_val


def test_save_and_retrieve(temp_db):
    tmpfile, save_scan, get_all_scans, get_findings_paginated = temp_db
    findings = [
        {
            "tool": "test",
            "severity": "HIGH",
            "id": "1",
            "target": "t",
            "title": "t",
            "description": "d",
        }
    ]
    save_scan(findings)
    scans = get_all_scans()
    assert len(scans) > 0
    paginated = get_findings_paginated(1, 10)
    assert paginated["total"] >= 1
    