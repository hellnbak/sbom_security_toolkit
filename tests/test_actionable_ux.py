from sbomops.workbench import ux
from sbomops.workbench.server import page


def test_version_and_page_shell():
    from sbomops.__version__ import __version__
    assert __version__ == "2.14.2"
    raw = page("Test", "<h1>ok</h1>", "/workflows").decode()
    assert "Command palette" in raw
    assert "Guided Workflows" in raw
    assert "Policy Simulator" in raw


def test_profiles_and_personas_complete():
    assert len(ux.SCAN_PROFILES) == 6
    assert len(ux.TASKS) == 7
    assert set(ux.PERSONAS) == {"developer", "security", "executive", "auditor"}


def test_policy_simulation():
    assert ux.policy_simulation("development")["blocked"] == 0
    assert ux.policy_simulation("high-assurance")["blocked"] > ux.policy_simulation("standard")["blocked"]


def test_ux_state_and_support_bundle(tmp_path, monkeypatch):
    monkeypatch.setattr(ux, "UX_DIR", tmp_path / "state")
    ux.UX_DIR.mkdir()
    ux.save("preferences.json", {"mode": "guided", "persona": "developer"})
    assert ux.preferences()["persona"] == "developer"
    ux.add_activity("test", "detail")
    assert ux.load("activity.json", [])[0]["action"] == "test"
    out = ux.create_support_bundle(tmp_path / "support.zip")
    assert out.exists() and out.stat().st_size > 0
