from io import StringIO

from rich.console import Console

import kasevra.ui.dashboard as dashboard


def test_header_renders_centered_branding(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(
        dashboard,
        "console",
        Console(file=output, force_terminal=False, width=150),
    )
    monkeypatch.setattr(dashboard, "COLOR_ENABLED", False)
    dashboard.header("doctor", "Environment check")
    rendered = output.getvalue()

    assert dashboard.PRODUCT_DESCRIPTION.upper() in rendered
    assert dashboard.TAGLINE in rendered
    assert "kasevra doctor" in rendered
    assert "Environment check" in rendered
    assert "v1.0.0" not in rendered
    assert "✔" not in rendered


def test_header_displays_block_wordmark_without_shield(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(
        dashboard,
        "console",
        Console(file=output, force_terminal=False, width=150),
    )
    monkeypatch.setattr(dashboard, "COLOR_ENABLED", False)
    dashboard.header()
    rendered = output.getvalue()

    assert "█████" in rendered
    assert dashboard.TAGLINE in rendered
    assert dashboard.PRODUCT_DESCRIPTION.upper() in rendered
    assert "✔" not in rendered


def test_section_renders_heading(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(
        dashboard,
        "console",
        Console(file=output, force_terminal=False, width=100),
    )

    dashboard.section("SECURITY CHECKS")

    assert "SECURITY CHECKS" in output.getvalue()


def test_status_renders_all_supported_states(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(
        dashboard,
        "console",
        Console(file=output, force_terminal=False, width=100),
    )
    monkeypatch.setattr(dashboard, "COLOR_ENABLED", False)

    for state, marker in (
        ("OK", "[OK]"),
        ("WARN", "[WARN]"),
        ("FAIL", "[FAIL]"),
        ("INFO", "[INFO]"),
        ("UNKNOWN", "[INFO]"),
    ):
        dashboard.status("Integrity", "Check completed", state)

        assert marker in output.getvalue()

    assert "Integrity: Check completed" in output.getvalue()


def test_summary_renders_rows(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(
        dashboard,
        "console",
        Console(file=output, force_terminal=False, width=100),
    )

    dashboard.summary(
        "COLLECTION SUMMARY",
        [("Files", "2"), ("Verification", "Passed")],
    )

    rendered = output.getvalue()
    assert "COLLECTION SUMMARY" in rendered
    assert "Files" in rendered
    assert "Verification" in rendered
    assert "Passed" in rendered


def test_dashboard_demo_discloses_preview_only(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(
        dashboard,
        "console",
        Console(file=output, force_terminal=False, width=100),
    )
    monkeypatch.setattr(dashboard, "COLOR_ENABLED", False)

    dashboard.dashboard_demo()

    rendered = output.getvalue()
    assert "VISUAL PREVIEW" in rendered
    assert "SAMPLE DATA ONLY" in rendered
    assert "no evidence collected" in rendered.lower()
    assert "not contacted" in rendered.lower()
    assert "kasevra collect" in rendered
    assert "kasevra verify" in rendered
    assert "Evidence collection" in rendered
    assert "Not run" in rendered


def test_plain_text_status_does_not_require_color(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(
        dashboard,
        "console",
        Console(file=output, force_terminal=False, width=100, no_color=True),
    )
    monkeypatch.setattr(dashboard, "COLOR_ENABLED", False)

    dashboard.status("Terminal", "Plain-text fallback", "OK")

    rendered = output.getvalue()
    assert "[OK]" in rendered
    assert "Plain-text fallback" in rendered
    assert "\x1b[" not in rendered
