"""Tests for KASEVRA environment diagnostics."""

from kasevra.commands import doctor
from kasevra.core.results import ResultStatus


def test_run_doctor_reports_success_when_checks_pass(monkeypatch) -> None:
    """Return success when all local environment checks pass."""
    monkeypatch.setattr(doctor.sys, "version_info", (3, 14, 8))
    monkeypatch.setattr(doctor.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(doctor.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(doctor.platform, "python_version", lambda: "3.14.8")
    monkeypatch.setattr(doctor, "version", lambda _: "1.0.0")

    result = doctor.run_doctor()

    assert result.status is ResultStatus.SUCCESS
    assert result.exit_code == 0
    assert result.details == {"checks": 4, "warnings": 0}


def test_run_doctor_warns_when_python_is_too_old(monkeypatch) -> None:
    """Report a partial result if Python is below the minimum version."""
    monkeypatch.setattr(doctor.sys, "version_info", (3, 10, 9))
    monkeypatch.setattr(doctor.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(doctor.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(doctor.platform, "python_version", lambda: "3.10.9")
    monkeypatch.setattr(doctor, "version", lambda _: "1.0.0")

    result = doctor.run_doctor()

    assert result.status is ResultStatus.PARTIAL
    assert result.exit_code == 2
    assert result.details == {"checks": 4, "warnings": 1}
