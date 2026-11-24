import pytest
from pydantic import ValidationError

from universe.models import Command, RiskLevel


def test_envelope_defaults():
    cmd = Command(source="ara", target="android.phone", action="dump_screen")
    assert cmd.id
    assert cmd.idempotency_key
    assert cmd.dry_run is True
    assert cmd.params == {}
    assert cmd.requires_confirmation is False


def test_envelope_rejects_empty_fields():
    with pytest.raises(ValidationError):
        Command(source=" ", target="android.phone", action="tap")
    with pytest.raises(ValidationError):
        Command(source="ara", target="", action="tap")


def test_risk_rank_and_gate():
    assert RiskLevel.CRITICAL.rank() > RiskLevel.HIGH.rank()
    assert RiskLevel.HIGH.needs_confirmation()
    assert RiskLevel.CRITICAL.needs_confirmation()
    assert not RiskLevel.LOW.needs_confirmation()
    assert not RiskLevel.MEDIUM.needs_confirmation()
