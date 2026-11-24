from universe.models import Command, RiskLevel, TargetConfig
from universe.registry import CapabilityRegistry
from universe.risk import classify, must_confirm
from pathlib import Path

CONFIGS = Path(__file__).resolve().parents[1] / "configs"


def _reg() -> CapabilityRegistry:
    r = CapabilityRegistry()
    r.load_dir(CONFIGS)
    return r


def test_read_only_is_low():
    reg = _reg()
    target = reg.get("android.phone")
    cmd = Command(source="ara", target="android.phone", action="dump_screen")
    cap = reg.resolve_capability(target, "dump_screen")
    assert classify(cmd, target, cap) == RiskLevel.LOW
    assert must_confirm(cmd, RiskLevel.LOW, cap) is False


def test_delete_and_pay_force_confirmation():
    reg = _reg()
    rest = reg.get("rest.generic")
    delete = Command(source="ara", target="rest.generic", action="delete_item", params={"id": "1"})
    cap = reg.resolve_capability(rest, "delete_item")
    risk = classify(delete, rest, cap)
    assert risk == RiskLevel.HIGH
    assert must_confirm(delete, risk, cap) is True

    pay = Command(source="ara", target="rest.generic", action="pay", params={"amount": 10})
    cap = reg.resolve_capability(rest, "pay")
    risk = classify(pay, rest, cap)
    assert risk == RiskLevel.CRITICAL
    assert must_confirm(pay, risk, cap) is True


def test_protected_package_raises_risk():
    reg = _reg()
    target = reg.get("android.phone")
    cmd = Command(
        source="ara",
        target="android.phone",
        action="open_app",
        params={"package": "com.kraken.trade"},
    )
    cap = reg.resolve_capability(target, "open_app")
    assert classify(cmd, target, cap) == RiskLevel.HIGH


def test_client_cannot_downgrade_risk():
    reg = _reg()
    rest = reg.get("rest.generic")
    cmd = Command(source="bot", target="rest.generic", action="pay", risk=RiskLevel.LOW)
    cap = reg.resolve_capability(rest, "pay")
    assert classify(cmd, rest, cap) == RiskLevel.CRITICAL


def test_esim_is_critical():
    reg = _reg()
    target = reg.get("android.phone")
    cmd = Command(source="ara", target="android.phone", action="esim_start")
    cap = reg.resolve_capability(target, "esim_start")
    assert classify(cmd, target, cap) == RiskLevel.CRITICAL
