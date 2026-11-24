from universe.models import RiskLevel


def test_loads_all_five_targets(registry):
    ids = sorted(t.id for t in registry.all())
    assert ids == [
        "android.phone",
        "browser.local",
        "mcp.generic",
        "rest.generic",
        "zapier.main",
    ]


def test_android_maps_phone_control_actions(registry):
    cfg = registry.get("android.phone")
    assert cfg.kind == "android"
    assert cfg.auth.token_env == "RELAY_TOKEN"
    assert cfg.endpoint["command_path"] == "/command"
    actions = {c.action for c in cfg.capabilities}
    for needed in ("tap", "open_app", "dump_screen", "esim_start", "youtube_play", "route_replay"):
        assert needed in actions
    assert "com.kraken.trade" in cfg.protected_packages
    cap = cfg.capability("esim_start")
    assert cap.risk == RiskLevel.CRITICAL
    assert "activation_code" in cap.sensitive_params


def test_public_capabilities_have_no_secrets(registry):
    public = registry.capabilities_public()
    blob = str(public)
    assert "Bearer" not in blob
    assert "token_env" not in blob
    assert any(i["target"] == "android.phone" and i["action"] == "tap" for i in public)
