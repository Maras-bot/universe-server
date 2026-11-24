"""Classificazione del rischio. High e critical richiedono sempre conferma."""

from __future__ import annotations

from typing import Any

from universe.models import Capability, Command, RiskLevel, TargetConfig

# Azioni irreversibili: conferma obbligatoria anche se il client non la chiede.
IRREVERSIBLE_ACTIONS = {
    "send",
    "send_message",
    "pay",
    "payment",
    "transfer",
    "withdraw",
    "purchase",
    "buy",
    "checkout",
    "publish",
    "post",
    "create_post",
    "share",
    "delete",
    "route_delete",
    "subscribe",
    "unsubscribe",
    "account_change",
    "esim_start",
    "confirm_and_send",
}

CRITICAL_ACTIONS = {
    "pay",
    "payment",
    "transfer",
    "withdraw",
    "purchase",
    "buy",
    "checkout",
    "esim_start",
    "account_change",
}

# Verbi che alzano il rischio se compaiono nel nome azione (es. zapier.send).
IRREVERSIBLE_VERBS = (
    "send",
    "pay",
    "publish",
    "delete",
    "transfer",
    "withdraw",
    "purchase",
    "checkout",
    "post",
    "share",
    "subscribe",
)


def _from_name(action: str) -> RiskLevel:
    name = action.lower().strip()
    if name in CRITICAL_ACTIONS or any(name.endswith("." + a) or name.endswith("_" + a) for a in CRITICAL_ACTIONS):
        return RiskLevel.CRITICAL
    if name in IRREVERSIBLE_ACTIONS:
        return RiskLevel.HIGH
    for verb in IRREVERSIBLE_VERBS:
        if name == verb or name.endswith("_" + verb) or name.endswith("." + verb) or verb + "_" in name:
            return RiskLevel.CRITICAL if verb in CRITICAL_ACTIONS or verb in {"pay", "transfer", "withdraw"} else RiskLevel.HIGH
    if name.startswith("get_") or name.endswith("_status") or name.startswith("list") or name.startswith("dump") or name.endswith("_list") or name in {
        "health",
        "dump_screen",
        "youtube_status",
        "esim_status",
        "record_status",
        "route_status",
        "routes_list",
        "route_export",
    }:
        return RiskLevel.LOW
    return RiskLevel.MEDIUM


def _higher(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return a if a.rank() >= b.rank() else b


def classify(
    command: Command,
    target: TargetConfig,
    capability: Capability | None,
) -> RiskLevel:
    """Prende il massimo tra: nome azione, capability YAML, rischio dichiarato dal client, regole target."""
    level = _from_name(command.action)
    if capability:
        level = _higher(level, capability.risk)
    if command.risk:
        level = _higher(level, command.risk)

    # App protette sul telefono: aprire o agire lì è almeno high.
    if target.kind == "android":
        pkg = str(command.params.get("package") or "")
        if pkg and pkg in set(target.protected_packages):
            level = _higher(level, RiskLevel.HIGH)
        if command.action == "esim_start":
            level = _higher(level, RiskLevel.CRITICAL)

    return level


def must_confirm(
    command: Command,
    risk: RiskLevel,
    capability: Capability | None,
) -> bool:
    if risk.needs_confirmation():
        return True
    if command.requires_confirmation:
        return True
    if capability and capability.requires_confirmation:
        return True
    if command.action in IRREVERSIBLE_ACTIONS:
        return True
    return False
