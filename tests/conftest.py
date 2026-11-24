from __future__ import annotations

from pathlib import Path

import pytest

from universe.audit import AuditLog
from universe.confirm import ConfirmationStore
from universe.registry import CapabilityRegistry
from universe.router import Router
from universe.settings import Settings

ROOT = Path(__file__).resolve().parents[1]
CONFIGS = ROOT / "configs"


@pytest.fixture
def configs_dir() -> Path:
    return CONFIGS


@pytest.fixture
def registry(configs_dir: Path) -> CapabilityRegistry:
    reg = CapabilityRegistry()
    reg.load_dir(configs_dir)
    return reg


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        dry_run=True,
        allow_live=False,
        configs_dir=str(CONFIGS),
        audit_path=str(tmp_path / "audit.jsonl"),
        confirmation_timeout_seconds=60,
    )


@pytest.fixture
def router(registry: CapabilityRegistry, settings: Settings) -> Router:
    return Router(
        registry,
        settings=settings,
        audit=AuditLog(settings.audit_path),
        confirmations=ConfirmationStore(timeout_seconds=60),
    )
