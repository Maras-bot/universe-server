"""Impostazioni di processo. Il live è spento finché non lo accendi tu."""

from __future__ import annotations

import os

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="UNIVERSE_", extra="ignore")

    dry_run: bool = True
    allow_live: bool = False
    token: str = ""  # deprecato: non usarlo come token condiviso
    configs_dir: str = "configs"
    audit_path: str = "logs/audit.jsonl"
    confirmation_timeout_seconds: int = 60
    confirmation_channel: str = "chat"  # chat | phone_notification

    bot_tokens_file: str = ""
    bot_tokens: str = ""  # JSON {client_id: token}, sconsigliato rispetto al file
    phone_token: str = ""
    relay_token: str = ""
    relay_accounts_file: str = ""
    relay_command_timeout: float = 30.0
    enable_docs: bool = False
    require_tls: bool = False
    max_request_bytes: int = 65536
    http_rate_limit_per_minute: int = 60
    http_rate_limit_unauth_per_minute: int = 20
    phone_hello_timeout_seconds: float = 5.0

    def effective_dry_run(self, command_dry_run: bool) -> bool:
        """Live solo se: allow_live, dry_run di processo spento, e il comando lo chiede."""
        if not self.allow_live:
            return True
        if self.dry_run:
            return True
        return command_dry_run

    def effective_relay_token(self) -> str:
        return self.relay_token or os.environ.get("RELAY_TOKEN", "")

    def effective_relay_accounts_file(self) -> str:
        return self.relay_accounts_file or os.environ.get("RELAY_ACCOUNTS_FILE", "")

    def effective_relay_command_timeout(self) -> float:
        raw = os.environ.get("RELAY_COMMAND_TIMEOUT", "")
        if raw:
            try:
                return float(raw)
            except ValueError:
                pass
        return self.relay_command_timeout
