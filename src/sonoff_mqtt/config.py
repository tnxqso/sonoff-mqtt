"""Configuration loading for sonoff-mqtt.

Secrets are kept out of the config file by allowing any string value to be
written as ${ENV_VAR}, resolved from the environment at load time. That keeps
config.yml safe to read, and lets a systemd unit hold the actual passwords in an
EnvironmentFile with restrictive permissions.

Validation is deliberately strict and happens at startup, so a missing key fails
loudly on launch rather than surfacing as an obscure error hours later.
"""

# 1. Standard library
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# 2. Third-party
import yaml

ENV_PATTERN = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


class ConfigError(Exception):
    """Raised when the configuration is missing or malformed."""


@dataclass
class AccountConfig:
    name: str
    email: str
    password: str
    country_code: str
    homes: List[str] = field(default_factory=list)


@dataclass
class AppConfig:
    appid: str
    appsecret: str


@dataclass
class MqttConfig:
    host: str
    port: int = 1883
    username: Optional[str] = None
    password: Optional[str] = None
    client_id: str = "sonoff-mqtt"
    base_topic: str = "sonoff"


@dataclass
class VerificationConfig:
    enabled: bool = True
    settle_seconds: float = 2.0
    max_attempts: int = 3
    retry_backoff_seconds: float = 5.0


@dataclass
class Config:
    accounts: List[AccountConfig]
    app: AppConfig
    mqtt: MqttConfig
    verification: VerificationConfig
    log_level: str = "INFO"
    ewelink_log_level: str = "INFO"


def _resolve_env(value: Any) -> Any:
    """Replace a ${VAR} string with the environment value it names.

    Anything that is not exactly ${VAR} is returned untouched, so a password
    that happens to contain a dollar sign is not mangled.
    """
    if not isinstance(value, str):
        return value
    match = ENV_PATTERN.match(value)
    if match is None:
        return value
    name = match.group(1)
    resolved = os.environ.get(name)
    if resolved is None:
        raise ConfigError(f"Config references ${{{name}}} but that variable is not set")
    return resolved


def _require(data: Dict[str, Any], key: str, where: str) -> Any:
    if key not in data or data[key] is None:
        raise ConfigError(f"Missing required key '{key}' in {where}")
    return data[key]


def load_config(path: Path) -> Config:
    """Read and validate the configuration file."""
    if not path.exists():
        raise ConfigError(
            f"No configuration at {path}. Copy config/config.example.yml and fill it in."
        )

    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    accounts_raw = _require(raw, "accounts", "config")
    if not accounts_raw:
        raise ConfigError("At least one account must be configured")

    accounts = []
    for index, entry in enumerate(accounts_raw):
        where = f"accounts[{index}]"
        accounts.append(
            AccountConfig(
                name=_require(entry, "name", where),
                email=_require(entry, "email", where),
                password=_resolve_env(_require(entry, "password", where)),
                country_code=str(_require(entry, "country_code", where)),
                homes=[str(h) for h in (entry.get("homes") or [])],
            )
        )

    names = [a.name for a in accounts]
    if len(names) != len(set(names)):
        raise ConfigError(f"Account names must be unique, got {names}")

    app_raw = _require(raw, "app", "config")
    app = AppConfig(
        appid=_resolve_env(_require(app_raw, "appid", "app")),
        appsecret=_resolve_env(_require(app_raw, "appsecret", "app")),
    )

    mqtt_raw = _require(raw, "mqtt", "config")
    mqtt = MqttConfig(
        host=_require(mqtt_raw, "host", "mqtt"),
        port=int(mqtt_raw.get("port", 1883)),
        username=_resolve_env(mqtt_raw.get("username")),
        password=_resolve_env(mqtt_raw.get("password")),
        client_id=mqtt_raw.get("client_id", "sonoff-mqtt"),
        base_topic=mqtt_raw.get("base_topic", "sonoff"),
    )

    ver_raw = raw.get("verification") or {}
    verification = VerificationConfig(
        enabled=bool(ver_raw.get("enabled", True)),
        settle_seconds=float(ver_raw.get("settle_seconds", 2.0)),
        max_attempts=int(ver_raw.get("max_attempts", 3)),
        retry_backoff_seconds=float(ver_raw.get("retry_backoff_seconds", 5.0)),
    )

    log_raw = raw.get("logging") or {}

    return Config(
        accounts=accounts,
        app=app,
        mqtt=mqtt,
        verification=verification,
        log_level=log_raw.get("level", "INFO"),
        ewelink_log_level=log_raw.get("ewelink_level", "INFO"),
    )
