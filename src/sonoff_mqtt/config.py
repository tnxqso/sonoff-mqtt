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

# 3. Project-local modules
from .vendor.ewelink.cloud import REGIONS

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


class MissingEnvVar(str):
    """Placeholder for a ${VAR} that could not be resolved.

    Subclasses str so it flows through the config unchanged and is falsy when
    empty, while still being recognisable to the dump. Only reachable when
    resolution is non-strict, which is the case for --dump-config.
    """

    def __new__(cls, name: str):
        obj = super().__new__(cls, "")
        obj.name = name
        return obj


def _resolve_env(value: Any, strict: bool = True) -> Any:
    """Replace a ${VAR} string with the environment value it names.

    Anything that is not exactly ${VAR} is returned untouched, so a password
    that happens to contain a dollar sign is not mangled.

    With strict=False an unresolvable variable yields a MissingEnvVar rather
    than raising. That is for --dump-config, which is most useful exactly when
    the configuration is broken: refusing to print it because a variable is
    missing withholds the answer at the moment it is needed.
    """
    if not isinstance(value, str):
        return value
    match = ENV_PATTERN.match(value)
    if match is None:
        return value
    name = match.group(1)
    resolved = os.environ.get(name)
    if resolved is None:
        if strict:
            raise ConfigError(
                f"Config references ${{{name}}} but that variable is not set"
            )
        return MissingEnvVar(name)
    return resolved


def _require(data: Dict[str, Any], key: str, where: str) -> Any:
    if key not in data or data[key] is None:
        raise ConfigError(f"Missing required key '{key}' in {where}")
    return data[key]


def load_config(path: Path, strict_env: bool = True) -> Config:
    """Read and validate the configuration file.

    strict_env=False lets an unresolvable ${VAR} through as a placeholder
    instead of failing, which is what --dump-config needs.
    """
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
        country_code = str(_require(entry, "country_code", where))
        if country_code not in REGIONS:
            raise ConfigError(
                f"Unknown country_code {country_code!r} in {where}. It selects the "
                f"eWeLink datacentre and must be a dialling code including the plus "
                f"sign, for example \"+46\". Quote it in YAML or it is read as a number."
            )
        accounts.append(
            AccountConfig(
                name=_require(entry, "name", where),
                email=_require(entry, "email", where),
                password=_resolve_env(_require(entry, "password", where), strict_env),
                country_code=country_code,
                homes=[str(h) for h in (entry.get("homes") or [])],
            )
        )

    names = [a.name for a in accounts]
    if len(names) != len(set(names)):
        raise ConfigError(f"Account names must be unique, got {names}")

    app_raw = _require(raw, "app", "config")
    app = AppConfig(
        appid=_resolve_env(_require(app_raw, "appid", "app"), strict_env),
        appsecret=_resolve_env(_require(app_raw, "appsecret", "app"), strict_env),
    )

    mqtt_raw = _require(raw, "mqtt", "config")
    base_topic = mqtt_raw.get("base_topic", "sonoff")
    if any(ch in str(base_topic) for ch in "/+#") or not str(base_topic).strip():
        raise ConfigError(
            f"Invalid mqtt.base_topic {base_topic!r}. It is a single level prefix, so "
            f"it cannot be empty or contain a slash, a plus or a hash."
        )

    mqtt = MqttConfig(
        host=_require(mqtt_raw, "host", "mqtt"),
        port=int(mqtt_raw.get("port", 1883)),
        username=_resolve_env(mqtt_raw.get("username"), strict_env),
        password=_resolve_env(mqtt_raw.get("password"), strict_env),
        client_id=mqtt_raw.get("client_id", "sonoff-mqtt"),
        base_topic=base_topic,
    )

    ver_raw = raw.get("verification") or {}

    max_attempts = int(ver_raw.get("max_attempts", 3))
    if max_attempts < 1:
        raise ConfigError(
            f"verification.max_attempts must be at least 1, got {max_attempts}. "
            f"It counts the first send, so 1 means send once and do not retry."
        )

    settle_seconds = float(ver_raw.get("settle_seconds", 2.0))
    if settle_seconds < 0.1:
        raise ConfigError(
            f"verification.settle_seconds must be at least 0.1, got {settle_seconds}. "
            f"The device needs time to switch and report before its state is read "
            f"back, otherwise every command appears to have failed."
        )

    retry_backoff = float(ver_raw.get("retry_backoff_seconds", 5.0))
    if retry_backoff < 0:
        raise ConfigError(
            f"verification.retry_backoff_seconds cannot be negative, got {retry_backoff}"
        )

    verification = VerificationConfig(
        enabled=bool(ver_raw.get("enabled", True)),
        settle_seconds=settle_seconds,
        max_attempts=max_attempts,
        retry_backoff_seconds=retry_backoff,
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

# ==============================================================================
# Redacted dump for support
# ==============================================================================

# Anything here is replaced with a placeholder rather than printed. The list is
# explicit rather than pattern based, so a field added later is only exposed if
# someone decides it is safe, not because it failed to match a regex.
REDACTED = "[REDACTED]"


def _redact(value: Any) -> str:
    """Show whether a secret is set without revealing it.

    An empty secret and a wrong secret produce very different symptoms, so it is
    worth distinguishing them in a dump.
    """
    if isinstance(value, MissingEnvVar):
        return f"(env var {value.name} is NOT SET)"
    if value is None:
        return "(not set)"
    if not str(value):
        return "(empty)"
    return REDACTED


def dump(config: "Config") -> str:
    """Render the effective configuration for a support request.

    Includes values the user did not set, because "I left it at the default" and
    "I set it to the same as the default" are indistinguishable otherwise, and
    only one of them survives a change of default.

    Passwords, the app secret and the MQTT password are never printed.
    """
    lines: List[str] = []
    lines.append("Effective configuration")
    lines.append("=" * 60)

    lines.append(f"accounts: {len(config.accounts)}")
    for account in config.accounts:
        lines.append(f"  - name         : {account.name}")
        lines.append(f"    email        : {account.email}")
        lines.append(f"    password     : {_redact(account.password)}")
        lines.append(f"    country_code : {account.country_code}")
        if account.homes:
            lines.append(f"    homes        : {account.homes}")
        else:
            lines.append("    homes        : (all homes the account can see)")

    lines.append("app:")
    lines.append(f"  appid     : {config.app.appid}")
    lines.append(f"  appsecret : {_redact(config.app.appsecret)}")

    lines.append("mqtt:")
    lines.append(f"  host       : {config.mqtt.host}")
    lines.append(f"  port       : {config.mqtt.port}")
    lines.append(f"  username   : {config.mqtt.username or '(not set)'}")
    lines.append(f"  password   : {_redact(config.mqtt.password)}")
    lines.append(f"  client_id  : {config.mqtt.client_id}")
    lines.append(f"  base_topic : {config.mqtt.base_topic}")

    lines.append("verification:")
    lines.append(f"  enabled               : {config.verification.enabled}")
    lines.append(f"  settle_seconds        : {config.verification.settle_seconds}")
    lines.append(f"  max_attempts          : {config.verification.max_attempts}")
    lines.append(f"  retry_backoff_seconds : {config.verification.retry_backoff_seconds}")

    lines.append("logging:")
    lines.append(f"  level         : {config.log_level}")
    lines.append(f"  ewelink_level : {config.ewelink_log_level}")

    lines.append("=" * 60)
    return "\n".join(lines)
