"""Entry point. Run with: python -m sonoff_mqtt --config config/config.yml"""

# 1. Standard library
import argparse
import asyncio
import logging
import sys
from pathlib import Path

# 3. Project-local
from .config import ConfigError, load_config
from .observer import Observer

_LOGGER = logging.getLogger(__name__)


def main() -> int:
    parser = argparse.ArgumentParser(prog="sonoff-mqtt")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/config.yml"),
        help="path to the configuration file",
    )
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 1

    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    logging.getLogger("sonoff_mqtt.vendor.ewelink").setLevel(
        getattr(logging, config.ewelink_log_level.upper(), logging.INFO)
    )

    observer = Observer(config)
    try:
        asyncio.run(observer.run())
    except KeyboardInterrupt:
        _LOGGER.info("Interrupted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
