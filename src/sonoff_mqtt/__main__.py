"""Entry point. Run with: python -m sonoff_mqtt --config config/config.yml"""

# 1. Standard library
import argparse
import asyncio
import logging
import sys
from pathlib import Path

# 3. Project-local
from .config import ConfigError, dump, load_config
from .lock import AlreadyRunning, SingleInstance
from .observer import Observer
from .version import __version__

_LOGGER = logging.getLogger(__name__)


def main() -> int:
    parser = argparse.ArgumentParser(prog="sonoff-mqtt")
    parser.add_argument(
        "--version",
        action="version",
        version=f"sonoff-mqtt {__version__}",
        help="print the version and exit",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/config.yml"),
        help="path to the configuration file",
    )
    parser.add_argument(
        "--dump-config",
        action="store_true",
        help="print the effective configuration and exit, with secrets redacted",
    )
    args = parser.parse_args()

    try:
        config = load_config(args.config, strict_env=not args.dump_config)
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 1

    if args.dump_config:
        # Deliberately printed rather than logged, so it can be piped into a
        # support request without the log format getting in the way
        print(dump(config))
        return 0

    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    logging.getLogger("sonoff_mqtt.vendor.ewelink").setLevel(
        getattr(logging, config.ewelink_log_level.upper(), logging.INFO)
    )

    # Logged before anything else, so the version is the first thing in the log
    # of any run. A bug report that starts with the log then answers "which
    # version" without having to ask.
    _LOGGER.info("sonoff-mqtt %s starting", __version__)

    lock = SingleInstance(config.mqtt.base_topic)
    try:
        lock.acquire()
    except AlreadyRunning as e:
        _LOGGER.error("%s", e)
        return 1

    observer = Observer(config)
    try:
        asyncio.run(observer.run())
    except KeyboardInterrupt:
        _LOGGER.info("Interrupted")
    finally:
        lock.release()
    return 0


if __name__ == "__main__":
    sys.exit(main())
