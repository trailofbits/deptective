import argparse
import logging
import sys
from typing import Optional, Sequence

from .dependencies import SBOMGenerator


def main(args: Optional[Sequence[str]] = None):
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs=argparse.REMAINDER)

    log_section = parser.add_argument_group(title="logging")
    log_group = log_section.add_mutually_exclusive_group()
    log_group.add_argument("--log-level", type=str, default="INFO", choices=list(
        logging.getLevelName(x)
        for x in range(1, 101)
        if not logging.getLevelName(x).startswith("Level")
    ), help='sets the log level for apt-trace (default=INFO)')
    log_group.add_argument("--debug", action="store_true", help="equivalent to `--log-level=DEBUG`")
    log_group.add_argument("--quiet", action="store_true", help="equivalent to `--log-level=CRITICAL`")

    args = parser.parse_args(args)

    if args.debug:
        numeric_log_level = logging.DEBUG
    elif args.quiet:
        numeric_log_level = logging.CRITICAL
    else:
        numeric_log_level = getattr(logging, args.log_level.upper(), None)
        if not isinstance(numeric_log_level, int):
            sys.stderr.write(f"Invalid log level: {args.log_level}\n")
            exit(1)

    logging.basicConfig(level=numeric_log_level)

    for sbom in SBOMGenerator().main(" ".join(args.command)):
        print(sbom)
        break
