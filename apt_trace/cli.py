import argparse
import logging
import sys
from typing import List, Optional, Sequence

from rich import traceback
from rich.console import Console
from rich.logging import RichHandler

from .dependencies import SBOMGenerationError, SBOM, SBOMGenerator


logger = logging.getLogger(__name__)


def main(args: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    results_group = parser.add_mutually_exclusive_group()
    results_group.add_argument("--num-results", "-n", type=int, default=1,
                               help="the maximum number of satisfying sets of package dependencies to discover; use "
                                    "zero to enumerate all possible results (default=1)")
    results_group.add_argument("--all", "-a", action="store_true", help="enumerate all possible results; "
                                                                        "equivalent to `--num-results 0`")
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

    console = Console(log_path=False, file=sys.stderr)

    logging.basicConfig(
        level=numeric_log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console)],
    )

    traceback.install(show_locals=True)

    results: List[SBOM] = []

    try:
        for i, sbom in enumerate(SBOMGenerator(console=console).main(" ".join(args.command))):
            if not sys.stdout.isatty():
                sys.stdout.write(str(sbom))
                sys.stdout.write("\n")
                sys.stdout.flush()
            else:
                results.append(sbom)
            logger.info(f"[bold white]Satisfying Dependencies:[/bold white] {sbom.rich_str}", extra={"markup": True})
            if not args.all and 0 < args.num_results and i == args.num_results - 1:
                break
    except SBOMGenerationError as e:
        logger.error(str(e))
        return 1
    except KeyboardInterrupt:
        return 1

    for sbom in results:
        sys.stdout.write(str(sbom))
        sys.stdout.write("\n")
    sys.stdout.flush()

    return 0
