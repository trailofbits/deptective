import argparse
from collections import defaultdict
import logging
import sys
from typing import List

from docker.errors import DockerException
from rich import traceback
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from textwrap import dedent

from .apt import AptDatabaseNotFoundError, AptCacheConfig
from .dependencies import (
    PackageResolutionError,
    SBOM,
    SBOMGenerator,
)
from .exceptions import SBOMGenerationError

logger = logging.getLogger(__name__)


def list_supported_configurations(console: Console | None = None):
    if console is None:
        console = Console()

    table = Table(title="Supported Package Managers")

    table.add_column("OS", justify="left", style="cyan", no_wrap=True)
    table.add_column("Release", style="magenta")
    table.add_column("Architectures", justify="right", style="green")

    rows: dict[tuple[str, str], set[str]] = defaultdict(set)

    for version in AptCacheConfig.versions(console=console):
        rows[(version.os, version.os_version)].add(version.arch)

    for os, os_version in sorted(rows.keys()):
        table.add_row(os, os_version, ", ".join(sorted(rows[(os, os_version)])))

    console.print(table)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", "-l", action="store_true",
                        help="list available OS versions for package resolution")
    results_group = parser.add_mutually_exclusive_group()
    results_group.add_argument(
        "--num-results",
        "-n",
        type=int,
        default=1,
        help=(
            "the maximum number of satisfying sets of package dependencies to discover;"
            " use zero to enumerate all possible results (default=1)"
        ),
    )
    results_group.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="enumerate all possible results; equivalent to `--num-results 0`",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)

    log_section = parser.add_argument_group(title="logging")
    log_group = log_section.add_mutually_exclusive_group()
    log_group.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=list(
            logging.getLevelName(x)
            for x in range(1, 101)
            if not logging.getLevelName(x).startswith("Level")
        ),
        help="sets the log level for apt-trace (default=INFO)",
    )
    log_group.add_argument(
        "--debug", action="store_true", help="equivalent to `--log-level=DEBUG`"
    )
    log_group.add_argument(
        "--quiet",
        action="store_true",
        help="equivalent to `--log-level=CRITICAL`",
    )

    args = parser.parse_args()

    if args.debug:
        numeric_log_level = logging.DEBUG
    elif args.quiet:
        numeric_log_level = logging.CRITICAL
    else:
        log_level = getattr(logging, args.log_level.upper(), None)
        if not isinstance(log_level, int):
            sys.stderr.write(f"Invalid log level: {args.log_level}\n")
            exit(1)
        numeric_log_level = log_level

    console = Console(log_path=False, file=sys.stderr)

    logging.basicConfig(
        level=numeric_log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console)],
    )

    traceback.install(show_locals=True)

    if args.list:
        list_supported_configurations(console)
        if not args.command:
            return 0

    if not args.command:
        parser.print_help()
        return 1

    results: List[SBOM] = []

    # rich has a tendency to gobble stdout, so save the old one before proceeding:
    old_stdout = sys.stdout

    try:
        for i, sbom in enumerate(
            SBOMGenerator(console=console).main(args.command[0], *args.command[1:])
        ):
            if not old_stdout.isatty():
                old_stdout.write(str(sbom))
                old_stdout.write("\n")
                old_stdout.flush()
            else:
                results.append(sbom)
            logger.info(
                dedent(
                    f"""\
            [bold white]Satisfying dependencies:[/bold white] {sbom.rich_str}
            [bold white]Install with:[/bold white] apt-get install {' '.join(sbom)}"""
                ),
                extra={"markup": True},
            )

            if not args.all and 0 < args.num_results and i == args.num_results - 1:
                break
    except DockerException as e:
        logger.error(f"An error occurred while communicating with Docker: {e!s}")
        return 1
    except AptDatabaseNotFoundError as e:
        logger.error(f"{e!s}\nPlease make sure that this OS version is still maintained.")
    except SBOMGenerationError as e:
        logger.error(str(e))
        if (
            isinstance(e, PackageResolutionError)
            and e.command_output is not None
            and e.command_output
        ):
            if e.command_output_str:
                console.print(
                    Panel(
                        e.command_output_str,
                        title=f"`{' '.join(args.command)}` Output",
                    )
                )
        return 1
    except KeyboardInterrupt:
        console.show_cursor()
        return 1

    for sbom in results:
        old_stdout.write(str(sbom))
        old_stdout.write("\n")
    old_stdout.flush()

    return 0
