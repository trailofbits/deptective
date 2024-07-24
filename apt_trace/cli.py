import argparse
import platform
from collections import defaultdict
import logging
import requests
import sys
from typing import List

from docker.errors import DockerException
from rich import traceback
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from textwrap import dedent

from . import apt
from .cache import SQLCache
from .dependencies import (
    PackageResolutionError,
    SBOM,
    SBOMGenerator,
)
from .exceptions import SBOMGenerationError, PackageDatabaseNotFoundError
from .package_manager import PackageManager, PackagingConfig

logger = logging.getLogger(__name__)
logging.getLogger("docker").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


def list_supported_configurations(console: Console | None = None):
    if console is None:
        console = Console()

    table = Table(title="Supported Package Managers")

    table.add_column("Package Manager", justify="left", style="bold cyan", no_wrap=True)
    table.add_column("OS", justify="left", style="magenta", no_wrap=True)
    table.add_column("Release", style="green")
    table.add_column("Architectures", justify="right", style="blue")

    rows: dict[str, dict[tuple[str, str], set[str]]] = defaultdict(lambda: defaultdict(set))

    for manager in PackageManager.MANAGERS_BY_NAME.values():
        for version in manager.versions():
            rows[version.NAME][(version.config.os, version.config.os_version)].add(version.config.arch)

    for manager_name in sorted(rows.keys()):
        row = rows[manager_name]
        for os, os_version in sorted(row.keys()):
            table.add_row(manager_name, os, os_version, ", ".join(sorted(row[(os, os_version)])))

    console.print(table)


def main() -> int:
    if platform.system().lower() != "linux":
        default_os = "ubuntu"
        default_release = "noble"
        default_arch = "amd64"
    else:
        local_config = PackagingConfig.get_local()
        default_os = local_config.os
        default_release = local_config.os_version
        default_arch = local_config.arch

    parser = argparse.ArgumentParser()
    parser.add_argument("--list", "-l", action="store_true",
                        help="list available OS versions and package managers for package resolution")
    parser.add_argument("--package-manager", "-p", choices=PackageManager.MANAGERS_BY_NAME.keys(),
                        default="apt", help="the package manager to use (default=apt)")
    parser.add_argument("--operating-system", "-os", type=str, default=default_os,
                        help=f"the operating system in which to resolve packages (default={default_os})")
    parser.add_argument("--release", "-r", type=str, default=default_release,
                        help=f"the release of the operating system in which to resolve packages "
                             f"(default={default_release})")
    parser.add_argument("--arch", type=str, default=default_arch,
                        help=f"the architecture in which to resolve packages (default={default_arch})")
    parser.add_argument("--rebuild", action="store_true", help="forces a rebuild of the package cache "
                                                               "(requires an Internet connection)")
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
        console.print("\n")
        console.print("Use the `--package-manager`, `--operating-system`, `--release`, and `--arch` options to specify "
                      "your desired runtime environment.\n")
        if not args.command:
            return 0

    if not args.command:
        parser.print_help()
        return 1

    package_manager = PackageManager.MANAGERS_BY_NAME[args.package_manager](
        PackagingConfig(os=args.operating_system, os_version=args.release, arch=args.arch)
    )
    if args.rebuild and SQLCache.exists(package_manager):
        SQLCache.path(package_manager).unlink()

    cache = SQLCache.from_disk(package_manager)

    results: List[SBOM] = []

    # rich has a tendency to gobble stdout, so save the old one before proceeding:
    old_stdout = sys.stdout

    try:
        for i, sbom in enumerate(
            SBOMGenerator(cache=cache, console=console).main(args.command[0], *args.command[1:])
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
        msg = str(e)
        if "ConnectionRefusedError" in msg or "Connection aborted" in msg:
            logger.error(f"Could not connect to Docker. Is it running?")
        else:
            logger.error(f"An error occurred while communicating with Docker: {msg}")
        return 1
    except requests.exceptions.Timeout as e:
        if logger.level <= logging.DEBUG:
            raise
        logger.error(f"Timed out while waiting for a response: {e!s}")
        return 1
    except PackageDatabaseNotFoundError as e:
        logger.error(f"{e!s}\nPlease make sure that this OS version is still maintained.\n"
                     f"Run `apt-trace --list` for a list of available OS versions and architectures.")
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
