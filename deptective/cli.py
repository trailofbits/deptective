import argparse
import logging
import platform
import shlex
import sys
from collections import defaultdict
from shutil import rmtree
from tempfile import mkdtemp
from textwrap import dedent
from typing import List, Optional

import requests  # type: ignore
from docker.errors import DockerException
from pathlib import Path
from rich import traceback
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from . import apt  # noqa: F401
from .cache import SQLCache
from .dependencies import (
    SBOM,
    PackageResolutionError,
    PreinstallError,
    SBOMGenerator,
)
from .exceptions import PackageDatabaseNotFoundError, SBOMGenerationError
from .package_manager import PackageManager, PackagingConfig

logger = logging.getLogger(__name__)
logging.getLogger("docker").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

DEFAULT_LINUX = ("ubuntu", "noble", "amd64")


def list_supported_configurations(console: Console | None = None):
    if console is None:
        console = Console()

    table = Table(title="Supported Package Managers")

    table.add_column("Package Manager", justify="left", style="bold cyan", no_wrap=True)
    table.add_column("OS", justify="left", style="magenta", no_wrap=True)
    table.add_column("Release", style="green")
    table.add_column("Architectures", justify="right", style="blue")

    rows: dict[str, dict[tuple[str, str], set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )

    for manager in PackageManager.MANAGERS_BY_NAME.values():
        for version in manager.versions():
            rows[version.NAME][(version.config.os, version.config.os_version)].add(
                version.config.arch
            )

    for manager_name in sorted(rows.keys()):
        row = rows[manager_name]
        for os, os_version in sorted(row.keys()):
            table.add_row(
                manager_name, os, os_version, ", ".join(sorted(row[(os, os_version)]))
            )

    console.print(table)


def load_cache(
    package_manager_name: str,
    operating_system: str,
    release: str,
    arch: str,
    rebuild: bool = False,
) -> SQLCache:
    mgr_class = PackageManager.MANAGERS_BY_NAME[package_manager_name]
    package_manager = mgr_class(
        PackagingConfig(os=operating_system, os_version=release, arch=arch)
    )
    if rebuild and SQLCache.exists(package_manager):
        SQLCache.path(package_manager).unlink()

    return SQLCache.from_disk(package_manager)


def main() -> int:
    if platform.system().lower() != "linux":
        default_os, default_release, default_arch = DEFAULT_LINUX
    else:
        local_config = PackagingConfig.get_local()
        default_os = local_config.os  # type: ignore
        default_release = local_config.os_version  # type: ignore
        default_arch = local_config.arch  # type: ignore

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--list",
        "-l",
        action="store_true",
        help="list available OS versions and package managers for package resolution",
    )
    parser.add_argument(
        "--package-manager",
        "-p",
        choices=sorted(PackageManager.MANAGERS_BY_NAME.keys()),
        default="apt",
        help="the package manager to use (default=apt)",
    )
    parser.add_argument(
        "--operating-system",
        "-os",
        type=str,
        default=default_os,
        help=f"the operating system in which to resolve packages (default={default_os})",
    )
    parser.add_argument(
        "--release",
        "-r",
        type=str,
        default=default_release,
        help=f"the release of the operating system in which to resolve packages "
        f"(default={default_release})",
    )
    parser.add_argument(
        "--arch",
        type=str,
        default=default_arch,
        help=f"the architecture in which to resolve packages (default={default_arch})",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="forces a rebuild of the package cache "
        "(requires an Internet connection)",
    )
    search_group = parser.add_mutually_exclusive_group()
    search_group.add_argument(
        "--search",
        "-s",
        action="store_true",
        help="instead of treating the final argument as a command to run, treat it as a path and list "
        "all packages that provide that file",
    )
    search_group.add_argument(
        "--multi-step",
        "-m",
        action="store_true",
        help="instead of reading the command from the command line, take a path to a file "
        "containing one command per line; this can speed up multi-command dependency "
        "resolutions. For example, `deptective --multi-step -n 1 steps.sh` will read the "
        "`steps.sh` file and run the commands on each line.",
    )
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
    log_section.add_argument(
        "--log-dir",
        "-d",
        type=Path,
        required=False,
        help="path to a directory in which to store runtime artifacts and logs",
    )
    log_section.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="overwrite an existing --log-dir " "if it already exists",
    )
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
        help="sets the log level for deptective (default=INFO)",
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
        console.print(
            "Use the `--package-manager`, `--operating-system`, `--release`, and `--arch` options to specify "
            "your desired runtime environment.\n"
        )
        if not args.command:
            return 0

    if not args.command and not args.rebuild:
        parser.print_help()
        return 1

    try:
        cache = load_cache(
            args.package_manager,
            args.operating_system,
            args.release,
            args.arch,
            args.rebuild,
        )
    except PackageDatabaseNotFoundError as e:
        if (
            args.operating_system == default_os
            and args.release == default_release
            and args.arch == default_arch
            and (default_os, default_release, default_arch) != DEFAULT_LINUX
        ):
            # we are running on linux that is not supported by the requested package manager
            cache = None  # type: ignore
        else:
            logger.error(
                f"{e!s}\nPlease make sure that this OS version is still maintained.\n"
                f"Run `deptective --list` for a list of available OS versions and architectures."
            )
            return 1
    if cache is None:
        logger.warning(
            f"The system OS, release, and/or architecture is not compatible with {args.package_manager}; "
            f"trying {':'.join(DEFAULT_LINUX)} instead…"
        )
        try:
            cache = load_cache(
                args.package_manager, *DEFAULT_LINUX, rebuild=args.rebuild
            )
        except PackageDatabaseNotFoundError:
            logger.error(
                f"Could not find an OS version and architecture for {args.package_manager}.\n"
                f"Run `deptective --list` for a list of available OS versions and architectures."
            )
            return 1

    if args.rebuild and not args.command:
        return 0

    results: List[SBOM] = []

    # rich has a tendency to gobble stdout, so save the old one before proceeding:
    old_stdout = sys.stdout

    success = False
    temp_logdir: Optional[Path] = None

    try:

        if args.search:
            success = True
            for path in args.command:
                pkgs = cache[path]
                if not pkgs:
                    logger.info(f"No packages found that provide {path}")
                    success = False
                    continue
                logger.info(
                    dedent(
                        f"[bold white]Packages providing[/bold white] {path}: "
                        f"{'[gray],[/gray] '.join(pkgs)}"
                    ),
                    extra={"markup": True},
                )
            if success:
                return 0
            else:
                return 1

        if hasattr(args, "log_dir") and args.log_dir:
            log_dir: Path = args.log_dir
        else:
            temp_logdir = Path(mkdtemp(prefix="deptective-"))
            log_dir = temp_logdir

        if log_dir.exists():
            if args.force:
                rmtree(log_dir)
            elif temp_logdir is None:
                logger.error(
                    f"The log directory {log_dir!s} already exists; either choose a different output "
                    f"path, delete the directory, or run again with the `--force` option."
                )
                return 1

        generator = SBOMGenerator(cache=cache, console=console)

        if args.multi_step:
            commands: list[list[str]] = []
            for path in args.command:
                try:
                    with open(path, "r") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            commands.append(shlex.split(line))
                except (FileNotFoundError, IOError) as e:
                    logger.error(f"Could not open multi-step file {path}: {e!s}")
                    return 1
            sbom_iter = generator.multi_step(*commands)
        else:
            sbom_iter = generator.main(args.command[0], *args.command[1:])

        for i, sbom in enumerate(sbom_iter):
            if not old_stdout.isatty():
                old_stdout.write(str(sbom))
                old_stdout.write("\n")
                old_stdout.flush()
            else:
                results.append(sbom)
            if not sbom:
                logger.info(
                    dedent(
                        "[bold white]The command executed successfully without the need for additional dependencies"
                        "[/bold white]"
                    ),
                    extra={"markup": True},
                )
            else:
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

        success = True
    except DockerException as e:
        msg = str(e)
        if "ConnectionRefusedError" in msg or "Connection aborted" in msg:
            logger.error("Could not connect to Docker. Is it running?")
        else:
            logger.error(f"An error occurred while communicating with Docker: {msg}")
        return 1
    except requests.exceptions.Timeout as e:
        if logger.level <= logging.DEBUG:
            raise
        logger.error(f"Timed out while waiting for a response: {e!s}")
        return 1
    except PackageDatabaseNotFoundError as e:
        logger.error(
            f"{e!s}\nPlease make sure that this OS version is still maintained.\n"
            f"Run `deptective --list` for a list of available OS versions and architectures."
        )
        return 1
    except PreinstallError as e:
        # This will likely happen if the preinstall failed due to Docker running out of space
        logger.error(str(e))
        return 1
    except SBOMGenerationError as e:
        logger.error(str(e))
        if isinstance(e, PackageResolutionError):
            if e.partial_sbom:
                with open(log_dir / "most_promising_sbom.txt", "w") as f:
                    f.write("\n".join(map(str, e.partial_sbom)))
                console.print(
                    Panel(
                        " ".join(
                            (
                                f":floppy_disk: [bold italic]{p}[/bold italic]"
                                for p in e.partial_sbom
                            )
                        ),
                        title="Most Promising Partial SBOM",
                    )
                )
            if (
                e.command_output is not None
                and e.command_output
                and e.command_output_str
            ):
                with open(log_dir / "final_output.txt", "wb") as f:
                    f.write(e.command_output)
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
    finally:
        if not success and temp_logdir is not None:
            old_stdout.write(f"\n\nA log was saved to {temp_logdir!s}\n")

    for sbom in results:
        old_stdout.write(str(sbom))
        old_stdout.write("\n")
    old_stdout.flush()

    if temp_logdir is not None:
        rmtree(temp_logdir)

    return 0
