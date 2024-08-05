import os
import time
from io import BytesIO
from logging import DEBUG, getLogger
from pathlib import Path
import sys
import tarfile
from tempfile import TemporaryDirectory
from typing import (
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

import docker
from docker.models.images import Image
import randomname
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, MofNCompleteColumn, TaskID
from rich.prompt import Confirm

from .cache import Cache, CACHE_DIR
from .containers import Container, ContainerProgress, DockerContainer
from .exceptions import SBOMGenerationError
from .strace import ParseError, lazy_parse_paths


logger = getLogger(__name__)


APT_STRACE_DIR = Path(__file__).absolute().parent / "strace"


class SBOM:
    def __init__(self, dependencies: Iterable[str] = ()):
        self.dependencies: Tuple[str, ...] = tuple(dependencies)
        self.dependency_set: FrozenSet[str] = frozenset(self.dependencies)

    def issuperset(self, sbom: "SBOM") -> bool:
        return self.dependency_set.issuperset(sbom.dependency_set)

    def __bool__(self):
        return bool(self.dependencies)

    def __len__(self):
        return len(self.dependencies)

    def __iter__(self):
        return iter(self.dependencies)

    def __getitem__(self, index: int) -> str:
        return self.dependencies[index]

    def __hash__(self):
        return hash(self.dependency_set)

    def __eq__(self, other):
        return isinstance(other, SBOM) and self.dependency_set == other.dependency_set

    def __add__(self, package_or_sbom: Union[str, "SBOM"]) -> "SBOM":
        if isinstance(package_or_sbom, SBOM):
            return SBOM(self.dependencies + package_or_sbom.dependencies)
        return SBOM(self.dependencies + (package_or_sbom,))

    @property
    def rich_str(self) -> str:
        package_names = [f":floppy_disk: [bold italic]{p}[/bold italic]" for p in self]
        return ", ".join(package_names)

    def __str__(self):
        return ", ".join(self.dependencies)


class NonZeroExit(SBOMGenerationError):
    pass


class PackageResolutionError(SBOMGenerationError):
    def __init__(self, message: str, command_output: bytes | None = None, partial_sbom: SBOM | None = None):
        super().__init__(message)
        self.command_output: bytes | None = command_output
        self.partial_sbom: SBOM | None = partial_sbom

    @property
    def command_output_str(self) -> str | None:
        if not self.command_output:
            return None

        try:
            return self.command_output.decode("utf-8")
        except UnicodeDecodeError:
            return repr(self.command_output)[2:-1]


class PreinstallError(SBOMGenerationError):
    pass


class IrrelevantPackageInstall(SBOMGenerationError):
    pass


def build_context(root_path: Path | str, dockerfile: str) -> BytesIO:
    fh = BytesIO()
    with tarfile.open(fileobj=fh, mode="w") as tar:
        def dockerfile_filter(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
            if info.name in ("Dockerfile", "./Dockerfile"):
                return None
            else:
                return info

        old_cwd = Path.cwd()
        try:
            os.chdir(root_path)
            tar.add(".", recursive=True, filter=dockerfile_filter)
        finally:
            os.chdir(old_cwd)
        dockerfile_utf8 = dockerfile.encode("utf-8")
        dockerfile_bytes = BytesIO(dockerfile_utf8)
        dockerfile_bytes.seek(0)
        info = tarfile.TarInfo(name="./Dockerfile")
        info.size = len(dockerfile_utf8)
        tar.addfile(info, dockerfile_bytes)
    fh.seek(0)
    return fh


class SBOMGenerator:
    def __init__(self, cache: Cache, console: Optional[Console] = None):
        self._client: Optional[docker.DockerClient] = None
        self._image_name: Optional[str] = None
        if console is None:
            console = Console(log_path=False, file=sys.stderr)
        self.console: Console = console
        self.cache: Cache = cache
        self.infeasible: Set[SBOM] = set()
        self.feasible: Set[SBOM] = set()

    @property
    def image_name(self) -> str:
        if self._image_name is None:
            while True:
                image_name = f"trailofbits/apt-trace-{randomname.get_name()}"
                if not self.client.images.list(name=image_name):
                    break
            self._image_name = image_name
        return self._image_name

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    @property
    def apt_strace_image(self) -> Image:
        pm = self.cache.package_manager
        dockerfile = pm.dockerfile()
        pm_suffix = f"{pm.NAME}-{pm.config.os}-{pm.config.os_version}-{pm.config.arch}"
        cached_dockerfile_path = CACHE_DIR / (
            f"Dockerfile-{pm_suffix}"
        )
        image_name = f"trailofbits/apt-strace-{pm_suffix}"
        if not cached_dockerfile_path.exists():
            cached_content = ""
        else:
            with open(cached_dockerfile_path, "r") as f:
                cached_content = f.read()
        if dockerfile == cached_content:
            # the dockerfile hasn't changed
            for image in self.client.images.list(name=image_name):
                history = image.history()
                if history:
                    creation_time = max(c["Created"] for c in image.history())
                    source = APT_STRACE_DIR / "apt-strace"
                    min_creation_time = source.stat().st_mtime
                    if creation_time < min_creation_time:
                        # it needs to be rebuilt!
                        break
                return image
        # we need to build the image!
        logger.info(
            f"Building the base Docker image…\n"
            "This is a one-time operation that may take a few minutes."
        )
        result = self.client.images.build(
            fileobj=build_context(str(APT_STRACE_DIR), dockerfile),
            dockerfile="./Dockerfile",
            custom_context=True,
            tag=image_name,
            rm=True,
            pull=True,
        )[0]
        with open(cached_dockerfile_path, "w") as f:
            f.write(dockerfile)
        return result

    def main(self, command: str, *args: str) -> Iterator[SBOM]:
        with SBOMGeneratorStep(self, command, args) as step:
            yielded = False
            try:
                for sbom in step.find_feasible_sboms():
                    self.feasible.add(sbom)
                    yield sbom
                    yielded = True
            except (Exception, KeyboardInterrupt) as e:
                import traceback
                if sys.stdin.isatty() and not yielded:
                    if not isinstance(e, KeyboardInterrupt):
                        logger.error(str(e))
                        prompt = "Would you like to see the most promising SBOM before the error is handled?"
                    else:
                        prompt = "Would you like to see the most promising SBOM before exiting?"
                    if Confirm.ask(prompt, console=self.console):
                        self.console.print(
                            Panel(
                                " ".join((f":floppy_disk: [bold italic]{p}[/bold italic]"
                                          for p in step.best_sbom.sbom)),
                                title="Most Promising Partial SBOM"
                            )
                        )
                        if step.best_sbom.command_output:
                            try:
                                cmd_output_str = step.best_sbom.command_output.decode("utf-8")
                            except UnicodeDecodeError:
                                cmd_output_str = repr(step.best_sbom.command_output)[2:-1]
                            if cmd_output_str:
                                self.console.print(
                                    Panel(
                                        cmd_output_str,
                                        title=f"`{command} {' '.join(args)}` Output",
                                    )
                                )
                raise e


class SBOMGeneratorStep(Container):
    def __init__(
        self,
        generator: SBOMGenerator,
        command: str,
        arguments: Iterable[str],
        preinstall: Iterable[str] = (),
        parent: Optional["SBOMGeneratorStep"] = None,
    ):
        if parent is None:
            p: Union[Image, SBOMGeneratorStep] = generator.apt_strace_image
            self.root: SBOMGeneratorStep = self
            self._best_sbom: SBOMGeneratorStep = self
        else:
            p = parent
            self.root = parent.root
            self._best_sbom = None
        super().__init__(parent=p, client=generator.client)
        self._log_tmpdir: Optional[TemporaryDirectory] = None
        self._logdir: Optional[Path] = None
        self.command: str = command
        self.args: Tuple[str, ...] = tuple(arguments)
        self.preinstall: Set[str] = set(preinstall)
        self.generator: SBOMGenerator = generator
        self.retval: int = -1
        if parent is not None:
            self.tried_packages: Set[str] = parent.tried_packages | parent.preinstall
            self._progress: ContainerProgress = parent._progress
            if self.level > self.best_sbom.level:
                self.root._best_sbom = self
        else:
            self.level = 0
            self.tried_packages = set()
            self._progress = ContainerProgress(
                *Progress.get_default_columns(),
                MofNCompleteColumn(),
                console=generator.console,
                transient=True,
                expand=True,
            )
        self._command_output: Optional[bytes] = None
        self.missing_files: List[str] = []
        self._task: Optional[TaskID] = None

    @property
    def command_output(self) -> Optional[bytes]:
        return self._command_output

    @command_output.setter
    def command_output(self, value: bytes):
        if value is None:
            raise ValueError("command_output cannot be None")
        elif self._command_output is not None and self._command_output != value:
            raise ValueError("The command output can only be set once!")
        self._command_output = value
        if self.level == self.best_sbom.level and len(value) > len(self.best_sbom.command_output):
            self.root._best_sbom = self

    @property
    def best_sbom(self) -> "SBOMGeneratorStep":
        return self.root._best_sbom

    def _missing_files(self, container: Container, *paths: Path | str) -> Set[str]:
        to_check: Set[str] = {str(p) for p in paths}
        progress = Progress(transient=True, console=self._progress.console)
        self._progress.file_progress = progress
        try:
            file_existence = container.files_exist(*(
                    to_check - set(self.missing_files)
            ), progress=progress)
            if logger.level <= DEBUG:
                if file_existence:
                    af = (f"\n{p} ({['NOT FOUND', 'EXISTS'][exists]})" for p, exists in file_existence.items())
                    logger.debug(f"Accessed files: {''.join(af)}")
                else:
                    logger.debug("No files accessed.")
        finally:
            self._progress.file_progress = None
        return {p for p, exists in file_existence.items() if not exists}

    @property
    def full_command(self) -> str:
        if self.args:
            return f"{self.command} {' '.join(self.args)}"
        else:
            return self.command

    @property
    def missing_files_without_duplicates(self) -> Iterator[str]:
        history: Set[str] = set()
        for f in self.missing_files:
            if f not in history:
                yield f
                history.add(f)

    @property
    def sbom(self) -> SBOM:
        node: Optional[SBOMGeneratorStep] = self
        s = SBOM()
        while isinstance(node, SBOMGeneratorStep):
            s = SBOM(node.preinstall) + s
            node = node.parent
        return s

    def _register_infeasible(self):
        sbom = self.sbom
        if sbom:
            logger.info(
                f"Infeasible dependency sequence: {sbom.rich_str}",
                extra={"markup": True},
            )
            self.generator.infeasible.add(sbom)
        raise PackageResolutionError(
            f"`{self.full_command}` exited with code {self.retval} having looked for missing"
            f" files {list(self.missing_files_without_duplicates)!r}, none of which are"
            f" satisfied by {self.generator.cache.package_manager.NAME} packages",
            command_output=self.command_output,
        )

    def find_feasible_sboms(self) -> Iterator[SBOM]:
        logger.debug(f"Running step {self.level}...")
        with self:
            # open a context so we keep the container running after the `self.run` command
            # so we can query it for missing files
            try:
                logger.debug(f"apt-strace /log/apt-trace.txt {self.full_command}")
                exe = self.run(
                    ["/log/apt-trace.txt", self.command] + list(self.args),
                    entrypoint="/usr/bin/apt-strace",
                    workdir="/workdir",
                )
                self._progress.execute(
                    exe,
                    title=self.full_command,
                    subtitle=self.sbom.rich_str,
                    scrollback=5,
                )
                while not exe.done:
                    self._progress.refresh()
                    time.sleep(0.5)
                self.retval = exe.exit_code
                self.command_output = exe.output
            finally:
                logger.debug(f"Ran, exit code {self.retval}")
            accessed_files: set[str] = set()
            with open(self._logdir / "apt-trace.txt") as log:
                for line in log:
                    try:
                        for arg in lazy_parse_paths(line):
                            if arg.startswith("/"):
                                accessed_files.add(arg)
                    except ParseError as e:
                        logger.warning(str(e))
                        continue

            new_missing_files = self._missing_files(exe.container, *accessed_files)
            for path in new_missing_files:
                if ".." in path:
                    resolved = str(Path(path).resolve())
                    if resolved != path:
                        # the path contains something like "/foo/bar/../baz",
                        # so resolve it to /foo/baz
                        self.missing_files.append(resolved)
                        continue
                self.missing_files.append(path)
        if self.retval == 0:
            yield SBOM()
            return
        elif not self.missing_files:
            raise NonZeroExit(
                f"`{self.full_command}` exited with code {self.retval} without accessing any"
                " files"
            )
        elif (
            isinstance(self.parent, SBOMGeneratorStep)
            and self.parent.command_output == self.command_output
            and self.parent.retval == self.retval
        ):
            # installing `package` produced the exact same result as before
            logger.info(
                f"Installing {', '.join(self.preinstall)} at this point is useless"
                f" because `{self.full_command}` has the same output with or without it"
            )
            raise IrrelevantPackageInstall(
                f"`{self.full_command}` exited with code {self.retval} regardless of the"
                f" install of package(s) {', '.join(self.preinstall)}"
            )
        packages_to_try: Dict[str, tuple[int, int]] = {}
        for i, file in enumerate(self.missing_files):
            for possibility in self.generator.cache[file]:
                if possibility in self.tried_packages or possibility in self.preinstall:
                    # we already tried this package
                    continue
                elif possibility in packages_to_try:
                    packages_to_try[possibility] = (packages_to_try[possibility][0] + 1, i)
                else:
                    packages_to_try[possibility] = (1, i)
        if not packages_to_try:
            self._register_infeasible()  # this always raises an exception
        yielded = False
        last_error: Optional[SBOMGenerationError] = None
        self._progress.update(self._task, total=len(packages_to_try))
        for _, _, package in sorted(
                ((count, idx, name) for name, (count, idx) in packages_to_try.items()), reverse=True
        ):
            try:
                step = SBOMGeneratorStep(
                    generator=self.generator,
                    command=self.command,
                    arguments=self.args,
                    preinstall=(package,),
                    parent=self,
                )
                if step.sbom in self.generator.infeasible:
                    # we already know that this substep's SBOM is infeasible
                    logger.debug(
                        f"Skipping substep {package} because we already know that it is"
                        " infeasible"
                    )
                    continue
                elif any(step.sbom.issuperset(f) for f in self.generator.feasible):
                    # this next step would produce a superset of an already known-good
                    # result, so skip it
                    logger.debug(
                        f"Skipping substep {package} because it is a superset of an"
                        " already discovered feasible solution"
                    )
                    continue
                with step as substep:
                    try:
                        for sbom in substep.find_feasible_sboms():
                            yield SBOM((package,)) + sbom
                            yielded = True
                    except SBOMGenerationError:
                        last_error = last_error
            except PreinstallError:
                # package was unable to be installed, so skip it
                logger.warning(
                    f"[red]:warning: Unable to preinstall package {package}",
                    extra={"markup": True},
                )
                continue
            finally:
                self._progress.update(self._task, advance=1)
        if not yielded:
            if last_error is not None:
                raise last_error
            elif self.level == 0:
                raise PackageResolutionError(
                    f"Could not find a feasible SBOM that satisfies all of the missing packages for "
                    f"`{self.full_command}`. The most promising partial SBOM exited with code {self.best_sbom.retval} "
                    f"having looked for missing files {list(self.best_sbom.missing_files_without_duplicates)!r}, none "
                    f"of which are satisfied by {self.generator.cache.package_manager.NAME} packages",
                    command_output=self.best_sbom.command_output,
                    partial_sbom=self.best_sbom.sbom
                )
            else:
                self._register_infeasible()  # this always raises an exception

    @property
    def volumes(self) -> Dict[str, Dict[str, str]]:
        cwd = Path.cwd().absolute()
        return {
            str(cwd): {"bind": "/src", "mode": "ro"},
            str(self._logdir): {"bind": "/log", "mode": "rw"},
        }

    def setup_image(self, container: DockerContainer):
        if self.level == 0:
            logger.info("Copying source files to the container...")
            retval, output = container.exec_run("cp -r /src /workdir")
            if retval != 0:
                raise ValueError(
                    "Error copying the source files to /workdir in the Docker image:"
                    f" {output}"
                )
            logger.info(f"Updating {self.generator.cache.package_manager.NAME} sources...")
            retval, output = self.generator.cache.package_manager.update(container)
            if retval != 0:
                raise ValueError(f"Error updating packages: {output}")
            # add the command and its relevant arguments to the missing files:
            for arg in self.args:
                if arg.startswith("/"):
                    self.missing_files.append(arg)
            if self.command.startswith("/"):
                self.missing_files.append(self.command)
            elif not self.command.startswith("."):
                # determine the $PATH inside the container:
                retval, output = container.exec_run("printenv PATH")
                if retval != 0:
                    raise ValueError(f"Error determining the $PATH inside of the container: {output}")
                for path in (p.strip() for p in output.decode("utf-8").split(":")):
                    self.missing_files.append(str(Path(path) / self.command))
        if self.preinstall:
            logger.info(
                f"Installing {', '.join(self.preinstall)} into {container.short_id}..."
            )
            retval, output = self.generator.cache.package_manager.install(container, *self.preinstall)
            if retval != 0:
                raise PreinstallError(
                    f"Error installing {' '.join(self.preinstall)}: {output}"
                )

    def _cleanup(self):
        log_tmpdir = self._log_tmpdir
        self._logdir = None
        self._log_tmpdir = None
        log_tmpdir.__exit__(None, None, None)
        self._progress.remove_task(self._task)
        if self.level == 0:
            self._progress.__exit__(None, None, None)

    def start(self):
        assert self._logdir is None
        if self.level == 0:
            self._progress.__enter__()
        if not self.preinstall:
            task_name = f":magnifying_glass_tilted_right: {self.command}"
        else:
            task_name = (
                f"[blue]{self.level}[/blue] :floppy_disk: [bold"
                f" italic]{', '.join(self.preinstall)}"
            )
        self._task = self._progress.add_task(task_name, total=None)
        self._log_tmpdir = TemporaryDirectory()
        self._logdir = Path(self._log_tmpdir.name).absolute()
        try:
            super().start()
        except SBOMGenerationError as e:
            self._cleanup()
            raise e

    def stop(self):
        super().stop()
        self._cleanup()
