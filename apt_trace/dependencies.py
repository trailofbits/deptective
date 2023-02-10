import time
from logging import getLogger
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from typing import Dict, FrozenSet, Iterable, Iterator, List, Optional, Set, Tuple, Union

import docker
from docker.errors import NotFound
from docker.models.images import Image
import randomname
from rich.console import Console
from rich.progress import Progress, MofNCompleteColumn, TaskID

from .apt import AptCache, file_to_packages
from .containers import Container, ContainerProgress, DockerContainer
from .signals import handle_signals


logger = getLogger(__name__)


APT_STRACE_DIR = Path(__file__).absolute().parent / "apt-strace"


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


class SBOMGenerationError(RuntimeError):
    pass


class NonZeroExit(SBOMGenerationError):
    pass


class PackageResolutionError(SBOMGenerationError):
    pass


class PreinstallError(SBOMGenerationError):
    pass


class SBOMGenerator:
    def __init__(self, console: Optional[Console] = None):
        self._client: Optional[docker.DockerClient] = None
        self._image_name: Optional[str] = None
        if console is None:
            console = Console(log_path=False, file=sys.stderr)
        self.console: Console = console
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
        client = docker.from_env()
        for image in client.images.list(name="trailofbits/apt-strace"):
            history = image.history()
            if history:
                creation_time = max(c["Created"] for c in image.history())
                dockerfile = APT_STRACE_DIR / "Dockerfile"
                source = APT_STRACE_DIR / "apt-strace.c"
                min_creation_time = max(dockerfile.stat().st_mtime, source.stat().st_mtime)
                if creation_time < min_creation_time:
                    # it needs to be rebuilt!
                    break
            return image
        # we need to build the image!
        return client.images.build(path=str(APT_STRACE_DIR), tag="trailofbits/apt-strace", rm=True, pull=True)[0]

    def main(self, command: str) -> Iterator[SBOM]:
        with SBOMGeneratorStep(self, command) as step:
            for sbom in step.find_feasible_sboms():
                self.feasible.add(sbom)
                yield sbom


class SBOMGeneratorStep(Container):
    def __init__(
            self,
            generator: SBOMGenerator,
            command: str,
            preinstall: Iterable[str] = (),
            parent: Optional["SBOMGeneratorStep"] = None
    ):
        if parent is None:
            p: Union[Image, SBOMGeneratorStep] = generator.apt_strace_image
        else:
            p = parent
        super().__init__(parent=p, client=generator.client)
        self._log_tmpdir: Optional[TemporaryDirectory] = None
        self._logdir: Optional[Path] = None
        self.command: str = command
        self.preinstall: Set[str] = set(preinstall)
        self.generator: SBOMGenerator = generator
        self.retval: int = -1
        if parent is not None:
            self.tried_packages: Set[str] = set(parent.tried_packages)
            self._progress: ContainerProgress = parent._progress
        else:
            self.level = 0
            self.tried_packages = set()
            self._progress = ContainerProgress(*Progress.get_default_columns(), MofNCompleteColumn(),
                                               console=generator.console, transient=True, expand=True)
        self.missing_files: List[str] = []
        self._task: Optional[TaskID] = None

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
            logger.info(f"Infeasible dependency sequence: {sbom.rich_str}", extra={"markup": True})
            self.generator.infeasible.add(sbom)
        raise PackageResolutionError(f"`{self.command}` exited with code {self.retval} having looked for "
                                     f"missing files {self.missing_files!r}, none of which are satisfied by "
                                     f"Ubuntu packages")

    def find_feasible_sboms(self) -> Iterator[SBOM]:
        logger.debug(f"Running step {self.level}...")
        try:
            logger.debug(f"apt-strace /log/apt-trace.txt {self.command}")
            exe = self.run(["/log/apt-trace.txt", self.command], entrypoint="/usr/bin/apt-strace", workdir="/workdir")
            self._progress.execute(exe, title=self.command, scrollback=5)
            while not exe.done:
                self._progress.refresh()
                time.sleep(0.5)
            self.retval = exe.exit_code
        finally:
            logger.debug(f"Ran, exit code {self.retval}")
        with open(self._logdir / "apt-trace.txt") as log:
            for line in log:
                if line.startswith("missing\t"):
                    self.missing_files.append(line[len("missing\t"):].strip())
        logger.debug(self.missing_files)
        if self.retval == 0:
            yield SBOM()
            return
        elif not self.missing_files:
            raise NonZeroExit(f"`{self.command}` exited with code {self.retval} without accessing any files")
        packages_to_try: List[str] = []
        history: Set[str] = set()
        for file in reversed(self.missing_files):
            # reverse the missing files so we try the last missing files first
            new_packages = set(file_to_packages(file)) - self.tried_packages - self.preinstall - history
            packages_to_try.extend(new_packages)
            history |= new_packages
        if not packages_to_try:
            self._register_infeasible()  # this always raises an exception
        yielded = False
        last_error: Optional[SBOMGenerationError] = None
        self._progress.update(self._task, total=len(packages_to_try))
        for package in packages_to_try:
            try:
                step = SBOMGeneratorStep(self.generator, self.command, preinstall=(package,), parent=self)
                if step.sbom in self.generator.infeasible:
                    # we already know that this substep's SBOM is infeasible
                    logger.debug(f"Skipping substep {package} because we already know that it is infeasible")
                    continue
                elif any(step.sbom.issuperset(f) for f in self.generator.feasible):
                    # this next step would produce a superset of an already known-good result, so skip it
                    logger.debug(f"Skipping substep {package} because it is a superset of an already discovered "
                                 f"feasible solution")
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
                logger.warning(f"[red]:warning: Unable to preinstall package {package}", extra={"markup": True})
                continue
            finally:
                self._progress.update(self._task, advance=1)
        if not yielded:
            if last_error is not None:
                raise last_error
            else:
                self._register_infeasible()  # this always raises an exception

    @property
    def volumes(self) -> Dict[str, Dict[str, str]]:
        cwd = Path.cwd().absolute()
        return {
            str(cwd): {"bind": "/src", "mode": "ro"},
            str(self._logdir): {"bind": "/log", "mode": "rw"}
        }

    def setup_image(self, container: DockerContainer):
        if self.level == 0:
            logger.info("Copying source files to the container...")
            retval, output = container.exec_run(
                "cp -r /src /workdir"
            )
            if retval != 0:
                raise ValueError(f"Error copying the source files to /workdir in the Docker image: {output}")
            logger.info("Updating APT sources...")
            retval, output = container.exec_run(
                "apt-get update -y"
            )
            if retval != 0:
                raise ValueError(f"Error running `apt-get update`: {output}")
        if self.preinstall:
            logger.info(f"Installing {', '.join(self.preinstall)} into {container.short_id}...")
            retval, output = container.exec_run(f"apt-get -y install {' '.join(self.preinstall)}")
            if retval != 0:
                raise PreinstallError(f"Error apt-get installing {' '.join(self.preinstall)}: {output}")

    def start(self):
        assert self._logdir is None
        if self.level == 0:
            # make sure that we pre-load the apt cache before starting our task, otherwise `rich` will mess
            # up its progress bars
            _ = AptCache.get().contents_db
            self._progress.__enter__()
        if not self.preinstall:
            task_name = f":magnifying_glass_tilted_right: {self.command}"
        else:
            task_name = f"[blue]{self.level}[/blue] :floppy_disk: [bold italic]{', '.join(self.preinstall)}"
        self._task = self._progress.add_task(task_name, total=None)
        self._log_tmpdir = TemporaryDirectory()
        self._logdir = Path(self._log_tmpdir.__enter__()).absolute()
        super().start()

    def stop(self):
        super().stop()
        log_tmpdir = self._log_tmpdir
        self._logdir = None
        self._log_tmpdir = None
        log_tmpdir.__exit__(None, None, None)
        self._progress.remove_task(self._task)
        if self.level == 0:
            self._progress.__exit__(None, None, None)
