from logging import getLogger
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterable, Iterator, List, Optional, Set, Tuple, Union

import docker
from docker.errors import NotFound
from docker.models.images import Image
import randomname
from tqdm import tqdm

from .apt import file_to_packages


logger = getLogger(__name__)


APT_STRACE_DIR = Path(__file__).absolute().parent / "apt-strace"


class SBOM:
    def __init__(self, dependencies: Iterable[str] = ()):
        self.dependencies: Tuple[str, ...] = tuple(dependencies)

    def __len__(self):
        return len(self.dependencies)

    def __iter__(self):
        return iter(self.dependencies)

    def __getitem__(self, index: int) -> str:
        return self.dependencies[index]

    def __hash__(self):
        return hash(self.dependencies)

    def __add__(self, package_or_sbom: Union[str, "SBOM"]) -> "SBOM":
        if isinstance(package_or_sbom, SBOM):
            return SBOM(self.dependencies + package_or_sbom.dependencies)
        return SBOM(self.dependencies + (package_or_sbom,))

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
    def __init__(self):
        self._client: Optional[docker.DockerClient] = None
        self._image_name: Optional[str] = None

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
            yield from step.run()


class SBOMGeneratorStep:
    def __init__(
            self,
            generator: SBOMGenerator,
            command: str,
            preinstall: Iterable[str] = (),
            parent: Optional["SBOMGeneratorStep"] = None
    ):
        self._image: Optional[Image] = None
        self._container = None
        self._log_tmpdir: Optional[TemporaryDirectory] = None
        self._logdir: Optional[Path] = None
        self.command: str = command
        self.preinstall: Set[str] = set(preinstall)
        self.generator: SBOMGenerator = generator
        self.parent: Optional[SBOMGeneratorStep] = parent
        self.retval: int = -1
        if parent is not None:
            self.level: int = parent.level + 1
            self.tried_packages: Set[str] = set(parent.tried_packages)
        else:
            self.level = 0
            self.tried_packages = set()
        self.missing_files: List[str] = []

    @property
    def parent_image(self) -> Image:
        if self.parent is None:
            return self.generator.apt_strace_image
        else:
            return self.parent.image

    @property
    def tag(self) -> str:
        return f"step{self.level}"

    @property
    def image(self) -> Image:
        if self._image is None:
            return self.parent_image
        return self._image

    def run(self) -> Iterator[SBOM]:
        logger.debug(f"Running step {self.level}...")
        try:
            logger.debug(f"apt-strace /log/apt-trace.txt {self.command}")
            self.retval, output = self._container.exec_run(
                f"apt-strace /log/apt-trace.txt {self.command}",
                workdir="/workdir",
                stdout=True,
                stderr=True
            )
        finally:
            logger.debug(f"Ran, exit code {self.retval}")
            # print(output)
            self._container.stop()
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
            raise PackageResolutionError(f"`{self.command}` exited with code {self.retval} having looked for missing "
                                         f"files {self.missing_files!r}, none of which are satisfied by Ubuntu "
                                         f"packages")
        yielded = False
        last_error: Optional[SBOMGenerationError] = None
        for package in tqdm(packages_to_try, desc=f"step {self.level}", unit="packages", leave=False):
            try:
                with SBOMGeneratorStep(self.generator, self.command, preinstall=(package,), parent=self) as substep:
                    try:
                        for sbom in substep.run():
                            yield SBOM((package,)) + sbom
                            yielded = True
                    except SBOMGenerationError:
                        last_error = last_error
            except PreinstallError:
                # package was unable to be installed, so skip it
                continue
        if not yielded:
            if last_error is not None:
                raise last_error
            else:
                raise PackageResolutionError(f"`{self.command}` exited with code {self.retval} having looked for "
                                             f"missing files {self.missing_files!r}, none of which are satisfied by "
                                             f"Ubuntu packages")

    def __enter__(self) -> "SBOMGeneratorStep":
        assert self._logdir is None
        self._log_tmpdir = TemporaryDirectory()
        self._logdir = Path(self._log_tmpdir.__enter__()).absolute()
        cwd = Path.cwd().absolute()
        self._container = self.generator.client.containers.run(
            image=self.parent_image, entrypoint="/bin/bash", detach=True, remove=True, tty=True, read_only=False,
            volumes={
                str(cwd): {"bind": "/src", "mode": "ro"},
                str(self._logdir): {"bind": "/log", "mode": "rw"}
            }
        )
        try:
            if self.level == 0:
                retval, output = self._container.exec_run(
                    "cp -r /src /workdir"
                )
                if retval != 0:
                    raise ValueError(f"Error copying the source files to /workdir in the Docker image: {output}")
            if self.preinstall:
                logger.info(f"Installing {', '.join(self.preinstall)} ...")
                retval, output = self._container.exec_run(f"apt-get -y install {' '.join(self.preinstall)}")
                if retval != 0:
                    raise PreinstallError(f"Error apt-get installing {' '.join(self.preinstall)}: {output}")
        except:
            self.cleanup()
            raise
        logger.debug(f"Committing as {self.generator.image_name}:{self.level}...")
        self._image = self._container.commit()
        self._image.tag(repository=self.generator.image_name, tag=self.tag)
        return self

    def cleanup(self):
        logger.debug("Removing the container...")
        try:
            self._container.remove(force=True)
            logger.debug("Removed.")
        except NotFound:
            # the container was already stopped
            logger.debug("Removed.")
        if self._image is not None:
            logger.debug(f"Removing image {self.generator.image_name}:{self.level} ...")
            self._image.remove(force=True)
            logger.debug("Removed.")
            self._image = None
        self._logdir = None
        self._log_tmpdir = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        log_tmpdir = self._log_tmpdir
        self.cleanup()
        log_tmpdir.__exit__(exc_type, exc_val, exc_tb)
