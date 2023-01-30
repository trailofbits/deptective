from logging import getLogger
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterable, Optional, Set

import docker
from docker.models.images import Image
import randomname

from .apt import apt_install, apt_isinstalled, apt_uninstall, file_to_packages
from .strace import SyscallTracer


logger = getLogger(__name__)


APT_STRACE_DIR = Path(__file__).absolute().parent / "apt-strace"


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

    # def __enter__(self) -> "SBOMGenerator":
    #     while True:
    #         image_name = f"trailofbits/apt-trace-{randomname.get_name()}"
    #         if not self.client.images.list(name=image_name):
    #             break
    #     self._image_name = image_name
    #
    # def __exit__(self, exc_type, exc_val, exc_tb):
    #     self._image_name = None

    def main(self) -> int:
        with SBOMGeneratorStep(self, "./configure") as step:
            if step.run():
                print("GOOD")
            else:
                print("BAD")

        # return SBOMGeneratorStep().main()


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
        self.missing_files: Set[str] = set()

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

    def run(self) -> bool:
        print(f"Running step {self.level}...")
        try:
            print(f"apt-strace /log/apt-trace.txt {self.command}")
            self.retval, output = self._container.exec_run(
                f"apt-strace /log/apt-trace.txt {self.command}",
                workdir="/workdir",
                stdout=True,
                stderr=True
            )
        finally:
            print(f"Ran, exit code {self.retval}")
            print(output)
        with open(self._logdir / "apt-trace.txt") as log:
            for line in log:
                if line.startswith("missing\t"):
                    self.missing_files.add(line[len("missing\t"):].strip())
        print(self.missing_files)
        if self.retval == 0:
            return True
        elif not self.missing_files:
            return False
        packages_to_try: Set[str] = set()
        for file in self.missing_files:
            packages_to_try |= set(file_to_packages(file)) - self.tried_packages
        if not packages_to_try:
            return False
        for package in packages_to_try:
            with SBOMGeneratorStep(self.generator, self.command, preinstall=(package,), parent=self) as substep:
                if substep.run():
                    return True
        return False

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
                print(f"Installing {', '.join(self.preinstall)} ...")
                retval, output = self._container.exec_run(f"apt-get -y install {' '.join(self.preinstall)}")
                if retval != 0:
                    raise ValueError(f"Error apt-get installing {' '.join(self.preinstall)}: {output}")
                print("Installed.")
        except:
            self.cleanup()
            raise
        print(f"Committing as {self.generator.image_name}:{self.level}...")
        self._image = self._container.commit()
        self._image.tag(repository=self.generator.image_name, tag=self.tag)
        print(f"Committed.")
        return self

    def cleanup(self):
        print("Stopping...")
        self._container.stop()
        print("Stopped.")
        print("Waiting...")
        self._container.wait()
        print("Done!")
        if self._image is not None:
            print(f"Removing {self.generator.image_name}:{self.level} ...")
            self._image.remove()
            print("Removed!")
            self._image = None
        self._logdir = None
        self._log_tmpdir = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        log_tmpdir = self._log_tmpdir
        self.cleanup()
        log_tmpdir.__exit__(exc_type, exc_val, exc_tb)


class SBOMGeneratorStepOld(SyscallTracer):
    def __init__(self, parent: Optional["SBOMGeneratorStep"] = None):
        self.parent: Optional[SBOMGeneratorStep] = parent
        self.new_packages: Set[str] = set()
        if parent is not None:
            self.new_packages = set(parent.new_packages)
        super().__init__()

    @property
    def installed(self) -> Set[str]:
        if self.parent is None:
            return self.new_packages
        else:
            return self.new_packages - self.parent.new_packages

    def backtrack(self):
        # uninstall the packages we installed
        for installed in self.installed:
            if not apt_uninstall(installed):
                logger.warning(f"Error auto-uninstalling package {installed}!")
        raise KeyboardInterrupt()

    def handle_missing_file(self, path: str):
        packages = file_to_packages(path)
        #packages = () #cached_file_to_packages(filename, self.cache)
        packages = [pkg for pkg in packages if pkg not in self.new_packages]
        if packages:
            if self.options.auto:
                if len(packages) == 1:
                    if apt_install(packages[0].strip()):
                        logger.info(f"Automatically installed dependency {packages[0]}")
                        self.new_packages.add(packages[0].strip())
                    else:
                        logger.warning(f"Error auto-installing package {packages[0]}!")
                        self.backtrack()
                    return
                else:
                    for package in map(str.strip, packages):
                        if apt_install(package):
                            logger.info(f"Automatically installed dependency {packages[0]}")
                            self.new_packages.add(package)
                            if SBOMGeneratorStep(parent=self).main() == 0:
                                return
                            else:
                                # this branch did not work
                                if apt_uninstall(package):
                                    self.new_packages.remove(package)
                                else:
                                    logger.warning(f"Error auto-uninstalling package {package}!")
                        else:
                            logger.info(f"Error installing dependency {package}")
                    self.backtrack()
                    return
            raise NotImplementedError("TODO: Re-implement non-auto mode")
            if self.options.auto_install_single and len(packages) == 1:
                # automatically install this package
                if not apt_install(packages[0].strip()):
                    logger.warning(f"Error auto-installing package {packages[0]}!")
                    Shell(filename=filename, packages=packages).cmdloop()
                else:
                    logger.info(f"Automatically installed dependency {packages[0]}")
            else:
                Shell(filename=filename, packages=packages).cmdloop()
