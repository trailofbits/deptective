import functools
import logging
from pathlib import Path
import sys
import time
from typing import Dict, List, Literal, Optional, TypeVar, Union

if sys.version_info < (3, 11):
    from typing_extensions import Self
else:
    from typing import Self

if sys.version_info >= (3, 12):
    from itertools import batched
else:
    from itertools import islice

    def batched(iterable, n):
        # batched('ABCDEFG', 3) → ABC DEF G
        if n < 1:
            raise ValueError("n must be at least one")
        iterator = iter(iterable)
        while batch := tuple(islice(iterator, n)):
            yield batch


import docker
import randomname
import requests.exceptions  # type: ignore
from docker.client import DockerClient
from docker.errors import NotFound
from docker.models.containers import Container as DockerContainer
from docker.models.images import Image
from rich.panel import Panel
from rich.progress import Progress

logger = logging.getLogger(__name__)


C = TypeVar("C")


class Execution:
    def __init__(self, container: "Container", docker_container: DockerContainer):
        self.container: Container = container
        self.docker_container: DockerContainer = docker_container
        self._closed = False
        self._output: bytes | None = None
        self._exit_code: int | None = None

        logging_driver = docker_container.attrs["HostConfig"]["LogConfig"]["Type"]

        if logging_driver != "json-file" and logging_driver != "journald":
            raise NotImplementedError(
                "The logging driver for this container is not supported!"
            )

    @property
    def done(self) -> bool:
        # If we are closed, then we are definitely done.
        if self._closed:
            return True

        try:
            # Refresh and check the container metadata.
            self.docker_container.reload()
            if self.docker_container.status == "exited":
                self.close()
                return True
        except NotFound:
            # the container is not running
            self.close()
            return True
        return False

    @functools.cached_property
    def exit_code(self) -> int:
        """Blocks until the execution completes and returns its exit code."""
        if self._exit_code is None:
            try:
                self._exit_code = self.docker_container.wait()["StatusCode"]
            except NotFound:
                # race condition: the container was closed by a different thread
                # which should have set self._exit_code
                pass
            finally:
                self.close()
        return self._exit_code  # type: ignore

    @property
    def output(self) -> bytes:
        """Blocks until the execution completes and returns its output."""
        _ = self.exit_code
        if self._output is None:
            self.close()
            if self._output is None:
                return b""
        return self._output

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._output = self.docker_container.logs(stdout=True, stderr=True, tail="all")
        if self._exit_code is None:
            self._exit_code = self.docker_container.wait()["StatusCode"]
        try:
            self.docker_container.remove(force=True)
            logger.debug(
                f"Waiting for container {self.docker_container.id} to be removed..."
            )
            self.docker_container.wait(condition="removed")
        except NotFound:
            logger.debug(f"Container {self.docker_container.id} was already removed")
        self.container.__exit__(None, None, None)

    def logs(self, scrollback: int = -1) -> bytes:
        if self.done:
            if scrollback < 0:
                return self.output
            else:
                return self.output[-scrollback:]
        elif scrollback < 0:
            tail: int | Literal["all"] = "all"
        else:
            tail = scrollback
        return self.docker_container.logs(stdout=True, stderr=True, tail=tail)


class Container:
    def __init__(
        self,
        parent: Optional[Union[Self, Image, str]],
        client: Optional[DockerClient] = None,
        image_name: Optional[str] = None,
    ):
        self._image: Optional[Image] = None
        self._entries: int = 0
        if client is not None:
            self.client: DockerClient = client
        elif isinstance(parent, Container):
            self.client = parent.client
        else:
            self.client = docker.from_env(timeout=5)
        if isinstance(parent, str):
            if image_name is None:
                if ":" in parent:
                    base_name = parent[: parent.find(":")]
                else:
                    base_name = parent
                image_name = f"{base_name}-{randomname.get_name()}"
            parent = self.client.images.get(parent)
        self.parent: Union[Self, Image] = parent
        if isinstance(parent, Container):
            self.level: int = parent.level + 1
            if image_name is None:
                image_name = parent.image_name
        else:
            self.level = 0
        if image_name is None:
            image_name = f"trailofbits/deptective-{randomname.get_name()}"
        self.image_name: str = image_name

    @property
    def parent_image(self) -> Image:
        if isinstance(self.parent, Image):
            return self.parent
        elif isinstance(self.parent, Container):
            return self.parent.image
        raise ValueError

    @property
    def image(self) -> Image:
        if self._image is None:
            return self.parent_image
        return self._image

    @property
    def volumes(self) -> Dict[str, Dict[str, str]]:
        return {}

    @property
    def tag(self) -> str:
        return f"step{self.level}"

    def setup_image(self, container: DockerContainer):
        pass

    def files_exist(
        self, *paths: Path | str, progress: Progress | None = None
    ) -> dict[str, bool]:
        str_paths: set[str] = {str(p) for p in paths}  # type: ignore
        if not str_paths:
            return {}
        ret: dict[str, bool] = {path.strip(): True for path in str_paths}
        with self:
            unique_paths = list(str_paths)
            if progress is None:
                iterator = iter(batched(unique_paths, n=255))
            else:
                iterator = progress.track(  # type: ignore
                    list(batched(unique_paths, n=255)),
                    description="checking for missing files…",
                )
            for files in iterator:
                result = self.run(
                    command=list(files),
                    entrypoint="/usr/bin/deptective-files-exist",
                    workdir="/workdir",
                )
                while not result.done:
                    time.sleep(0.25)
                if result.exit_code != 0:
                    error_message = (
                        f"Error running deptective-files-exist:\n\n{result.output.decode('utf-8')}\n\n"
                        f"Inputs: {' '.join(unique_paths)})"
                    )
                    logger.error(error_message)
                    raise RuntimeError(error_message)
                for line in result.output.splitlines():
                    ret[line.decode("utf-8").strip()] = False
            return ret

    def file_exists(self, path: Path | str) -> bool:
        return self.files_exist(path)[str(path)]

    def create(
        self,
        command: Union[str, List[str]],
        workdir: str = "/workdir",
        entrypoint: str = "/bin/bash",
        additional_volumes: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> DockerContainer:
        volumes = self.volumes
        if additional_volumes is not None:
            volumes = dict(volumes.items())
            volumes.update(additional_volumes)
        with self:
            image = self.image.id

            container = self.client.containers.create(
                image=image,
                command=command,
                tty=True,
                read_only=False,
                detach=True,
                volumes=volumes,
                working_dir=workdir,
                entrypoint=entrypoint,
            )
            try:
                container.start()

                return container
            except Exception:
                try:
                    container.remove(force=True)
                    logger.debug(
                        f"Waiting for container {container.id} to be removed..."
                    )
                    container.wait(condition="removed")
                    raise
                except NotFound:
                    logger.debug(f"Container {container.id} was already removed")
                    raise

    def run(
        self,
        command: Union[str, List[str]],
        workdir: str = "/workdir",
        entrypoint: str = "/bin/bash",
    ) -> Execution:
        self.__enter__()
        try:
            return Execution(
                self,
                self.create(command=command, workdir=workdir, entrypoint=entrypoint),
            )  # this calls self.__exit__(...) when it is complete
        except RuntimeError as e:
            self.__exit__(type(e), e, None)
            raise

    def start(self):
        if self._image is not None:
            raise ValueError("The container is already started!")
        if isinstance(self.parent, Container):
            _ = self.parent.__enter__()

        container = self.client.containers.run(
            image=self.parent_image,
            entrypoint="/bin/bash",
            detach=True,
            remove=True,
            tty=True,
            read_only=False,
            volumes=self.volumes,
        )
        try:
            self.setup_image(container)

            logger.debug(f"Committing as {self.image_name}:{self.level}...")
            self._image = container.commit()
            self._image.tag(repository=self.image_name, tag=self.tag)
        finally:
            try:
                container.remove(force=True)
                logger.debug(f"Waiting for container {container.id} to be removed...")
                container.wait(condition="removed")
            except NotFound:
                pass

    def stop(self):
        if self._image is None:
            raise ValueError("The container is not running!")
        logger.debug(f"Removing image {self.image_name}:{self.level} ...")
        try:
            self._image.remove(force=True)
            logger.debug("Removed.")
        except requests.exceptions.Timeout as e:
            logger.warning(f"Timed out waiting for container to be removed: {e!s}")
        self._image = None
        if isinstance(self.parent, Container):
            self.parent.__exit__(None, None, None)

    def __enter__(self) -> Self:
        self._entries += 1
        if self._entries == 1:
            try:
                self.start()
            except Exception as e:
                self._entries -= 1
                raise e
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._entries -= 1
        assert self._entries >= 0
        if self._entries == 0:
            self.stop()


class ContainerProgress(Progress):
    execution: Optional[Execution] = None
    _scrollback: int = 10
    _exec_title: Optional[str] = None
    _exec_subtitle: Optional[str] = None
    _file_progress: Optional[Progress] = None

    def execute(
        self,
        execution: Execution,
        title: Optional[str] = None,
        subtitle: Optional[str] = None,
        scrollback: int = 10,
    ):
        if self.execution is not None and not self.execution.done:
            raise ValueError("An execution is already assigned to this progress!")
        self.execution = execution
        self._scrollback = scrollback
        self._exec_title = title
        self._exec_subtitle = subtitle
        self._file_progress = None

    @property
    def file_progress(self) -> Progress | None:
        return self._file_progress

    @file_progress.setter
    def file_progress(self, progress: Progress | None):
        if progress is not self._file_progress:
            self._file_progress = progress
            if progress is None:
                self.execution = None
            self.refresh()

    def get_renderables(self):
        yield self.make_tasks_table(self.tasks)
        if self.execution is not None:
            lines: List[str] = []
            for line in self.execution.logs(scrollback=self._scrollback).split(b"\n"):
                try:
                    lines.append(line.decode("utf-8"))
                except UnicodeDecodeError:
                    lines.append(repr(line)[2:-1])
            while lines and not lines[-1].strip():
                lines.pop()
            yield Panel(
                "\n".join(lines),
                title=self._exec_title,
                subtitle=self._exec_subtitle,
            )
        if self.file_progress is not None:
            yield self.file_progress
