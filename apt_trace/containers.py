import logging
import functools
from pathlib import Path
from typing import Dict, List, Literal, Optional, Self, TypeVar, Union

import docker
import requests.exceptions
from docker.client import DockerClient
from docker.errors import NotFound
from docker.models.containers import Container as DockerContainer
from docker.models.images import Image

import randomname

from rich.panel import Panel
from rich.progress import Progress


logger = logging.getLogger(__name__)


C = TypeVar("C")


class Execution:
    def __init__(self, container: "Container", docker_container: DockerContainer):
        self.container: Container = container
        self.docker_container: DockerContainer = docker_container
        self._closed = False

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

        # Refresh and check the container metadata.
        self.docker_container.reload()
        return self.docker_container.status == "exited"

    @functools.cached_property
    def exit_code(self) -> int:
        return self.docker_container.wait()["StatusCode"]

    @functools.cached_property
    def output(self) -> bytes:
        try:
            # the following line blocks until the container's processes completes:
            _ = self.exit_code
            return self.docker_container.logs(stdout=True, stderr=True)
        finally:
            self.close()

    def close(self):
        if self._closed:
            raise ValueError("The container is already closed!")
        try:
            self.docker_container.remove(force=True)
            logger.debug(
                f"Waiting for container {self.docker_container.id} to be removed..."
            )
            self.docker_container.wait(condition="removed")
        except NotFound:
            logger.debug(f"Container {self.docker_container.id} was already removed")
        self.container.__exit__(None, None, None)
        self._closed = True

    def logs(self, scrollback: int = -1) -> bytes:
        if self._closed:
            return b""
        if scrollback < 0:
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
        self.parent = parent
        if isinstance(parent, Container):
            self.level: int = parent.level + 1
            if image_name is None:
                image_name = parent.image_name
        else:
            self.level = 0
        if image_name is None:
            image_name = f"trailofbits/apt-trace-{randomname.get_name()}"
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

    def files_exist(self, *paths: Path | str) -> dict[str, bool]:
        paths = {str(p) for p in paths}
        ret: dict[str, bool] = {}
        if not paths:
            return ret
        with self:
            container = self.create(command="")
            try:
                for path in paths:
                    try:
                        _ = container.get_archive(path)
                        ret[path] = True
                    except NotFound:
                        ret[path] = False
            finally:
                try:
                    container.stop()
                    container.remove(force=True)
                    logger.debug(f"Waiting for container {container.id} to be removed...")
                    container.wait(condition="removed")
                except (NotFound, requests.exceptions.Timeout):
                    pass
            return ret

    def file_exists(self, path: Path | str) -> bool:
        return self.files_exist(path)[str(path)]

    def create(
        self,
        command: Union[str, List[str]],
        workdir: str = "/workdir",
        entrypoint: str = "/bin/bash",
    ) -> DockerContainer:
        with self:
            image = self.image.id

            container = self.client.containers.create(
                image=image,
                command=command,
                tty=True,
                read_only=False,
                detach=True,
                volumes=self.volumes,
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
                self, self.create(command=command, workdir=workdir, entrypoint=entrypoint)
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
    _execution: Optional[Execution] = None
    _scrollback: int = 10
    _exec_title: Optional[str] = None
    _exec_subtitle: Optional[str] = None

    def execute(
        self,
        execution: Execution,
        title: Optional[str] = None,
        subtitle: Optional[str] = None,
        scrollback: int = 10,
    ):
        if self._execution is not None and not self._execution.done:
            raise ValueError("An execution is already assigned to this progress!")
        self._execution = execution
        self._scrollback = scrollback
        self._exec_title = title
        self._exec_subtitle = subtitle

    def get_renderables(self):
        yield self.make_tasks_table(self.tasks)
        if self._execution is not None:
            if self._execution.done:
                self._execution = None
            else:
                lines: List[str] = []
                for line in self._execution.logs(scrollback=self._scrollback).split(
                    b"\n"
                ):
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
