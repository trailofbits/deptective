import logging
from typing import IO, Dict, List, Optional, Union

import docker
from docker.client import DockerClient
from docker.errors import NotFound
from docker.models.containers import Container as DockerContainer
from docker.models.images import Image

import randomname

from rich.panel import Panel
from rich.progress import Progress


logger = logging.getLogger(__name__)


class Execution:
    def __init__(self, container: "Container", docker_container: DockerContainer):
        self.container: Container = container
        self.docker_container: Optional[DockerContainer] = docker_container

        logging_driver = docker_container.attrs['HostConfig']['LogConfig']['Type']

        if logging_driver != "json-file" and logging_driver != "journald":
            raise NotImplementedError("The logging driver for this container is not supported!")

        self._stream: IO = docker_container.logs(
            stdout=True, stderr=True, stream=False
        )
        self.exit_code: Optional[int] = None

    @property
    def done(self) -> bool:
        return self.exit_code is not None or self.docker_container is None

    def _checkup(self):
        if self.docker_container.status == "running" or self.exit_code is not None:
            return
        try:
            self.exit_code = self.docker_container.wait()["StatusCode"]
        finally:
            self.close()

    def close(self):
        if self.docker_container is None:
            raise ValueError("The container is already closed!")
        try:
            self.docker_container.remove(force=True)
            logger.debug(f"Waiting for container {self.docker_container.id} to be removed...")
            self.docker_container.wait(condition="removed")
        except NotFound:
            logger.debug(f"Container {self.docker_container.id} was already removed")
        self.docker_container = None
        self.container.__exit__(None, None, None)

    def logs(self, scrollback: int = -1) -> bytes:
        if self.docker_container is None:
            return ""
        try:
            if scrollback < 0:
                tail = "all"
            else:
                tail = scrollback
            return self.docker_container.logs(stdout=True, stderr=True, tail=tail)
        finally:
            self._checkup()


class Container:
    def __init__(
            self,
            parent: Optional[Union["Container", Image, str]],
            client: Optional[DockerClient] = None,
            image_name: Optional[str] = None
    ):
        self._image: Optional[Image] = None
        self._entries: int = 0
        if client is not None:
            self.client: DockerClient = client
        elif isinstance(parent, Container):
            self.client = parent.client
        else:
            self.client = docker.from_env()
        if isinstance(parent, str):
            if image_name is None:
                if ":" in parent:
                    base_name = parent[:parent.find(":")]
                else:
                    base_name = parent
                image_name = f"{base_name}-{randomname.get_name()}"
            parent = self.client.images.get(parent)
        self.parent: Union[Container, Image] = parent
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
        return self.parent.image

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

    def run(
            self, command: Union[str, List[str]], workdir: str = "/workdir", entrypoint: str = "/bin/bash"
    ) -> Execution:
        self.__enter__()
        try:
            image = self.image.id

            container = self.client.containers.create(image=image, command=command, tty=True, read_only=False,
                                                      detach=True, volumes=self.volumes, working_dir=workdir,
                                                      entrypoint=entrypoint)
            try:
                container.start()

                return Execution(self, container)  # this calls self.__exit__(...) when it is complete
            except:
                try:
                    container.remove(force=True)
                    logger.debug(f"Waiting for container {container.id} to be removed...")
                    container.wait(condition="removed")
                except NotFound:
                    logger.debug(f"Container {container.id} was already removed")
        except RuntimeError as e:
            self.__exit__(type(e), e, None)

    def start(self):
        if self._image is not None:
            raise ValueError(f"The container is already started!")
        if isinstance(self.parent, Container):
            _ = self.parent.__enter__()
        container = self.client.containers.run(
            image=self.parent_image, entrypoint="/bin/bash", detach=True, remove=True, tty=True, read_only=False,
            volumes=self.volumes
        )
        try:
            self.setup_image(container)

            logger.debug(f"Committing as {self.image_name}:{self.level}...")
            self._image = container.commit()
            self._image.tag(repository=self.image_name, tag=self.tag)

        except KeyboardInterrupt:
            logger.info(":stop_sign: caught keyboard interrupt; cleaning up...")
            self.stop()
            raise
        except:
            self.stop()
            raise
        finally:
            logger.debug(f"Removing the container for step {self.level}...")
            try:
                container.remove(force=True)
                logger.debug(f"Waiting for the container to be removed...")
                container.wait(condition="removed")
                logger.debug("Removed.")
            except NotFound:
                # the container was already stopped
                logger.debug("The container had already been removed.")

    def stop(self):
        if self._image is None:
            raise ValueError("The container is not running!")
        logger.debug(f"Removing image {self.image_name}:{self.level} ...")
        self._image.remove(force=True)
        logger.debug("Removed.")
        self._image = None
        if isinstance(self.parent, Container):
            self.parent.__exit__(None, None, None)

    def __enter__(self) -> "Container":
        self._entries += 1
        if self._entries == 1:
            self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._entries -= 1
        assert self._entries >= 0
        if self._entries == 0:
            self.stop()


class ContainerProgress(Progress):
    _execution: Optional[Execution] = None
    _scrollback: int = 10

    def execute(self, execution: Execution, scrollback: int = 10):
        if self._execution is not None and not self._execution.done:
            raise ValueError("An execution is already assigned to this progress!")
        self._execution = execution
        self._scrollback = scrollback

    def get_renderables(self):
        yield self.make_tasks_table(self.tasks)
        if self._execution is not None:
            if not self._execution.done:
                self._execution = None
            else:
                lines: List[str] = []
                for line in self._execution.logs(scrollback=self._scrollback).split(b"\n"):
                    try:
                        lines.append(line.decode("utf-8"))
                    except UnicodeDecodeError:
                        lines.append(repr(line)[2:-1])
                yield Panel("\n".join(lines))
