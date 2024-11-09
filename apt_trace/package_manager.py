import platform
import re
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from inspect import isabstract
from pathlib import Path
from typing import Dict, FrozenSet, Iterator, Optional, Tuple, Type, TypeVar

from .containers import DockerContainer

T = TypeVar("T")


@dataclass(eq=True, frozen=True, unsafe_hash=True)
class PackagingConfig:
    os: str
    os_version: str
    arch: str

    @classmethod
    def get_local(cls: Type[T]) -> Optional[T]:
        """Returns a config equal to the local operating system, or None if it cannot be determined"""
        local_os = sys.platform.lower()
        local_release = platform.release()
        arch = platform.machine().lower()
        os_release_path = Path("/etc/os-release")
        if os_release_path.exists():
            var_pattern = re.compile(
                r"\s*(?P<var>\S+)\s*=\s*(\"(?P<quoted>[^\"])*\"|(?P<unquoted>\S*)|\'(?P<singlequoted>[^\'])*\')\s*"
            )
            version_id: Optional[str] = None
            version_codename: Optional[str] = None
            with open(os_release_path, "r") as f:
                for line in f:
                    line = line.strip()
                    m = var_pattern.match(line)
                    if m:
                        var = m["var"].lower()
                        quoted, unquoted, singlequoted = (
                            m["quoted"],
                            m["unquoted"],
                            m["singlequoted"],
                        )
                        if quoted is not None:
                            value = quoted
                        elif unquoted is not None:
                            value = unquoted
                        elif singlequoted is not None:
                            value = singlequoted
                        else:
                            continue
                        if var == "id":
                            local_os = value
                        elif var == "version_id":
                            version_id = value
                        elif var == "version_codename":
                            version_codename = value
            if version_codename:
                local_release = version_codename
            elif version_id:
                local_release = version_id
        return cls(os=local_os, os_version=local_release, arch=arch)  # type: ignore


class PackageManager(ABC):
    MANAGERS_BY_NAME: Dict[str, Type["PackageManager"]]
    NAME: str

    def __init__(self, config: PackagingConfig):
        self.config: PackagingConfig = config

    def __eq__(self, other):
        return (
            isinstance(other, PackageManager)
            and self.NAME == other.NAME
            and self.config == other.config
        )

    def __hash__(self):
        return hash((self.NAME, self.config))

    def __init_subclass__(cls, **kwargs):
        if not isabstract(cls):
            if (
                not hasattr(PackageManager, "MANAGERS_BY_NAME")
                or PackageManager.MANAGERS_BY_NAME is None
            ):
                PackageManager.MANAGERS_BY_NAME = {}
            if not hasattr(cls, "NAME") or not cls.NAME:
                raise TypeError(f"{cls.__name__} must define a NAME attribute")
            elif cls.NAME in PackageManager.MANAGERS_BY_NAME:
                raise TypeError(
                    f"Package Manager {cls.__name__} cannot be named {cls.NAME} because that name is "
                    f"already assigned to {PackageManager.MANAGERS_BY_NAME[cls.NAME]}"
                )
            PackageManager.MANAGERS_BY_NAME[cls.NAME] = cls

    @abstractmethod
    def update(self, container: DockerContainer) -> Tuple[int, bytes]:
        raise NotImplementedError()

    @abstractmethod
    def install(self, container: DockerContainer, *packages: str) -> Tuple[int, bytes]:
        raise NotImplementedError()

    @abstractmethod
    def iter_packages(self) -> Iterator[Tuple[str, FrozenSet[str]]]:
        raise NotImplementedError()

    @classmethod
    def versions(cls: Type[T]) -> Iterator[T]:
        raise NotImplementedError()

    @abstractmethod
    def dockerfile(self) -> str:
        raise NotImplementedError()
