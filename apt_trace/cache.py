from abc import ABC, abstractmethod
from dataclasses import dataclass
from inspect import isabstract
from pathlib import Path
import sqlite3
from typing import Dict, FrozenSet, Generic, Iterable, Iterator, Set, Tuple, Type, TypeVar, Union

from appdirs import AppDirs


APP_DIRS = AppDirs("apt-trace", "Trail of Bits")
CACHE_DIR = Path(APP_DIRS.user_cache_dir)
if not CACHE_DIR.exists():
    CACHE_DIR.mkdir(parents=True)

T = TypeVar("T")


@dataclass(eq=True, frozen=True)
class CacheConfig:
    os: str
    os_version: str
    arch: str

    @abstractmethod
    def iter_packages(self) -> Iterator[Tuple[str, FrozenSet[str]]]:
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def versions(cls: Type[T]) -> Iterator[T]:
        raise NotImplementedError()


C = TypeVar("C", bound=CacheConfig)


class Cache(ABC, Generic[C]):
    LOADED: Dict[CacheConfig, "Cache"]
    SUBCLASSES: Set[Type["Cache"]]

    def __init__(self, config: C):
        self.config: C = config

    def __contains__(self, filename: Union[str, bytes, Path]):
        return bool(self[filename])

    @abstractmethod
    def __iter__(self) -> Iterator[Tuple[str, FrozenSet[str]]]:
        raise NotImplementedError()

    def __getitem__(self, filename: Union[str, bytes, Path]) -> FrozenSet[str]:
        if isinstance(filename, Path):
            filename = str(filename)
        elif isinstance(filename, bytes):
            filename = filename.decode("utf-8")
        if filename.startswith("/"):
            filename = filename[
                1:
            ]  # the contents paths do not start with a leading slash
        return self.packages_providing(filename)

    def __enter__(self) -> "Cache[C]":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.save()

    def __init_subclass__(cls, **kwargs):
        if not hasattr(Cache, "SUBCLASSES") or Cache.SUBCLASSES is None:
            setattr(Cache, "SUBCLASSES", set())
        if not isabstract(cls):
            Cache.SUBCLASSES.add(cls)

    @classmethod
    def get_caches(cls: Type[T], os: str, os_version: str, arch: str) -> Iterator[T]:
        if not hasattr(Cache, "SUBCLASSES") or Cache.SUBCLASSES is None:
            setattr(Cache, "SUBCLASSES", set())
        for subclass in Cache.SUBCLASSES:
            try:
                config = subclass.get_config(os=os, os_version=os_version, arch=arch)
                yield subclass.get(config)
            except (NotImplementedError, ValueError):
                pass

    @classmethod
    def get(cls: Type[T], config: C) -> T:
        if not hasattr(cls, "LOADED") or cls.LOADED is None:
            setattr(cls, "LOADED", {})
        if config not in cls.LOADED:
            if cls.exists(config):
                cls.LOADED[config] = cls.from_disk(config)
            else:
                # No caches on disk: we need to download and persist
                instance = cls.from_iterable(config, config.iter_packages())
                cls.LOADED[config] = instance
                instance.save()

        return cls.LOADED[config]

    @classmethod
    def get_config(cls, os: str, os_version: str, arch: str) -> C:
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def exists(cls, config: C) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def packages_providing(self, filename: str) -> FrozenSet[str]:
        """Returns the set of all packages providing filename.
        Note that filename will never contain a leading '/' slash.

        """
        raise NotImplementedError()

    @abstractmethod
    def save(self):
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def from_disk(cls: Type[T], config: C) -> T:
        raise NotImplementedError()

    @classmethod
    def from_iterable(cls: Type[T], config: C, packages: Iterable[Tuple[str, Iterable[str]]]) -> T:
        """
        Imports the iterable `packages` into the native cache format, returning a new
        cache object.
        """
        raise NotImplementedError()

    @abstractmethod
    def delete(self):
        raise NotImplementedError()


class SQLCache(Cache[C], ABC, Generic[C]):
    def __init__(self, config: C, conn: sqlite3.Connection):
        super().__init__(config)
        self.conn: sqlite3.Connection = conn

    @classmethod
    def path(cls, config: C) -> Path:
        return CACHE_DIR / f"{cls.__name__}_{config.os}_{config.os_version}_{config.arch}.sqlite3"

    def __iter__(self) -> Iterator[Tuple[str, FrozenSet[str]]]:
        cur = self.conn.cursor()
        res = cur.execute("SELECT filename, package FROM files GROUP BY filename")
        filename: str | None = None
        packages: Set[str] = set()
        while results := res.fetchmany(1024):
            for f, package in results:
                if filename is None:
                    filename = f
                elif filename == f:
                    packages.add(package)
                else:
                    yield filename, frozenset(packages)
                    filename = None
                    packages = set()

        if filename is not None:
            yield filename, frozenset(packages)

    @classmethod
    def from_disk(cls: Type[T], config: C) -> T:
        db_path = str(cls.path(config))
        return cls(config, conn=sqlite3.connect(db_path))

    @classmethod
    def from_iterable(cls: Type[T], config: C, packages: Iterable[Tuple[str, Iterable[str]]]) -> T:
        ret = cls.from_disk(config)

        try:
            ret._create_tables()
            with ret.conn:
                for filename, pkgs in packages:
                    ret.conn.executemany(
                        "INSERT INTO files(filename, package) VALUES(?, ?)",
                        [(filename, package) for package in pkgs],
                    )
            return ret
        except:
            contents_db_path = ret.path(config)
            if contents_db_path.exists():
                contents_db_path.unlink()
            raise

    @classmethod
    def exists(cls, config: C) -> bool:
        return cls.path(config).exists()

    def packages_providing(self, filename: str) -> FrozenSet[str]:
        cur = self.conn.cursor()
        res = cur.execute("SELECT package FROM files WHERE filename = ?", (filename,))
        return frozenset(c[0] for c in res.fetchall())

    def _create_tables(self):
        assert self.conn is not None
        cur = self.conn.cursor()
        cur.execute(
            """CREATE TABLE files(
            filename TEXT NOT NULL,
            package TEXT NOT NULL
        )"""
        )
        cur.execute("CREATE INDEX filenames ON files(filename)")
        cur.execute("CREATE INDEX packages ON files(package)")
        self.conn.commit()

    def save(self):
        contents_db_path = self.path(self.config)
        if not contents_db_path.exists():
            self.conn.commit()
        assert contents_db_path.exists()

    def delete(self):
        self.path(self.config).unlink()
        if self.config in self.__class__.LOADED:
            del self.__class__.LOADED[self.config]
