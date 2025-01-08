import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path
from typing import FrozenSet, Iterable, Iterator, Set, Tuple, Type, TypeVar, Union

from appdirs import AppDirs

from .package_manager import PackageManager

APP_DIRS = AppDirs("deptective", "Trail of Bits")
CACHE_DIR = Path(APP_DIRS.user_cache_dir)
if not CACHE_DIR.exists():
    CACHE_DIR.mkdir(parents=True)

T = TypeVar("T")


class Cache(ABC):
    def __init__(self, package_manager: PackageManager):
        self.package_manager: PackageManager = package_manager

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

    def __enter__(self: T) -> T:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.save()

    @classmethod
    @abstractmethod
    def exists(cls, package_manager: PackageManager) -> bool:
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
    def from_disk(cls: Type[T], package_manager: PackageManager) -> T:
        raise NotImplementedError()

    @classmethod
    def from_iterable(
        cls: Type[T],
        package_manager: PackageManager,
        packages: Iterable[Tuple[str, Iterable[str]]],
    ) -> T:
        """
        Imports the iterable `packages` into the native cache format, returning a new
        cache object.
        """
        raise NotImplementedError()

    @abstractmethod
    def delete(self):
        raise NotImplementedError()


class SQLCache(Cache, ABC):
    def __init__(self, package_manager: PackageManager, conn: sqlite3.Connection):
        super().__init__(package_manager)
        self.conn: sqlite3.Connection = conn

    @classmethod
    def path(cls, package_manager: PackageManager) -> Path:
        return CACHE_DIR / (
            f"{package_manager.NAME}_{package_manager.config.os}_{package_manager.config.os_version}_"
            f"{package_manager.config.arch}.sqlite3"
        )

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
    def from_disk(cls: Type[T], package_manager: PackageManager) -> T:
        db_path = cls.path(package_manager)  # type: ignore
        if not db_path.exists():
            return cls.from_iterable(package_manager, package_manager.iter_packages())  # type: ignore
        return cls(package_manager, conn=sqlite3.connect(str(db_path)))  # type: ignore

    @classmethod
    def from_iterable(
        cls: Type[T],
        package_manager: PackageManager,
        packages: Iterable[Tuple[str, Iterable[str]]],
    ) -> T:
        ret: T = cls(package_manager, conn=sqlite3.connect(str(cls.path(package_manager))))  # type: ignore

        try:
            ret._create_tables()  # type: ignore
            with ret.conn:  # type: ignore
                for filename, pkgs in packages:
                    ret.conn.executemany(  # type: ignore
                        "INSERT INTO files(filename, package) VALUES(?, ?)",
                        [(filename, package) for package in pkgs],
                    )
            return ret
        except:
            contents_db_path = ret.path(package_manager)  # type: ignore
            if contents_db_path.exists():
                contents_db_path.unlink()
            raise

    @classmethod
    def exists(cls, package_manager: PackageManager) -> bool:
        return cls.path(package_manager).exists()

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
        contents_db_path = self.path(self.package_manager)
        if not contents_db_path.exists():
            self.conn.commit()
        assert contents_db_path.exists()

    def delete(self):
        self.path(self.package_manager).unlink()
