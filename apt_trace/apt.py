from abc import abstractmethod
import functools
import gzip
import logging
from pathlib import Path
import pickle
import re
import sqlite3
from typing import Dict, FrozenSet, Iterable, Iterator, Optional, Set, Union, Tuple, Type, TypeVar

from appdirs import AppDirs
import rich.progress

from .logs import DownloadWithProgress, get_console, iterative_readlines


logger = logging.getLogger(__name__)


APP_DIRS = AppDirs("apt-trace", "Trail of Bits")
CACHE_DIR = Path(APP_DIRS.user_cache_dir)
if not CACHE_DIR.exists():
    CACHE_DIR.mkdir(parents=True)


C = TypeVar("C")


class AptCache:
    LOADED: Dict[Tuple[str, str], "AptCache"] = {}
    VERSIONS: Dict[int, Type["AptCache"]] = {}

    def __init__(self, arch: str = "amd64", ubuntu_version: str = "kinetic"):
        self.arch: str = arch
        self.ubuntu_version: str = ubuntu_version

    def __contains__(self, filename: Union[str, bytes, Path]):
        return bool(self[filename])

    @abstractmethod
    def __iter__(self) -> Iterator[Tuple[str, Set[str]]]:
        raise NotImplementedError()

    def __getitem__(self, filename: Union[str, bytes, Path]) -> FrozenSet[str]:
        if isinstance(filename, Path):
            filename = str(filename)
        elif isinstance(filename, bytes):
            filename = filename.decode("utf-8")
        if filename.startswith("/"):
            filename = filename[1:]  # the contents paths do not start with a leading slash
        return self.packages_providing(filename)

    @abstractmethod
    def exists(self) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def packages_providing(self, filename: str) -> FrozenSet[str]:
        raise NotImplementedError()

    def __init_subclass__(cls, **kwargs):
        version = cls.get_version()
        if version in AptCache.VERSIONS:
            raise TypeError(f"{cls.__name__} is version {version}, but that version is already associated with "
                            f"{AptCache.VERSIONS[version].__name__}")
        AptCache.VERSIONS[version] = cls
        return super().__init_subclass__(**kwargs)

    def download(self) -> Iterator[Tuple[str, FrozenSet[str]]]:
        contents_url = f"http://security.ubuntu.com/ubuntu/dists/" \
                       f"{self.ubuntu_version}/Contents-{self.arch}.gz"
        logger.info(f"Downloading {contents_url}\nThis is a one-time download and may take a few minutes.")
        contents_pattern = re.compile(r"(\S+)\s+(\S.*)")
        with DownloadWithProgress(contents_url) as p, gzip.open(p, "rb") as gz:  # type: ignore
            for line in iterative_readlines(gz):  # type: ignore
                m = contents_pattern.match(line.decode("utf-8"))
                if not m:
                    raise ValueError(f"Unexpected line: {line!r}")
                filename = m.group(1)
                packages = frozenset(pkg.split("/")[-1].strip() for pkg in m.group(2).split(","))
                yield filename, packages

    @abstractmethod
    def save(self):
        raise NotImplementedError()

    def preload(self):
        pass

    @classmethod
    @abstractmethod
    def get_version(cls) -> int:
        raise NotImplementedError()

    @classmethod
    def latest_version(cls) -> int:
        return max(AptCache.VERSIONS.keys())

    @classmethod
    def next_newest_version(cls) -> Optional[Type["AptCache"]]:
        our_version = cls.get_version()
        later_versions = {v for v in AptCache.VERSIONS.keys() if v > our_version}
        if later_versions:
            return AptCache.VERSIONS[min(later_versions)]
        else:
            return None

    @classmethod
    @abstractmethod
    def load(cls: Type[C], arch:str, ubuntu_version:str, packages: Iterable[Tuple[str, Iterable[str]]]) -> C:
        raise NotImplementedError()

    def upgrade_to_latest(self) -> "AptCache":
        ret = self
        while True:
            next_newest = ret.next_newest_version()
            if next_newest is None:
                break
            prev = ret
            logger.info(f"Upgrading from APT cache version {ret.get_version()} to {next_newest.get_version()}...")
            ret = next_newest.load(arch=self.arch, ubuntu_version=self.ubuntu_version, packages=prev)
            ret.save()
            prev.delete()
            logger.info("[bold green]Upgraded!", extra={"markup": True})
        return ret

    @classmethod
    def get(cls, arch: str = "amd64", ubuntu_version: str = "kinetic") -> "AptCache":
        if (arch, ubuntu_version) not in cls.LOADED:
            all_versions: Dict[int, AptCache] = {
                v: c(arch, ubuntu_version)
                for v, c in AptCache.VERSIONS.items()
            }
            existing_versions: Dict[int, AptCache] = {
                v: c
                for v, c in all_versions.items()
                if c.exists()
            }
            if not existing_versions:
                cls.LOADED[(arch, ubuntu_version)] = AptCache.VERSIONS[cls.latest_version()](arch, ubuntu_version)
            else:
                latest_existing_version = max(existing_versions.keys())
                cls.LOADED[(arch, ubuntu_version)] = existing_versions[latest_existing_version].upgrade_to_latest()
        return cls.LOADED[(arch, ubuntu_version)]

    @abstractmethod
    def delete(self):
        raise NotImplementedError()


class AptCacheV1(AptCache):
    def __init__(self, arch: str = "amd64", ubuntu_version: str = "kinetic"):
        super().__init__(arch=arch, ubuntu_version=ubuntu_version)
        self._contents_db: Optional[Dict[bytes, FrozenSet[str]]] = None
        self._contents_db_cache: Path = CACHE_DIR / f"{ubuntu_version}_{arch}_contents.pkl"

    def __iter__(self) -> Iterator[Tuple[str, FrozenSet[str]]]:
        self.preload()
        yield from ((f.decode("utf-8"), s) for f, s in self._contents_db.items())

    @classmethod
    def get_version(cls) -> int:
        return 1

    @classmethod
    def load(
            cls: Type["AptCacheV1"], arch: str, ubuntu_version: str, packages: Iterable[Tuple[str, Iterable[str]]]
    ) -> "AptCacheV1":
        ret = cls(arch=arch, ubuntu_version=ubuntu_version)
        ret._contents_db = {
            f.encode("utf-8"): frozenset(p)
            for f, p in packages
        }
        return ret

    def exists(self) -> bool:
        return self._contents_db is not None or self._contents_db_cache.exists()

    def delete(self):
        if self._contents_db_cache.exists():
            self._contents_db_cache.unlink()
        self._contents_db = None

    def save(self):
        if self._contents_db is None:
            self.preload()
        with open(self._contents_db_cache, 'wb') as contents_db_fd:
            pickle.dump(self._contents_db, contents_db_fd)

    def preload(self):
        if self._contents_db is not None:
            return
        elif not self.exists():
            existing_load: Optional[AptCache] = None
            self._contents_db = self.load(
                arch=self.arch, ubuntu_version=self.ubuntu_version, packages=self.download()
            )._contents_db
            self.save()
        else:
            key = (self.arch, self.ubuntu_version)
            if key in self.LOADED:
                existing_load = self.LOADED[key]
                if isinstance(existing_load, AptCacheV1) and existing_load._contents_db is not None:
                    self._contents_db = existing_load._contents_db
                    return
                if existing_load is self:
                    existing_load = None
            else:
                existing_load = None
            assert self._contents_db_cache.exists()
            logger.info(f"Loading cached APT sources for Ubuntu {self.ubuntu_version} {self.arch}")
            with rich.progress.open(
                    self._contents_db_cache, 'rb', transient=True, console=get_console(logger)
            ) as f:
                self._contents_db = pickle.load(f)
        if isinstance(existing_load, AptCacheV1):
            assert existing_load._contents_db is None
            existing_load._contents_db = self._contents_db

    def packages_providing(self, filename: str) -> FrozenSet[str]:
        self.preload()
        f = filename.encode("utf-8")
        if f in self._contents_db:
            return self._contents_db[f]
        else:
            return frozenset()


class AptCacheV2(AptCache):
    def __init__(self, arch: str = "amd64", ubuntu_version: str = "kinetic"):
        super().__init__(arch=arch, ubuntu_version=ubuntu_version)
        self._contents_db: Optional[Dict[bytes, FrozenSet[str]]] = None
        self._contents_db_path: Path = CACHE_DIR / f"{ubuntu_version}_{arch}_contents.sqlite3"
        self.conn: Optional[sqlite3.Connection] = None

    def __iter__(self) -> Iterator[Tuple[str, FrozenSet[str]]]:
        self.preload()
        cur = self.conn.cursor()
        res = cur.execute("SELECT filename, package FROM files GROUP BY filename")
        filename: Optional[str] = None
        packages: Set[str] = set()
        while True:
            results = res.fetchmany(1024)
            if not results:
                break
            for f, package in results:
                if filename is None:
                    filename = f
                if filename == f:
                    packages.add(package)
                else:
                    if len(packages) > 1:
                        breakpoint()
                    yield filename, frozenset(packages)
                    filename = None
                    packages = set()
        if filename is not None:
            yield filename, frozenset(packages)

    def exists(self) -> bool:
        return self._contents_db_path.exists()

    def packages_providing(self, filename: str) -> FrozenSet[str]:
        self.preload()
        cur = self.conn.cursor()
        res = cur.execute("SELECT package FROM files WHERE filename = ?", (filename,))
        return frozenset(c[0] for c in res.fetchall())

    @classmethod
    def get_version(cls) -> int:
        return 2

    def preload(self):
        if self.conn is not None:
            return
        elif not self.exists():
            assert self.conn is None
            loaded = self.load(arch=self.arch, ubuntu_version=self.ubuntu_version, packages=self.download(),
                               in_memory=False)
            loaded.conn.close()
            assert self.exists()
        self.conn = sqlite3.connect(str(self._contents_db_path))

    def _create_tables(self):
        assert self.conn is not None
        cur = self.conn.cursor()
        cur.execute("""CREATE TABLE files(
            filename TEXT NOT NULL,
            package TEXT NOT NULL
        )""")
        cur.execute("CREATE INDEX filenames ON files(filename)")
        cur.execute("CREATE INDEX packages ON files(package)")
        self.conn.commit()

    def save(self):
        if not self._contents_db_path.exists():
            self.load(arch=self.arch, ubuntu_version=self.ubuntu_version, packages=self, in_memory=False).conn.close()
        assert self._contents_db_path.exists()

    @classmethod
    def load(
            cls: Type["AptCacheV2"], arch: str, ubuntu_version: str, packages: Iterable[Tuple[str, Iterable[str]]],
            in_memory: bool = True
    ) -> "AptCacheV2":
        ret = cls(arch=arch, ubuntu_version=ubuntu_version)
        if in_memory:
            ret.conn = sqlite3.connect(":memory:")
        else:
            ret.conn = sqlite3.connect(str(ret._contents_db_path))
        try:
            ret._create_tables()
            with ret.conn:
                for filename, pkgs in packages:
                    ret.conn.executemany("INSERT INTO files(filename, package) VALUES(?, ?)", [
                        (filename, package) for package in pkgs
                    ])
            return ret
        except:
            if not in_memory and ret._contents_db_path.exists():
                ret._contents_db_path.unlink()
            raise

    def delete(self):
        self._contents_db_path.unlink()


@functools.lru_cache(maxsize=128)
def file_to_packages(
        filename: Union[str, bytes, Path], arch: str = "amd64", ubuntu_version: str = "kinetic"
) -> FrozenSet[str]:
    logger.debug(f"searching for packages associated with {filename!r}")
    cache = AptCache.get(arch, ubuntu_version)
    result = cache[filename]
    logger.debug(f"File {filename!r} is associated with packages {result!r}")
    return result
