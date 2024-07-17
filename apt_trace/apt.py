from __future__ import annotations

from abc import abstractmethod
from appdirs import AppDirs
from dataclasses import dataclass
import functools
import gzip
from html.parser import HTMLParser
import logging
from pathlib import Path
import re
import sqlite3
from typing import (
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    Optional,
    Set,
    Union,
    Tuple,
    Type,
    TypeVar,
)
from urllib.error import HTTPError
from urllib.request import urlopen

from rich.console import Console

from .exceptions import SBOMGenerationError
from .logs import DownloadWithProgress, iterative_readlines


logger = logging.getLogger(__name__)


APP_DIRS = AppDirs("apt-trace", "Trail of Bits")
CACHE_DIR = Path(APP_DIRS.user_cache_dir)
if not CACHE_DIR.exists():
    CACHE_DIR.mkdir(parents=True)


T = TypeVar("T")


class AptResolutionError(SBOMGenerationError):
    pass


class AptDatabaseNotFoundError(AptResolutionError):
    pass


class UbuntuDistParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.subdirectories: set[str] = set()
        self.contents: set[str] = set()

    def handle_starttag(self, tag, attrs):
        if tag == "a" and attrs:
            is_href, url = attrs[0]
            if is_href == "href" and not url.startswith("/"):
                if url.endswith("/"):
                    # this is a link to a subdirectory
                    self.subdirectories.add(url)
                elif url.startswith("Contents-") and url.endswith(".gz"):
                    # this is a contents file
                    self.contents.add(url)

    def handle_endtag(self, tag):
        pass

    def handle_data(self, data):
        pass


@dataclass(eq=True, frozen=True)
class AptCacheConfig:
    os = "ubuntu"
    os_version: str
    arch: str

    @classmethod
    def versions(cls: Type[T], console: Optional[Console] = None) -> Iterator[T]:
        """Yields all possible configurations"""
        contents_url = "http://security.ubuntu.com/ubuntu/dists/"
        request = urlopen(contents_url)
        data = request.read()
        parser = UbuntuDistParser()
        parser.feed(data.decode("utf-8"))
        for subdir in parser.subdirectories:
            subdir_url = f"{contents_url}{subdir}"
            sub_request = urlopen(subdir_url)
            sub_data = sub_request.read()
            sub_parser = UbuntuDistParser()
            sub_parser.feed(sub_data.decode("utf-8"))
            for contents in sub_parser.contents:
                arch = contents[len("Contents-"):-len(".gz")]
                yield cls(
                    os_version=subdir[:-1],
                    arch=arch,
                )

    def download(self) -> Iterator[Tuple[str, FrozenSet[str]]]:
        """
        Downloads the APT file database and presents it as an iterator.
        """
        contents_url = (
            "http://security.ubuntu.com/ubuntu/dists/"
            f"{self.os_version}/Contents-{self.arch}.gz"
        )
        logger.info(
            f"Downloading {contents_url}\n"
            "This is a one-time download and may take a few minutes."
        )
        contents_pattern = re.compile(r"(\S+)\s+(\S.*)")
        try:
            with DownloadWithProgress(contents_url) as p, gzip.open(p, "rb") as gz:
                for line in iterative_readlines(gz):  # type: ignore
                    m = contents_pattern.match(line.decode("utf-8"))
                    if not m:
                        raise ValueError(f"Unexpected line: {line!r}")
                    filename = m.group(1)
                    packages = frozenset(
                        pkg.split("/")[-1].strip() for pkg in m.group(2).split(",")
                    )
                    yield filename, packages
            error = None
        except HTTPError as e:
            error = e
        if error is not None:
            if error.code == 404:
                raise AptDatabaseNotFoundError(f"Received an HTTP 404 error when trying to download the package "
                                               f"database for {self.os}:{self.os_version}-{self.arch} from "
                                               f"{contents_url}")
            else:
                raise AptResolutionError(f"Error trying to download the package database for "
                                         f"{self.os}:{self.os_version}-{self.arch} from {contents_url}: {error!s}")


class AptCache:
    LOADED: Dict[AptCacheConfig, AptCache] = {}
    VERSIONS: Dict[int, Type[AptCache]] = {}

    def __init__(self, config: AptCacheConfig):
        self.config = config

    def __contains__(self, filename: Union[str, bytes, Path]):
        return bool(self[filename])

    @abstractmethod
    def __iter__(self) -> Iterator[Tuple[str, FrozenSet[str]]]:
        raise NotImplementedError

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

    @classmethod
    @abstractmethod
    def exists(cls, config: AptCacheConfig) -> bool:
        raise NotImplementedError

    @abstractmethod
    def packages_providing(self, filename: str) -> FrozenSet[str]:
        raise NotImplementedError

    def __init_subclass__(cls, **kwargs):
        version = cls.version()
        if version in AptCache.VERSIONS:
            raise TypeError(
                f"{cls.__name__} is version {version}, but that version is already"
                f" associated with {AptCache.VERSIONS[version].__name__}"
            )
        AptCache.VERSIONS[version] = cls
        return super().__init_subclass__(**kwargs)

    @abstractmethod
    def save(self):
        """
        Persists the native cache format to disk.
        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def version(cls) -> int:
        raise NotImplementedError

    @classmethod
    def latest_version(cls) -> int:
        return max(AptCache.VERSIONS.keys())

    @classmethod
    def next_version(cls) -> Type[AptCache] | None:
        our_version = cls.version()
        later_versions = {v for v in AptCache.VERSIONS.keys() if v > our_version}
        if later_versions:
            return AptCache.VERSIONS[min(later_versions)]
        else:
            return None

    @classmethod
    @abstractmethod
    def from_disk(
        cls,
        config: AptCacheConfig,
    ) -> AptCache:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def from_iterable(
        cls,
        config: AptCacheConfig,
        packages: Iterable[Tuple[str, Iterable[str]]],
    ) -> AptCache:
        """
        Imports the iterable `packages` into the native cache format, returning a new
        cache object.
        """
        raise NotImplementedError

    def upgrade(self) -> AptCache:
        """
        Upgrades the current native cache to the newest format, returning a new cache.
        """
        ret = self
        while True:
            newer = ret.next_version()
            if newer is None:
                break
            current = ret
            logger.info(
                f"Upgrading from APT cache version {ret.version()} to"
                f" {newer.version()}..."
            )
            ret = newer.from_iterable(
                config=self.config,
                packages=current,
            )
            ret.save()
            current.delete()
            logger.info("[bold green]Upgraded!", extra={"markup": True})
        return ret

    @classmethod
    def get(cls, config: AptCacheConfig) -> AptCache:
        if config in cls.LOADED:
            return cls.LOADED[config]

        # Map out the versions with cache files on disk
        existing_versions: Dict[int, Type[AptCache]] = {
            v: c for v, c in AptCache.VERSIONS.items() if c.exists(config)
        }

        # No caches on disk: we need to download and persist
        if not existing_versions:
            target = AptCache.VERSIONS[cls.latest_version()]
            cls.LOADED[config] = target.from_iterable(config, config.download())
        else:
            latest_version = max(existing_versions.keys())
            cls.LOADED[config] = (
                existing_versions[latest_version].from_disk(config).upgrade()
            )

        return cls.LOADED[config]

    @abstractmethod
    def delete(self):
        raise NotImplementedError


class AptCacheV2(AptCache):
    def __init__(self, config: AptCacheConfig, *, conn: sqlite3.Connection):
        super().__init__(config)
        self._contents_db_path: Path = (
            CACHE_DIR / f"{config.os_version}_{config.arch}_contents.sqlite3"
        )
        self.conn = conn

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
    def path(cls, config: AptCacheConfig) -> Path:
        return CACHE_DIR / f"{config.os_version}_{config.arch}_contents.sqlite3"

    @classmethod
    def exists(cls, config: AptCacheConfig) -> bool:
        return cls.path(config).exists()

    def packages_providing(self, filename: str) -> FrozenSet[str]:
        cur = self.conn.cursor()
        res = cur.execute("SELECT package FROM files WHERE filename = ?", (filename,))
        return frozenset(c[0] for c in res.fetchall())

    @classmethod
    def version(cls) -> int:
        return 2

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
        if not self._contents_db_path.exists():
            self.conn.commit()
        assert self._contents_db_path.exists()

    @classmethod
    def from_disk(
        cls,
        config: AptCacheConfig,
    ) -> AptCacheV2:
        db_path = str(cls.path(config))
        return cls(config, conn=sqlite3.connect(db_path))

    @classmethod
    def from_iterable(
        cls,
        config: AptCacheConfig,
        packages: Iterable[Tuple[str, Iterable[str]]],
    ) -> AptCacheV2:
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
            if ret._contents_db_path.exists():
                ret._contents_db_path.unlink()
            raise

    def delete(self):
        self._contents_db_path.unlink()


@functools.lru_cache(maxsize=128)
def file_to_packages(
    filename: Union[str, bytes, Path],
    arch: str = "amd64",
    os_version: str = "noble",
) -> FrozenSet[str]:
    logger.debug(f"searching for packages associated with {filename!r}")
    cache = AptCache.get(AptCacheConfig(os_version, arch))
    result = cache[filename]
    logger.debug(f"File {filename!r} is associated with packages {result!r}")
    return result


DEFAULT_CONFIG = AptCacheConfig("noble", "amd64")


def prime_caches():
    AptCache.get(DEFAULT_CONFIG)
