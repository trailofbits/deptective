from __future__ import annotations

import functools
import gzip
from html.parser import HTMLParser
import logging
from pathlib import Path
import re
from typing import (
    FrozenSet,
    Iterator,
    Union,
    Tuple,
    Type,
    TypeVar,
)
from urllib.error import HTTPError
from urllib.request import urlopen

from .cache import CacheConfig, SQLCache
from .exceptions import PackageDatabaseNotFoundError, PackageResolutionError
from .logs import DownloadWithProgress, iterative_readlines


logger = logging.getLogger(__name__)


T = TypeVar("T")


class AptResolutionError(PackageResolutionError):
    pass


class AptDatabaseNotFoundError(PackageDatabaseNotFoundError):
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


class AptCacheConfig(CacheConfig):
    @classmethod
    def versions(cls: Type[T]) -> Iterator[T]:
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
                    os="ubuntu",
                    os_version=subdir[:-1],
                    arch=arch,
                )

    def iter_packages(self) -> Iterator[Tuple[str, FrozenSet[str]]]:
        return self.download()

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


class AptCache(SQLCache[AptCacheConfig]):
    @classmethod
    def get_config(cls, os: str, os_version: str, arch: str) -> AptCacheConfig:
        if os != "ubuntu":
            raise ValueError(f"{cls.__name__} only supports `ubuntu` as an os, not {os!r}")
        return AptCacheConfig(os=os, os_version=os_version, arch=arch)


@functools.lru_cache(maxsize=128)
def file_to_packages(
    filename: Union[str, bytes, Path],
    arch: str = "amd64",
    os_version: str = "noble",
) -> FrozenSet[str]:
    logger.debug(f"searching for packages associated with {filename!r}")
    cache = AptCache.get(AptCache.get_config("ubuntu", os_version, arch))
    result = cache[filename]
    logger.debug(f"File {filename!r} is associated with packages {result!r}")
    return result
