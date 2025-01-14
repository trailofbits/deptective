import gzip
import logging
import re
from html.parser import HTMLParser
from typing import (
    FrozenSet,
    Iterator,
    Tuple,
    Type,
    TypeVar,
)
from urllib.error import HTTPError
from urllib.request import urlopen

from .containers import DockerContainer
from .exceptions import PackageDatabaseNotFoundError, PackageResolutionError
from .logs import DownloadWithProgress, iterative_readlines
from .package_manager import PackageManager, PackagingConfig

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


class Apt(PackageManager):
    NAME = "apt"

    def update(self, container: DockerContainer) -> Tuple[int, bytes]:
        return container.exec_run("apt-get update -y")

    def install(self, container: DockerContainer, *packages: str) -> Tuple[int, bytes]:
        if not packages:
            return 0, b""
        return container.exec_run(f"apt-get -y install {' '.join(packages)}")

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
                arch = contents[len("Contents-") : -len(".gz")]
                yield cls(  # type: ignore
                    PackagingConfig(
                        os="ubuntu",
                        os_version=subdir[:-1],
                        arch=arch,
                    )
                )

    def iter_packages(self) -> Iterator[Tuple[str, FrozenSet[str]]]:
        """
        Downloads the APT file database and presents it as an iterator.
        """
        contents_url = (
            "http://security.ubuntu.com/ubuntu/dists/"
            f"{self.config.os_version}/Contents-{self.config.arch}.gz"
        )
        logger.info(
            f"Downloading {contents_url}\n"
            "This is a one-time download and may take a few minutes."
        )
        # for some reason, Ubuntu doesn't include /usr/bin/cc in its package database:
        yield "usr/bin/cc", frozenset({"gcc", "g++", "clang"})
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
                raise AptDatabaseNotFoundError(
                    f"Received an HTTP 404 error when trying to download the package "
                    f"database for "
                    f"{self.config.os}:{self.config.os_version}-{self.config.arch} from "
                    f"{contents_url}"
                )
            else:
                raise AptResolutionError(
                    f"Error trying to download the package database for "
                    f"{self.config.os}:{self.config.os_version}-{self.config.arch} from "
                    f"{contents_url}: {error!s}"
                )

    def dockerfile(self) -> str:
        return f"""FROM {self.config.os}:{self.config.os_version} AS builder
        
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && apt-get install -y strace

FROM {self.config.os}:{self.config.os_version}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update
RUN echo "APT::Get::Install-Recommends \"false\";" >> /etc/apt/apt.conf
RUN echo "APT::Get::Install-Suggests \"false\";" >> /etc/apt/apt.conf
RUN mkdir /src/
COPY --from=builder /usr/bin/strace /usr/bin/strace-native
COPY deptective-strace /usr/bin/deptective-strace
COPY deptective-files-exist /usr/bin/deptective-files-exist

ENTRYPOINT ["/usr/bin/deptective-strace"]
"""
