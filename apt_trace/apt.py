import functools
import glob
import gzip
import logging
import lz4.frame
import os
from pathlib import Path
import pickle
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Set, Union, Tuple
import urllib.request

from appdirs import AppDirs


logger = logging.getLogger(__name__)


APP_DIRS = AppDirs("apt-trace", "Trail of Bits")
CACHE_DIR = Path(APP_DIRS.user_cache_dir)
if not CACHE_DIR.exists():
    CACHE_DIR.mkdir(parents=True)

contents_db: Dict[bytes, Set[str]] = {}
_loaded_dbs: Set[Path] = set()

CONTENTS_DB = CACHE_DIR / "contents.pkl"
LOADED_DBS = CACHE_DIR / "loadeddb.pkl"


class AptCache:
    LOADED: Dict[Tuple[str, str], "AptCache"] = {}

    def __init__(self, arch: str = "amd64", ubuntu_version: str = "kinetic"):
        self.arch: str = arch
        self.ubuntu_version: str = ubuntu_version
        self._contents_db: Optional[Dict[bytes, Set[str]]] = None
        self._contents_db_cache: Path = CACHE_DIR / f"{ubuntu_version}_{arch}_contents.pkl"

    def __contains__(self, filename: Union[str, bytes, Path]):
        return self[filename]

    def __getitem__(self, filename: Union[str, bytes, Path]) -> Set[str]:
        if isinstance(filename, Path):
            filename = str(filename)
        if isinstance(filename, str):
            filename = filename.encode("utf-8")
        if filename.startswith(b"/"):
            filename = filename[1:]  # the contents paths do not start with a leading slash
        if filename in self.contents_db:
            return self.contents_db[filename]
        else:
            return set()

    @classmethod
    def get(cls, arch: str = "amd64", ubuntu_version: str = "kinetic") -> "AptCache":
        if (arch, ubuntu_version) not in cls.LOADED:
            cls.LOADED[(arch, ubuntu_version)] = AptCache(arch, ubuntu_version)
        return cls.LOADED[(arch, ubuntu_version)]

    @property
    def contents_db(self) -> Dict[bytes, Set[str]]:
        if self._contents_db is None:
            key = (self.arch, self.ubuntu_version)
            if key in self.LOADED and self.LOADED[key]._contents_db is not None:
                self._contents_db = self.LOADED[key]._contents_db
            elif self._contents_db_cache.exists():
                logger.info(f"Loading cached APT sources for Ubuntu {self.ubuntu_version} {self.arch}")
                with open(self._contents_db_cache, 'rb') as f:
                    self._contents_db = pickle.load(f)
            else:
                self._contents_db = {}
                contents_url = f"http://security.ubuntu.com/ubuntu/dists/" \
                               f"{self.ubuntu_version}/Contents-{self.arch}.gz"
                logger.info(f"Downloading {contents_url}\nThis is a one-time download and may take a few minutes.")
                response = urllib.request.urlopen(contents_url)
                contents_pattern = re.compile(r"(\S+)\s+(\S.*)")
                for line in gzip.decompress(response.read()).decode("utf-8").splitlines():
                    m = contents_pattern.match(line)
                    if not m:
                        raise ValueError(f"Unexpected line: {line!r}")
                    filename = m.group(1).encode("utf-8")
                    packages = (pkg.split("/")[-1].strip() for pkg in m.group(1).split(","))
                    self._contents_db.setdefault(filename, set()).update(packages)
                with open(self._contents_db_cache, 'wb') as contents_db_fd:
                    pickle.dump(self._contents_db, contents_db_fd)
            if key in self.LOADED and self.LOADED[key]._contents_db is None:
                self.LOADED[key]._contents_db = self._contents_db
        return self._contents_db


def load_databases():
    global contents_db, _loaded_dbs
    if LOADED_DBS.exists():
        logger.info("Loading cached APT sources")
        with open(LOADED_DBS, 'rb') as loaded_dbs_fd:
            _loaded_dbs = pickle.load(loaded_dbs_fd)
    if CONTENTS_DB.exists():
        logger.info("Loading cached file mapping")
        with open(CONTENTS_DB, 'rb') as contents_db_fd:
            contents_db = pickle.load(contents_db_fd)


def dump_databases():
    logger.info("Dumping new database version!")
    with open(LOADED_DBS, 'wb') as loaded_dbs_fd:
        pickle.dump(_loaded_dbs, loaded_dbs_fd)
    with open(CONTENTS_DB, 'wb') as contents_db_fd:
        pickle.dump(contents_db, contents_db_fd)


is_root = os.getuid() == 0


def run_as_root(command: List[str]) -> subprocess.CompletedProcess:
    if not is_root:
        if shutil.which("sudo") is None:
            raise ValueError("this command must either be run as root or `sudo` must be installed and in the PATH")
        sudo_prefix = ["sudo"]
    else:
        sudo_prefix = []
    return subprocess.run(sudo_prefix + command, stderr=subprocess.DEVNULL)


updated = False  # Controls when to update the cache


def apt_install(package):
    return run_as_root(["apt", "-y", "install", package]).returncode == 0


def apt_uninstall(package):
    return run_as_root(["apt", "-y", "uninstall", package]).returncode == 0


def apt_isinstalled(package):
    return 'installed' in subprocess.run(
        ["apt", "-qq", "list", package], stderr=subprocess.DEVNULL, stdout=subprocess.PIPE
    ).stdout.decode("utf8")


@functools.lru_cache(maxsize=128)
def file_to_packages(
        filename: Union[str, bytes, Path], arch: str = "amd64", ubuntu_version: str = "kinetic"
) -> Tuple[str, ...]:
    logger.debug(f"searching for packages associated with {filename!r}")
    cache = AptCache.get(arch, ubuntu_version)
    result = tuple(cache[filename])
    logger.info(f"File {filename!r} is associated with packages {result!r}")
    return result
