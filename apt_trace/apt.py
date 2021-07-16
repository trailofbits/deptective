import functools
import glob
import logging
import lz4.frame
import os
from pathlib import Path
import pickle
import shutil
import subprocess
from typing import Dict, List, Set, Union, Tuple

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


@functools.lru_cache
def apt_install(package):
    return run_as_root(["apt", "-y", "install", package]).returncode == 0


def apt_isinstalled(package):
    return 'installed' in subprocess.run(
        ["apt", "-qq", "list", package], stderr=subprocess.DEVNULL, stdout=subprocess.PIPE
    ).stdout.decode("utf8")


@functools.lru_cache(maxsize=128)
def file_to_packages(filename: Union[str, bytes, Path], arch: str = "amd64") -> Tuple[str, ...]:
    """
    Downloads and uses apt-file database directly
    # http://security.ubuntu.com/ubuntu/dists/focal-security/Contents-amd64.gz
    # http://security.ubuntu.com/ubuntu/dists/focal-security/Contents-i386.gz
    """
    if arch not in ("amd64", "i386"):
        raise ValueError("Only amd64 and i386 supported")
    logger.debug(f"searching for packages associated with {filename!r}")
    # ensure that the filename is a byte string:
    try:
        if isinstance(filename, str):
            filename = filename.encode("utf-8")
        elif isinstance(filename, Path):
            filename = str(filename).encode("utf-8")
    except UnicodeEncodeError:
        logger.warning(f"File {filename!r} cannot be encoded in UTF-8; skipping")
        return ()
    global updated
    dump = False
    if not updated:
        load_databases()
        for dbfile in glob.glob(f'/var/lib/apt/lists/*Contents-{arch}.lz4'):
            if not dbfile in _loaded_dbs:
                logger.info(f"Rebuilding contents db {dbfile}")
                with lz4.frame.open(dbfile, mode='r') as contents:
                    for line in contents.readlines():
                        size = len(line.split()[-1])
                        packages_i_lst = line[-size-1:]
                        filename_i = b'/'+line[:-size-1].strip()
                        packages_i = (pkg.split(b"/")[-1].decode("utf-8").strip() for pkg in packages_i_lst.split(b","))
                        contents_db.setdefault(filename_i, set()).update(packages_i)
                _loaded_dbs.add(dbfile)
                dump = True
        updated = True
        if dump:
            dump_databases()
    result = tuple(contents_db.get(filename, set()))
    logger.info(f"File {filename!r} is associated with packages {result!r}")
    return result
