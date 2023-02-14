from functools import partial
from logging import Handler, Logger, getLogger
from pathlib import Path
from typing import Iterator, Optional
from urllib.parse import urlparse
import urllib.request

from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn, DownloadColumn, Progress, TextColumn, TimeRemainingColumn, TransferSpeedColumn, TaskID
)


_logger = getLogger(__name__)


def handlers(logger: Logger) -> Iterator[Handler]:
    log: Optional[Logger] = logger
    while log is not None:
        yield from log.handlers
        log = log.parent


def get_console(logger: Logger) -> Optional[Console]:
    for handler in handlers(logger):
        if isinstance(handler, RichHandler):
            return handler.console
    return None


class Download:
    def __init__(self, progress: "DownloadWithProgress"):
        self._progress: DownloadWithProgress = progress
        self._task_id: TaskID = progress.progress.add_task("download", filename=progress.filename, start=False)
        self._response = urllib.request.urlopen(progress.url)
        self._progress.progress.update(self._task_id, total=int(self._response.info()["Content-length"]))
        self._progress.progress.start_task(self._task_id)

    def __getattr__(self, item):
        try:
            return getattr(self._response, item)
        except AttributeError:
            pass
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{item!s}'")

    def read(self, __size: int = ...) -> bytes | None:
        ret = self._response.read(__size)
        self._progress.progress.update(self._task_id, advance=len(ret))
        return ret


class DownloadWithProgress:
    def __init__(
            self,
            url: str,
            console: Optional[Console] = None,
            progress: Optional[Progress] = None
    ):
        self.url: str = url
        if console is None:
            if progress is not None:
                console = progress.console
            else:
                console = get_console(_logger)
        self.console: Console = console
        if progress is None:
            self._enter_progress: bool = True
            progress = Progress(
                TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
                BarColumn(bar_width=None),
                "[progress.percentage]{task.percentage:>3.1f}%",
                "•",
                DownloadColumn(),
                "•",
                TransferSpeedColumn(),
                "•",
                TimeRemainingColumn(),
                console=console
            )
        else:
            self._enter_progress = False
        self.progress: Progress = progress
        self.filename: str = Path(urlparse(self.url).path).name

    def __enter__(self) -> Download:
        if self._enter_progress:
            self.progress.__enter__()
        return Download(self)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._enter_progress:
            self.progress.__exit__(exc_type, exc_val, exc_tb)
        self.progress.console.log(f"Downloaded {self.filename}")


def stream_lines(data: Iterator[bytes]) -> Iterator[bytes]:
    prev_line: bytes = b""
    for chunk in data:
        lines = chunk.split(b"\n")
        if len(lines) == 1 and not lines[0]:
            if prev_line:
                yield prev_line
                prev_line = b""
        else:
            yield prev_line + lines[0]
            yield from lines[1:-1]
            if lines[-1]:
                # the chunk did not end with a newline
                prev_line = lines[-1]
            else:
                yield lines[-1]
                prev_line = b""
    if prev_line:
        yield prev_line
