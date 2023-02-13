from logging import Handler, Logger
from typing import Iterator, Optional

from rich.console import Console
from rich.logging import RichHandler


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
