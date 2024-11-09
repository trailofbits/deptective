import logging
import signal
from functools import partial, wraps
from types import FrameType
from typing import Any, Callable, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)


class SignalHandler:
    def __init__(
        self,
        signals: Iterable[int] = (
            signal.SIGINT,
            signal.SIGTERM,
            signal.SIGHUP,
            signal.SIGQUIT,
        ),
    ):
        self.handling_signals: Tuple[int, ...] = tuple(signals)
        self.signals_received: List[Tuple[int, Any]] = []
        self._old_handlers: Tuple[Callable[[int, FrameType | None], Any], ...] = ()

    @property
    def handled_signals(self) -> bool:
        return bool(self.signals_received)

    def __enter__(self):
        self.signal_received = False
        self._old_handlers = tuple(
            (signal.signal(sig, self.handler) for sig in self.handling_signals)  # type: ignore
        )

    def handler(self, sig, frame):
        self.signals_received.append((sig, frame))
        logger.warning(f"Caught {signal.Signals(sig).name}; handling...")

    def __exit__(self, type, value, traceback):
        for sig, old_handler in zip(self.handling_signals, self._old_handlers):
            signal.signal(signal.SIGINT, old_handler)


def handle_signals(
    func: Optional[Callable] = None, *, signals: Optional[Iterable[int]] = None
):
    if func is None:
        return partial(handle_signals, signals=signals)

    @wraps(func)
    def wrapper(*args, **kwargs):
        if signals is None:
            with SignalHandler():
                return func(*args, **kwargs)
        else:
            with SignalHandler(signals):
                return func(*args, **kwargs)

    return wrapper
