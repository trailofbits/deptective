import logging

import tqdm


class LogFormatter(logging.Formatter):
    gray = "\x1b[37;2m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    blue = "\x1b[34;1m"
    bold_red = "\x1b[31;1m"
    white = "\x1b[37;20m"
    invert = "\x1b[0;7m"
    reset = "\x1b[0m"
    base_format = f"{gray}%(asctime)s {blue}[{invert}LEVELCOLOR%(levelname)s{gray}{blue}]{reset} " \
                  f"{white}%(message)s{reset}"
    debug_info = f"{blue}({gray}%(filename)s:%(lineno)d{blue}){reset}"

    FORMAT_COLORS = {
        logging.DEBUG: gray,
        logging.INFO: gray,
        logging.WARNING: yellow,
        logging.ERROR: red,
        logging.CRITICAL: bold_red
    }

    def format(self, record) -> str:
        color = self.FORMAT_COLORS.get(record.levelno, LogFormatter.gray)
        fmt = LogFormatter.base_format.replace("LEVELCOLOR", color)
        if record.levelno <= logging.DEBUG:
            fmt = f"{fmt} {LogFormatter.debug_info}"
        formatter = logging.Formatter(fmt)
        return formatter.format(record)


class TqdmLoggingHandler(logging.Handler):
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)

    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.tqdm.write(msg)
            self.flush()
        except Exception:
            self.handleError(record)


class Logger(logging.Logger):
    def __init__(self, name, level=logging.NOTSET):
        super().__init__(name=name, level=level)

        assert not self.hasHandlers()

        handler = TqdmLoggingHandler()
        handler.setLevel(level)
        handler.setFormatter(LogFormatter())
        self.addHandler(handler)

        self.propagate = False
