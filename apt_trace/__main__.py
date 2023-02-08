import logging

from .logger import Logger

logging.setLoggerClass(Logger)

from .cli import main


if __name__ == "__main__":
    main()
